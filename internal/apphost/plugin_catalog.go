package apphost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/platform"
	"github.com/enbu-net/enbu/pkg/plugin"
	"github.com/opencontainers/go-digest"
)

var (
	ErrPluginNotInstalled = errors.New("apphost: plugin is not installed")
	ErrPluginCatalog      = errors.New("apphost: invalid plugin catalog")
)

// PluginResolver returns only capabilities that have been re-verified against
// separately provisioned local trust. A repository digest can select an
// installed package but cannot create trust.
type PluginResolver interface {
	Resolve(context.Context, digest.Digest) (plugin.VerifiedPackage, error)
}

type PluginInstaller interface {
	Install(context.Context, io.Reader, io.Reader) (digest.Digest, error)
}

type filePluginCatalog struct{ root string }

// InstallPlugin is a device-scoped trust operation. It is intentionally not a
// workspace Action: installed code gains no workspace access until a later,
// explicit TransformAction supplies immutable input capabilities.
func (runtime *Runtime) InstallPlugin(ctx context.Context, packageSource, trustSource io.Reader) (digest.Digest, error) {
	if err := runtime.validateContext(ctx); err != nil {
		return "", err
	}
	installer, ok := runtime.plugins.(PluginInstaller)
	if !ok || installer == nil {
		return "", ErrPluginCatalog
	}
	return installer.Install(ctx, packageSource, trustSource)
}

func newFilePluginCatalog(root string) (*filePluginCatalog, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrPluginCatalog
	}
	if err := platform.EnsurePrivateDir(root); err != nil {
		return nil, err
	}
	return &filePluginCatalog{root: root}, nil
}

// Install treats the supplied TrustGrant as an explicit local trust decision.
// Organization grants require an authenticated organization delivery channel
// and are intentionally rejected by this local-file entry point.
func (catalog *filePluginCatalog) Install(ctx context.Context, packageSource, trustSource io.Reader) (digest.Digest, error) {
	if ctx == nil || packageSource == nil || trustSource == nil {
		return "", ErrPluginCatalog
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	packageBytes, err := readBounded(ctx, packageSource, plugin.MaxPackageBytes)
	if err != nil {
		return "", err
	}
	defer clearBuffer(packageBytes)
	trustBytes, err := readBounded(ctx, trustSource, plugin.MaxTrustGrantBytes)
	if err != nil {
		return "", err
	}
	defer clearBuffer(trustBytes)
	pkg, err := plugin.DecodePackage(packageBytes)
	if err != nil {
		return "", err
	}
	grant, err := plugin.DecodeTrustGrant(trustBytes)
	if err != nil {
		return "", err
	}
	if grant.Scope != plugin.TrustScopeLocal {
		return "", fmt.Errorf("%w: unauthenticated organization trust grant", plugin.ErrUntrustedPackage)
	}
	verified, err := plugin.VerifyPackage(pkg, grant)
	if err != nil {
		return "", err
	}
	directory := catalog.packageDirectory(verified.Digest())
	if err := platform.EnsurePrivateDir(directory); err != nil {
		return "", err
	}
	// The package is the local visibility point. A crash after the trust write
	// but before the package write leaves no resolvable plugin capability.
	if err := writeSecure(filepath.Join(directory, "trust.cbor"), trustBytes); err != nil {
		return "", err
	}
	if err := writeSecure(filepath.Join(directory, "package.cbor"), packageBytes); err != nil {
		return "", err
	}
	return verified.Digest(), nil
}

func (catalog *filePluginCatalog) Resolve(ctx context.Context, requested digest.Digest) (plugin.VerifiedPackage, error) {
	if catalog == nil || ctx == nil || requested.Validate() != nil || requested.Algorithm() != digest.SHA256 {
		return plugin.VerifiedPackage{}, ErrPluginCatalog
	}
	if err := ctx.Err(); err != nil {
		return plugin.VerifiedPackage{}, err
	}
	directory := catalog.packageDirectory(requested)
	packageBytes, err := readRegularBounded(ctx, filepath.Join(directory, "package.cbor"), plugin.MaxPackageBytes)
	if errors.Is(err, os.ErrNotExist) {
		return plugin.VerifiedPackage{}, ErrPluginNotInstalled
	}
	if err != nil {
		return plugin.VerifiedPackage{}, err
	}
	defer clearBuffer(packageBytes)
	trustBytes, err := readRegularBounded(ctx, filepath.Join(directory, "trust.cbor"), plugin.MaxTrustGrantBytes)
	if errors.Is(err, os.ErrNotExist) {
		return plugin.VerifiedPackage{}, ErrPluginNotInstalled
	}
	if err != nil {
		return plugin.VerifiedPackage{}, err
	}
	defer clearBuffer(trustBytes)
	pkg, err := plugin.DecodePackage(packageBytes)
	if err != nil {
		return plugin.VerifiedPackage{}, err
	}
	grant, err := plugin.DecodeTrustGrant(trustBytes)
	if err != nil || grant.Scope != plugin.TrustScopeLocal {
		return plugin.VerifiedPackage{}, fmt.Errorf("%w: local trust record", plugin.ErrUntrustedPackage)
	}
	verified, err := plugin.VerifyPackage(pkg, grant)
	if err != nil {
		return plugin.VerifiedPackage{}, err
	}
	if verified.Digest() != requested {
		return plugin.VerifiedPackage{}, fmt.Errorf("%w: requested digest mismatch", plugin.ErrUntrustedPackage)
	}
	return verified, nil
}

func (catalog *filePluginCatalog) packageDirectory(value digest.Digest) string {
	return filepath.Join(catalog.root, value.Encoded())
}

func readRegularBounded(ctx context.Context, path string, maximum int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > int64(maximum) {
		return nil, ErrPluginCatalog
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, readErr := readBounded(ctx, file, maximum)
	closeErr := file.Close()
	return data, errors.Join(readErr, closeErr)
}

func readBounded(ctx context.Context, source io.Reader, maximum int) ([]byte, error) {
	if maximum <= 0 {
		return nil, ErrPluginCatalog
	}
	var buffer bytes.Buffer
	if _, err := io.Copy(&buffer, &contextReader{ctx: ctx, reader: io.LimitReader(source, int64(maximum)+1)}); err != nil {
		return nil, err
	}
	if buffer.Len() == 0 || buffer.Len() > maximum {
		clearBuffer(buffer.Bytes())
		return nil, ErrPluginCatalog
	}
	return buffer.Bytes(), nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func writeSecure(path string, data []byte) error {
	writer, err := platform.NewSecureWriter(path)
	if err != nil {
		return err
	}
	defer func() { _ = writer.Abort() }()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

func clearBuffer(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
