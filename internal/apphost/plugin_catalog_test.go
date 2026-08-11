package apphost

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/enbu-net/enbu/pkg/plugin"
)

func TestFilePluginCatalogInstallsAndReverifiesExactLocalTrust(t *testing.T) {
	t.Parallel()

	catalog, err := newFilePluginCatalog(filepath.Join(t.TempDir(), "plugins"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	namespaces := []plugin.TypeNamespace{{Group: "plugins.example.net", Version: "v1alpha1"}}
	pkg, err := plugin.NewPackage([]byte("\x00asm\x01\x00\x00\x00"), "plugins.example.net", "github:123", namespaces)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err = plugin.SignPackage(pkg, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	packageDigest, err := plugin.PackageDigest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := plugin.NewTrustGrant(plugin.TrustScopeLocal, packageDigest, pkg.Issuer, pkg.Subject, namespaces, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	packageBytes, err := plugin.EncodePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	trustBytes, err := plugin.EncodeTrustGrant(grant)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := catalog.Install(context.Background(), bytes.NewReader(packageBytes), bytes.NewReader(trustBytes))
	if err != nil {
		t.Fatal(err)
	}
	if installed != packageDigest {
		t.Fatalf("installed digest = %s, want %s", installed, packageDigest)
	}
	verified, err := catalog.Resolve(context.Background(), packageDigest)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Digest() != packageDigest {
		t.Fatalf("resolved digest = %s", verified.Digest())
	}

	path := filepath.Join(catalog.packageDirectory(packageDigest), "package.cbor")
	if err := os.WriteFile(path, append(packageBytes, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Resolve(context.Background(), packageDigest); err == nil {
		t.Fatal("tampered installed package resolved")
	}
}

func TestFilePluginCatalogRejectsUnauthenticatedOrganizationTrust(t *testing.T) {
	t.Parallel()

	catalog, err := newFilePluginCatalog(filepath.Join(t.TempDir(), "plugins"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	namespaces := []plugin.TypeNamespace{{Group: "plugins.example.net", Version: "v1alpha1"}}
	pkg, err := plugin.NewPackage([]byte("\x00asm\x01\x00\x00\x00"), "plugins.example.net", "github:123", namespaces)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err = plugin.SignPackage(pkg, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	packageDigest, err := plugin.PackageDigest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := plugin.NewTrustGrant(plugin.TrustScopeOrganization, packageDigest, pkg.Issuer, pkg.Subject, namespaces, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	packageBytes, _ := plugin.EncodePackage(pkg)
	trustBytes, _ := plugin.EncodeTrustGrant(grant)
	if _, err := catalog.Install(context.Background(), bytes.NewReader(packageBytes), bytes.NewReader(trustBytes)); !errors.Is(err, plugin.ErrUntrustedPackage) {
		t.Fatalf("Install organization trust = %v", err)
	}
}
