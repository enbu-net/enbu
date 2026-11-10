package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// maxBinarySize bounds what an archive may unpack, so a broken or hostile
// archive cannot fill the disk. The desktop binary is about 60 MB.
const maxBinarySize = 512 << 20

// binaryName is the desktop binary inside the Linux and Windows archives.
func binaryName(goos string) string {
	if goos == "windows" {
		return "enbu-desktop.exe"
	}
	return "enbu-desktop"
}

// Install replaces target (see Target) with the app in a verified release
// archive. The new copy is written beside target first and then renamed into
// place, so a failure leaves the running app as it was.
func Install(ctx context.Context, goos, archive, target string) error {
	switch goos {
	case "linux":
		return installBinary(target, func(w io.Writer) error { return extractTarGz(archive, binaryName(goos), w) }, false)
	case "windows":
		return installBinary(target, func(w io.Writer) error { return extractZip(archive, binaryName(goos), w) }, true)
	case "darwin":
		return installApp(ctx, archive, target)
	default:
		return fmt.Errorf("self-update is not supported on %s", goos)
	}
}

// installBinary writes the new binary to target.new and renames it over
// target. Windows cannot replace a running executable, but it can rename
// one, so there the old binary moves to target.old first (see CleanUp).
func installBinary(target string, extract func(io.Writer) error, moveAside bool) error {
	next := target + ".new"
	f, err := os.OpenFile(next, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if err := extract(f); err != nil {
		_ = f.Close()
		_ = os.Remove(next)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(next)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(next)
		return err
	}
	if moveAside {
		old := target + ".old"
		_ = os.Remove(old)
		if err := os.Rename(target, old); err != nil {
			_ = os.Remove(next)
			return err
		}
		if err := os.Rename(next, target); err != nil {
			_ = os.Rename(old, target)
			_ = os.Remove(next)
			return err
		}
		return nil
	}
	if err := os.Rename(next, target); err != nil {
		_ = os.Remove(next)
		return err
	}
	return nil
}

// CleanUp removes what an earlier update left beside target: the old
// Windows binary, which could not be deleted while it ran, and a new copy an
// interrupted update did not rename into place.
func CleanUp(target string) {
	_ = os.RemoveAll(target + ".old")
	_ = os.RemoveAll(target + ".new")
}

func copyLimited(w io.Writer, r io.Reader) error {
	n, err := io.Copy(w, io.LimitReader(r, maxBinarySize+1))
	if err != nil {
		return err
	}
	if n > maxBinarySize {
		return errors.New("archive entry is too large")
	}
	return nil
}

func extractTarGz(archive, name string, w io.Writer) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%s is not in the archive", name)
		}
		if err != nil {
			return err
		}
		if header.Typeflag == tar.TypeReg && path.Clean(header.Name) == name {
			return copyLimited(w, tr)
		}
	}
}

func extractZip(archive, name string, w io.Writer) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()
	for _, file := range zr.File {
		if path.Clean(file.Name) != name || file.FileInfo().IsDir() {
			continue
		}
		r, err := file.Open()
		if err != nil {
			return err
		}
		defer func() { _ = r.Close() }()
		return copyLimited(w, r)
	}
	return fmt.Errorf("%s is not in the archive", name)
}

// installApp mounts the disk image, copies the app bundle in it beside
// target with ditto (which keeps the bundle's signature and attributes), and
// swaps the two bundles by renaming.
func installApp(ctx context.Context, dmg, target string) error {
	mount, err := os.MkdirTemp("", "enbu-update-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(mount) }()
	attach := exec.CommandContext(ctx, "hdiutil", "attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", mount, dmg)
	if out, err := attach.CombinedOutput(); err != nil {
		return fmt.Errorf("mount the update: %w: %s", err, strings.TrimSpace(string(out)))
	}
	defer func() { _ = exec.Command("hdiutil", "detach", mount, "-force").Run() }()

	apps, err := filepath.Glob(filepath.Join(mount, "*.app"))
	if err != nil || len(apps) != 1 {
		return fmt.Errorf("the update holds %d app bundles, want 1", len(apps))
	}
	next := target + ".new"
	_ = os.RemoveAll(next)
	if out, err := exec.CommandContext(ctx, "ditto", apps[0], next).CombinedOutput(); err != nil {
		_ = os.RemoveAll(next)
		return fmt.Errorf("copy the update: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return swapDirs(target, next)
}

// swapDirs puts next in target's place and removes the old target.
func swapDirs(target, next string) error {
	old := target + ".old"
	_ = os.RemoveAll(old)
	if err := os.Rename(target, old); err != nil {
		_ = os.RemoveAll(next)
		return err
	}
	if err := os.Rename(next, target); err != nil {
		_ = os.Rename(old, target)
		_ = os.RemoveAll(next)
		return err
	}
	_ = os.RemoveAll(old)
	return nil
}
