// reproarchive writes release archives whose bytes depend only on the files
// they hold: entries in a fixed order, the time from SOURCE_DATE_EPOCH, owner
// root, mode 0644 or 0755, and Go's own compressor, so two builds of the same
// commit give the same archive on any machine.
//
//	reproarchive zip OUT.zip DIR            pack DIR's files, sorted by path
<<<<<<< HEAD
//	reproarchive tar OUT.tar.gz DIR         the same as a gzip-compressed tar
=======
>>>>>>> origin/main
//	reproarchive rezip FILE.zip             rewrite a zip in place, keeping its entry order
package main

import (
<<<<<<< HEAD
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
=======
	"archive/zip"
	"bytes"
	"compress/flate"
>>>>>>> origin/main
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
<<<<<<< HEAD
	"path"
=======
>>>>>>> origin/main
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "reproarchive:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 2 {
<<<<<<< HEAD
		return errors.New("usage: reproarchive zip|tar OUT DIR | rezip FILE")
=======
		return errors.New("usage: reproarchive zip OUT DIR | rezip FILE")
>>>>>>> origin/main
	}
	mtime, err := sourceDate(os.Getenv("SOURCE_DATE_EPOCH"))
	if err != nil {
		return err
	}
	switch {
	case args[0] == "zip" && len(args) == 3:
		files, err := collect(args[2])
		if err != nil {
			return err
		}
		return writeFile(args[1], func(w io.Writer) error { return writeZip(w, files, mtime) })
<<<<<<< HEAD
	case args[0] == "tar" && len(args) == 3:
		files, err := collect(args[2])
		if err != nil {
			return err
		}
		return writeFile(args[1], func(w io.Writer) error { return writeTarGz(w, files, mtime) })
=======
>>>>>>> origin/main
	case args[0] == "rezip" && len(args) == 2:
		files, err := readZip(args[1])
		if err != nil {
			return err
		}
		return writeFile(args[1], func(w io.Writer) error { return writeZip(w, files, mtime) })
	}
	return fmt.Errorf("unknown command %q", args)
}

// sourceDate reads SOURCE_DATE_EPOCH (https://reproducible-builds.org/specs/source-date-epoch/).
// It is required: without it the archive would carry the build time.
func sourceDate(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, errors.New("SOURCE_DATE_EPOCH is not set (use the commit time: git log -1 --format=%ct)")
	}
	sec, err := strconv.ParseInt(v, 10, 64)
	if err != nil || sec < 0 {
		return time.Time{}, fmt.Errorf("SOURCE_DATE_EPOCH %q is not a Unix time", v)
	}
<<<<<<< HEAD
	// Zip times have two-second steps and no time zone; tar keeps whole seconds.
=======
	// Zip times have two-second steps and no time zone.
>>>>>>> origin/main
	return time.Unix(sec, 0).UTC(), nil
}

type entry struct {
	name string // slash-separated, relative
	exec bool
	data []byte
}

// collect reads every regular file under dir, sorted by path.
func collect(dir string) ([]entry, error) {
	var files []entry
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s: only regular files can be archived", p)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files = append(files, entry{name: filepath.ToSlash(rel), exec: info.Mode()&0o111 != 0, data: data})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s has no files", dir)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	return files, nil
}

// readZip reads a zip's files in their stored order; that order can matter
// (a VSIX lists [Content_Types].xml and its manifest first).
func readZip(name string) ([]entry, error) {
	r, err := zip.OpenReader(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	var files []entry
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		files = append(files, entry{name: f.Name, exec: f.Mode()&0o111 != 0, data: data})
	}
	return files, nil
}

func mode(e entry) fs.FileMode {
	if e.exec {
		return 0o755
	}
	return 0o644
}

func writeZip(w io.Writer, files []entry, mtime time.Time) error {
	zw := zip.NewWriter(w)
	zw.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestCompression)
	})
	for _, e := range files {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: mtime}
		h.SetMode(mode(e))
		fw, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		if _, err := fw.Write(e.data); err != nil {
			return err
		}
	}
	return zw.Close()
}

<<<<<<< HEAD
func writeTarGz(w io.Writer, files []entry, mtime time.Time) error {
	gz, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return err
	}
	// The gzip header keeps no name and no time.
	tw := tar.NewWriter(gz)
	dirs := map[string]bool{}
	for _, e := range files {
		// Parent directories first, so extracting gives them a fixed mode too.
		for _, d := range parents(e.name) {
			if dirs[d] {
				continue
			}
			dirs[d] = true
			if err := tw.WriteHeader(&tar.Header{
				Typeflag: tar.TypeDir, Name: d + "/", Mode: 0o755, ModTime: mtime,
				Uname: "root", Gname: "root", Format: tar.FormatPAX,
			}); err != nil {
				return err
			}
		}
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: e.name, Mode: int64(mode(e)), Size: int64(len(e.data)), ModTime: mtime,
			Uname: "root", Gname: "root", Format: tar.FormatPAX,
		}); err != nil {
			return err
		}
		if _, err := tw.Write(e.data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// parents lists the directories above name, outermost first.
func parents(name string) []string {
	var out []string
	for d := path.Dir(name); d != "."; d = path.Dir(d) {
		out = append([]string{d}, out...)
	}
	return out
}

=======
>>>>>>> origin/main
// writeFile builds the archive in memory and then replaces name, so rezip can
// rewrite the file it read and a failure leaves nothing half written.
func writeFile(name string, build func(io.Writer) error) error {
	var buf bytes.Buffer
	if err := build(&buf); err != nil {
		return err
	}
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}
