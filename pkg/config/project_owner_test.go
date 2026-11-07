//go:build linux || darwin

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSaveProjectPreservesSupplementaryGroup(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	group := -1
	for _, candidate := range groups {
		if candidate != os.Getegid() {
			group = candidate
			break
		}
	}
	if group == -1 {
		t.Skip("a supplementary group is required to exercise shared-file ownership")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "enbu.toml")
	original, err := MarshalProject(atomicProjectFixture("before"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, original, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, -1, group); err != nil {
		t.Fatal(err)
	}
	if err := SaveProjectTo(dir, atomicProjectFixture("after")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if int(stat.Uid) != os.Geteuid() || int(stat.Gid) != group || info.Mode().Perm() != 0o640 {
		t.Fatalf("shared configuration lost ownership/access: uid=%d gid=%d mode=%v", stat.Uid, stat.Gid, info.Mode())
	}
}
