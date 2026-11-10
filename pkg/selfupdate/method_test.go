package selfupdate

import "testing"

func TestDetect(t *testing.T) {
	writable := func(dirs ...string) func(string) bool {
		return func(dir string) bool {
			for _, d := range dirs {
				if d == dir {
					return true
				}
			}
			return false
		}
	}
	exists := func(paths ...string) func(string) bool { return writable(paths...) }
	tests := []struct {
		name string
		in   Installation
		want Method
	}{
		{"development build", Installation{GOOS: "linux", Version: "dev", Executable: "/home/u/bin/enbu-desktop", Writable: writable("/home/u/bin")}, MethodDevelopment},
		{"dirty build", Installation{GOOS: "linux", Version: "v1.2.3-dirty", Executable: "/home/u/bin/enbu-desktop", Writable: writable("/home/u/bin")}, MethodDevelopment},
		{"empty version", Installation{GOOS: "windows", Executable: `C:\enbu\enbu-desktop.exe`}, MethodDevelopment},
		{"linux archive in a writable directory", Installation{GOOS: "linux", Version: "v1.2.3", Executable: "/home/u/bin/enbu-desktop", Writable: writable("/home/u/bin")}, MethodSelf},
		{"linux archive in a read-only directory", Installation{GOOS: "linux", Version: "v1.2.3", Executable: "/srv/apps/enbu-desktop", Writable: writable()}, MethodManual},
		{"deb or rpm", Installation{GOOS: "linux", Version: "v1.2.3", Executable: "/usr/bin/enbu-desktop", Writable: writable("/usr/bin")}, MethodSystemPackage},
		{"linuxbrew", Installation{GOOS: "linux", Version: "v1.2.3", Executable: "/home/linuxbrew/.linuxbrew/Cellar/enbu/1.2.3/bin/enbu-desktop", Writable: writable("/home/linuxbrew/.linuxbrew/Cellar/enbu/1.2.3/bin")}, MethodHomebrew},
		{"mac app from the dmg", Installation{GOOS: "darwin", Version: "v1.2.3", Executable: "/Applications/enbu-desktop.app/Contents/MacOS/enbu-desktop", Writable: writable("/Applications"), Exists: exists()}, MethodSelf},
		{"mac app from a Homebrew cask", Installation{GOOS: "darwin", Version: "v1.2.3", Executable: "/Applications/enbu-desktop.app/Contents/MacOS/enbu-desktop", Writable: writable("/Applications"), Exists: exists("/opt/homebrew/Caskroom/enbu-desktop")}, MethodHomebrew},
		{"mac app where this user may not write", Installation{GOOS: "darwin", Version: "v1.2.3", Executable: "/Applications/enbu-desktop.app/Contents/MacOS/enbu-desktop", Writable: writable(), Exists: exists()}, MethodManual},
		{"mac binary outside a bundle", Installation{GOOS: "darwin", Version: "v1.2.3", Executable: "/Users/u/bin/enbu-desktop", Writable: writable("/Users/u/bin"), Exists: exists()}, MethodManual},
		{"windows zip", Installation{GOOS: "windows", Version: "v1.2.3", Executable: `C:\Users\u\enbu\enbu-desktop.exe`, Writable: func(string) bool { return true }}, MethodSelf},
		{"no writable check", Installation{GOOS: "linux", Version: "v1.2.3", Executable: "/home/u/enbu-desktop"}, MethodManual},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Detect(tt.in); got != tt.want {
				t.Errorf("Detect() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewer(t *testing.T) {
	tests := []struct {
		current, latest string
		want            bool
	}{
		{"v0.9.0", "v0.10.0", true},
		{"v0.9.0", "v0.9.1", true},
		{"v0.9.0", "v0.9.0", false},
		{"v1.0.0", "v0.9.9", false},
		{"dev", "v1.0.0", false},
		{"v0.9.0", "v1.0.0-rc.1", false},
		{"v0.9.0", "garbage", false},
	}
	for _, tt := range tests {
		if got := Newer(tt.current, tt.latest); got != tt.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}

func TestIsRelease(t *testing.T) {
	for version, want := range map[string]bool{
		"v1.2.3": true, "v1.2": false, "1.2.3": false, "v1.2.3-rc.1": false, "v1.2.3+meta": false, "": false, "(unset)": false,
	} {
		if got := IsRelease(version); got != want {
			t.Errorf("IsRelease(%q) = %v, want %v", version, got, want)
		}
	}
}

func TestTarget(t *testing.T) {
	if got, ok := Target("darwin", "/Applications/enbu-desktop.app/Contents/MacOS/enbu-desktop"); !ok || got != "/Applications/enbu-desktop.app" {
		t.Errorf("darwin bundle = %q, %v", got, ok)
	}
	if _, ok := Target("darwin", "/usr/local/bin/enbu-desktop"); ok {
		t.Error("a mac binary outside a bundle has no target")
	}
	if got, ok := Target("linux", "/home/u/enbu-desktop"); !ok || got != "/home/u/enbu-desktop" {
		t.Errorf("linux = %q, %v", got, ok)
	}
}

func TestAssetName(t *testing.T) {
	tests := []struct{ goos, goarch, want string }{
		{"linux", "amd64", "enbu-desktop_v0.9.0_linux_amd64.tar.gz"},
		{"linux", "arm64", "enbu-desktop_v0.9.0_linux_arm64.tar.gz"},
		{"darwin", "arm64", "enbu-desktop_v0.9.0_darwin_arm64.dmg"},
		{"windows", "amd64", "enbu-desktop_v0.9.0_windows_amd64.zip"},
	}
	for _, tt := range tests {
		if got, ok := AssetName("v0.9.0", tt.goos, tt.goarch); !ok || got != tt.want {
			t.Errorf("AssetName(%s/%s) = %q, %v", tt.goos, tt.goarch, got, ok)
		}
	}
	if _, ok := AssetName("v0.9.0", "freebsd", "amd64"); ok {
		t.Error("freebsd has no desktop release")
	}
	if _, ok := AssetName("v0.9.0", "linux", "386"); ok {
		t.Error("386 has no desktop release")
	}
}
