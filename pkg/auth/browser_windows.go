package auth

import "golang.org/x/sys/windows"

// systemDirectory is System32, where Windows keeps rundll32.exe.
func systemDirectory() string {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return `C:\Windows\System32`
	}
	return dir
}
