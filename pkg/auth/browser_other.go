//go:build !windows

package auth

// systemDirectory is where Windows keeps rundll32.exe. Other platforms only
// build the Windows command in tests.
func systemDirectory() string { return `C:\Windows\System32` }
