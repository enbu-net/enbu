package process

import "golang.org/x/sys/unix"

// Harden keeps other processes of the same user out of enbu's memory, which
// holds decrypted secrets and, with the keyring backend, the private key. A
// process that is not dumpable cannot be attached to with ptrace or read
// through /proc/PID/mem by a non-root process of the same user, even where
// Yama's ptrace_scope allows it, and leaves no core dump. ssh-agent and
// gpg-agent do the same. execve makes a command started by enbu run dumpable
// again, so it behaves as if run directly.
func Harden() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
