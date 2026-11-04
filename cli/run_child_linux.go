package cli

import (
	"os/exec"
	"runtime"
	"syscall"
)

// bindToEnbu makes the kernel kill the command if enbu dies first. Forwarded
// signals cover a SIGTERM or SIGHUP sent to enbu, but not SIGKILL, the OOM
// killer or a crash, which would leave the command running with the secrets on
// its own.
//
// Linux sends the parent-death signal when the thread that started the child
// exits, not the process (golang/go#27505), and Go ends a thread when a
// goroutine exits while locked to it. So the calling goroutine stays locked to
// its thread until release, which the caller defers past Wait. Only the command
// itself is covered; processes it starts have their own parent.
func bindToEnbu(child *exec.Cmd) (release func()) {
	runtime.LockOSThread()
	if child.SysProcAttr == nil {
		child.SysProcAttr = &syscall.SysProcAttr{}
	}
	child.SysProcAttr.Pdeathsig = syscall.SIGKILL
	return runtime.UnlockOSThread
}
