package cli

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// containCommand puts enbu into a job object that ends every process in it
// once its last handle closes. The command and the processes it starts inherit
// the job, and enbu holds the only handle, so the processes that hold the
// secrets end with enbu however it ends: Ctrl-C, a closed console, or
// TerminateProcess from Task Manager or a parent such as an editor. Windows
// cannot forward a termination signal, so without the job a killed enbu would
// leave the command running on its own.
func containCommand() error { return joinKillOnCloseJob() }

// joinKillOnCloseJob runs once per process: enbu needs one job however many
// commands it runs, as in tests.
var joinKillOnCloseJob = sync.OnceValue(func() error {
	job, err := newKillOnCloseJob()
	if err != nil {
		return err
	}
	if err := windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		_ = windows.CloseHandle(job)
		return fmt.Errorf("joining the job object: %w", err)
	}
	// The handle stays open on purpose: the job lives exactly as long as enbu.
	return nil
})

// newKillOnCloseJob creates a job that terminates its processes when its last
// handle closes. A process may still leave the job if it asks to when it
// starts a child (CREATE_BREAKAWAY_FROM_JOB), which only programs that mean to
// outlive their parent do; refusing would make them fail to start.
func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("creating a job object: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("configuring the job object: %w", err)
	}
	return job, nil
}
