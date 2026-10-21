package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/spf13/cobra"
)

func TestDebugShowsTheCauseOfAnInternalError(t *testing.T) {
	cause := errors.New("open /dev/tpmrm0: permission denied")
	render := func() string {
		cmd := &cobra.Command{Use: "enbu"}
		cmd.PersistentFlags().Bool("json", false, "")
		var errOut bytes.Buffer
		cmd.SetErr(&errOut)
		RenderExecutionError(cmd, apperr.Wrap(apperr.CodeInternal, "unexpected error", cause, nil), nil)
		return errOut.String()
	}
	if out := render(); strings.Contains(out, "permission denied") {
		t.Fatalf("cause shown without ENBU_DEBUG: %q", out)
	}
	t.Setenv("ENBU_DEBUG", "1")
	if out := render(); !strings.Contains(out, "permission denied") {
		t.Fatalf("cause hidden with ENBU_DEBUG: %q", out)
	}
}
