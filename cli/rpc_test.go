package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
)

func TestRPCServesDesktopServiceOverStdio(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	cmd := NewWithApp("1.2.3", app.New())
	var stdout bytes.Buffer
	cmd.SetIn(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"GetAppVersion"}` + "\n"))
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"rpc", "--stdio"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("rpc --stdio: %v", err)
	}
	var resp struct {
		ID     int    `json:"id"`
		Result string `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("stdout %q is not one JSON-RPC response: %v", stdout.String(), err)
	}
	if resp.ID != 1 || resp.Result != "1.2.3" {
		t.Errorf("response = %+v, want id 1 result 1.2.3", resp)
	}
}

func TestRPCNeedsStdio(t *testing.T) {
	cmd := NewWithApp("1.2.3", app.New())
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"rpc"})
	if err := cmd.Execute(); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Errorf("rpc without --stdio error = %v, want %q", err, apperr.CodeInvalidArgument)
	}
}

func TestRPCIsHidden(t *testing.T) {
	cmd := NewWithApp("1.2.3", app.New())
	rpc, _, err := cmd.Find([]string{"rpc"})
	if err != nil || rpc.Name() != "rpc" || !rpc.Hidden {
		t.Errorf("rpc command = %v (%v), want a hidden command", rpc, err)
	}
}
