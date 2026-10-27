package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/desktop"
	"github.com/enbu-net/enbu/pkg/apperr"
)

// client drives a Server over in-memory pipes.
type client struct {
	t    *testing.T
	in   *io.PipeWriter
	out  *bufio.Scanner
	done chan error
	core *desktop.Service
}

func startServer(t *testing.T) *client {
	t.Helper()
	return startServerWith(t, nil)
}

// startServerWith serves a server that patch can change before it starts.
func startServerWith(t *testing.T, patch func(*Server)) *client {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")

	core := desktop.NewService(app.New())
	core.AppVersion = "1.2.3"
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	done := make(chan error, 1)
	server := NewServer(core)
	if patch != nil {
		patch(server)
	}
	go func() {
		done <- server.Serve(context.Background(), reqR, respW)
		_ = respW.Close()
	}()
	c := &client{t: t, in: reqW, out: bufio.NewScanner(respR), done: done, core: core}
	t.Cleanup(func() {
		_ = reqW.Close()
		go func() {
			for c.out.Scan() {
			}
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve() did not return after stdin closed")
		}
	})
	return c
}

func (c *client) send(raw string) {
	c.t.Helper()
	if _, err := io.WriteString(c.in, raw+"\n"); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *client) request(id int, method string, params ...any) {
	c.t.Helper()
	msg := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	data, err := json.Marshal(msg)
	if err != nil {
		c.t.Fatalf("marshal: %v", err)
	}
	c.send(string(data))
}

func (c *client) receive() message {
	c.t.Helper()
	if !c.out.Scan() {
		c.t.Fatalf("no message from server: %v", c.out.Err())
	}
	var msg message
	if err := json.Unmarshal(c.out.Bytes(), &msg); err != nil {
		c.t.Fatalf("unmarshal %q: %v", c.out.Bytes(), err)
	}
	return msg
}

func TestMethodsMatchDesktopBindings(t *testing.T) {
	// desktop/wails is a main package that needs the native toolkit to build,
	// so read the bound methods from its source.
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "wails", "binding.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse binding.go: %v", err)
	}
	var bound []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || !fn.Name.IsExported() {
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if ident, isIdent := star.X.(*ast.Ident); ok && isIdent && ident.Name == "DesktopService" {
			bound = append(bound, fn.Name.Name)
		}
	}
	got := slices.Sorted(slices.Values(Methods))
	slices.Sort(bound)
	if !slices.Equal(got, bound) {
		t.Errorf("Methods = %v\nwant the methods bound in desktop/wails: %v", got, bound)
	}
}

func TestInitialize(t *testing.T) {
	c := startServer(t)
	c.request(1, "initialize")
	resp := c.receive()
	if resp.Error != nil {
		t.Fatalf("initialize error = %+v", resp.Error)
	}
	var got InitializeResult
	if err := json.Unmarshal(resp.Result, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if got.ProtocolVersion != ProtocolVersion || got.AppVersion != "1.2.3" || len(got.Methods) != len(Methods) {
		t.Errorf("initialize = %+v", got)
	}
	if !slices.Contains(got.Events, desktop.EventProgress) {
		t.Errorf("events = %v, want %q", got.Events, desktop.EventProgress)
	}
}

func TestCallsServiceMethods(t *testing.T) {
	c := startServer(t)

	c.request(1, "GetAppVersion")
	resp := c.receive()
	if string(resp.ID) != "1" || string(resp.Result) != `"1.2.3"` {
		t.Errorf("GetAppVersion response = id %s result %s error %+v", resp.ID, resp.Result, resp.Error)
	}

	c.request(2, "ListRepositories")
	resp = c.receive()
	if resp.Error != nil || string(resp.Result) == "" {
		t.Errorf("ListRepositories response = result %s error %+v", resp.Result, resp.Error)
	}
}

func TestApplicationErrorCarriesPayload(t *testing.T) {
	c := startServer(t)
	c.request(1, "SelectRepository", filepath.Join(t.TempDir(), "missing"))
	resp := c.receive()
	if resp.Error == nil || resp.Error.Code != codeApplication || resp.Error.Data == nil {
		t.Fatalf("error = %+v, want an application error with a payload", resp.Error)
	}
	if resp.Error.Data.Code != apperr.CodeInvalidArgument {
		t.Errorf("payload code = %q, want %q", resp.Error.Data.Code, apperr.CodeInvalidArgument)
	}
}

func TestRejectsBadRequests(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		code int
	}{
		{"invalid JSON", `{`, codeParseError},
		{"wrong version", `{"jsonrpc":"1.0","id":1,"method":"GetAppVersion"}`, codeInvalidRequest},
		{"unknown method", `{"jsonrpc":"2.0","id":1,"method":"Start"}`, codeMethodNotFound},
		{"params not an array", `{"jsonrpc":"2.0","id":1,"method":"ListSecrets","params":{"env":"dev"}}`, codeInvalidParams},
		{"too many params", `{"jsonrpc":"2.0","id":1,"method":"ListSecrets","params":["dev","x"]}`, codeInvalidParams},
		{"wrong param type", `{"jsonrpc":"2.0","id":1,"method":"ListSecrets","params":[1]}`, codeInvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := startServer(t)
			c.send(tt.raw)
			resp := c.receive()
			if resp.Error == nil || resp.Error.Code != tt.code {
				t.Errorf("error = %+v, want code %d", resp.Error, tt.code)
			}
		})
	}
}

func TestNotificationGetsNoResponse(t *testing.T) {
	c := startServer(t)
	c.send(`{"jsonrpc":"2.0","method":"GetAppVersion"}`)
	c.request(2, "GetAppVersion")
	if resp := c.receive(); string(resp.ID) != "2" {
		t.Errorf("first response id = %s, want 2", resp.ID)
	}
}

func TestEventsBecomeNotifications(t *testing.T) {
	c := startServer(t)
	// Serve installs the emitter before it reads; a request round trip
	// guarantees that has happened.
	c.request(1, "GetAppVersion")
	c.receive()

	// The pipe blocks the writer until the test reads.
	go c.core.OnProgress("fetching")
	msg := c.receive()
	if msg.Method != methodEvent || msg.ID != nil {
		t.Fatalf("message = %+v, want an event notification", msg)
	}
	var params struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		t.Fatalf("unmarshal params: %v", err)
	}
	if params.Name != desktop.EventProgressMessage || params.Data != "fetching" {
		t.Errorf("event = %+v", params)
	}
}

func TestBrowseRepositoryAsksClientForDirectory(t *testing.T) {
	c := startServer(t)
	c.request(1, "BrowseRepository")

	ask := c.receive()
	if ask.Method != methodPickDir || ask.ID == nil {
		t.Fatalf("message = %+v, want a pickDirectory request", ask)
	}
	// The person closed the dialog without choosing.
	c.send(`{"jsonrpc":"2.0","id":` + string(ask.ID) + `,"result":""}`)

	resp := c.receive()
	if resp.Error != nil || string(resp.ID) != "1" {
		t.Fatalf("BrowseRepository response = %+v", resp)
	}
	var repo desktop.RepoInfo
	if err := json.Unmarshal(resp.Result, &repo); err != nil || repo.Path != "" {
		t.Errorf("repo = %+v (%v), want none selected", repo, err)
	}
}

func TestClientErrorFailsServerCall(t *testing.T) {
	c := startServer(t)
	c.request(1, "BrowseRepository")
	ask := c.receive()
	c.send(`{"jsonrpc":"2.0","id":` + string(ask.ID) + `,"error":{"code":-32000,"message":"no window"}}`)

	resp := c.receive()
	if resp.Error == nil || resp.Error.Data == nil || resp.Error.Data.Code != apperr.CodeInternal {
		t.Errorf("error = %+v, want an internal application error", resp.Error)
	}
}

func TestPendingCallsFailWhenClientLeaves(t *testing.T) {
	c := startServer(t)
	c.request(1, "BrowseRepository")
	if ask := c.receive(); ask.Method != methodPickDir {
		t.Fatalf("message = %+v, want a pickDirectory request", ask)
	}
	// Closing stdin must not leave Serve waiting for the dialog; the cleanup
	// fails the test if Serve does not return.
}

func TestPanicRepliesInternalAndKeepsServing(t *testing.T) {
	c := startServerWith(t, func(s *Server) {
		s.methods["ListSecrets"] = reflect.ValueOf(func(env string) (desktop.SecretsResponse, error) {
			panic("secret value " + env)
		})
	})
	c.request(1, "ListSecrets", "dev")
	resp := c.receive()
	if resp.Error == nil || resp.Error.Data == nil || resp.Error.Data.Code != apperr.CodeInternal {
		t.Fatalf("error = %+v, want an internal application error", resp.Error)
	}
	if strings.Contains(resp.Error.Message, "secret") {
		t.Errorf("error message %q leaks the panic value", resp.Error.Message)
	}

	c.request(2, "GetAppVersion")
	if resp := c.receive(); string(resp.Result) != `"1.2.3"` {
		t.Errorf("after a panic GetAppVersion = %s, %+v", resp.Result, resp.Error)
	}
}
