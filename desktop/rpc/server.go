// Package rpc serves desktop.Service over JSON-RPC 2.0 on a byte stream, one
// JSON message per line. Editor extensions run `enbu rpc --stdio` as a child
// process and show the same frontend as the desktop app against it.
//
// Requests call the methods in Methods with positional params. The server sends
// backend events as "event" notifications and asks the client for what needs
// the editor: "pickDirectory" (a native folder dialog) and "openExternal" (the
// OS browser).
//
// Requests are handled concurrently, as the desktop app's binding calls are:
// a folder dialog or a GitHub sign-in waits on the client while other calls go
// on. A client that needs one call to finish before the next, such as a write
// before a sync, waits for its response first, as the UI does.
//
// Params and results carry secret values. Nothing here logs them.
package rpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strconv"
	"sync"

	"github.com/enbu-net/enbu/desktop"
	"github.com/enbu-net/enbu/pkg/apperr"
)

// ProtocolVersion changes when a client built for an older server can no
// longer talk to this one.
const ProtocolVersion = 1

// Methods are the desktop.Service methods a client may call. They are the
// methods desktop/wails binds for the desktop app, by the same names.
var Methods = []string{
	"GetAuthStatus",
	"StartOAuthLogin",
	"GetOAuthLoginStatus",
	"CancelOAuthLogin",
	"Logout",
	"BrowseRepository",
	"SelectRepository",
	"GetRepoStatus",
	"Initialize",
	"SuggestStorage",
	"ListEnvironments",
	"CreateEnvironment",
	"SwitchEnvironment",
	"RenameEnvironment",
	"DeleteEnvironment",
	"PurgeIncarnation",
	"ListSecrets",
	"AddSecret",
	"EditSecret",
	"DeleteSecret",
	"PullSecrets",
	"SyncSecrets",
	"ListConflicts",
	"ResolveConflicts",
	"ImportSecrets",
	"ListHistory",
	"DiffHistory",
	"RestoreHistory",
	"ListRepositories",
	"RemoveRepository",
	"ListMembers",
	"ListJoinRequests",
	"ApproveMember",
	"RemoveMember",
	"SetAdmin",
	"ResolveMemberFork",
	"GetIdentity",
	"DiagnoseIdentity",
	"UpgradeIdentity",
	"ReadConfig",
	"WriteConfig",
	"GetAppVersion",
}

// Methods handled by the server itself rather than desktop.Service.
const (
	methodInitialize = "initialize"
	methodEvent      = "event"
	methodPickDir    = "pickDirectory"
	methodOpenURL    = "openExternal"
)

// JSON-RPC error codes. An application error carries its AppError payload as
// the error's data, so the client shows it the way the desktop app does.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeApplication    = -32000
)

// maxMessageSize bounds one message; a variable so tests can lower it.
var maxMessageSize = 16 << 20

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a JSON-RPC error object.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    *apperr.Payload `json:"data,omitempty"`
}

func (e *Error) Error() string { return e.Message }

// UnmarshalJSON accepts any data a client puts in an error, as JSON-RPC allows;
// only an AppError payload is kept. A response that failed to decode would
// leave the call waiting for it.
func (e *Error) UnmarshalJSON(data []byte) error {
	var wire struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	e.Code, e.Message, e.Data = wire.Code, wire.Message, nil
	var payload apperr.Payload
	if len(wire.Data) > 0 && json.Unmarshal(wire.Data, &payload) == nil && payload.Code != "" {
		e.Data = &payload
	}
	return nil
}

// InitializeResult answers the "initialize" request a client sends first.
type InitializeResult struct {
	ProtocolVersion int      `json:"protocol_version"`
	AppVersion      string   `json:"app_version"`
	Methods         []string `json:"methods"`
	Events          []string `json:"events"`
}

type eventParams struct {
	Name string `json:"name"`
	Data any    `json:"data"`
}

// Server is one connection to one client.
type Server struct {
	core    *desktop.Service
	methods map[string]reflect.Value

	writeMu sync.Mutex
	enc     *json.Encoder

	callMu  sync.Mutex
	nextID  int
	pending map[string]chan message

	wg sync.WaitGroup
}

// NewServer serves core and routes its dialogs, browser and events to the
// client. It panics when a name in Methods is not a method of desktop.Service.
func NewServer(core *desktop.Service) *Server {
	s := &Server{
		core:    core,
		methods: make(map[string]reflect.Value, len(Methods)),
		pending: make(map[string]chan message),
	}
	value := reflect.ValueOf(core)
	for _, name := range Methods {
		m := value.MethodByName(name)
		if !m.IsValid() {
			panic("rpc: desktop.Service has no method " + name)
		}
		s.methods[name] = m
	}
	return s
}

// Serve reads requests from r and writes responses to w until r ends, then
// waits for the calls in flight. Cancelling ctx cancels the calls in flight.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	s.enc = json.NewEncoder(w)
	s.core.Start(ctx)
	s.core.SetEventEmitter(func(name string, data any) {
		s.notify(methodEvent, eventParams{Name: name, Data: data})
	})
	s.core.SetDirectoryPicker(func(ctx context.Context) (string, error) {
		var path string
		err := s.call(ctx, methodPickDir, nil, &path)
		return path, err
	})
	s.core.SetBrowserOpener(func(url string) error {
		return s.call(ctx, methodOpenURL, []string{url}, nil)
	})

	reader := bufio.NewReaderSize(r, 64<<10)
	var readErr error
	for {
		line, err := readLine(reader)
		if errors.Is(err, errTooLong) {
			s.reply(nil, nil, &Error{Code: codeInvalidRequest, Message: "message too large"})
			continue
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
		if len(line) == 0 {
			continue
		}
		var msg message
		if err := json.Unmarshal(line, &msg); err != nil {
			s.reply(nil, nil, &Error{Code: codeParseError, Message: "invalid JSON"})
			continue
		}
		if msg.Method == "" {
			s.resolve(msg)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(msg)
		}()
	}
	cancel()
	s.failPending()
	s.wg.Wait()
	// Nothing is left to answer; the service must not write to a closed stream.
	s.core.SetEventEmitter(nil)
	s.core.SetDirectoryPicker(nil)
	s.core.SetBrowserOpener(nil)
	return readErr
}

var errTooLong = errors.New("rpc message too large")

// readLine reads one message. A line over maxMessageSize is skipped to its end
// and reported as errTooLong, so the next message is read as usual.
func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	tooLong := false
	for {
		chunk, err := r.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > maxMessageSize {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case err != nil && (len(line) == 0 || !errors.Is(err, io.EOF)):
			return nil, err
		case tooLong:
			return nil, errTooLong
		default:
			return bytes.TrimSpace(line), nil
		}
	}
}

func (s *Server) handle(msg message) {
	// A panic in one method must not end the process and every other call with
	// it. Its value and stack can hold arguments, which can be secret values,
	// so neither is logged.
	defer func() {
		if recover() != nil {
			s.reply(msg.ID, nil, applicationError(msg.Method, errors.New("method panicked")))
		}
	}()
	if msg.JSONRPC != "2.0" {
		s.reply(msg.ID, nil, &Error{Code: codeInvalidRequest, Message: "jsonrpc must be 2.0"})
		return
	}
	if msg.Method == methodInitialize {
		s.reply(msg.ID, InitializeResult{
			ProtocolVersion: ProtocolVersion,
			AppVersion:      s.core.GetAppVersion(),
			Methods:         Methods,
			Events:          []string{desktop.EventProgress, desktop.EventProgressMessage, desktop.EventConflictRetry},
		}, nil)
		return
	}
	method, ok := s.methods[msg.Method]
	if !ok {
		s.reply(msg.ID, nil, &Error{Code: codeMethodNotFound, Message: "method not found: " + msg.Method})
		return
	}
	args, err := decodeParams(method.Type(), msg.Params)
	if err != nil {
		s.reply(msg.ID, nil, &Error{Code: codeInvalidParams, Message: err.Error()})
		return
	}
	result, err := invoke(method, args)
	if err != nil {
		s.reply(msg.ID, nil, applicationError(msg.Method, err))
		return
	}
	s.reply(msg.ID, result, nil)
}

// decodeParams turns positional params into the method's arguments. Missing
// trailing params are zero values, as an omitted argument is in the bindings.
func decodeParams(t reflect.Type, raw json.RawMessage) ([]reflect.Value, error) {
	var params []json.RawMessage
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, errors.New("params must be an array")
		}
	}
	if len(params) > t.NumIn() {
		return nil, fmt.Errorf("expected at most %d params, got %d", t.NumIn(), len(params))
	}
	args := make([]reflect.Value, t.NumIn())
	for i := range args {
		arg := reflect.New(t.In(i))
		if i < len(params) {
			if err := json.Unmarshal(params[i], arg.Interface()); err != nil {
				return nil, fmt.Errorf("param %d: invalid %s", i, t.In(i))
			}
		}
		args[i] = arg.Elem()
	}
	return args, nil
}

var errorType = reflect.TypeFor[error]()

// invoke calls a method returning (T, error), error, or T.
func invoke(method reflect.Value, args []reflect.Value) (any, error) {
	out := method.Call(args)
	var result any
	var err error
	for _, v := range out {
		if v.Type() == errorType {
			if !v.IsNil() {
				err = v.Interface().(error)
			}
			continue
		}
		result = v.Interface()
	}
	return result, err
}

func applicationError(method string, err error) *Error {
	normalized := apperr.Normalize(err)
	payload := apperr.PayloadOf(normalized)
	if payload.Code == apperr.CodeInternal || payload.Code == apperr.CodeUnavailable {
		slog.Error("rpc operation failed", "method", method, "err", normalized)
	}
	return &Error{Code: codeApplication, Message: payload.Message, Data: &payload}
}

func (s *Server) reply(id json.RawMessage, result any, rpcErr *Error) {
	if id == nil && rpcErr == nil {
		return // a notification gets no response
	}
	msg := message{JSONRPC: "2.0", ID: id, Error: rpcErr}
	if id == nil {
		msg.ID = json.RawMessage("null")
	}
	if rpcErr == nil {
		data, err := json.Marshal(result)
		if err != nil {
			slog.Error("rpc result not encodable", "err", err)
			msg.Error = applicationError("", err)
		} else {
			msg.Result = data
		}
	}
	s.write(msg)
}

func (s *Server) notify(method string, params any) {
	data, err := json.Marshal(params)
	if err != nil {
		slog.Error("rpc notification not encodable", "method", method, "err", err)
		return
	}
	s.write(message{JSONRPC: "2.0", Method: method, Params: data})
}

func (s *Server) write(msg message) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.enc.Encode(msg); err != nil {
		slog.Error("rpc write failed", "err", err)
	}
}

// call sends a request to the client and waits for its response.
func (s *Server) call(ctx context.Context, method string, params any, result any) error {
	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	s.callMu.Lock()
	s.nextID++
	id := "s" + strconv.Itoa(s.nextID)
	ch := make(chan message, 1)
	s.pending[id] = ch
	s.callMu.Unlock()
	defer func() {
		s.callMu.Lock()
		delete(s.pending, id)
		s.callMu.Unlock()
	}()

	rawID, _ := json.Marshal(id)
	s.write(message{JSONRPC: "2.0", ID: rawID, Method: method, Params: data})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case resp, ok := <-ch:
		if !ok {
			return errors.New("rpc client disconnected")
		}
		if resp.Error != nil {
			return resp.Error
		}
		if result != nil && len(resp.Result) > 0 {
			return json.Unmarshal(resp.Result, result)
		}
		return nil
	}
}

// resolve hands a client's response to the call waiting for it.
func (s *Server) resolve(msg message) {
	var id string
	if err := json.Unmarshal(msg.ID, &id); err != nil {
		return
	}
	s.callMu.Lock()
	ch := s.pending[id]
	delete(s.pending, id)
	s.callMu.Unlock()
	if ch != nil {
		ch <- msg
	}
}

func (s *Server) failPending() {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	for id, ch := range s.pending {
		close(ch)
		delete(s.pending, id)
	}
}
