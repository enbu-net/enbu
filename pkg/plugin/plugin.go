// Package plugin hosts signed, deterministic WebAssembly transforms. A
// transform receives immutable input handles and returns staged drafts; it
// cannot access files, network, process state, clock, randomness, or secrets
// outside the handles explicitly supplied by the host.
package plugin

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/opencontainers/go-digest"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const (
	MaxModuleBytes     = 16 * 1024 * 1024
	MaxInputBytes      = 64 * 1024 * 1024
	MaxOutputBytes     = 64 * 1024 * 1024
	MaxOutputName      = 253
	DefaultMemoryPages = 64
	DefaultCallLimit   = 100_000
	pluginDomain       = "enbu.net/plugin-package/v1\x00"
)

var (
	ErrInvalidPackage = errors.New("plugin: invalid package")
	ErrExecution      = errors.New("plugin: execution failed")
	ErrLimit          = errors.New("plugin: resource limit exceeded")
	ErrUnknownImport  = errors.New("plugin: unknown import")
)

type Package struct {
	Module    []byte
	Digest    digest.Digest
	Signature []byte
}

func VerifyPackage(pkg Package, publicKey ed25519.PublicKey) error {
	if len(pkg.Module) == 0 || len(pkg.Module) > MaxModuleBytes || !bytesHasWasmHeader(pkg.Module) {
		return fmt.Errorf("%w: module", ErrInvalidPackage)
	}
	if pkg.Digest != digest.FromBytes(pkg.Module) {
		return fmt.Errorf("%w: module digest", ErrInvalidPackage)
	}
	if len(publicKey) != ed25519.PublicKeySize || len(pkg.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, append([]byte(pluginDomain), pkg.Module...), pkg.Signature) {
		return fmt.Errorf("%w: package signature", ErrInvalidPackage)
	}
	return nil
}

type Input struct {
	Reader io.ReaderAt
	Size   int64
}

type Draft struct {
	Name string
	Data []byte
}

type Limits struct {
	MemoryPages uint32
	CallLimit   uint64
	MaxInput    int64
	MaxOutput   int64
}

func DefaultLimits() Limits {
	return Limits{MemoryPages: DefaultMemoryPages, CallLimit: DefaultCallLimit, MaxInput: MaxInputBytes, MaxOutput: MaxOutputBytes}
}

type Host struct{ limits Limits }

func NewHost(limits Limits) (*Host, error) {
	if limits.MemoryPages == 0 || limits.MemoryPages > 65536 || limits.CallLimit == 0 || limits.MaxInput < 0 || limits.MaxOutput < 0 || limits.MaxOutput > MaxOutputBytes {
		return nil, fmt.Errorf("%w: limits", ErrLimit)
	}
	return &Host{limits: limits}, nil
}

type execution struct {
	input    Input
	limits   Limits
	calls    uint64
	mu       sync.Mutex
	outputs  map[uint32]*output
	nextID   uint32
	totalOut int64
}

type output struct {
	name   string
	data   []byte
	closed bool
}

func (host *Host) Execute(ctx context.Context, module []byte, input Input) ([]Draft, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrExecution)
	}
	if len(module) == 0 || len(module) > MaxModuleBytes || !bytesHasWasmHeader(module) {
		return nil, fmt.Errorf("%w: module", ErrInvalidPackage)
	}
	if input.Reader == nil || input.Size < 0 || input.Size > host.limits.MaxInput {
		return nil, fmt.Errorf("%w: input", ErrLimit)
	}
	exec := &execution{input: input, limits: host.limits, outputs: make(map[uint32]*output), nextID: 1}
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithMemoryLimitPages(host.limits.MemoryPages).WithCloseOnContextDone(true))
	defer func() { _ = runtime.Close(ctx) }()
	if err := exec.instantiateHost(ctx, runtime); err != nil {
		return nil, err
	}
	compiled, err := runtime.CompileModule(ctx, module)
	if err != nil {
		return nil, fmt.Errorf("%w: compile: %v", ErrInvalidPackage, err)
	}
	defer func() { _ = compiled.Close(ctx) }()
	if err := validateImports(compiled); err != nil {
		return nil, err
	}
	instance, err := runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("enbu-plugin"))
	if err != nil {
		return nil, fmt.Errorf("%w: instantiate: %v", ErrInvalidPackage, err)
	}
	defer func() { _ = instance.Close(ctx) }()
	transform := instance.ExportedFunction("enbu_transform")
	if transform == nil {
		return nil, fmt.Errorf("%w: missing enbu_transform export", ErrInvalidPackage)
	}
	results, err := transform.Call(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: call: %v", ErrExecution, err)
	}
	if len(results) != 1 || results[0] != 0 {
		return nil, fmt.Errorf("%w: plugin returned %d", ErrExecution, results)
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	drafts := make([]Draft, 0, len(exec.outputs))
	for _, staged := range exec.outputs {
		if !staged.closed {
			return nil, fmt.Errorf("%w: output %q not closed", ErrExecution, staged.name)
		}
		drafts = append(drafts, Draft{Name: staged.name, Data: append([]byte(nil), staged.data...)})
	}
	return drafts, nil
}

func validateImports(module wazero.CompiledModule) error {
	allowed := map[string]struct{}{
		"input_len": {}, "read_at": {}, "output_create": {}, "output_write": {}, "output_close": {},
	}
	for _, function := range module.ImportedFunctions() {
		moduleName, name, imported := function.Import()
		if !imported {
			continue
		}
		if moduleName != "enbu" {
			return fmt.Errorf("%w: module %q", ErrUnknownImport, moduleName)
		}
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("%w: function %q", ErrUnknownImport, name)
		}
	}
	return nil
}

func (exec *execution) instantiateHost(ctx context.Context, runtime wazero.Runtime) error {
	builder := runtime.NewHostModuleBuilder("enbu")
	builder.NewFunctionBuilder().WithFunc(exec.inputLen).Export("input_len")
	builder.NewFunctionBuilder().WithFunc(exec.readAt).Export("read_at")
	builder.NewFunctionBuilder().WithFunc(exec.outputCreate).Export("output_create")
	builder.NewFunctionBuilder().WithFunc(exec.outputWrite).Export("output_write")
	builder.NewFunctionBuilder().WithFunc(exec.outputClose).Export("output_close")
	_, err := builder.Instantiate(ctx)
	return err
}

func (exec *execution) countCall() bool {
	exec.mu.Lock()
	defer exec.mu.Unlock()
	if exec.calls >= exec.limits.CallLimit {
		return false
	}
	exec.calls++
	return true
}

func (exec *execution) inputLen(ctx context.Context, _ api.Module) uint64 {
	if !exec.countCall() || ctx.Err() != nil {
		return ^uint64(0)
	}
	return uint64(exec.input.Size)
}

func (exec *execution) readAt(ctx context.Context, module api.Module, offset uint64, ptr, length uint32) int32 {
	if !exec.countCall() || ctx.Err() != nil || offset > uint64(exec.input.Size) || uint64(length) > uint64(exec.input.Size)-offset {
		return -1
	}
	buffer := make([]byte, length)
	read, err := exec.input.Reader.ReadAt(buffer, int64(offset))
	if err != nil && (!errors.Is(err, io.EOF) || read != len(buffer)) {
		return -1
	}
	if !module.Memory().Write(ptr, buffer[:read]) {
		return -1
	}
	return int32(read)
}

func (exec *execution) outputCreate(ctx context.Context, module api.Module, namePtr, nameLen uint32) int32 {
	if !exec.countCall() || ctx.Err() != nil || nameLen == 0 || nameLen > MaxOutputName {
		return -1
	}
	nameBytes, ok := module.Memory().Read(namePtr, nameLen)
	if !ok || !utf8.Valid(nameBytes) || strings.IndexByte(string(nameBytes), 0) >= 0 {
		return -1
	}
	name := string(nameBytes)
	if strings.ContainsAny(name, "/\\") || strings.IndexByte(name, 0) >= 0 {
		return -1
	}
	for _, character := range name {
		if character < 0x20 || character == 0x7f {
			return -1
		}
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	for _, existing := range exec.outputs {
		if existing.name == name {
			return -1
		}
	}
	id := exec.nextID
	exec.nextID++
	exec.outputs[id] = &output{name: name}
	return int32(id)
}

func (exec *execution) outputWrite(ctx context.Context, module api.Module, handle, ptr, length uint32) int32 {
	if !exec.countCall() || ctx.Err() != nil {
		return -1
	}
	data, ok := module.Memory().Read(ptr, length)
	if !ok {
		return -1
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	staged, ok := exec.outputs[handle]
	if !ok || staged.closed || int64(length) > exec.limits.MaxOutput-exec.totalOut {
		return -1
	}
	staged.data = append(staged.data, data...)
	exec.totalOut += int64(length)
	return int32(length)
}

func (exec *execution) outputClose(ctx context.Context, _ api.Module, handle uint32) int32 {
	if !exec.countCall() || ctx.Err() != nil {
		return -1
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	staged, ok := exec.outputs[handle]
	if !ok || staged.closed {
		return -1
	}
	staged.closed = true
	return 0
}

func bytesHasWasmHeader(module []byte) bool {
	return len(module) >= 8 && module[0] == 0 && module[1] == 'a' && module[2] == 's' && module[3] == 'm' && module[4] == 1
}
