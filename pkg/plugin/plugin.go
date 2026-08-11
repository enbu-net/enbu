// Package plugin hosts signed, deterministic WebAssembly transforms. A
// transform receives immutable input handles and returns staged drafts; it
// cannot access files, network, process state, clock, randomness, or secrets
// outside the handles explicitly supplied by the host.
package plugin

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const (
	MaxModuleBytes     = 16 * 1024 * 1024
	MaxInputBytes      = 64 * 1024 * 1024
	MaxOutputBytes     = 64 * 1024 * 1024
	MaxInputs          = 1024
	MaxOutputName      = 253
	MaxOutputTypeRef   = 512
	MaxOutputs         = 1024
	MaxMemoryPages     = 1024
	MaxCallLimit       = 1_000_000
	DefaultMemoryPages = 64
	DefaultCallLimit   = 100_000
	MaxDuration        = time.Minute
	DefaultDuration    = 5 * time.Second

	// MediaTypeDraft is a plaintext, transient staging object. Callers must use
	// a private local ObjectSink and encrypt accepted drafts before publication.
	MediaTypeDraft = "application/vnd.enbu.plugin.draft.v1"
)

var (
	ErrExecution     = errors.New("plugin: execution failed")
	ErrLimit         = errors.New("plugin: resource limit exceeded")
	ErrUnknownImport = errors.New("plugin: unknown import")

	errWallClockDeadline = errors.New("plugin: host wall-clock deadline")
)

type Input struct {
	Reader io.ReaderAt
	Size   int64
}

type Draft struct {
	Type     artifact.TypeRef
	Metadata artifact.Metadata
	Object   artifact.Descriptor
}

type Limits struct {
	MemoryPages uint32
	CallLimit   uint64
	MaxInput    int64
	MaxOutput   int64
	Duration    time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MemoryPages: DefaultMemoryPages,
		CallLimit:   DefaultCallLimit,
		MaxInput:    MaxInputBytes,
		MaxOutput:   MaxOutputBytes,
		Duration:    DefaultDuration,
	}
}

type Host struct{ limits Limits }

func NewHost(limits Limits) (*Host, error) {
	if limits.MemoryPages == 0 || limits.MemoryPages > MaxMemoryPages ||
		limits.CallLimit == 0 || limits.CallLimit > MaxCallLimit ||
		limits.MaxInput < 0 || limits.MaxInput > MaxInputBytes ||
		limits.MaxOutput < 0 || limits.MaxOutput > MaxOutputBytes ||
		limits.Duration <= 0 || limits.Duration > MaxDuration {
		return nil, fmt.Errorf("%w: limits", ErrLimit)
	}
	return &Host{limits: limits}, nil
}

type execution struct {
	inputs           []Input
	sink             artifact.ObjectSink
	outputNamespaces []TypeNamespace
	limits           Limits
	calls            uint64
	mu               sync.Mutex
	outputs          map[uint32]*output
	outputNames      map[string]struct{}
	nextID           uint32
	totalOut         int64
	fatal            error
}

type output struct {
	mu         sync.Mutex
	typeRef    artifact.TypeRef
	metadata   artifact.Metadata
	writer     *io.PipeWriter
	result     <-chan ingestResult
	hash       hash.Hash
	size       int64
	closed     bool
	descriptor artifact.Descriptor
	err        error
}

type ingestResult struct {
	descriptor artifact.Descriptor
	err        error
}

// Execute runs one already verified package in a fresh wazero instance and
// stages output bytes directly into sink. It never materializes complete output
// bodies in process memory.
func (host *Host) Execute(
	ctx context.Context,
	pkg VerifiedPackage,
	inputs []Input,
	sink artifact.ObjectSink,
) ([]Draft, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrExecution)
	}
	if host == nil {
		return nil, fmt.Errorf("%w: nil host", ErrExecution)
	}
	executionCtx, cancel := context.WithTimeoutCause(ctx, host.limits.Duration, errWallClockDeadline)
	defer cancel()
	if len(pkg.module) == 0 || len(pkg.module) > MaxModuleBytes ||
		pkg.moduleDigest != digest.FromBytes(pkg.module) || pkg.digest == "" ||
		len(pkg.outputNamespaces) == 0 {
		if err := executionContextError(ctx, executionCtx); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: module", ErrInvalidPackage)
	}
	if len(inputs) == 0 || len(inputs) > MaxInputs {
		return nil, fmt.Errorf("%w: input count", ErrLimit)
	}
	inputSnapshots := append([]Input(nil), inputs...)
	var totalInput int64
	for index, input := range inputSnapshots {
		if input.Reader == nil || input.Size < 0 || input.Size > host.limits.MaxInput-totalInput {
			return nil, fmt.Errorf("%w: input %d", ErrLimit, index)
		}
		totalInput += input.Size
	}
	if sink == nil {
		return nil, fmt.Errorf("%w: nil output sink", ErrExecution)
	}
	if err := executionContextError(ctx, executionCtx); err != nil {
		return nil, err
	}
	exec := &execution{
		inputs:           inputSnapshots,
		sink:             sink,
		outputNamespaces: cloneNamespaces(pkg.outputNamespaces),
		limits:           host.limits,
		outputs:          make(map[uint32]*output),
		outputNames:      make(map[string]struct{}),
		nextID:           1,
	}
	defer exec.abortOutputs()
	runtime := wazero.NewRuntimeWithConfig(executionCtx, wazero.NewRuntimeConfig().WithMemoryLimitPages(host.limits.MemoryPages).WithCloseOnContextDone(true))
	defer func() { _ = runtime.Close(executionCtx) }()
	if err := exec.instantiateHost(executionCtx, runtime); err != nil {
		if contextErr := executionContextError(ctx, executionCtx); contextErr != nil {
			return nil, contextErr
		}
		return nil, err
	}
	compiled, err := runtime.CompileModule(executionCtx, pkg.module)
	if err != nil {
		if contextErr := executionContextError(ctx, executionCtx); contextErr != nil {
			return nil, contextErr
		}
		return nil, fmt.Errorf("%w: compile: %v", ErrInvalidPackage, err)
	}
	defer func() { _ = compiled.Close(executionCtx) }()
	if err := validateImports(compiled); err != nil {
		return nil, err
	}
	instance, err := runtime.InstantiateModule(executionCtx, compiled, wazero.NewModuleConfig().WithName("enbu-plugin"))
	if err != nil {
		if contextErr := executionContextError(ctx, executionCtx); contextErr != nil {
			return nil, contextErr
		}
		return nil, fmt.Errorf("%w: instantiate: %v", ErrInvalidPackage, err)
	}
	defer func() { _ = instance.Close(executionCtx) }()
	transform := instance.ExportedFunction("enbu_transform")
	if transform == nil {
		return nil, fmt.Errorf("%w: missing enbu_transform export", ErrInvalidPackage)
	}
	results, err := transform.Call(executionCtx)
	if err != nil {
		if contextErr := executionContextError(ctx, executionCtx); contextErr != nil {
			return nil, contextErr
		}
		return nil, fmt.Errorf("%w: call: %v", ErrExecution, err)
	}
	if contextErr := executionContextError(ctx, executionCtx); contextErr != nil {
		return nil, contextErr
	}
	if len(results) != 1 || results[0] != 0 {
		return nil, fmt.Errorf("%w: plugin returned %d", ErrExecution, results)
	}
	if err := exec.failure(); err != nil {
		return nil, err
	}
	return exec.collectDrafts()
}

// executionContextError distinguishes caller cancellation from the host-owned
// wall-clock ceiling. Callers retain their normal context semantics, while a
// background context can never disable the plugin execution limit.
func executionContextError(parent, executionCtx context.Context) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if errors.Is(context.Cause(executionCtx), errWallClockDeadline) {
		return fmt.Errorf("%w: wall-clock execution: %w", ErrLimit, context.DeadlineExceeded)
	}
	return executionCtx.Err()
}

func validateImports(module wazero.CompiledModule) error {
	allowed := map[string]struct{}{
		"input_count": {}, "input_len": {}, "read_at": {}, "output_create": {}, "output_write": {}, "output_close": {},
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
	builder.NewFunctionBuilder().WithFunc(exec.inputCount).Export("input_count")
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
		if exec.fatal == nil {
			exec.fatal = ErrLimit
		}
		return false
	}
	exec.calls++
	return true
}

func (exec *execution) inputCount(ctx context.Context, _ api.Module) uint32 {
	if !exec.countCall() || ctx.Err() != nil {
		return ^uint32(0)
	}
	return uint32(len(exec.inputs))
}

func (exec *execution) inputLen(ctx context.Context, _ api.Module, handle uint32) uint64 {
	if !exec.countCall() || ctx.Err() != nil {
		return ^uint64(0)
	}
	input, ok := exec.input(handle)
	if !ok {
		return ^uint64(0)
	}
	return uint64(input.Size)
}

func (exec *execution) readAt(ctx context.Context, module api.Module, handle uint32, offset uint64, ptr, length uint32) int32 {
	if !exec.countCall() || ctx.Err() != nil {
		return -1
	}
	input, ok := exec.input(handle)
	if !ok {
		return -1
	}
	if offset > uint64(input.Size) || uint64(length) > uint64(input.Size)-offset {
		exec.fail(errors.New("input read is out of range"))
		return -1
	}
	memory := module.Memory()
	if memory == nil {
		exec.fail(errors.New("plugin has no memory"))
		return -1
	}
	buffer := make([]byte, length)
	read, err := input.Reader.ReadAt(buffer, int64(offset))
	if err != nil && (!errors.Is(err, io.EOF) || read != len(buffer)) {
		exec.fail(fmt.Errorf("read input: %w", err))
		return -1
	}
	if !memory.Write(ptr, buffer[:read]) {
		exec.fail(errors.New("input destination is out of range"))
		return -1
	}
	return int32(read)
}

func (exec *execution) input(handle uint32) (Input, bool) {
	if uint64(handle) >= uint64(len(exec.inputs)) {
		exec.fail(errors.New("invalid input handle"))
		return Input{}, false
	}
	return exec.inputs[handle], true
}

func (exec *execution) outputCreate(
	ctx context.Context,
	module api.Module,
	namePtr, nameLen, typePtr, typeLen uint32,
) int32 {
	if !exec.countCall() || ctx.Err() != nil ||
		nameLen == 0 || nameLen > MaxOutputName ||
		typeLen == 0 || typeLen > MaxOutputTypeRef {
		exec.fail(ErrLimit)
		return -1
	}
	memory := module.Memory()
	if memory == nil {
		exec.fail(errors.New("plugin has no memory"))
		return -1
	}
	nameBytes, ok := memory.Read(namePtr, nameLen)
	if !ok || !utf8.Valid(nameBytes) {
		exec.fail(errors.New("invalid output name"))
		return -1
	}
	typeBytes, ok := memory.Read(typePtr, typeLen)
	if !ok || !utf8.Valid(typeBytes) {
		exec.fail(errors.New("invalid output type"))
		return -1
	}
	metadata := artifact.Metadata{Name: string(nameBytes)}
	if err := metadata.ValidateExtension(); err != nil {
		exec.fail(errors.New("invalid output metadata"))
		return -1
	}
	typeRef, err := artifact.ParseTypeRef(string(typeBytes))
	if err != nil || typeRef.ValidateExtension() != nil || !exec.allows(typeRef) {
		exec.fail(errors.New("output type is not declared and trusted"))
		return -1
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	if len(exec.outputs) >= MaxOutputs {
		if exec.fatal == nil {
			exec.fatal = ErrLimit
		}
		return -1
	}
	if _, exists := exec.outputNames[metadata.Name]; exists {
		if exec.fatal == nil {
			exec.fatal = errors.New("duplicate output name")
		}
		return -1
	}
	id := exec.nextID
	if id == 0 || id > math.MaxInt32 {
		if exec.fatal == nil {
			exec.fatal = ErrLimit
		}
		return -1
	}
	exec.nextID++
	exec.outputs[id] = exec.startOutput(ctx, typeRef, metadata)
	exec.outputNames[metadata.Name] = struct{}{}
	return int32(id)
}

func (exec *execution) outputWrite(ctx context.Context, module api.Module, handle, ptr, length uint32) int32 {
	if !exec.countCall() || ctx.Err() != nil || uint64(length) > math.MaxInt32 {
		exec.fail(ErrLimit)
		return -1
	}
	memory := module.Memory()
	if memory == nil {
		exec.fail(errors.New("plugin has no memory"))
		return -1
	}
	data, ok := memory.Read(ptr, length)
	if !ok {
		exec.fail(errors.New("invalid output memory range"))
		return -1
	}
	exec.mu.Lock()
	staged, ok := exec.outputs[handle]
	if !ok {
		if exec.fatal == nil {
			exec.fatal = errors.New("invalid output handle")
		}
		exec.mu.Unlock()
		return -1
	}
	if int64(length) > exec.limits.MaxOutput-exec.totalOut {
		if exec.fatal == nil {
			exec.fatal = ErrLimit
		}
		exec.mu.Unlock()
		return -1
	}
	// Reserve quota before releasing the execution lock. Failed writes remain
	// charged so a hostile sink or module cannot repeatedly recycle quota.
	exec.totalOut += int64(length)
	exec.mu.Unlock()

	staged.mu.Lock()
	defer staged.mu.Unlock()
	if staged.closed || staged.err != nil {
		exec.fail(errors.New("invalid output handle state"))
		return -1
	}
	written, err := writeContext(ctx, staged.writer, data)
	if written > 0 {
		_, _ = staged.hash.Write(data[:written])
		staged.size += int64(written)
	}
	if err != nil || written != len(data) {
		if err == nil {
			err = io.ErrShortWrite
		}
		staged.err = err
		_ = staged.writer.CloseWithError(err)
		exec.fail(err)
		return -1
	}
	return int32(written)
}

func (exec *execution) outputClose(ctx context.Context, _ api.Module, handle uint32) int32 {
	if !exec.countCall() || ctx.Err() != nil {
		exec.fail(ErrLimit)
		return -1
	}
	exec.mu.Lock()
	staged, ok := exec.outputs[handle]
	exec.mu.Unlock()
	if !ok {
		exec.fail(errors.New("invalid output handle"))
		return -1
	}
	staged.mu.Lock()
	defer staged.mu.Unlock()
	if staged.closed || staged.err != nil {
		exec.fail(errors.New("invalid output handle state"))
		return -1
	}
	staged.closed = true
	if err := staged.writer.Close(); err != nil {
		staged.err = err
		exec.fail(err)
		return -1
	}
	var result ingestResult
	select {
	case result = <-staged.result:
	case <-ctx.Done():
		staged.err = ctx.Err()
		exec.fail(ctx.Err())
		return -1
	}
	if result.err != nil {
		staged.err = result.err
		exec.fail(result.err)
		return -1
	}
	if err := result.descriptor.Validate(); err != nil {
		staged.err = fmt.Errorf("invalid sink descriptor: %w", err)
		exec.fail(staged.err)
		return -1
	}
	expected := artifact.Descriptor{
		MediaType: MediaTypeDraft,
		Digest:    digest.NewDigest(digest.SHA256, staged.hash),
		Size:      staged.size,
	}
	if result.descriptor != expected {
		staged.err = errors.New("sink descriptor does not match staged output")
		exec.fail(staged.err)
		return -1
	}
	staged.descriptor = result.descriptor
	return 0
}

func (exec *execution) allows(typeRef artifact.TypeRef) bool {
	for _, namespace := range exec.outputNamespaces {
		if namespace.Contains(typeRef) {
			return true
		}
	}
	return false
}

func (exec *execution) fail(err error) {
	if err == nil {
		return
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	if exec.fatal == nil {
		exec.fatal = err
	}
}

func (exec *execution) failure() error {
	exec.mu.Lock()
	defer exec.mu.Unlock()
	if exec.fatal == nil {
		return nil
	}
	if errors.Is(exec.fatal, ErrLimit) {
		return fmt.Errorf("%w: plugin host call", ErrLimit)
	}
	return fmt.Errorf("%w: plugin host call: %v", ErrExecution, exec.fatal)
}

func (exec *execution) startOutput(
	ctx context.Context,
	typeRef artifact.TypeRef,
	metadata artifact.Metadata,
) *output {
	reader, writer := io.Pipe()
	results := make(chan ingestResult, 1)
	go func() {
		descriptor, err := exec.sink.Ingest(ctx, MediaTypeDraft, reader)
		if err != nil {
			_ = reader.CloseWithError(err)
		} else {
			_ = reader.Close()
		}
		results <- ingestResult{descriptor: descriptor, err: err}
	}()
	return &output{
		typeRef:  typeRef,
		metadata: metadata,
		writer:   writer,
		result:   results,
		hash:     sha256.New(),
	}
}

func (exec *execution) collectDrafts() ([]Draft, error) {
	exec.mu.Lock()
	outputs := make([]*output, 0, len(exec.outputs))
	for _, staged := range exec.outputs {
		outputs = append(outputs, staged)
	}
	exec.mu.Unlock()

	drafts := make([]Draft, 0, len(outputs))
	for _, staged := range outputs {
		staged.mu.Lock()
		if staged.err != nil {
			name, err := staged.metadata.Name, staged.err
			staged.mu.Unlock()
			return nil, fmt.Errorf("%w: output %q: %v", ErrExecution, name, err)
		}
		if !staged.closed {
			name := staged.metadata.Name
			staged.mu.Unlock()
			return nil, fmt.Errorf("%w: output %q not closed", ErrExecution, name)
		}
		if staged.descriptor == (artifact.Descriptor{}) {
			name := staged.metadata.Name
			staged.mu.Unlock()
			return nil, fmt.Errorf("%w: output %q has no descriptor", ErrExecution, name)
		}
		drafts = append(drafts, Draft{
			Type:     staged.typeRef,
			Metadata: staged.metadata,
			Object:   staged.descriptor,
		})
		staged.mu.Unlock()
	}
	sort.Slice(drafts, func(i, j int) bool {
		if drafts[i].Metadata.Name == drafts[j].Metadata.Name {
			return drafts[i].Type.String() < drafts[j].Type.String()
		}
		return drafts[i].Metadata.Name < drafts[j].Metadata.Name
	})
	return drafts, nil
}

func (exec *execution) abortOutputs() {
	exec.mu.Lock()
	outputs := make([]*output, 0, len(exec.outputs))
	for _, staged := range exec.outputs {
		outputs = append(outputs, staged)
	}
	exec.mu.Unlock()

	for _, staged := range outputs {
		staged.mu.Lock()
		if !staged.closed {
			staged.closed = true
			staged.err = ErrExecution
			_ = staged.writer.CloseWithError(ErrExecution)
		}
		staged.mu.Unlock()
	}
}

func writeContext(ctx context.Context, destination io.Writer, data []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	written, err := destination.Write(data)
	if err == nil {
		err = ctx.Err()
	}
	return written, err
}

func bytesHasWasmHeader(module []byte) bool {
	return len(module) >= 8 && module[0] == 0 && module[1] == 'a' && module[2] == 's' && module[3] == 'm' && module[4] == 1
}
