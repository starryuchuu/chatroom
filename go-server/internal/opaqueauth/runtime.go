// Package opaqueauth runs the shared, fixed OPAQUE implementation in a sandbox.
// The module has no filesystem, environment, network or WASI imports.
package opaqueauth

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const MaxMessageBytes = 128 * 1024

//go:embed opaque_core.wasm
var core []byte

var ErrAuthentication = errors.New("authentication failed")

var once sync.Once
var runtime wazero.Runtime
var compiled wazero.CompiledModule
var initializationError error

func initialize() {
	ctx := context.Background()
	runtime = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithMemoryLimitPages(4096).WithCloseOnContextDone(true))
	_, initializationError = runtime.NewHostModuleBuilder("env").NewFunctionBuilder().WithFunc(func(_ context.Context, module api.Module, ptr, size uint32) uint32 {
		if size > MaxMessageBytes {
			return 1
		}
		buffer, ok := module.Memory().Read(ptr, size)
		if !ok {
			return 1
		}
		if _, err := rand.Read(buffer); err != nil {
			return 1
		}
		return 0
	}).Export("chatroom_random").Instantiate(ctx)
	if initializationError == nil {
		compiled, initializationError = runtime.CompileModule(ctx, core)
	}
}

// Call never includes inputs, secrets, runtime traps or intermediate state in an error.
// Every operation receives a fresh memory instance and an independent random source.
func Call(ctx context.Context, request map[string]interface{}) (map[string]interface{}, error) {
	input, err := json.Marshal(request)
	if err != nil || len(input) > MaxMessageBytes {
		return nil, ErrAuthentication
	}
	defer clear(input)
	once.Do(initialize)
	if initializationError != nil {
		return nil, ErrAuthentication
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	module, err := runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return nil, ErrAuthentication
	}
	defer func() {
		if memory := module.Memory(); memory != nil {
			if bytes, ok := memory.Read(0, memory.Size()); ok {
				clear(bytes)
			}
		}
		module.Close(context.Background())
	}()
	alloc, run := module.ExportedFunction("alloc"), module.ExportedFunction("run")
	if alloc == nil || run == nil {
		return nil, ErrAuthentication
	}
	allocated, err := alloc.Call(ctx, uint64(len(input)))
	if err != nil || len(allocated) != 1 || allocated[0] > 0xffffffff {
		return nil, ErrAuthentication
	}
	if !module.Memory().Write(uint32(allocated[0]), input) {
		return nil, ErrAuthentication
	}
	result, err := run.Call(ctx, allocated[0], uint64(len(input)))
	if err != nil || len(result) != 1 {
		return nil, ErrAuthentication
	}
	ptr, size := uint32(result[0]>>32), uint32(result[0])
	if size == 0 || size > MaxMessageBytes {
		return nil, ErrAuthentication
	}
	output, ok := module.Memory().Read(ptr, size)
	if !ok {
		return nil, ErrAuthentication
	}
	var decoded map[string]interface{}
	if json.Unmarshal(output, &decoded) != nil || decoded == nil || decoded["error"] != nil {
		return nil, ErrAuthentication
	}
	return decoded, nil
}
