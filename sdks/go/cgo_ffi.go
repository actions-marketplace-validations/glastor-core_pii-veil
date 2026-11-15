//go:build cgo_veil

package piiveil

/*
#cgo CFLAGS: -I../../crates/veil-ffi/include
#cgo LDFLAGS: -L../../target/release -lpii_veil_ffi
#include <stdlib.h>
#include "pii_veil.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

// FfiEngine wraps the native Rust `pii-veil-ffi` C-ABI handle (`VeilHandle*`) via cgo.
// Build with: `cargo build --release -p pii-veil-ffi && go build -tags cgo_veil`
type FfiEngine struct {
	handle *C.VeilHandle
}

// NewFfiEngine creates a native Rust C-ABI engine handle (`0` = Placeholder, `1` = Synthetic, `2` = Mask).
func NewFfiEngine(mode uint32, secretKey string) (*FfiEngine, error) {
	var cKey *C.char
	if secretKey != "" {
		cKey = C.CString(secretKey)
		defer C.free(unsafe.Pointer(cKey))
	}
	h := C.veil_new(C.uint32_t(mode), cKey)
	if h == nil {
		return nil, errors.New("veil_new returned NULL handle")
	}
	return &FfiEngine{handle: h}, nil
}

// Redact calls the native Rust `veil_redact` C-ABI function.
func (f *FfiEngine) Redact(input string) (string, error) {
	if f.handle == nil {
		return "", errors.New("FfiEngine is closed")
	}
	cIn := C.CString(input)
	defer C.free(unsafe.Pointer(cIn))

	cOut := C.veil_redact(f.handle, cIn)
	if cOut == nil {
		return "", errors.New("veil_redact returned NULL")
	}
	defer C.veil_string_free(cOut)
	return C.GoString(cOut), nil
}

// Restore calls the native Rust `veil_restore` C-ABI function.
func (f *FfiEngine) Restore(sanitized string) (string, error) {
	if f.handle == nil {
		return "", errors.New("FfiEngine is closed")
	}
	cIn := C.CString(sanitized)
	defer C.free(unsafe.Pointer(cIn))

	cOut := C.veil_restore(f.handle, cIn)
	if cOut == nil {
		return "", errors.New("veil_restore returned NULL")
	}
	defer C.veil_string_free(cOut)
	return C.GoString(cOut), nil
}

// RedactJSON calls the native Rust `veil_redact_json` C-ABI function.
func (f *FfiEngine) RedactJSON(jsonInput string) (string, error) {
	if f.handle == nil {
		return "", errors.New("FfiEngine is closed")
	}
	cIn := C.CString(jsonInput)
	defer C.free(unsafe.Pointer(cIn))

	cOut := C.veil_redact_json(f.handle, cIn)
	if cOut == nil {
		return "", errors.New("veil_redact_json failed")
	}
	defer C.veil_string_free(cOut)
	return C.GoString(cOut), nil
}

// Close frees the underlying Rust `VeilHandle`.
func (f *FfiEngine) Close() {
	if f.handle != nil {
		C.veil_free(f.handle)
		f.handle = nil
	}
}
