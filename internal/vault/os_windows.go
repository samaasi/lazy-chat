//go:build windows

package vault

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapiProtect wraps data with Windows DPAPI: only the same Windows user on the
// same machine can unwrap it, without any passphrase.
func dpapiProtect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("vault: nothing to protect")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	entropy := []byte(osEntropy)
	ent := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

// dpapiUnprotect reverses dpapiProtect.
func dpapiUnprotect(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, ErrCorrupt
	}
	in := windows.DataBlob{Size: uint32(len(blob)), Data: &blob[0]}
	entropy := []byte(osEntropy)
	ent := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, errors.New("vault: this key file was created by another Windows user or machine and cannot be unlocked here")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
