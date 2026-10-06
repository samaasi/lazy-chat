//go:build !windows

package vault

func osProtect([]byte) ([]byte, error)   { return nil, ErrUnsupported }
func osUnprotect([]byte) ([]byte, error) { return nil, ErrUnsupported }
