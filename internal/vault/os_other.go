//go:build !windows

package vault

func dpapiProtect([]byte) ([]byte, error)   { return nil, ErrUnsupported }
func dpapiUnprotect([]byte) ([]byte, error) { return nil, ErrUnsupported }
