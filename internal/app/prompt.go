package app

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// terminalPassphrasePrompt reads a passphrase from the terminal without
// echoing it. When a new passphrase is being chosen it asks twice.
func terminalPassphrasePrompt(in *os.File, out io.Writer) func(confirm bool) (string, error) {
	read := func(label string) (string, error) {
		fmt.Fprint(out, label)
		b, err := term.ReadPassword(int(in.Fd()))
		fmt.Fprintln(out)
		return string(b), err
	}
	return func(confirm bool) (string, error) {
		if confirm {
			fmt.Fprintln(out, "Choose a passphrase to encrypt your messages and keys on this computer.")
			fmt.Fprintln(out, "There is no recovery: if you forget it, the data cannot be read again.")
		}
		first, err := read("Passphrase: ")
		if err != nil {
			return "", err
		}
		if !confirm {
			return first, nil
		}
		second, err := read("Repeat passphrase: ")
		if err != nil {
			return "", err
		}
		if first != second {
			return "", errors.New("the passphrases do not match")
		}
		return first, nil
	}
}
