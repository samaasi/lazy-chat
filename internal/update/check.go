package update

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// CheckInterval is how often the start-up check contacts GitHub at most.
const CheckInterval = 24 * time.Hour

type checkState struct {
	Checked time.Time `json:"checked"`
	Latest  string    `json:"latest"`
}

// Available is the start-up notice: it returns the newest version if it is
// newer than the running one, or "" when up to date, when it checked recently
// and found nothing, or when it cannot tell. It contacts GitHub at most once
// per `every`, remembering the answer in stateFile, and never returns an error:
// a failed check must never get in the user's way.
func (u *Updater) Available(ctx context.Context, stateFile string, every time.Duration, now time.Time) string {
	if !IsRelease(u.Current) {
		return "" // a development build has nothing to compare
	}
	var st checkState
	if b, err := os.ReadFile(stateFile); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	if !st.Checked.IsZero() && now.Sub(st.Checked) < every && !st.Checked.After(now) {
		if newer, err := Newer(st.Latest, u.Current); err == nil && newer {
			return st.Latest
		}
		return ""
	}
	rel, err := u.Latest(ctx)
	if err != nil {
		return ""
	}
	st = checkState{Checked: now, Latest: rel.Version}
	if b, err := json.Marshal(st); err == nil {
		_ = os.MkdirAll(filepath.Dir(stateFile), 0o700)
		_ = os.WriteFile(stateFile, b, 0o600)
	}
	if newer, err := Newer(rel.Version, u.Current); err == nil && newer {
		return rel.Version
	}
	return ""
}
