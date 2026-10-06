package update

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// version is a parsed semantic version: v1.2.3 or v1.2.3-rc.1.
type version struct {
	major, minor, patch int
	pre                 string
}

func parseVersion(s string) (version, error) {
	orig := s
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 { // build metadata does not affect precedence
		s = s[:i]
	}
	var v version
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s, v.pre = s[:i], s[i+1:]
		if v.pre == "" {
			return v, fmt.Errorf("invalid version %q", orig)
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("invalid version %q", orig)
	}
	nums := [3]*int{&v.major, &v.minor, &v.patch}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || len(p) > 1 && p[0] == '0' {
			return v, fmt.Errorf("invalid version %q", orig)
		}
		*nums[i] = n
	}
	return v, nil
}

// compare returns -1, 0 or 1 as a is older than, equal to or newer than b.
func compare(a, b version) int {
	for _, d := range []int{a.major - b.major, a.minor - b.minor, a.patch - b.patch} {
		if d != 0 {
			if d < 0 {
				return -1
			}
			return 1
		}
	}
	switch {
	case a.pre == b.pre:
		return 0
	case a.pre == "": // a release is newer than its own pre-release
		return 1
	case b.pre == "":
		return -1
	}
	return comparePre(a.pre, b.pre)
}

func comparePre(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		switch {
		case aerr == nil && berr == nil && an != bn:
			if an < bn {
				return -1
			}
			return 1
		case aerr == nil && berr != nil:
			return -1 // numbers sort before words
		case aerr != nil && berr == nil:
			return 1
		case aerr != nil && berr != nil && as[i] != bs[i]:
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

// pseudoVersion matches the versions Go derives from a commit (v0.0.0-<time>-<hash>)
// for builds made from a checkout rather than a tagged release.
var pseudoVersion = regexp.MustCompile(`(^|[.-])\d{14}-[0-9a-f]{12}$`)

// IsRelease reports whether v looks like a published release: a clean semantic
// version, not a development build or a pseudo-version from a checkout.
func IsRelease(v string) bool {
	pv, err := parseVersion(v)
	return err == nil && !pseudoVersion.MatchString(pv.pre) && !strings.Contains(v, "dirty")
}

// Newer reports whether candidate is a newer version than current.
func Newer(candidate, current string) (bool, error) {
	c, err := parseVersion(candidate)
	if err != nil {
		return false, err
	}
	cur, err := parseVersion(current)
	if err != nil {
		return false, err
	}
	return compare(c, cur) > 0, nil
}
