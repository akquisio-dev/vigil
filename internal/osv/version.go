package osv

import (
	"strconv"
	"strings"
)

// Compare orders two versions of one ecosystem: -1, 0 or 1. Versions it
// cannot read sort as equal to nothing in particular; callers treat a
// failed parse as "not affected" rather than guessing.
func Compare(eco, a, b string) (int, bool) {
	switch eco {
	case PyPI:
		x, ok1 := parsePEP440(a)
		y, ok2 := parsePEP440(b)
		if !ok1 || !ok2 {
			return 0, false
		}
		return comparePEP440(x, y), true
	default:
		x, ok1 := parseSemver(a)
		y, ok2 := parseSemver(b)
		if !ok1 || !ok2 {
			return 0, false
		}
		return compareSemver(x, y), true
	}
}

type semver struct {
	core [3]uint64
	pre  []string
}

// parseSemver reads SemVer 2.0 with an optional "v" (Go modules). Missing
// minor or patch count as 0; build metadata is ignored.
func parseSemver(s string) (semver, bool) {
	var v semver
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if core == "" || len(parts) > 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return v, false
		}
		v.core[i] = n
	}
	if hasPre {
		if pre == "" {
			return v, false
		}
		v.pre = strings.Split(pre, ".")
	}
	return v, true
}

func compareSemver(a, b semver) int {
	for i := range a.core {
		if c := cmpU(a.core[i], b.core[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, ex := strconv.ParseUint(a.pre[i], 10, 64)
		y, ey := strconv.ParseUint(b.pre[i], 10, 64)
		switch {
		case ex == nil && ey == nil:
			if c := cmpU(x, y); c != 0 {
				return c
			}
		case ex == nil:
			return -1
		case ey == nil:
			return 1
		default:
			if c := strings.Compare(a.pre[i], b.pre[i]); c != 0 {
				return c
			}
		}
	}
	return cmpU(uint64(len(a.pre)), uint64(len(b.pre)))
}

func cmpU(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// pep440 is a parsed Python version: epoch!release[{a|b|rc}N][.postN][.devN].
// Local versions (+...) are ignored.
type pep440 struct {
	epoch   uint64
	release []uint64
	preKind int // 0 a, 1 b, 2 rc, 3 none
	pre     uint64
	post    int64 // -1 none
	dev     int64 // -1 none
}

func parsePEP440(s string) (pep440, bool) {
	v := pep440{preKind: 3, post: -1, dev: -1}
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	if e, rest, ok := strings.Cut(s, "!"); ok {
		n, err := strconv.ParseUint(e, 10, 64)
		if err != nil {
			return v, false
		}
		v.epoch, s = n, rest
	}
	i := 0
	for {
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j == i {
			return v, false
		}
		n, _ := strconv.ParseUint(s[i:j], 10, 64)
		v.release = append(v.release, n)
		i = j
		if i+1 < len(s) && s[i] == '.' && s[i+1] >= '0' && s[i+1] <= '9' {
			i++
			continue
		}
		break
	}
	rest := s[i:]
	num := func() (uint64, bool) {
		rest = strings.TrimLeft(rest, ".-_")
		j := 0
		for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
			j++
		}
		n, _ := strconv.ParseUint(rest[:j], 10, 64)
		rest = rest[j:]
		return n, true
	}
	take := func(words ...string) bool {
		r := strings.TrimLeft(rest, ".-_")
		for _, w := range words {
			if strings.HasPrefix(r, w) {
				rest = r[len(w):]
				return true
			}
		}
		return false
	}
	switch {
	case take("alpha", "a"):
		v.preKind = 0
		v.pre, _ = num()
	case take("beta", "b"):
		v.preKind = 1
		v.pre, _ = num()
	case take("rc", "c", "preview", "pre"):
		v.preKind = 2
		v.pre, _ = num()
	}
	if take("post", "rev", "r") {
		n, _ := num()
		v.post = int64(n)
	} else if strings.HasPrefix(rest, "-") && len(rest) > 1 && rest[1] >= '0' && rest[1] <= '9' {
		n, _ := num()
		v.post = int64(n)
	}
	if take("dev") {
		n, _ := num()
		v.dev = int64(n)
	}
	return v, rest == ""
}

func comparePEP440(a, b pep440) int {
	if c := cmpU(a.epoch, b.epoch); c != 0 {
		return c
	}
	for i := 0; i < len(a.release) || i < len(b.release); i++ {
		var x, y uint64
		if i < len(a.release) {
			x = a.release[i]
		}
		if i < len(b.release) {
			y = b.release[i]
		}
		if c := cmpU(x, y); c != 0 {
			return c
		}
	}
	// A dev release of a final version (1.0.dev1) comes before its
	// pre-releases.
	ak, bk := a.preKind, b.preKind
	if ak == 3 && a.post < 0 && a.dev >= 0 {
		ak = -1
	}
	if bk == 3 && b.post < 0 && b.dev >= 0 {
		bk = -1
	}
	if ak != bk {
		return cmpI(int64(ak), int64(bk))
	}
	if c := cmpU(a.pre, b.pre); c != 0 {
		return c
	}
	if c := cmpI(a.post, b.post); c != 0 {
		return c
	}
	// No dev part sorts after any dev part.
	ad, bd := a.dev, b.dev
	if ad < 0 {
		ad = 1 << 62
	}
	if bd < 0 {
		bd = 1 << 62
	}
	return cmpI(ad, bd)
}

func cmpI(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// NormalizeName applies the ecosystem's name rules: PyPI names compare
// case-insensitively with runs of "-", "_" and "." equal (PEP 503).
func NormalizeName(eco, name string) string {
	if eco != PyPI {
		return name
	}
	var b strings.Builder
	sep := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			sep = true
			continue
		}
		if sep && b.Len() > 0 {
			b.WriteByte('-')
		}
		sep = false
		b.WriteRune(r)
	}
	return b.String()
}
