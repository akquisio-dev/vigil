// Package dpkgver compares Debian package versions the way dpkg does
// ([epoch:]upstream[-revision], with "~" sorting before everything, even
// the end of the string).
package dpkgver

import "strings"

// Compare returns -1, 0 or 1 when a is older than, equal to or newer than b.
func Compare(a, b string) int {
	ea, ua, ra := split(a)
	eb, ub, rb := split(b)
	if c := cmpNum(ea, eb); c != 0 {
		return c
	}
	if c := cmpPart(ua, ub); c != 0 {
		return c
	}
	return cmpPart(ra, rb)
}

func split(v string) (epoch, upstream, revision string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, v = v[:i], v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		v, revision = v[:i], v[i+1:]
	}
	return epoch, v, revision
}

func order(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z':
		return int(c)
	case c == '~':
		return -1
	case c == 0:
		return 0
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func cmpNum(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// cmpPart is dpkg's verrevcmp: alternating non-digit and digit runs.
func cmpPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ca, cb byte
			if i < len(a) && !isDigit(a[i]) {
				ca = a[i]
			}
			if j < len(b) && !isDigit(b[j]) {
				cb = b[j]
			}
			oa, ob := order(ca), order(cb)
			if oa != ob {
				if oa < ob {
					return -1
				}
				return 1
			}
			if ca != 0 {
				i++
			}
			if cb != 0 {
				j++
			}
			if ca == 0 && cb == 0 {
				break
			}
		}
		si := i
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		sj := j
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if c := cmpNum(a[si:i], b[sj:j]); c != 0 {
			return c
		}
	}
	return 0
}
