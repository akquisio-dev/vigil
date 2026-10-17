// Package yara implements the part of the YARA rule language that most
// published rules for Linux malware use, without cgo or other libraries:
//
//	rule name : tag1 tag2 {
//	  meta:      key = "value"  key = 1  key = true
//	  strings:   $a = "text" nocase wide ascii fullword
//	             $b = { 7F 45 4C 46 ?? 0? [2-4] ( 01 | 02 ) }
//	             $c = /regex/is
//	  condition: any of them | all of ($a*) | 2 of ($a, $b) | $a and not $b
//	             | #a > 3 | $a at 0 | $a in (0..1024) | filesize < 2MB
//	             | uint32(0) == 0x464c457f | uint16be(4) != 0 | ( ... )
//	}
//
// Imports, modules, private and global rules, rule references in conditions
// and for-loops are not supported; a rule that uses them fails to compile
// and is skipped with a message. Regular expressions use Go's syntax and
// are meant for text.
package yara

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
)

type Rule struct {
	Name    string
	Tags    []string
	Meta    map[string]string
	strings []*str
	cond    node
}

type str struct {
	id       string
	text     [][]byte // alternatives (ascii, wide), already lower case with nocase
	nocase   bool
	fullword bool
	hex      []hexTok
	re       *regexp.Regexp
}

type hexTok struct {
	b, mask byte
	jmin    int // >= 0: a jump of jmin..jmax bytes instead of a byte
	jmax    int
	alt     [][]hexTok
}

// ---------- lexer ----------

type tok struct {
	kind string // ident, string, hex, regex, num, sym, var, count, eof
	s    string
	n    int64
	line int
}

type lexer struct {
	src  string
	pos  int
	line int
}

func (l *lexer) errf(f string, a ...any) error {
	return fmt.Errorf("line %d: %s", l.line, fmt.Sprintf(f, a...))
}

func (l *lexer) skip() {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\n':
			l.line++
			l.pos++
		case c == ' ' || c == '\t' || c == '\r':
			l.pos++
		case strings.HasPrefix(l.src[l.pos:], "//"):
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		case strings.HasPrefix(l.src[l.pos:], "/*"):
			end := strings.Index(l.src[l.pos+2:], "*/")
			if end < 0 {
				l.pos = len(l.src)
				return
			}
			l.line += strings.Count(l.src[l.pos:l.pos+2+end], "\n")
			l.pos += end + 4
		default:
			return
		}
	}
}

// next reads a token; afterEq makes "/" start a regex and "{" a hex string.
func (l *lexer) next(afterEq bool) (tok, error) {
	l.skip()
	if l.pos >= len(l.src) {
		return tok{kind: "eof", line: l.line}, nil
	}
	c := l.src[l.pos]
	start := l.pos
	t := tok{line: l.line}
	switch {
	case c == '"':
		var b strings.Builder
		l.pos++
		for l.pos < len(l.src) && l.src[l.pos] != '"' {
			if l.src[l.pos] == '\\' && l.pos+1 < len(l.src) {
				l.pos++
				switch e := l.src[l.pos]; e {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case 'r':
					b.WriteByte('\r')
				case 'x':
					if l.pos+2 >= len(l.src) {
						return t, l.errf("bad \\x escape")
					}
					v, err := strconv.ParseUint(l.src[l.pos+1:l.pos+3], 16, 8)
					if err != nil {
						return t, l.errf("bad \\x escape")
					}
					b.WriteByte(byte(v))
					l.pos += 2
				default:
					b.WriteByte(e)
				}
				l.pos++
				continue
			}
			if l.src[l.pos] == '\n' {
				return t, l.errf("newline in string")
			}
			b.WriteByte(l.src[l.pos])
			l.pos++
		}
		if l.pos >= len(l.src) {
			return t, l.errf("unterminated string")
		}
		l.pos++
		t.kind, t.s = "string", b.String()
	case afterEq && c == '{':
		end := strings.IndexByte(l.src[l.pos:], '}')
		if end < 0 {
			return t, l.errf("unterminated hex string")
		}
		t.kind, t.s = "hex", l.src[l.pos+1:l.pos+end]
		l.line += strings.Count(t.s, "\n")
		l.pos += end + 1
	case afterEq && c == '/':
		l.pos++
		var b strings.Builder
		for l.pos < len(l.src) && l.src[l.pos] != '/' {
			if l.src[l.pos] == '\\' && l.pos+1 < len(l.src) {
				b.WriteByte('\\')
				l.pos++
			}
			if l.src[l.pos] == '\n' {
				return t, l.errf("newline in regex")
			}
			b.WriteByte(l.src[l.pos])
			l.pos++
		}
		if l.pos >= len(l.src) {
			return t, l.errf("unterminated regex")
		}
		l.pos++
		flags := ""
		for l.pos < len(l.src) && (l.src[l.pos] == 'i' || l.src[l.pos] == 's') {
			flags += string(l.src[l.pos])
			l.pos++
		}
		t.kind, t.s = "regex", b.String()
		if flags != "" {
			t.s = "(?" + flags + ")" + t.s
		}
	case c == '$' || c == '#' || c == '@' || c == '!':
		l.pos++
		for l.pos < len(l.src) && (isIdent(l.src[l.pos]) || l.src[l.pos] == '*') {
			l.pos++
		}
		if c == '!' && l.pos == start+1 {
			if strings.HasPrefix(l.src[l.pos:], "=") {
				l.pos++
				return tok{kind: "sym", s: "!=", line: t.line}, nil
			}
			return t, l.errf("unexpected !")
		}
		t.kind = map[byte]string{'$': "var", '#': "count", '@': "offset", '!': "length"}[c]
		t.s = l.src[start+1 : l.pos]
	case c >= '0' && c <= '9':
		if strings.HasPrefix(l.src[l.pos:], "0x") || strings.HasPrefix(l.src[l.pos:], "0X") {
			l.pos += 2
			for l.pos < len(l.src) && unicode.Is(unicode.ASCII_Hex_Digit, rune(l.src[l.pos])) {
				l.pos++
			}
		} else {
			for l.pos < len(l.src) && l.src[l.pos] >= '0' && l.src[l.pos] <= '9' {
				l.pos++
			}
		}
		lit := l.src[start:l.pos]
		n, err := strconv.ParseInt(lit, 0, 64)
		if err != nil {
			return t, l.errf("bad number %q", lit)
		}
		t.kind, t.n = "num", n
		// size suffixes
		if strings.HasPrefix(l.src[l.pos:], "KB") {
			t.n *= 1024
			l.pos += 2
		} else if strings.HasPrefix(l.src[l.pos:], "MB") {
			t.n *= 1024 * 1024
			l.pos += 2
		}
	case isIdent(c):
		for l.pos < len(l.src) && isIdent(l.src[l.pos]) {
			l.pos++
		}
		t.kind, t.s = "ident", l.src[start:l.pos]
	default:
		for _, s := range []string{"==", "!=", "<=", ">=", "..", "{", "}", "(", ")", ":", "=", ",", "<", ">", "-"} {
			if strings.HasPrefix(l.src[l.pos:], s) {
				l.pos += len(s)
				return tok{kind: "sym", s: s, line: t.line}, nil
			}
		}
		return t, l.errf("unexpected %q", c)
	}
	return t, nil
}

func isIdent(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// ---------- parser ----------

type parser struct {
	lx   *lexer
	cur  tok
	rule *Rule
}

func (p *parser) advance(afterEq bool) error {
	t, err := p.lx.next(afterEq)
	p.cur = t
	return err
}

func (p *parser) expect(kind, s string) error {
	if p.cur.kind != kind || s != "" && p.cur.s != s {
		want := s
		if want == "" {
			want = kind
		}
		got := p.cur.s
		if got == "" {
			got = p.cur.kind
		}
		return fmt.Errorf("line %d: expected %s, found %s", p.cur.line, want, got)
	}
	return p.advance(false)
}

// Compile parses a source with one or more rules. Rules that fail are left
// out; their errors are returned next to the rules that compiled.
func Compile(src string) ([]*Rule, []error) {
	lx := &lexer{src: src, line: 1}
	p := &parser{lx: lx}
	var rules []*Rule
	var errs []error
	if err := p.advance(false); err != nil {
		return nil, []error{err}
	}
	for p.cur.kind != "eof" {
		start := p.lx.pos
		r, err := p.rule_()
		if err != nil {
			errs = append(errs, err)
			// skip to the end of this rule: the next line starting with "rule"
			p.lx.pos = start
			idx := strings.Index(p.lx.src[p.lx.pos+1:], "\nrule ")
			if idx >= 0 {
				idx++
			}
			for _, kw := range []string{"\nprivate rule ", "\nglobal rule ", "\nimport ", "\ninclude "} {
				if i := strings.Index(p.lx.src[p.lx.pos+1:], kw); i >= 0 && (idx < 0 || i+1 < idx) {
					idx = i + 1
				}
			}
			if idx < 0 {
				break
			}
			p.lx.line += strings.Count(p.lx.src[p.lx.pos:p.lx.pos+idx], "\n")
			p.lx.pos += idx + 1
			if err := p.advance(false); err != nil {
				errs = append(errs, err)
				break
			}
			continue
		}
		rules = append(rules, r)
		if len(rules) > 5000 {
			errs = append(errs, errors.New("more than 5000 rules"))
			break
		}
	}
	return rules, errs
}

func (p *parser) rule_() (*Rule, error) {
	if p.cur.kind == "ident" && (p.cur.s == "import" || p.cur.s == "include") {
		return nil, fmt.Errorf("line %d: %s is not supported", p.cur.line, p.cur.s)
	}
	if p.cur.kind == "ident" && (p.cur.s == "private" || p.cur.s == "global") {
		return nil, fmt.Errorf("line %d: %s rules are not supported", p.cur.line, p.cur.s)
	}
	if err := p.expect("ident", "rule"); err != nil {
		return nil, err
	}
	if p.cur.kind != "ident" {
		return nil, fmt.Errorf("line %d: rule name expected", p.cur.line)
	}
	r := &Rule{Name: p.cur.s, Meta: map[string]string{}}
	p.rule = r
	if err := p.advance(false); err != nil {
		return nil, err
	}
	if p.cur.kind == "sym" && p.cur.s == ":" {
		p.advance(false)
		for p.cur.kind == "ident" {
			r.Tags = append(r.Tags, p.cur.s)
			p.advance(false)
		}
	}
	if err := p.expect("sym", "{"); err != nil {
		return nil, err
	}
	for {
		if p.cur.kind != "ident" {
			return nil, fmt.Errorf("line %d: section expected in rule %s", p.cur.line, r.Name)
		}
		section := p.cur.s
		p.advance(false)
		if err := p.expect("sym", ":"); err != nil {
			return nil, err
		}
		switch section {
		case "meta":
			for p.cur.kind == "ident" && p.cur.s != "strings" && p.cur.s != "condition" {
				k := p.cur.s
				p.advance(false)
				if p.cur.kind == "sym" && p.cur.s == ":" {
					// next section ("strings:"): step back
					return nil, fmt.Errorf("line %d: meta %s has no value", p.cur.line, k)
				}
				if err := p.expect("sym", "="); err != nil {
					return nil, err
				}
				switch p.cur.kind {
				case "string", "ident":
					r.Meta[k] = p.cur.s
				case "num":
					r.Meta[k] = strconv.FormatInt(p.cur.n, 10)
				case "sym":
					if p.cur.s == "-" {
						p.advance(false)
						r.Meta[k] = "-" + strconv.FormatInt(p.cur.n, 10)
					}
				}
				p.advance(false)
			}
		case "strings":
			for p.cur.kind == "var" {
				s, err := p.string_()
				if err != nil {
					return nil, err
				}
				r.strings = append(r.strings, s)
			}
		case "condition":
			n, err := p.or()
			if err != nil {
				return nil, err
			}
			r.cond = n
			if err := p.expect("sym", "}"); err != nil {
				return nil, err
			}
			return r, nil
		default:
			return nil, fmt.Errorf("line %d: unknown section %q", p.cur.line, section)
		}
	}
}

func (p *parser) string_() (*str, error) {
	s := &str{id: p.cur.s}
	if s.id == "" {
		s.id = fmt.Sprintf("anon%d", len(p.rule.strings))
	}
	for _, o := range p.rule.strings {
		if o.id == s.id {
			return nil, fmt.Errorf("line %d: duplicate string $%s", p.cur.line, s.id)
		}
	}
	if err := p.advance(false); err != nil {
		return nil, err
	}
	if p.cur.kind != "sym" || p.cur.s != "=" {
		return nil, fmt.Errorf("line %d: = expected after $%s", p.cur.line, s.id)
	}
	if err := p.advance(true); err != nil {
		return nil, err
	}
	val := p.cur
	if err := p.advance(false); err != nil {
		return nil, err
	}
	mods := map[string]bool{}
	for p.cur.kind == "ident" && (p.cur.s == "nocase" || p.cur.s == "wide" || p.cur.s == "ascii" || p.cur.s == "fullword" || p.cur.s == "private") {
		mods[p.cur.s] = true
		p.advance(false)
	}
	if p.cur.kind == "ident" && (p.cur.s == "xor" || p.cur.s == "base64" || p.cur.s == "base64wide") {
		return nil, fmt.Errorf("line %d: modifier %s is not supported", p.cur.line, p.cur.s)
	}
	switch val.kind {
	case "string":
		if val.s == "" {
			return nil, fmt.Errorf("line %d: empty string", val.line)
		}
		s.nocase, s.fullword = mods["nocase"], mods["fullword"]
		base := val.s
		if s.nocase {
			base = strings.ToLower(base)
		}
		if !mods["wide"] || mods["ascii"] {
			s.text = append(s.text, []byte(base))
		}
		if mods["wide"] {
			var w []byte
			for _, u := range utf16.Encode([]rune(base)) {
				w = append(w, byte(u), byte(u>>8))
			}
			s.text = append(s.text, w)
		}
	case "hex":
		toks, err := parseHex(val.s)
		if err != nil {
			return nil, fmt.Errorf("line %d: $%s: %v", val.line, s.id, err)
		}
		s.hex = toks
	case "regex":
		re, err := regexp.Compile(val.s)
		if err != nil {
			return nil, fmt.Errorf("line %d: $%s: %v", val.line, s.id, err)
		}
		if mods["nocase"] {
			re, _ = regexp.Compile("(?i)" + val.s)
		}
		s.re = re
	default:
		return nil, fmt.Errorf("line %d: string, hex string or regex expected", val.line)
	}
	return s, nil
}

func parseHex(src string) ([]hexTok, error) {
	fields := strings.Fields(strings.NewReplacer("[", " [ ", "]", " ] ", "(", " ( ", ")", " ) ", "|", " | ").Replace(src))
	toks, rest, err := parseHexSeq(fields, false)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected %q in hex string", rest[0])
	}
	if len(toks) == 0 {
		return nil, errors.New("empty hex string")
	}
	if toks[0].jmax > 0 || toks[len(toks)-1].jmax > 0 {
		return nil, errors.New("hex string cannot start or end with a jump")
	}
	return toks, nil
}

func parseHexSeq(f []string, inAlt bool) ([]hexTok, []string, error) {
	var out []hexTok
	for len(f) > 0 {
		w := f[0]
		switch {
		case w == "|" || w == ")":
			if !inAlt {
				return nil, nil, fmt.Errorf("unexpected %q", w)
			}
			return out, f, nil
		case w == "(":
			var alts [][]hexTok
			f = f[1:]
			for {
				seq, rest, err := parseHexSeq(f, true)
				if err != nil {
					return nil, nil, err
				}
				alts = append(alts, seq)
				if len(rest) == 0 {
					return nil, nil, errors.New("unterminated alternative")
				}
				f = rest[1:]
				if rest[0] == ")" {
					break
				}
			}
			out = append(out, hexTok{jmin: -1, alt: alts})
			continue
		case w == "[":
			end := -1
			for i, x := range f {
				if x == "]" {
					end = i
					break
				}
			}
			if end < 0 {
				return nil, nil, errors.New("unterminated jump")
			}
			spec := strings.Join(f[1:end], "")
			lo, hi, ok := strings.Cut(spec, "-")
			a, err1 := strconv.Atoi(lo)
			b := a
			var err2 error
			if ok {
				if hi == "" {
					b = 1 << 16
				} else {
					b, err2 = strconv.Atoi(hi)
				}
			}
			if lo == "" {
				a, err1 = 0, nil
			}
			if err1 != nil || err2 != nil || a < 0 || b < a || b > 1<<16 {
				return nil, nil, fmt.Errorf("bad jump [%s]", spec)
			}
			out = append(out, hexTok{jmin: a, jmax: b})
			f = f[end+1:]
			continue
		default:
			if len(w)%2 != 0 {
				return nil, nil, fmt.Errorf("bad hex %q", w)
			}
			for i := 0; i < len(w); i += 2 {
				var b, m byte
				for k := 0; k < 2; k++ {
					c := w[i+k]
					shift := uint(4 * (1 - k))
					switch {
					case c == '?':
					case unicode.Is(unicode.ASCII_Hex_Digit, rune(c)):
						v, _ := strconv.ParseUint(string(c), 16, 8)
						b |= byte(v) << shift
						m |= 0xF << shift
					default:
						return nil, nil, fmt.Errorf("bad hex %q", w)
					}
				}
				out = append(out, hexTok{b: b, mask: m, jmin: -1})
			}
		}
		f = f[1:]
	}
	if inAlt {
		return out, nil, nil
	}
	return out, f, nil
}

// ---------- conditions ----------

type node interface {
	eval(c *ctx) (int64, bool)
}

type ctx struct {
	data    []byte
	lower   []byte // data in lower case, made once for all nocase strings
	rule    *Rule
	matches map[string][]int // string id -> offsets
}

func (c *ctx) offsets(s *str) []int {
	if m, ok := c.matches[s.id]; ok {
		return m
	}
	m := c.findAll(s)
	c.matches[s.id] = m
	return m
}

type boolOp struct {
	op   string
	l, r node
}

func (b boolOp) eval(c *ctx) (int64, bool) {
	switch b.op {
	case "and":
		_, x := b.l.eval(c)
		if !x {
			return 0, false
		}
		_, y := b.r.eval(c)
		return 0, y
	case "or":
		_, x := b.l.eval(c)
		if x {
			return 0, true
		}
		_, y := b.r.eval(c)
		return 0, y
	}
	_, x := b.l.eval(c)
	return 0, !x
}

type cmpOp struct {
	op   string
	l, r node
}

func (o cmpOp) eval(c *ctx) (int64, bool) {
	a, _ := o.l.eval(c)
	b, _ := o.r.eval(c)
	var ok bool
	switch o.op {
	case "==":
		ok = a == b
	case "!=":
		ok = a != b
	case "<":
		ok = a < b
	case ">":
		ok = a > b
	case "<=":
		ok = a <= b
	case ">=":
		ok = a >= b
	}
	return 0, ok
}

type numNode int64

func (n numNode) eval(*ctx) (int64, bool) { return int64(n), n != 0 }

type boolLit bool

func (b boolLit) eval(*ctx) (int64, bool) { return 0, bool(b) }

type filesizeNode struct{}

func (filesizeNode) eval(c *ctx) (int64, bool) { return int64(len(c.data)), true }

type intRead struct {
	size int
	be   bool
	at   node
}

func (r intRead) eval(c *ctx) (int64, bool) {
	off, _ := r.at.eval(c)
	if off < 0 || off+int64(r.size) > int64(len(c.data)) {
		return 0, false
	}
	b := c.data[off : off+int64(r.size)]
	var v uint64
	for i := 0; i < r.size; i++ {
		if r.be {
			v = v<<8 | uint64(b[i])
		} else {
			v |= uint64(b[i]) << (8 * i)
		}
	}
	return int64(v), true
}

type strNode struct {
	s      *str
	at     node // optional
	lo, hi node // optional "in (lo..hi)"
}

func (n strNode) eval(c *ctx) (int64, bool) {
	offs := c.offsets(n.s)
	switch {
	case n.at != nil:
		want, _ := n.at.eval(c)
		for _, o := range offs {
			if int64(o) == want {
				return 1, true
			}
		}
		return 0, false
	case n.lo != nil:
		lo, _ := n.lo.eval(c)
		hi, _ := n.hi.eval(c)
		for _, o := range offs {
			if int64(o) >= lo && int64(o) <= hi {
				return 1, true
			}
		}
		return 0, false
	}
	return int64(len(offs)), len(offs) > 0
}

type countNode struct{ s *str }

func (n countNode) eval(c *ctx) (int64, bool) {
	k := len(c.offsets(n.s))
	return int64(k), k > 0
}

type ofNode struct {
	need int // -1: all
	set  []*str
}

func (n ofNode) eval(c *ctx) (int64, bool) {
	need := n.need
	if need < 0 {
		need = len(n.set)
	}
	if need == 0 {
		return 0, true
	}
	hit := 0
	for _, s := range n.set {
		if len(c.offsets(s)) > 0 {
			hit++
			if hit >= need {
				return 1, true
			}
		}
	}
	return 0, false
}

func (p *parser) find(id string) (*str, error) {
	for _, s := range p.rule.strings {
		if s.id == id {
			return s, nil
		}
	}
	return nil, fmt.Errorf("line %d: undefined string $%s", p.cur.line, id)
}

func (p *parser) or() (node, error) {
	l, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.cur.kind == "ident" && p.cur.s == "or" {
		p.advance(false)
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		l = boolOp{"or", l, r}
	}
	return l, nil
}

func (p *parser) and() (node, error) {
	l, err := p.not()
	if err != nil {
		return nil, err
	}
	for p.cur.kind == "ident" && p.cur.s == "and" {
		p.advance(false)
		r, err := p.not()
		if err != nil {
			return nil, err
		}
		l = boolOp{"and", l, r}
	}
	return l, nil
}

func (p *parser) not() (node, error) {
	if p.cur.kind == "ident" && p.cur.s == "not" {
		p.advance(false)
		n, err := p.not()
		if err != nil {
			return nil, err
		}
		return boolOp{op: "not", l: n}, nil
	}
	return p.cmp()
}

func (p *parser) cmp() (node, error) {
	l, err := p.primary()
	if err != nil {
		return nil, err
	}
	if p.cur.kind == "sym" {
		switch p.cur.s {
		case "==", "!=", "<", ">", "<=", ">=":
			op := p.cur.s
			p.advance(false)
			r, err := p.primary()
			if err != nil {
				return nil, err
			}
			return cmpOp{op, l, r}, nil
		}
	}
	return l, nil
}

func (p *parser) set() ([]*str, error) {
	if p.cur.kind == "ident" && p.cur.s == "them" {
		p.advance(false)
		if len(p.rule.strings) == 0 {
			return nil, fmt.Errorf("line %d: \"them\" without strings", p.cur.line)
		}
		return p.rule.strings, nil
	}
	if err := p.expect("sym", "("); err != nil {
		return nil, err
	}
	var out []*str
	for {
		if p.cur.kind != "var" {
			return nil, fmt.Errorf("line %d: $string expected in set", p.cur.line)
		}
		pat := p.cur.s
		if strings.HasSuffix(pat, "*") {
			pre := strings.TrimSuffix(pat, "*")
			n := 0
			for _, s := range p.rule.strings {
				if strings.HasPrefix(s.id, pre) {
					out = append(out, s)
					n++
				}
			}
			if n == 0 {
				return nil, fmt.Errorf("line %d: no string matches $%s", p.cur.line, pat)
			}
		} else {
			s, err := p.find(pat)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		p.advance(false)
		if p.cur.kind == "sym" && p.cur.s == "," {
			p.advance(false)
			continue
		}
		if err := p.expect("sym", ")"); err != nil {
			return nil, err
		}
		return out, nil
	}
}

func (p *parser) primary() (node, error) {
	t := p.cur
	switch t.kind {
	case "sym":
		if t.s == "(" {
			p.advance(false)
			n, err := p.or()
			if err != nil {
				return nil, err
			}
			return n, p.expect("sym", ")")
		}
		if t.s == "-" {
			p.advance(false)
			if p.cur.kind != "num" {
				return nil, fmt.Errorf("line %d: number expected", p.cur.line)
			}
			n := -p.cur.n
			p.advance(false)
			return numNode(n), nil
		}
	case "num":
		p.advance(false)
		if p.cur.kind == "ident" && p.cur.s == "of" {
			p.advance(false)
			set, err := p.set()
			if err != nil {
				return nil, err
			}
			return ofNode{need: int(t.n), set: set}, nil
		}
		return numNode(t.n), nil
	case "var":
		if t.s == "" || strings.HasSuffix(t.s, "*") {
			return nil, fmt.Errorf("line %d: anonymous or wildcard string outside a set", t.line)
		}
		s, err := p.find(t.s)
		if err != nil {
			return nil, err
		}
		p.advance(false)
		n := strNode{s: s}
		if p.cur.kind == "ident" && p.cur.s == "at" {
			p.advance(false)
			at, err := p.primary()
			if err != nil {
				return nil, err
			}
			n.at = at
		} else if p.cur.kind == "ident" && p.cur.s == "in" {
			p.advance(false)
			if err := p.expect("sym", "("); err != nil {
				return nil, err
			}
			lo, err := p.primary()
			if err != nil {
				return nil, err
			}
			if err := p.expect("sym", ".."); err != nil {
				return nil, err
			}
			hi, err := p.primary()
			if err != nil {
				return nil, err
			}
			if err := p.expect("sym", ")"); err != nil {
				return nil, err
			}
			n.lo, n.hi = lo, hi
		}
		return n, nil
	case "count":
		s, err := p.find(t.s)
		if err != nil {
			return nil, err
		}
		p.advance(false)
		return countNode{s}, nil
	case "ident":
		switch t.s {
		case "true", "false":
			p.advance(false)
			return boolLit(t.s == "true"), nil
		case "filesize":
			p.advance(false)
			return filesizeNode{}, nil
		case "any", "all", "none":
			p.advance(false)
			if err := p.expect("ident", "of"); err != nil {
				return nil, err
			}
			set, err := p.set()
			if err != nil {
				return nil, err
			}
			need := map[string]int{"any": 1, "all": -1, "none": 0}[t.s]
			if t.s == "none" {
				return boolOp{op: "not", l: ofNode{need: 1, set: set}}, nil
			}
			return ofNode{need: need, set: set}, nil
		case "uint8", "uint16", "uint32", "uint16be", "uint32be", "uint8be":
			size := map[string]int{"uint8": 1, "uint16": 2, "uint32": 4, "uint16be": 2, "uint32be": 4, "uint8be": 1}[t.s]
			be := strings.HasSuffix(t.s, "be")
			p.advance(false)
			if err := p.expect("sym", "("); err != nil {
				return nil, err
			}
			at, err := p.or()
			if err != nil {
				return nil, err
			}
			if err := p.expect("sym", ")"); err != nil {
				return nil, err
			}
			return intRead{size: size, be: be, at: at}, nil
		}
		return nil, fmt.Errorf("line %d: %q is not supported in conditions", t.line, t.s)
	}
	return nil, fmt.Errorf("line %d: unexpected %s %s in condition", t.line, t.kind, t.s)
}

// ---------- matching ----------

const maxMatches = 1000

// hexBudget caps the work of one hex string on one file: patterns with
// wide jumps could otherwise take minutes on a large file. A string that
// runs out counts the matches found so far.
const hexBudget = 20_000_000

func (c *ctx) findAll(s *str) []int {
	data := c.data
	var out []int
	switch {
	case s.text != nil:
		hay := data
		if s.nocase {
			if c.lower == nil {
				c.lower = bytes.ToLower(data)
			}
			hay = c.lower
		}
		for _, needle := range s.text {
			for i := 0; len(out) < maxMatches; {
				j := bytes.Index(hay[i:], needle)
				if j < 0 {
					break
				}
				at := i + j
				if !s.fullword || wordBoundary(data, at, len(needle)) {
					out = append(out, at)
				}
				i = at + 1
			}
		}
		sort.Ints(out)
	case s.hex != nil:
		budget := hexBudget
		for i := 0; i < len(data) && len(out) < maxMatches && budget > 0; i++ {
			if s.hex[0].jmin < 0 && s.hex[0].alt == nil && data[i]&s.hex[0].mask != s.hex[0].b {
				continue
			}
			if matchHex(data, i, s.hex, 0, &budget) {
				out = append(out, i)
			}
		}
	case s.re != nil:
		for _, loc := range s.re.FindAllIndex(data, maxMatches) {
			out = append(out, loc[0])
		}
	}
	return out
}

func wordBoundary(data []byte, at, n int) bool {
	alnum := func(c byte) bool { return isIdent(c) }
	if at > 0 && alnum(data[at-1]) {
		return false
	}
	if end := at + n; end < len(data) && alnum(data[end]) {
		return false
	}
	return true
}

// matchHex reports whether the hex tokens match data at position i. The
// recursion depth is bounded by the pattern, the work by budget.
func matchHex(data []byte, i int, toks []hexTok, depth int, budget *int) bool {
	if depth > 64 || *budget <= 0 {
		return false
	}
	*budget--
	for k := 0; k < len(toks); k++ {
		t := toks[k]
		switch {
		case t.alt != nil:
			for _, a := range t.alt {
				seq := append(append([]hexTok{}, a...), toks[k+1:]...)
				if matchHex(data, i, seq, depth+1, budget) {
					return true
				}
			}
			return false
		case t.jmin >= 0:
			hi := t.jmax
			if hi > 4096 {
				hi = 4096
			}
			for j := t.jmin; j <= hi; j++ {
				if i+j > len(data) {
					return false
				}
				if matchHex(data, i+j, toks[k+1:], depth+1, budget) {
					return true
				}
			}
			return false
		default:
			if i >= len(data) || data[i]&t.mask != t.b {
				return false
			}
			i++
		}
	}
	return true
}

// Match returns the rules that match data.
func Match(rules []*Rule, data []byte) []*Rule {
	var out []*Rule
	var lower []byte
	for _, r := range rules {
		c := &ctx{data: data, rule: r, matches: map[string][]int{}, lower: lower}
		if _, ok := r.cond.eval(c); ok {
			out = append(out, r)
		}
		lower = c.lower
	}
	return out
}
