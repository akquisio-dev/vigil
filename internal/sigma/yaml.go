package sigma

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var aliasName = regexp.MustCompile(`^\*[A-Za-z0-9_-]+$`)

// A small YAML reader for Sigma rules: block mappings and sequences by
// indentation, plain, quoted and block (| >) scalars, flow sequences of
// scalars ([a, b]) and comments. Anchors, tags and flow mappings are not
// supported; Sigma rules do not need them.

type yline struct {
	indent int
	text   string // without indentation and comment
	no     int
}

func stripComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			if i == 0 || s[i-1] != '\\' {
				inD = !inD
			}
		case c == '#' && !inS && !inD && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return strings.TrimRight(s[:i], " \t")
		}
	}
	return strings.TrimRight(s, " \t")
}

// splitDocs splits a file at "---" lines.
func splitDocs(src string) []string {
	var docs []string
	var cur []string
	for _, l := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		if strings.TrimRight(l, " ") == "---" {
			if len(cur) > 0 {
				docs = append(docs, strings.Join(cur, "\n"))
			}
			cur = nil
			continue
		}
		cur = append(cur, l)
	}
	if len(cur) > 0 {
		docs = append(docs, strings.Join(cur, "\n"))
	}
	return docs
}

type yparser struct {
	lines []yline
	pos   int
	raw   []string
}

func parseYAML(src string) (any, error) {
	p := &yparser{raw: strings.Split(src, "\n")}
	for i, l := range p.raw {
		if strings.Contains(l, "\t") && strings.TrimLeft(l, " ")[:1] == "\t" {
			return nil, fmt.Errorf("line %d: tabs for indentation", i+1)
		}
		t := stripComment(l)
		if strings.TrimSpace(t) == "" {
			continue
		}
		ind := len(t) - len(strings.TrimLeft(t, " "))
		p.lines = append(p.lines, yline{indent: ind, text: strings.TrimSpace(t), no: i + 1})
	}
	if len(p.lines) == 0 {
		return nil, fmt.Errorf("empty document")
	}
	v, err := p.block(p.lines[0].indent)
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.lines) {
		return nil, fmt.Errorf("line %d: unexpected indentation", p.lines[p.pos].no)
	}
	return v, nil
}

func (p *yparser) block(indent int) (any, error) {
	if p.pos >= len(p.lines) {
		return nil, nil
	}
	l := p.lines[p.pos]
	if strings.HasPrefix(l.text, "- ") || l.text == "-" {
		return p.seq(indent)
	}
	return p.mapping(indent)
}

func (p *yparser) seq(indent int) (any, error) {
	var out []any
	for p.pos < len(p.lines) {
		l := p.lines[p.pos]
		if l.indent < indent {
			break
		}
		if l.indent > indent || !(strings.HasPrefix(l.text, "- ") || l.text == "-") {
			return nil, fmt.Errorf("line %d: bad sequence item", l.no)
		}
		item := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
		if item == "" {
			p.pos++
			if p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
				v, err := p.block(p.lines[p.pos].indent)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			} else {
				out = append(out, nil)
			}
			continue
		}
		if k, _, ok := splitKey(item); ok && k != "" {
			// "- key: value" starts a mapping whose keys are indented to
			// the column after "- ".
			col := indent + (len(l.text) - len(item))
			p.lines[p.pos] = yline{indent: col, text: item, no: l.no}
			v, err := p.mapping(col)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		p.pos++
		v, err := p.scalar(item, l)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// splitKey splits "key: value"; keys may be quoted and contain "|".
func splitKey(s string) (string, string, bool) {
	if strings.HasPrefix(s, "'") || strings.HasPrefix(s, `"`) {
		q := s[0]
		end := strings.IndexByte(s[1:], q)
		if end < 0 {
			return "", "", false
		}
		rest := s[end+2:]
		if !strings.HasPrefix(rest, ":") {
			return "", "", false
		}
		return s[1 : end+1], strings.TrimSpace(rest[1:]), true
	}
	for i := 0; i < len(s); i++ {
		if s[i] == ':' && (i+1 == len(s) || s[i+1] == ' ') {
			return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
		}
		if s[i] == '\'' || s[i] == '"' || s[i] == '[' {
			return "", "", false
		}
	}
	return "", "", false
}

func (p *yparser) mapping(indent int) (any, error) {
	out := map[string]any{}
	var order []string
	for p.pos < len(p.lines) {
		l := p.lines[p.pos]
		if l.indent < indent {
			break
		}
		if l.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation", l.no)
		}
		k, v, ok := splitKey(l.text)
		if !ok {
			return nil, fmt.Errorf("line %d: key: value expected", l.no)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %q", l.no, k)
		}
		p.pos++
		switch {
		case v == "":
			if p.pos < len(p.lines) && (p.lines[p.pos].indent > indent ||
				p.lines[p.pos].indent == indent && strings.HasPrefix(p.lines[p.pos].text, "- ")) {
				val, err := p.block(p.lines[p.pos].indent)
				if err != nil {
					return nil, err
				}
				out[k] = val
			} else {
				out[k] = nil
			}
		case v == "|" || v == ">" || v == "|-" || v == ">-":
			out[k] = p.blockScalar(indent, v[0] == '>')
		default:
			val, err := p.scalar(v, l)
			if err != nil {
				return nil, err
			}
			out[k] = val
		}
		order = append(order, k)
	}
	return out, nil
}

// blockScalar collects the raw lines indented deeper than indent.
func (p *yparser) blockScalar(indent int, fold bool) string {
	var parts []string
	for p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
		parts = append(parts, p.lines[p.pos].text)
		p.pos++
	}
	if fold {
		return strings.Join(parts, " ")
	}
	return strings.Join(parts, "\n")
}

func (p *yparser) scalar(s string, l yline) (any, error) {
	switch {
	case strings.HasPrefix(s, "["):
		if !strings.HasSuffix(s, "]") {
			return nil, fmt.Errorf("line %d: flow sequences must fit on one line", l.no)
		}
		var out []any
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			return []any{}, nil
		}
		for _, part := range splitFlow(inner) {
			v, err := p.scalar(strings.TrimSpace(part), l)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case strings.HasPrefix(s, "{"):
		return nil, fmt.Errorf("line %d: flow mappings are not supported", l.no)
	case strings.HasPrefix(s, "&") || aliasName.MatchString(s):
		return nil, fmt.Errorf("line %d: anchors and aliases are not supported", l.no)
	case strings.HasPrefix(s, "'"):
		if !strings.HasSuffix(s, "'") || len(s) < 2 {
			return nil, fmt.Errorf("line %d: unterminated string", l.no)
		}
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	case strings.HasPrefix(s, `"`):
		v, err := strconv.Unquote(s)
		if err != nil {
			return nil, fmt.Errorf("line %d: bad string %s", l.no, s)
		}
		return v, nil
	case s == "null" || s == "~":
		return nil, nil
	}
	return s, nil
}

func splitFlow(s string) []string {
	var out []string
	var cur strings.Builder
	q := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
			cur.WriteByte(c)
		case c == '\'' || c == '"':
			q = c
			cur.WriteByte(c)
		case c == ',':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(out, cur.String())
}
