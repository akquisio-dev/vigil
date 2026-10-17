// Package sigma compiles Sigma rules (https://sigmahq.io) for the Linux
// log sources vigil has events for, and matches them against field
// values. Supported: the detection part with named selections (maps,
// lists of maps, keyword lists), the modifiers contains, startswith,
// endswith, all, re, cidr, windash and the comparison modifiers lt, lte,
// gt, gte; wildcards * and ?; conditions with and, or, not, parentheses,
// "1 of x*", "all of x*", "1 of them", "all of them". Matching is case
// insensitive, as Sigma defines it. Aggregations (count, near, |) and
// base64 modifiers are not supported; such rules fail to compile.
package sigma

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Rule struct {
	ID          string
	Title       string
	Description string
	Level       string // informational, low, medium, high, critical
	Status      string
	Tags        []string
	Product     string
	Category    string
	Service     string
	Fields      []string // all fields the rule uses
	sel         map[string]selection
	cond        cnode
}

// Getter returns the value of a Sigma field for the event being matched,
// and false when the event does not have it.
type Getter func(field string) (string, bool)

type matcher struct {
	field  string // "" for keywords
	values []string
	mod    string // "", contains, startswith, endswith, re, cidr, lt, lte, gt, gte
	all    bool
	re     []*regexp.Regexp
	pfx    []netip.Prefix
	nums   []float64
	null   bool // field must be absent or empty
}

type selection struct {
	any [][]matcher // OR of AND-groups
}

// ParseFile compiles every rule in a YAML file ("---" separates rules).
func ParseFile(src string) ([]*Rule, []error) {
	var rules []*Rule
	var errs []error
	for i, doc := range splitDocs(src) {
		if strings.TrimSpace(stripComment(doc)) == "" {
			continue
		}
		r, err := Parse(doc)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %d: %w", i+1, err))
			continue
		}
		rules = append(rules, r)
	}
	return rules, errs
}

func asString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	}
	return fmt.Sprint(v)
}

// Parse compiles one rule.
func Parse(doc string) (*Rule, error) {
	v, err := parseYAML(doc)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("rule is not a mapping")
	}
	r := &Rule{ID: asString(m["id"]), Title: asString(m["title"]), Description: asString(m["description"]),
		Level: strings.ToLower(asString(m["level"])), Status: asString(m["status"]), sel: map[string]selection{}}
	if r.Title == "" {
		return nil, errors.New("title missing")
	}
	if tags, ok := m["tags"].([]any); ok {
		for _, t := range tags {
			r.Tags = append(r.Tags, strings.ToLower(asString(t)))
		}
	}
	if ls, ok := m["logsource"].(map[string]any); ok {
		r.Product, r.Category, r.Service = strings.ToLower(asString(ls["product"])), strings.ToLower(asString(ls["category"])), strings.ToLower(asString(ls["service"]))
	}
	det, ok := m["detection"].(map[string]any)
	if !ok {
		return nil, errors.New("detection missing")
	}
	fields := map[string]bool{}
	var conds []string
	for name, body := range det {
		if name == "condition" {
			switch c := body.(type) {
			case string:
				conds = []string{c}
			case []any:
				for _, x := range c {
					conds = append(conds, asString(x))
				}
			default:
				return nil, errors.New("condition must be a string")
			}
			continue
		}
		if name == "timeframe" {
			return nil, errors.New("timeframe (aggregation) is not supported")
		}
		sel, err := compileSelection(body, fields)
		if err != nil {
			return nil, fmt.Errorf("selection %s: %w", name, err)
		}
		r.sel[name] = sel
	}
	if len(conds) == 0 {
		return nil, errors.New("condition missing")
	}
	var nodes []cnode
	for _, c := range conds {
		if strings.Contains(c, "|") {
			return nil, errors.New("aggregations in the condition are not supported")
		}
		n, err := parseCondition(c, r.sel)
		if err != nil {
			return nil, fmt.Errorf("condition: %w", err)
		}
		nodes = append(nodes, n)
	}
	r.cond = nodes[0]
	for _, n := range nodes[1:] {
		r.cond = cbin{"or", r.cond, n}
	}
	for f := range fields {
		r.Fields = append(r.Fields, f)
	}
	sort.Strings(r.Fields)
	return r, nil
}

func compileSelection(body any, fields map[string]bool) (selection, error) {
	switch b := body.(type) {
	case map[string]any:
		g, err := compileGroup(b, fields)
		if err != nil {
			return selection{}, err
		}
		return selection{any: [][]matcher{g}}, nil
	case []any:
		var sel selection
		var keywords []string
		for _, item := range b {
			switch x := item.(type) {
			case map[string]any:
				g, err := compileGroup(x, fields)
				if err != nil {
					return selection{}, err
				}
				sel.any = append(sel.any, g)
			default:
				keywords = append(keywords, asString(x))
			}
		}
		if len(keywords) > 0 {
			mt, err := compileMatcher("", "", keywords)
			if err != nil {
				return selection{}, err
			}
			sel.any = append(sel.any, []matcher{mt})
		}
		return sel, nil
	case string:
		mt, err := compileMatcher("", "", []string{b})
		if err != nil {
			return selection{}, err
		}
		return selection{any: [][]matcher{{mt}}}, nil
	}
	return selection{}, errors.New("selection must be a mapping or a list")
}

func compileGroup(m map[string]any, fields map[string]bool) ([]matcher, error) {
	var out []matcher
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		field, mods, _ := strings.Cut(k, "|")
		var vals []string
		null := false
		switch v := m[k].(type) {
		case nil:
			null = true
		case []any:
			for _, x := range v {
				if x == nil {
					null = true
					continue
				}
				vals = append(vals, asString(x))
			}
		default:
			vals = []string{asString(v)}
		}
		mt, err := compileMatcher(field, mods, vals)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		mt.null = null && len(vals) == 0
		fields[field] = true
		out = append(out, mt)
	}
	return out, nil
}

func compileMatcher(field, mods string, vals []string) (matcher, error) {
	mt := matcher{field: field}
	for _, mod := range strings.Split(mods, "|") {
		switch mod {
		case "":
		case "contains", "startswith", "endswith", "re", "cidr", "lt", "lte", "gt", "gte":
			if mt.mod != "" {
				return mt, fmt.Errorf("modifiers %s and %s together are not supported", mt.mod, mod)
			}
			mt.mod = mod
		case "all":
			mt.all = true
		case "windash":
			// "-x" also as "/x" and the other dashes; on Linux only "-" matters
		case "i", "m", "s":
			// regex flags, folded in below
		default:
			return mt, fmt.Errorf("modifier %q is not supported", mod)
		}
	}
	switch mt.mod {
	case "re":
		flags := "(?i)"
		if strings.Contains(mods, "|s") {
			flags = "(?is)"
		}
		for _, v := range vals {
			re, err := regexp.Compile(flags + v)
			if err != nil {
				return mt, err
			}
			mt.re = append(mt.re, re)
		}
	case "cidr":
		for _, v := range vals {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				return mt, err
			}
			mt.pfx = append(mt.pfx, p.Masked())
		}
	case "lt", "lte", "gt", "gte":
		for _, v := range vals {
			n, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return mt, err
			}
			mt.nums = append(mt.nums, n)
		}
	default:
		for _, v := range vals {
			mt.values = append(mt.values, strings.ToLower(v))
		}
	}
	return mt, nil
}

// globMatch matches Sigma wildcards (* and ?, \ escapes them), case
// already folded.
func globMatch(pat, s string) bool {
	if !strings.ContainsAny(pat, "*?") {
		return unescape(pat) == s
	}
	// path.Match treats / specially; map it away.
	p := strings.NewReplacer("/", "\x00", "[", "\\[", "]", "\\]").Replace(pat)
	ok, err := path.Match(p, strings.ReplaceAll(s, "/", "\x00"))
	return err == nil && ok
}

func unescape(s string) string {
	return strings.NewReplacer(`\*`, "*", `\?`, "?", `\\`, `\`).Replace(s)
}

func (mt matcher) matchValue(v string) bool {
	lv := strings.ToLower(v)
	one := func(i int) bool {
		switch mt.mod {
		case "re":
			return mt.re[i].MatchString(v)
		case "cidr":
			a, err := netip.ParseAddr(v)
			return err == nil && mt.pfx[i].Contains(a.Unmap())
		case "lt", "lte", "gt", "gte":
			n, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return false
			}
			want := mt.nums[i]
			return mt.mod == "lt" && n < want || mt.mod == "lte" && n <= want || mt.mod == "gt" && n > want || mt.mod == "gte" && n >= want
		}
		p := mt.values[i]
		switch mt.mod {
		case "contains":
			return globMatch("*"+p+"*", lv)
		case "startswith":
			return globMatch(p+"*", lv)
		case "endswith":
			return globMatch("*"+p, lv)
		}
		return globMatch(p, lv)
	}
	n := len(mt.values) + len(mt.re) + len(mt.pfx) + len(mt.nums)
	if n == 0 {
		return false
	}
	for i := 0; i < n; i++ {
		ok := one(i)
		if mt.all && !ok {
			return false
		}
		if !mt.all && ok {
			return true
		}
	}
	return mt.all
}

func (mt matcher) match(get Getter, all func() []string) bool {
	if mt.field == "" {
		// keywords: anywhere in any field
		for _, v := range all() {
			k := matcher{values: mt.values, all: mt.all, mod: "contains"}
			if k.matchValue(v) {
				return true
			}
		}
		return false
	}
	v, ok := get(mt.field)
	if mt.null {
		return !ok || v == ""
	}
	if !ok {
		return false
	}
	return mt.matchValue(v)
}

func (s selection) match(get Getter, all func() []string) bool {
	for _, g := range s.any {
		ok := true
		for _, mt := range g {
			if !mt.match(get, all) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// Match evaluates the rule. all returns every field value, for keywords.
func (r *Rule) Match(get Getter, all func() []string) bool {
	_, ok := r.cond.eval(r, get, all)
	return ok
}

// ---------- condition ----------

type cnode interface {
	eval(r *Rule, get Getter, all func() []string) (int, bool)
}

type cbin struct {
	op   string
	l, r cnode
}

func (b cbin) eval(r *Rule, get Getter, all func() []string) (int, bool) {
	_, x := b.l.eval(r, get, all)
	if b.op == "and" && !x || b.op == "or" && x {
		return 0, x
	}
	_, y := b.r.eval(r, get, all)
	return 0, y
}

type cnot struct{ n cnode }

func (c cnot) eval(r *Rule, get Getter, all func() []string) (int, bool) {
	_, x := c.n.eval(r, get, all)
	return 0, !x
}

type cref string

func (c cref) eval(r *Rule, get Getter, all func() []string) (int, bool) {
	return 0, r.sel[string(c)].match(get, all)
}

type cof struct {
	need  int // -1 all
	names []string
}

func (c cof) eval(r *Rule, get Getter, all func() []string) (int, bool) {
	hit := 0
	for _, n := range c.names {
		if r.sel[n].match(get, all) {
			hit++
			if c.need > 0 && hit >= c.need {
				return 0, true
			}
		} else if c.need < 0 {
			return 0, false
		}
	}
	return 0, c.need < 0 && hit == len(c.names)
}

func tokenizeCond(s string) []string {
	s = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s)
	return strings.Fields(s)
}

func parseCondition(s string, sel map[string]selection) (cnode, error) {
	toks := tokenizeCond(s)
	pos := 0
	var or, and, unary func() (cnode, error)
	peek := func() string {
		if pos < len(toks) {
			return strings.ToLower(toks[pos])
		}
		return ""
	}
	names := func(pat string) ([]string, error) {
		var out []string
		for n := range sel {
			if pat == "them" || strings.HasSuffix(pat, "*") && strings.HasPrefix(n, strings.TrimSuffix(pat, "*")) || n == pat {
				if pat == "them" && strings.HasPrefix(n, "_") {
					continue
				}
				out = append(out, n)
			}
		}
		sort.Strings(out)
		if len(out) == 0 {
			return nil, fmt.Errorf("no selection matches %q", pat)
		}
		return out, nil
	}
	unary = func() (cnode, error) {
		t := peek()
		switch {
		case t == "not":
			pos++
			n, err := unary()
			return cnot{n}, err
		case t == "(":
			pos++
			n, err := or()
			if err != nil {
				return nil, err
			}
			if peek() != ")" {
				return nil, errors.New("missing )")
			}
			pos++
			return n, nil
		case t == "1" || t == "all" || t == "any":
			if pos+2 < len(toks) && strings.ToLower(toks[pos+1]) == "of" {
				need := 1
				if t == "all" {
					need = -1
				}
				ns, err := names(toks[pos+2])
				if err != nil {
					return nil, err
				}
				pos += 3
				return cof{need, ns}, nil
			}
		case t == "":
			return nil, errors.New("unexpected end")
		}
		name := toks[pos]
		if _, ok := sel[name]; !ok {
			return nil, fmt.Errorf("unknown selection %q", name)
		}
		pos++
		return cref(name), nil
	}
	and = func() (cnode, error) {
		l, err := unary()
		if err != nil {
			return nil, err
		}
		for peek() == "and" {
			pos++
			r, err := unary()
			if err != nil {
				return nil, err
			}
			l = cbin{"and", l, r}
		}
		return l, nil
	}
	or = func() (cnode, error) {
		l, err := and()
		if err != nil {
			return nil, err
		}
		for peek() == "or" {
			pos++
			r, err := and()
			if err != nil {
				return nil, err
			}
			l = cbin{"or", l, r}
		}
		return l, nil
	}
	n, err := or()
	if err != nil {
		return nil, err
	}
	if pos != len(toks) {
		return nil, fmt.Errorf("unexpected %q", toks[pos])
	}
	return n, nil
}
