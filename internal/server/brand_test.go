package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrandSVGIsChecked(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o644)
		return p
	}
	good := write("good.svg", `<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><path fill="currentColor" d="M0 0h10v10z"/></svg>`)
	index := []byte("<head>\n<link rel=\"icon\" href=\"favicon.svg?v=1\">\n</head><body><div id=\"app\"></div></body>")
	out, assets, err := applyBrand(index, &BrandConfig{Name: `A "B" <c>`, Logo: good, Icon: good})
	if err != nil {
		t.Fatal(err)
	}
	page := string(out)
	for _, want := range []string{`<template id="brand-logo"><svg`, `content="A &#34;B&#34; &lt;c&gt;"`, `href="brand-icon.svg?v=` + assets.iconVersion + `"`} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q in %s", want, page)
		}
	}
	for _, bad := range []string{
		`<svg><script>alert(1)</script></svg>`,
		`<svg onload="x()"></svg>`,
		`<svg><a href="https://evil.example/">x</a></svg>`,
		`<svg><foreignObject><div/></foreignObject></svg>`,
		`no svg here`,
	} {
		if _, err := readBrandSVG(write("bad.svg", bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
