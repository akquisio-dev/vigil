package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"os"
	"regexp"
)

const maxBrandSVG = 64 << 10

// SVG files from the config are placed inline in the page. They come from
// the operator, but a copied file with a script or an external reference
// should still not reach the dashboard.
var unsafeSVG = regexp.MustCompile(`(?i)<script|<foreignobject|\son[a-z]+\s*=|javascript:|href\s*=\s*["']?(https?:|//)|<!entity|<\?xml-stylesheet`)

func readBrandSVG(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > maxBrandSVG {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxBrandSVG)
	}
	b = bytes.TrimSpace(b)
	if i := bytes.Index(b, []byte("<svg")); i >= 0 {
		b = b[i:]
	} else {
		return nil, fmt.Errorf("%s: no <svg> element", path)
	}
	if unsafeSVG.Match(b) {
		return nil, fmt.Errorf("%s: scripts, event handlers and external references are not allowed", path)
	}
	return b, nil
}

type brandAssets struct {
	icon, iconVersion string
}

// applyBrand writes the configured name and logo into index.html.
func applyBrand(index []byte, cfg *BrandConfig) ([]byte, brandAssets, error) {
	var out brandAssets
	if cfg == nil {
		return index, out, nil
	}
	var head []byte
	if cfg.Name != "" {
		head = fmt.Appendf(head, "<meta name=\"vigil-brand\" content=\"%s\">\n", html.EscapeString(cfg.Name))
	}
	if cfg.Logo != "" {
		logo, err := readBrandSVG(cfg.Logo)
		if err != nil {
			return index, out, err
		}
		index = bytes.Replace(index, []byte(`<div id="app"></div>`), append(append([]byte(`<template id="brand-logo">`), logo...), []byte("</template>\n<div id=\"app\"></div>")...), 1)
	}
	if cfg.Icon != "" {
		icon, err := readBrandSVG(cfg.Icon)
		if err != nil {
			return index, out, err
		}
		sum := sha256.Sum256(icon)
		out.icon, out.iconVersion = string(icon), hex.EncodeToString(sum[:6])
		index = regexp.MustCompile(`href="favicon\.svg[^"]*"`).ReplaceAll(index, []byte(`href="brand-icon.svg?v=`+out.iconVersion+`"`))
	}
	index = bytes.Replace(index, []byte("</head>"), append(head, []byte("</head>")...), 1)
	return index, out, nil
}
