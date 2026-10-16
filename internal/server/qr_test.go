package server

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"testing"
)

// TestQRWritePNG writes QR codes as PNG files for an outside decoder:
//
//	VIGIL_QR_DIR=/tmp/qr go test ./internal/server -run TestQRWritePNG
func TestQRWritePNG(t *testing.T) {
	dir := os.Getenv("VIGIL_QR_DIR")
	if dir == "" {
		t.Skip("set VIGIL_QR_DIR")
	}
	for name, text := range map[string]string{
		"v1":   "vigil",
		"totp": TOTPURI("joey", "7A5NRSVFXO3ESJ2QFLYL3NKUJML6NCAW", "vigil"),
		"long": TOTPURI("a-rather-long-user-name-for-testing", "7A5NRSVFXO3ESJ2QFLYL3NKUJML6NCAW", "Akquisio vigil") + "&x=0123456789",
	} {
		q, err := QR(text)
		if err != nil {
			t.Fatal(err)
		}
		const scale, quiet = 8, 4
		n := len(q)
		img := image.NewGray(image.Rect(0, 0, (n+2*quiet)*scale, (n+2*quiet)*scale))
		for y := range img.Bounds().Dy() {
			for x := range img.Bounds().Dx() {
				r, c := y/scale-quiet, x/scale-quiet
				v := uint8(255)
				if r >= 0 && c >= 0 && r < n && c < n && q[r][c] {
					v = 0
				}
				img.SetGray(x, y, color.Gray{v})
			}
		}
		f, _ := os.Create(dir + "/" + name + ".png")
		png.Encode(f, img)
		f.Close()
		os.WriteFile(dir+"/"+name+".txt", []byte(text), 0o644)
	}
}

func TestQRSizes(t *testing.T) {
	q, err := QR(TOTPURI("joey", "7A5NRSVFXO3ESJ2QFLYL3NKUJML6NCAW", "vigil"))
	if err != nil || len(q) < 21 || len(q)%4 != 1 {
		t.Fatalf("size %d, %v", len(q), err)
	}
	if _, err := QR(string(make([]byte, 300))); err == nil {
		t.Fatal("too long text must fail")
	}
}
