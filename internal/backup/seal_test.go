package backup

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func seal(t *testing.T, pub string, data []byte) []byte {
	t.Helper()
	pk, err := ParsePublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := Seal(&buf, pk)
	if err != nil {
		t.Fatal(err)
	}
	// Odd write sizes cross chunk borders at every position.
	for rest := data; len(rest) > 0; {
		n := min(len(rest), 7919)
		if _, err := w.Write(rest[:n]); err != nil {
			t.Fatal(err)
		}
		rest = rest[n:]
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func open(sec string, sealed []byte) ([]byte, error) {
	k, err := ParseSecret(sec)
	if err != nil {
		return nil, err
	}
	r, err := Open(bytes.NewReader(sealed), k)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestSealRoundTrip(t *testing.T) {
	sec, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 3 * chunkSize, 3*chunkSize + 17} {
		data := make([]byte, size)
		rand.Read(data)
		sealed := seal(t, pub, data)
		if !IsSealed(sealed) {
			t.Fatal("no magic")
		}
		got, err := open(sec, sealed)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
}

func TestSealDetectsDamage(t *testing.T) {
	sec, pub, _ := GenerateKey()
	data := make([]byte, 3*chunkSize+100)
	rand.Read(data)
	sealed := seal(t, pub, data)
	head := len(magic) + 32
	full := chunkSize + tagSize

	// Cut at every chunk border and inside chunks: never a silent short read.
	for _, cut := range []int{head, head + 1, head + full, head + 2*full, head + 3*full, len(sealed) - 1} {
		if _, err := open(sec, sealed[:cut]); !errors.Is(err, ErrDamaged) {
			t.Errorf("cut at %d: %v", cut, err)
		}
	}
	flip := bytes.Clone(sealed)
	flip[head+full+5] ^= 1
	if _, err := open(sec, flip); !errors.Is(err, ErrDamaged) {
		t.Errorf("flipped bit: %v", err)
	}
	swap := bytes.Clone(sealed)
	copy(swap[head:head+full], sealed[head+full:head+2*full])
	copy(swap[head+full:head+2*full], sealed[head:head+full])
	if _, err := open(sec, swap); !errors.Is(err, ErrDamaged) {
		t.Errorf("swapped chunks: %v", err)
	}
	other, _, _ := GenerateKey()
	if _, err := open(other, sealed); !errors.Is(err, ErrDamaged) {
		t.Errorf("other key: %v", err)
	}
	if _, err := open(sec, []byte("vigil-backup 2\n")); err == nil {
		t.Error("foreign header accepted")
	}
}

func TestKeyParsing(t *testing.T) {
	sec, pub, _ := GenerateKey()
	if _, err := ParsePublic(sec); err == nil {
		t.Error("secret accepted as public key")
	}
	if _, err := ParseSecret(pub); err == nil {
		t.Error("public accepted as secret key")
	}
	k, _ := ParseSecret(sec + "\n")
	p, _ := ParsePublic(" " + pub + "\n")
	if !k.PublicKey().Equal(p) {
		t.Error("key pair does not match")
	}
}
