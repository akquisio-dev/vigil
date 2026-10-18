// Package backup seals vigil server backups for a recipient key.
//
// A backup holds the server key, password hashes and TOTP secrets, so it
// is encrypted to an X25519 public key. The server only needs the public
// key; the secret key belongs somewhere else, so neither losing nor
// breaking into the server opens old backups.
//
// Format: the line "vigil-backup 1\n", a 32 byte ephemeral public key, then
// the stream in chunks of up to 64 KiB, each sealed with AES-256-GCM. The
// nonce is the chunk counter plus a flag for the last chunk, so reordered,
// dropped or cut off chunks fail to open.
package backup

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

const (
	magic        = "vigil-backup 1\n"
	publicPrefix = "vigil-backup-1:"
	secretPrefix = "VIGIL-BACKUP-SECRET-1:"
	chunkSize    = 64 << 10
	tagSize      = 16
)

// ErrDamaged means the file is cut off, altered or for another key.
var ErrDamaged = errors.New("backup is damaged, cut off or sealed for another key")

// GenerateKey returns a new secret key and its public key, both as text.
func GenerateKey() (secret, public string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return secretPrefix + enc(k.Bytes()), publicPrefix + enc(k.PublicKey().Bytes()), nil
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func ParsePublic(s string) (*ecdh.PublicKey, error) {
	raw, ok := strings.CutPrefix(strings.TrimSpace(s), publicPrefix)
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if !ok || err != nil || len(b) != 32 {
		return nil, errors.New(`not a backup public key (expected "vigil-backup-1:...")`)
	}
	return ecdh.X25519().NewPublicKey(b)
}

func ParseSecret(s string) (*ecdh.PrivateKey, error) {
	raw, ok := strings.CutPrefix(strings.TrimSpace(s), secretPrefix)
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if !ok || err != nil || len(b) != 32 {
		return nil, errors.New("not a backup secret key")
	}
	return ecdh.X25519().NewPrivateKey(b)
}

// Fingerprint names a public key in logs and manifests.
func Fingerprint(pub *ecdh.PublicKey) string {
	h := sha256.Sum256(pub.Bytes())
	return enc(h[:8])
}

func streamKey(shared, eph, recipient []byte) (cipher.AEAD, error) {
	salt := append(append([]byte{}, eph...), recipient...)
	key, err := hkdf.Key(sha256.New, shared, salt, "vigil-backup 1 stream", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func nonce(n uint64, last bool) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint64(b[3:11], n)
	if last {
		b[11] = 1
	}
	return b
}

type sealer struct {
	w    io.Writer
	aead cipher.AEAD
	buf  []byte
	n    uint64
	done bool
}

// Seal returns a writer that encrypts to pub. Close writes the last chunk;
// without it the backup does not open.
func Seal(w io.Writer, pub *ecdh.PublicKey) (io.WriteCloser, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	aead, err := streamKey(shared, eph.PublicKey().Bytes(), pub.Bytes())
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w, magic); err != nil {
		return nil, err
	}
	if _, err := w.Write(eph.PublicKey().Bytes()); err != nil {
		return nil, err
	}
	return &sealer{w: w, aead: aead, buf: make([]byte, 0, chunkSize)}, nil
}

func (s *sealer) Write(p []byte) (int, error) {
	if s.done {
		return 0, errors.New("backup: write after close")
	}
	total := len(p)
	for len(p) > 0 {
		// A full chunk is only flushed once more data follows, so the
		// last chunk is never a full one that lacks its flag.
		if len(s.buf) == chunkSize {
			if err := s.flush(false); err != nil {
				return total - len(p), err
			}
		}
		k := copy(s.buf[len(s.buf):chunkSize], p)
		s.buf = s.buf[:len(s.buf)+k]
		p = p[k:]
	}
	return total, nil
}

func (s *sealer) flush(last bool) error {
	out := s.aead.Seal(nil, nonce(s.n, last), s.buf, nil)
	s.n++
	s.buf = s.buf[:0]
	_, err := s.w.Write(out)
	return err
}

func (s *sealer) Close() error {
	if s.done {
		return nil
	}
	s.done = true
	return s.flush(true)
}

type opener struct {
	r    *bufio.Reader
	aead cipher.AEAD
	n    uint64
	out  []byte
	last bool
}

// Open returns a reader for a sealed backup. Reading fails with ErrDamaged
// when any chunk is altered or the stream ends before its last chunk.
func Open(r io.Reader, key *ecdh.PrivateKey) (io.Reader, error) {
	br := bufio.NewReaderSize(r, chunkSize+tagSize+1)
	head := make([]byte, len(magic)+32)
	if _, err := io.ReadFull(br, head); err != nil || string(head[:len(magic)]) != magic {
		return nil, errors.New("not a sealed vigil backup")
	}
	eph, err := ecdh.X25519().NewPublicKey(head[len(magic):])
	if err != nil {
		return nil, ErrDamaged
	}
	shared, err := key.ECDH(eph)
	if err != nil {
		return nil, ErrDamaged
	}
	aead, err := streamKey(shared, eph.Bytes(), key.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	return &opener{r: br, aead: aead}, nil
}

// IsSealed tells a sealed backup from a plain one by its first bytes.
func IsSealed(head []byte) bool { return strings.HasPrefix(string(head), magic) }

func (o *opener) Read(p []byte) (int, error) {
	for len(o.out) == 0 {
		if o.last {
			return 0, io.EOF
		}
		if err := o.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, o.out)
	o.out = o.out[n:]
	return n, nil
}

func (o *opener) next() error {
	ct := make([]byte, chunkSize+tagSize)
	n, err := io.ReadFull(o.r, ct)
	switch {
	case err == io.ErrUnexpectedEOF || err == io.EOF:
		o.last = true
	case err != nil:
		return err
	default:
		if _, perr := o.r.Peek(1); perr == io.EOF {
			o.last = true
		}
	}
	if n < tagSize {
		return ErrDamaged
	}
	pt, oerr := o.aead.Open(ct[:0], nonce(o.n, o.last), ct[:n], nil)
	if oerr != nil {
		return ErrDamaged
	}
	o.n++
	o.out = pt
	return nil
}
