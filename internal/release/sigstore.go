package release

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Checking a release signature without cosign, with the standard library
// only. The release workflow signs SHA256SUMS keylessly: Fulcio issues a
// short-lived certificate to the workflow run, cosign signs with it, and
// Rekor, the public transparency log, records the signature and returns a
// signed entry timestamp. A signature is accepted when
//
//  1. the certificate chains to the Fulcio root, at the time Rekor saw it,
//  2. the certificate was issued to this repository's release workflow for
//     exactly the expected tag, by GitHub's token issuer,
//  3. the signature over SHA256SUMS verifies with the certificate's key,
//  4. Rekor's signed entry timestamp verifies with the Rekor key, and the
//     log entry is about this signature, this certificate and this file.
//
// The roots in roots/ come from Sigstore's trusted_root.json as distributed
// through its TUF repository (Fulcio CA valid from 2022-04-13 and the Rekor
// log at rekor.sigstore.dev). They change rarely; a new root needs a new
// vigil release.

//go:embed roots/*.pem
var rootFiles embed.FS

const ghIssuer = "https://token.actions.githubusercontent.com"

var (
	oidIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1} // raw string
	oidIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8} // DER UTF8String
)

// Identity is the certificate subject expected for a release tag.
func Identity(repo, version string) string {
	return fmt.Sprintf("https://github.com/%s/.github/workflows/release.yml@refs/tags/%s", repo, version)
}

type bundle struct {
	Signature string `json:"base64Signature"`
	Cert      string `json:"cert"`
	Rekor     struct {
		SET     string `json:"SignedEntryTimestamp"`
		Payload struct {
			Body           string `json:"body"`
			IntegratedTime int64  `json:"integratedTime"`
			LogIndex       int64  `json:"logIndex"`
			LogID          string `json:"logID"`
		} `json:"Payload"`
	} `json:"rekorBundle"`
}

type hashedRekord struct {
	Kind string `json:"kind"`
	Spec struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			Content   string `json:"content"`
			PublicKey struct {
				Content string `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	} `json:"spec"`
}

// VerifySums checks that sums (a SHA256SUMS file) was signed by the release
// workflow of repo for the tag version, using the cosign bundle next to it.
func VerifySums(sums, bundleJSON []byte, repo, version string) error {
	var b bundle
	if err := json.Unmarshal(bundleJSON, &b); err != nil {
		return fmt.Errorf("signature bundle: %w", err)
	}
	if b.Signature == "" || b.Cert == "" || b.Rekor.SET == "" || b.Rekor.Payload.Body == "" {
		return errors.New("signature bundle: incomplete (not a cosign bundle with a transparency log entry)")
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil {
		return errors.New("signature bundle: bad signature encoding")
	}
	certPEM, err := base64.StdEncoding.DecodeString(b.Cert)
	if err != nil {
		return errors.New("signature bundle: bad certificate encoding")
	}
	cert, err := parseCert(certPEM)
	if err != nil {
		return err
	}
	signedAt := time.Unix(b.Rekor.Payload.IntegratedTime, 0)

	// 1. chain
	roots, inter, rekorKey, err := trust()
	if err != nil {
		return err
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: signedAt,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil {
		return fmt.Errorf("certificate: %w", err)
	}

	// 2. identity
	want := Identity(repo, version)
	if len(cert.URIs) != 1 || cert.URIs[0].String() != want {
		got := ""
		if len(cert.URIs) > 0 {
			got = cert.URIs[0].String()
		}
		return fmt.Errorf("signed by %q, want %q", got, want)
	}
	if iss := issuer(cert); iss != ghIssuer {
		return fmt.Errorf("certificate issuer %q, want %q", iss, ghIssuer)
	}

	// 3. signature
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("certificate key is not ECDSA")
	}
	digest := sha256.Sum256(sums)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errors.New("signature does not match SHA256SUMS")
	}

	// 4. transparency log
	p := b.Rekor.Payload
	der, err := x509.MarshalPKIXPublicKey(rekorKey)
	if err != nil {
		return err
	}
	if keyID := sha256.Sum256(der); p.LogID != hex.EncodeToString(keyID[:]) {
		return fmt.Errorf("log entry from unknown log %s", p.LogID)
	}
	// The SET signs the payload as canonical JSON: sorted keys, no spaces.
	canon := `{"body":` + strconv.Quote(p.Body) + `,"integratedTime":` + strconv.FormatInt(p.IntegratedTime, 10) +
		`,"logID":` + strconv.Quote(p.LogID) + `,"logIndex":` + strconv.FormatInt(p.LogIndex, 10) + `}`
	set, err := base64.StdEncoding.DecodeString(b.Rekor.SET)
	if err != nil {
		return errors.New("log entry: bad timestamp encoding")
	}
	setDigest := sha256.Sum256([]byte(canon))
	if !ecdsa.VerifyASN1(rekorKey, setDigest[:], set) {
		return errors.New("log entry: signed entry timestamp does not verify")
	}
	body, err := base64.StdEncoding.DecodeString(p.Body)
	if err != nil {
		return errors.New("log entry: bad body encoding")
	}
	var rec hashedRekord
	if err := json.Unmarshal(body, &rec); err != nil || rec.Kind != "hashedrekord" {
		return errors.New("log entry: not a hashedrekord")
	}
	if rec.Spec.Data.Hash.Algorithm != "sha256" || rec.Spec.Data.Hash.Value != hex.EncodeToString(digest[:]) {
		return errors.New("log entry is about another file")
	}
	if rs, err := base64.StdEncoding.DecodeString(rec.Spec.Signature.Content); err != nil || !bytes.Equal(rs, sig) {
		return errors.New("log entry is about another signature")
	}
	logPEM, err := base64.StdEncoding.DecodeString(rec.Spec.Signature.PublicKey.Content)
	if err != nil {
		return errors.New("log entry: bad certificate encoding")
	}
	logCert, err := parseCert(logPEM)
	if err != nil || !bytes.Equal(logCert.Raw, cert.Raw) {
		return errors.New("log entry is about another certificate")
	}
	return nil
}

func parseCert(p []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(p)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("signature bundle: no certificate")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func issuer(c *x509.Certificate) string {
	for _, e := range c.Extensions {
		switch {
		case e.Id.Equal(oidIssuerV2):
			var s string
			if _, err := asn1.UnmarshalWithParams(e.Value, &s, "utf8"); err == nil {
				return s
			}
		case e.Id.Equal(oidIssuerV1):
			return string(e.Value)
		}
	}
	return ""
}

func trust() (roots, inter *x509.CertPool, rekor *ecdsa.PublicKey, err error) {
	load := func(name string) []byte {
		b, e := rootFiles.ReadFile("roots/" + name)
		if e != nil && err == nil {
			err = e
		}
		return b
	}
	roots, inter = x509.NewCertPool(), x509.NewCertPool()
	if !roots.AppendCertsFromPEM(load("fulcio_root.pem")) || !inter.AppendCertsFromPEM(load("fulcio_intermediate.pem")) {
		return nil, nil, nil, errors.New("embedded Fulcio certificates unreadable")
	}
	blk, _ := pem.Decode(load("rekor.pem"))
	if blk == nil {
		return nil, nil, nil, errors.New("embedded Rekor key unreadable")
	}
	k, e := x509.ParsePKIXPublicKey(blk.Bytes)
	if e != nil {
		return nil, nil, nil, e
	}
	rekor, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, nil, errors.New("embedded Rekor key is not ECDSA")
	}
	return roots, inter, rekor, err
}
