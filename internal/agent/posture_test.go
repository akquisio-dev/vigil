package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, p, s string, mode os.FileMode) string {
	t.Helper()
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(s), mode); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, mode)
	return p
}

func TestSshdConfigParser(t *testing.T) {
	dir := t.TempDir()
	write(t, dir+"/d/10-first.conf", "PasswordAuthentication no\n", 0o644)
	write(t, dir+"/d/50-cloud.conf", "PasswordAuthentication yes\nPermitRootLogin yes\n", 0o644)
	main := write(t, dir+"/sshd_config", "Include "+dir+"/d/*.conf\nPermitRootLogin prohibit-password\nMatch User x\nPermitEmptyPasswords yes\n", 0o644)
	m := map[string]string{}
	parseSshdConfig(main, m, 0)
	if m["passwordauthentication"] != "no" || m["permitrootlogin"] != "yes" || m["permitemptypasswords"] != "" {
		t.Fatalf("first value wins, Match ends the global part: %v", m)
	}
}

func TestAccountAndSysctlChecks(t *testing.T) {
	dir := t.TempDir()
	shadow := write(t, dir+"/shadow", "root:$6$x:1::::::\nsvc::1::::::\nbackdoor::1::::::\nlocked:!:1::::::\n", 0o600)
	passwd := write(t, dir+"/passwd", "root:x:0:0::/root:/bin/bash\nsvc:x:5:5::/:/usr/sbin/nologin\nbackdoor:x:0:0::/:/bin/sh\nlocked:x:6:6::/:/bin/bash\n", 0o644)
	cs := accountChecks(shadow, passwd)
	if len(cs) != 1 || cs[0].OK || cs[0].Value != "backdoor" {
		t.Fatalf("empty password: %+v", cs)
	}
	write(t, dir+"/sys/kernel/randomize_va_space", "0\n", 0o644)
	write(t, dir+"/sys/kernel/kptr_restrict", "1\n", 0o644)
	write(t, dir+"/sys/fs/suid_dumpable", "1\n", 0o644)
	got := map[string]postureCheck{}
	for _, c := range sysctlChecks(dir + "/sys") {
		got[c.Check+":"+c.Key] = c
	}
	if c := got["aslr:"]; c.OK || c.Value != "0" {
		t.Fatalf("aslr: %+v", got)
	}
	if !got["sysctl:kernel.kptr_restrict"].OK || got["sysctl:fs.suid_dumpable"].OK || len(got) != 3 {
		t.Fatalf("sysctl: %+v", got)
	}
}

func TestNftFilters(t *testing.T) {
	ufw := "table ip filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tjump ufw-before-input\n\t}\n}\n"
	if ok, _ := nftFilters([]byte(ufw)); !ok {
		t.Fatal("ufw policy drop")
	}
	rules := "table inet f {\n\tchain in {\n\t\ttype filter hook input priority 0; policy accept;\n\t\tct state established accept\n\t\ttcp dport 22 accept\n\t\tdrop\n\t}\n}\n"
	if ok, _ := nftFilters([]byte(rules)); !ok {
		t.Fatal("drop rule at the end")
	}
	docker := "table ip filter {\n\tchain FORWARD {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n"
	if ok, _ := nftFilters([]byte(docker)); ok {
		t.Fatal("forward drop does not filter input")
	}
}

func TestCertsAndBackups(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.org"}, DNSNames: []string{"example.org", "www.example.org"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10*24*time.Hour + time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	p := write(t, dir+"/live/example.org/fullchain.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)
	ci := readCert(p, now)
	if ci.Subject != "example.org" || ci.Days != 10 || !ci.SelfSign || len(ci.Names) != 2 {
		t.Fatalf("cert: %+v", ci)
	}
	if ci := readCert(dir+"/missing.pem", now); ci.Error == "" {
		t.Fatal("missing file must report an error")
	}
	if ci := readCert(p, now.Add(12*24*time.Hour)); ci.Days >= 0 {
		t.Fatalf("expired: %+v", ci)
	}

	old := write(t, dir+"/bk/db-1.sql.gz", "x", 0o600)
	os.Chtimes(old, now.Add(-50*time.Hour), now.Add(-50*time.Hour))
	write(t, dir+"/bk/db-2.sql.gz", "tiny", 0o600)
	bs := backupStatus([]Backup{
		{Name: "db", Path: dir + "/bk", MaxAgeHours: 26, MinBytes: 1000},
		{Name: "files", Path: dir + "/bk/*.sql.gz", MaxAgeHours: 26},
		{Name: "gone", Path: dir + "/nothing/*.tar", MaxAgeHours: 26},
	}, now)
	if bs[0].Problem != "small" || !strings.HasSuffix(bs[0].Newest, "db-2.sql.gz") || bs[1].Problem != "" || !bs[1].OK || bs[2].Problem != "missing" {
		t.Fatalf("backups: %+v", bs)
	}
	os.Chtimes(dir+"/bk/db-2.sql.gz", now.Add(-30*time.Hour), now.Add(-30*time.Hour))
	if bs := backupStatus([]Backup{{Name: "db", Path: dir + "/bk/*", MaxAgeHours: 26}}, now); bs[0].Problem != "old" || bs[0].AgeHours != 30 {
		t.Fatalf("old: %+v", bs)
	}
}

func TestFindSecrets(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)}))
	openssh := func(cipher string) string {
		b := []byte("openssh-key-v1\x00")
		b = binary.BigEndian.AppendUint32(b, uint32(len(cipher)))
		b = append(append(b, cipher...), make([]byte, 64)...)
		return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString(b) + "\n-----END OPENSSH PRIVATE KEY-----\n"
	}
	kinds := func(name, content string) string {
		var k []string
		for _, h := range findSecrets(name, []byte(content)) {
			k = append(k, h.Kind)
		}
		return strings.Join(k, ",")
	}
	cases := []struct{ name, content, want string }{
		{"key.pem", "x\n" + rsaPEM, "private_key"},
		{"id_ed25519", openssh("none"), "private_key"},
		{"id_ed25519", openssh("aes256-ctr"), ""},
		{"app.yml", "aws_access_key_id: AKIAABCDEFGHIJKLMNOP\n", "aws_key"},
		{"config", "[remote \"origin\"]\n\turl = https://bot:ghp_" + strings.Repeat("a", 36) + "@github.com/x/y\n", "github_token,url_credentials"},
		{"README.md", "use mysql://user:password@localhost/db or https://u:${TOKEN}@host\n", ""},
		{"settings.py", "DATABASE = 'postgres://app:S3cr3tPw@db.internal/app'\n", "url_credentials"},
		{".env", "# x\nDB_PASSWORD=hunter22hunter\nAPP_NAME=shop\nAPI_TOKEN=\nSECRET_KEY=changeme\n", "env_secret"},
		{".env.example", "DB_PASSWORD=hunter22hunter\n", ""},
		{".pgpass", "db:5432:app:app:pw123\n", "pgpass"},
		{"notes.txt", "nothing here", ""},
	}
	for _, c := range cases {
		if got := kinds(c.name, c.content); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	hs := findSecrets(".env", []byte("A=1\nB=2\nDB_PASSWORD=hunter22hunter\n"))
	if len(hs) != 1 || hs[0].Line != 3 || len(hs[0].FP) != 12 {
		t.Fatalf("line and fingerprint: %+v", hs)
	}
}

func TestWalkSecretsOnlyReadsWhatOthersCanRead(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "vigil-secrets-")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Chmod(dir, 0o755)
	if !worldReachable(dir) {
		t.Skip("temp directory not reachable for other users")
	}
	secret := ".env"
	open := write(t, dir+"/app/"+secret, "DB_PASSWORD=hunter22hunter\n", 0o644)
	write(t, dir+"/app/private.env", "DB_PASSWORD=hunter22hunter\n", 0o600)
	write(t, dir+"/closed/.env", "DB_PASSWORD=hunter22hunter\n", 0o644)
	os.Chmod(dir+"/closed", 0o700)
	write(t, dir+"/app/node_modules/x/.env", "DB_PASSWORD=hunter22hunter\n", 0o644)
	write(t, dir+"/app/.git/config", "url = https://u:tok3n12345@example.org/r\n", 0o644)
	write(t, dir+"/app/.git/objects/ab", "DB_PASSWORD=hunter22hunter\n", 0o644)
	canary := write(t, dir+"/app/bait.env", "AWS_SECRET_KEY=abcdefabcdef\n", 0o644)
	found, files, err := walkSecrets(context.Background(), []string{dir}, map[string]bool{}, map[string]bool{canary: true})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range found {
		paths = append(paths, f.path)
	}
	if len(found) != 2 || found[0].path != dir+"/app/.git/config" && found[1].path != dir+"/app/.git/config" || files < 1 {
		t.Fatalf("found %v (files %d)", paths, files)
	}
	for _, f := range found {
		if f.path != open && f.path != dir+"/app/.git/config" {
			t.Fatalf("unexpected %s", f.path)
		}
	}

	a := &Agent{cfg: &Config{MaxQueue: 100}, flushNow: make(chan struct{}, 1)}
	ss := &SecretState{Known: map[string]bool{}}
	a.diffSecrets(ss, found)
	ev := eventTypes(a)["secret.exposed"]
	if len(ev) != 2 || ev[0]["baseline"] != true || ev[0]["mode"] != "0644" {
		t.Fatalf("baseline events: %v", ev)
	}
	a.diffSecrets(ss, found)
	if n := len(eventTypes(a)["secret.exposed"]); n != 0 {
		t.Fatalf("reported again: %d", n)
	}
	a.diffSecrets(ss, found[:1])
	a.diffSecrets(ss, found)
	if ev := eventTypes(a)["secret.exposed"]; len(ev) != 1 || ev[0]["baseline"] != nil {
		t.Fatalf("a secret that comes back is new: %v", ev)
	}
}

func TestSourcePackages(t *testing.T) {
	st := write(t, t.TempDir()+"/status", `Package: libssl3t64
Status: install ok installed
Version: 3.0.13-0ubuntu3.5
Source: openssl

Package: openssl
Status: install ok installed
Version: 3.0.13-0ubuntu3.4

Package: linux-image-6.8.0-60-generic
Status: install ok installed
Version: 6.8.0-60.63
Source: linux-signed (6.8.0-60.63)

Package: linux-modules-6.8.0-147-generic
Status: install ok installed
Version: 6.8.0-147.147
Source: linux

Package: removed
Status: deinstall ok config-files
Version: 1.0
`, 0o644)
	got := sourcePackages(st, func(a, b string) bool { return a > b })
	want := "linux=6.8.0-147.147 linux-signed=6.8.0-60.63 openssl=3.0.13-0ubuntu3.5"
	var parts []string
	for _, p := range got {
		parts = append(parts, p.Name+"="+p.Version)
	}
	if strings.Join(parts, " ") != want {
		t.Fatalf("got %v", parts)
	}
}
