package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Canary content is generated on the agent. The server only names a type,
// so a compromised server cannot use canaries to write arbitrary content.

const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randString(n int, alphabet string) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		v, _ := rand.Int(rand.Reader, max)
		b[i] = alphabet[v.Int64()]
	}
	return string(b)
}

func pick(list []string) string {
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(len(list))))
	return list[v.Int64()]
}

func randHex(n int) string { return randString(n, "0123456789abcdef") }

func password() string {
	return randString(4, "ABCDEFGHJKLMNPQRSTUVWXYZ") + randString(6, "abcdefghijkmnopqrstuvwxyz") +
		randString(3, "23456789") + pick([]string{"!", "#", "%", "?", "$"})
}

func param(p map[string]string, k, def string) string {
	if v := strings.TrimSpace(p[k]); v != "" {
		return v
	}
	return def
}

// clean keeps parameters printable and single-line.
func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

func GenerateCanary(typ string, params map[string]string) ([]byte, error) {
	domain := clean(param(params, "domain", "example.internal"), 80)
	switch typ {
	case "credentials":
		return genCredentials(domain), nil
	case "env":
		return genEnv(domain), nil
	case "ssh-key":
		return genSSHKey(clean(param(params, "comment", pick([]string{"backup@" + domain, "deploy@" + domain, "root@old-" + strings.Split(domain, ".")[0]})), 80))
	case "sql-dump":
		return genSQLDump(domain, clean(params["email"], 120)), nil
	}
	return nil, fmt.Errorf("unknown canary type %q", typ)
}

func genCredentials(domain string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# access list, updated %s\n\n", time.Now().AddDate(0, -2, 0).Format("2006-01-02"))
	entries := []struct{ name, host, user string }{
		{"database (primary)", "db1." + domain + ":3306", "admin"},
		{"backup storage", "backup." + domain, "backup"},
		{"admin panel", "https://admin." + domain, "root"},
		{"mail", "mail." + domain, "postmaster@" + domain},
	}
	for _, e := range entries {
		fmt.Fprintf(&b, "%s\n  host: %s\n  user: %s\n  pass: %s\n\n", e.name, e.host, e.user, password())
	}
	return []byte(b.String())
}

func genEnv(domain string) []byte {
	lines := []string{
		"NODE_ENV=production",
		"APP_URL=https://" + domain,
		"APP_SECRET=" + randHex(64),
		"DB_HOST=127.0.0.1",
		"DB_PORT=3306",
		"DB_NAME=app_prod",
		"DB_USER=app_admin",
		"DB_PASSWORD=" + password(),
		"REDIS_URL=redis://:" + randString(24, alnum) + "@127.0.0.1:6379/0",
		"JWT_SECRET=" + randString(48, alnum),
		"SMTP_HOST=mail." + domain,
		"SMTP_USER=noreply@" + domain,
		"SMTP_PASSWORD=" + password(),
		"BACKUP_S3_KEY=" + randString(20, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
		"BACKUP_S3_SECRET=" + randString(40, alnum+"/+"),
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

// genSSHKey writes a real, unencrypted OpenSSH ed25519 key that is
// authorized nowhere.
func genSSHKey(comment string) ([]byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pubBlob := append(sshString([]byte("ssh-ed25519")), sshString(pub)...)

	check := make([]byte, 4)
	rand.Read(check)
	var sec []byte
	sec = append(sec, check...)
	sec = append(sec, check...)
	sec = append(sec, sshString([]byte("ssh-ed25519"))...)
	sec = append(sec, sshString(pub)...)
	sec = append(sec, sshString(priv)...)
	sec = append(sec, sshString([]byte(comment))...)
	for i := byte(1); len(sec)%8 != 0; i++ {
		sec = append(sec, i)
	}

	var blob []byte
	blob = append(blob, []byte("openssh-key-v1\x00")...)
	blob = append(blob, sshString([]byte("none"))...)
	blob = append(blob, sshString([]byte("none"))...)
	blob = append(blob, sshString(nil)...)
	blob = binary.BigEndian.AppendUint32(blob, 1)
	blob = append(blob, sshString(pubBlob)...)
	blob = append(blob, sshString(sec)...)

	enc := base64.StdEncoding.EncodeToString(blob)
	var b strings.Builder
	b.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for len(enc) > 70 {
		b.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	b.WriteString(enc + "\n-----END OPENSSH PRIVATE KEY-----\n")
	return []byte(b.String()), nil
}

var (
	firstNames = []string{"Anna", "Lukas", "Mia", "Jonas", "Lea", "Felix", "Sophie", "Paul", "Emma", "Leon", "Hannah", "Tim", "Laura", "Noah", "Julia", "Max", "Lena", "Ben", "Sarah", "David"}
	lastNames  = []string{"Schmidt", "Meyer", "Wagner", "Becker", "Hoffmann", "Koch", "Richter", "Klein", "Wolf", "Neumann", "Braun", "Zimmermann", "Hartmann", "Lange", "Krause", "Werner"}
)

// genSQLDump looks like a mysqldump of a user table. An optional tracking
// e-mail address is planted as the admin row: mail arriving there proves the
// dump left the server.
func genSQLDump(domain, email string) []byte {
	var b strings.Builder
	now := time.Now().AddDate(0, 0, -9)
	fmt.Fprintf(&b, "-- MySQL dump 10.13  Distrib 8.0.39, for Linux (x86_64)\n--\n-- Host: localhost    Database: app_prod\n")
	fmt.Fprintf(&b, "-- ------------------------------------------------------\n-- Server version\t8.0.39\n\n")
	b.WriteString("DROP TABLE IF EXISTS `users`;\nCREATE TABLE `users` (\n  `id` int unsigned NOT NULL AUTO_INCREMENT,\n" +
		"  `email` varchar(190) NOT NULL,\n  `name` varchar(120) NOT NULL,\n  `password_hash` varchar(100) NOT NULL,\n" +
		"  `role` enum('user','moderator','admin') NOT NULL DEFAULT 'user',\n  `created_at` datetime NOT NULL,\n" +
		"  PRIMARY KEY (`id`),\n  UNIQUE KEY `email` (`email`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n")
	b.WriteString("LOCK TABLES `users` WRITE;\nINSERT INTO `users` VALUES ")
	if email == "" {
		email = "admin@" + domain
	}
	rows := []string{fmt.Sprintf("(1,'%s','Administrator','%s','admin','%s')", sqlEscape(email), bcryptLike(), now.AddDate(-1, 0, 0).Format("2006-01-02 15:04:05"))}
	for i := 2; i <= 40; i++ {
		fn, ln := pick(firstNames), pick(lastNames)
		mail := strings.ToLower(fmt.Sprintf("%s.%s%d@%s", fn, ln, i, pick([]string{"gmail.com", "web.de", "gmx.de", "outlook.com", "t-online.de"})))
		role := "user"
		if i <= 4 {
			role = "moderator"
		}
		created := now.Add(-time.Duration(i*37) * time.Hour)
		rows = append(rows, fmt.Sprintf("(%d,'%s','%s %s','%s','%s','%s')", i, mail, fn, ln, bcryptLike(), role, created.Format("2006-01-02 15:04:05")))
	}
	b.WriteString(strings.Join(rows, ","))
	b.WriteString(";\nUNLOCK TABLES;\n\n-- Dump completed on " + now.Format("2006-01-02 15:04:05") + "\n")
	return []byte(b.String())
}

func bcryptLike() string {
	return "$2b$12$" + randString(53, alnum+"./")
}

func sqlEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s)
}
