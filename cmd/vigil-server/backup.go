package main

import (
	"crypto/ecdh"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/akquisio-dev/vigil/internal/backup"
	"github.com/akquisio-dev/vigil/internal/server"
)

// backupCmd: keygen, check, or a backup into backup.dir, a file or stdout.
func backupCmd(args []string) {
	sub := ""
	if len(args) > 0 && (args[0] == "keygen" || args[0] == "check") {
		sub, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/vigil/server.json", "server config file")
	out := fs.String("out", "", "write one backup to this file (- for stdout) instead of backup.dir")
	to := fs.String("to", "", "public key to seal for (default: backup.recipient)")
	plain := fs.Bool("plain", false, "write an unsealed backup (it holds the server key and password hashes)")
	keyPath := fs.String("key", "", "check: secret key file")
	fs.Parse(args)

	switch sub {
	case "keygen":
		if *out == "" || fs.NArg() > 0 {
			log.Fatal("usage: vigil-server backup keygen -out SECRET_KEY_FILE")
		}
		sec, pub, err := backup.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := fmt.Fprintln(f, sec); err != nil {
			log.Fatal(err)
		}
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
		pk, _ := backup.ParsePublic(pub)
		fmt.Printf("secret key written to %s (fingerprint %s).\n", *out, backup.Fingerprint(pk))
		fmt.Printf("Keep it OFF the server, and a second copy offline. Without it no backup opens.\n\n")
		fmt.Printf("Put the public key into server.json:\n\n  \"backup\": {\"recipient\": %q}\n", pub)
		return
	case "check":
		if fs.NArg() != 1 {
			log.Fatal("usage: vigil-server backup check [-key SECRET_KEY_FILE] FILE")
		}
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		m, err := server.CheckBackup(f, readSecret(*keyPath))
		if err != nil {
			log.Fatalf("BAD: %v", err)
		}
		printManifest(m)
		return
	}
	if fs.NArg() > 0 {
		fail()
	}
	cfg := mustConfig(*cfgPath)
	opt := server.BackupOptions{ConfigPath: *cfgPath}
	switch {
	case *plain && *to != "":
		log.Fatal("-plain and -to exclude each other")
	case *plain:
	case *to != "":
		opt.Recipient = mustPublic(*to)
	case cfg.Backup != nil:
		opt.Recipient = mustPublic(cfg.Backup.Recipient)
	default:
		log.Fatal(`no key to seal the backup for: set "backup": {"recipient": ...} in server.json (see backup keygen), pass -to, or -plain`)
	}
	if *out == "" {
		if cfg.Backup == nil {
			log.Fatal("no backup.dir in server.json; pass -out FILE")
		}
		path, m, err := server.BackupToDir(cfg, opt, cfg.Backup.Dir, cfg.Backup.Keep)
		if err != nil {
			log.Fatal(err)
		}
		fi, _ := os.Stat(path)
		fmt.Printf("%s: %d files, %d bytes, events up to %d\n", path, len(m.Files), fi.Size(), m.ChainSeq)
		warnSkipped(m)
		return
	}
	var w io.Writer = os.Stdout
	var f *os.File
	if *out != "-" {
		var err error
		f, err = os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		w = f
	}
	m, err := server.WriteBackup(cfg, opt, w)
	if err == nil && f != nil {
		err = f.Close()
	}
	if err != nil {
		if f != nil {
			os.Remove(*out)
		}
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "backup: %d files, events up to %d\n", len(m.Files), m.ChainSeq)
	warnSkipped(m)
}

func restoreCmd(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/vigil/server.json", "server config file, for data_dir")
	dataDir := fs.String("data-dir", "", "restore into this directory (default: data_dir of -config, else /var/lib/vigil)")
	keyPath := fs.String("key", "", "secret key file")
	cfgOut := fs.String("config-out", "", "also write the backed up config files below this directory")
	force := fs.Bool("force", false, "restore a backup made by a newer vigil")
	fs.Parse(args)
	if fs.NArg() != 1 {
		log.Fatal("usage: vigil-server restore [-config ...|-data-dir DIR] -key SECRET_KEY_FILE [-config-out DIR] FILE")
	}
	dir := *dataDir
	if dir == "" {
		dir = "/var/lib/vigil"
		if cfg, err := server.LoadConfig(*cfgPath); err == nil {
			dir = cfg.DataDir
		} else if !errors.Is(err, os.ErrNotExist) {
			log.Fatal(err)
		}
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	res, err := server.RestoreBackup(f, readSecret(*keyPath), server.RestoreOptions{DataDir: dir, ConfigOut: *cfgOut, Force: *force})
	if err != nil {
		log.Fatalf("restore failed, nothing changed: %v", err)
	}
	printManifest(res.Manifest)
	fmt.Printf("\nrestored into %s\n", dir)
	if res.OldData != "" {
		fmt.Printf("the previous data is kept in %s\n", res.OldData)
	}
	for _, c := range res.Config {
		fmt.Printf("config file: %s\n", c)
	}
	if *cfgOut == "" && hasConfig(res.Manifest) {
		fmt.Println("the backup also holds config files; restore them with -config-out DIR")
	}
	fmt.Println("\nStart the server; agents reconnect with their keys, nothing needs to be enrolled again.")
}

func hasConfig(m *server.BackupManifest) bool {
	for _, f := range m.Files {
		if strings.HasPrefix(f.Path, "config/") {
			return true
		}
	}
	return false
}

func printManifest(m *server.BackupManifest) {
	fmt.Printf("ok: vigil %s backup of %s from %s\n", m.Version, m.Host, m.Created.Format("2006-01-02 15:04:05 MST"))
	var size int64
	for _, f := range m.Files {
		size += f.Size
	}
	fmt.Printf("    %d files, %d bytes, event chain verified up to record %d\n", len(m.Files), size, m.ChainSeq)
	warnSkipped(m)
}

func warnSkipped(m *server.BackupManifest) {
	for _, s := range m.Skipped {
		fmt.Fprintf(os.Stderr, "warning: %s was not readable and is not in the backup\n", s)
	}
}

func mustPublic(s string) *ecdh.PublicKey {
	pk, err := backup.ParsePublic(s)
	if err != nil {
		log.Fatal(err)
	}
	return pk
}

func readSecret(p string) *ecdh.PrivateKey {
	if p == "" {
		return nil
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		log.Fatal(err)
	}
	k, err := backup.ParseSecret(string(raw))
	if err != nil {
		log.Fatal(err)
	}
	return k
}
