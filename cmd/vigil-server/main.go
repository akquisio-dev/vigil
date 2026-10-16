// Command vigil-server is the central node of vigil.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/akquisio-dev/vigil/internal/server"
)

const usage = `usage:
  vigil-server run         [-config /etc/vigil/server.json]
  vigil-server user add    [-config ...] [-role viewer|analyst|admin] NAME
  vigil-server user remove [-config ...] NAME
  vigil-server user list   [-config ...]
  vigil-server verify      [-config ...]
  vigil-server rules check DIR
  vigil-server rules test  FILE EVENTS.jsonl
  vigil-server version`

func main() {
	log.SetFlags(0)
	args := os.Args[1:]
	if len(args) == 0 {
		fail()
	}
	cmd := args[0]
	args = args[1:]
	sub := ""
	if cmd == "rules" {
		rulesCmd(args)
		return
	}
	if cmd == "user" {
		if len(args) == 0 {
			fail()
		}
		sub, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/vigil/server.json", "server config file")
	role := fs.String("role", "admin", "user add: viewer, analyst or admin")
	fs.Parse(args)

	switch cmd {
	case "version":
		fmt.Println(server.Version)
	case "run":
		s := mustServer(*cfgPath)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := s.Run(ctx); err != nil {
			log.Fatal(err)
		}
	case "verify":
		cfg := mustConfig(*cfgPath)
		st, err := server.OpenStore(filepath.Join(cfg.DataDir, "events"), 1)
		if err != nil {
			log.Fatal(err)
		}
		seq, head := st.Head()
		if !st.ChainOK {
			log.Fatalf("BROKEN: %s", st.ChainError)
		}
		fmt.Printf("ok, %d records, head %s\n", seq, head)
	case "user":
		userCmd(mustConfig(*cfgPath).DataDir, sub, *role, fs.Args())
	default:
		fail()
	}
}

func rulesCmd(args []string) {
	switch {
	case len(args) == 2 && args[0] == "check":
		n, errs := server.LoadCustomRules(args[1])
		for _, e := range errs {
			fmt.Println("error:", e)
		}
		fmt.Printf("%d rules loaded\n", n)
		if len(errs) > 0 {
			os.Exit(1)
		}
	case len(args) == 3 && args[0] == "test":
		f, err := os.Open(args[2])
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		n, err := server.TryCustomRules(args[1], f, os.Stdout)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%d findings\n", n)
	default:
		fail()
	}
}

func userCmd(dir, sub, role string, args []string) {
	switch sub {
	case "list":
		users, err := server.LoadUsers(dir)
		if err != nil {
			log.Fatal(err)
		}
		func() {
			names := make([]string, 0, len(users))
			for n := range users {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				u := users[n]
				r := u.Role
				if r == "" {
					r = "admin"
				}
				fmt.Printf("%s\t%s\tcreated %s\tlast login %s\tpasskeys %d\n", n, r, u.Created.Format(time.DateOnly), u.LastLogin.Format(time.DateTime), len(u.Passkeys))
			}
		}()
	case "remove":
		if len(args) != 1 {
			fail()
		}
		err := server.UpdateUsers(dir, func(users map[string]*server.User) error {
			if users[args[0]] == nil {
				return errors.New("no such user")
			}
			delete(users, args[0])
			return nil
		})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("removed")
	case "add":
		if len(args) != 1 || strings.TrimSpace(args[0]) == "" || len(args[0]) > 64 {
			fail()
		}
		name := args[0]
		if _, _, err := server.NewUser(name, role); err != nil {
			log.Fatal(err)
		}
		pw := readPassword()
		hash, err := server.HashPassword(pw)
		if err != nil {
			log.Fatal(err)
		}
		secret := server.NewTOTPSecret()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			log.Fatal(err)
		}
		err = server.UpdateUsers(dir, func(users map[string]*server.User) error {
			if users[name] != nil {
				return errors.New("user exists; remove it first to reset password and TOTP")
			}
			users[name] = &server.User{Name: name, Role: role, PassHash: hash, TOTPSecret: secret, Created: time.Now().UTC()}
			return nil
		})
		if err != nil {
			log.Fatal(err)
		}
		uri := server.TOTPURI(name, secret, "vigil")
		fmt.Printf("\nuser %s (%s) created.\nScan this with an authenticator app (TOTP is required to log in):\n\n", name, role)
		if qr, err := server.QRTerminal(uri); err == nil {
			fmt.Print(qr)
		}
		fmt.Printf("\n  secret: %s\n  uri:    %s\n\nAfter the first login, add a passkey under Settings.\n\n", secret, uri)
	default:
		fail()
	}
}

// readPassword reads from stdin without echo when stdin is a terminal.
func readPassword() string {
	fmt.Fprint(os.Stderr, "password (min. 12 characters): ")
	tty := isTerminal()
	if tty {
		stty("-echo")
		defer func() { stty("echo"); fmt.Fprintln(os.Stderr) }()
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		log.Fatal("no password given")
	}
	pw := strings.TrimRight(line, "\r\n")
	if len(pw) < 12 {
		if tty {
			stty("echo")
		}
		log.Fatal("\npassword too short")
	}
	return pw
}

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func stty(arg string) {
	p, err := os.StartProcess("/bin/stty", []string{"stty", arg}, &os.ProcAttr{Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}})
	if err == nil {
		p.Wait()
	}
}

func mustConfig(path string) *server.Config {
	cfg, err := server.LoadConfig(path)
	if err != nil {
		log.Fatal(err)
	}
	return cfg
}

func mustServer(path string) *server.Server {
	s, err := server.New(mustConfig(path))
	if err != nil {
		log.Fatal(err)
	}
	return s
}

func fail() {
	fmt.Fprintln(os.Stderr, usage)
	os.Exit(2)
}
