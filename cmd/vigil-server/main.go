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
  vigil-server user add    [-config ...] NAME
  vigil-server user remove [-config ...] NAME
  vigil-server user list   [-config ...]
  vigil-server verify      [-config ...]
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
	if cmd == "user" {
		if len(args) == 0 {
			fail()
		}
		sub, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/vigil/server.json", "server config file")
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
		userCmd(mustConfig(*cfgPath).DataDir, sub, fs.Args())
	default:
		fail()
	}
}

func userCmd(dir string, sub string, args []string) {
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
				fmt.Printf("%s\tcreated %s\tlast login %s\n", n, u.Created.Format(time.DateOnly), u.LastLogin.Format(time.DateTime))
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
			users[name] = &server.User{Name: name, PassHash: hash, TOTPSecret: secret, Created: time.Now().UTC()}
			return nil
		})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("\nuser %s created.\nAdd this to an authenticator app (TOTP is required to log in):\n\n  secret: %s\n  uri:    %s\n\n",
			name, secret, server.TOTPURI(name, secret, "vigil"))
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
