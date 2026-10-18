// Command vigil-agent is the host sensor of vigil.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/akquisio-dev/vigil/internal/agent"
	"github.com/akquisio-dev/vigil/internal/notify"
	"github.com/akquisio-dev/vigil/internal/release"
)

const usage = `usage:
  vigil-agent run    [-config /etc/vigil/agent.json]
  vigil-agent enroll [-config /etc/vigil/agent.json] -server URL -token TOKEN
  vigil-agent version [-verify]
  vigil-agent fallback test [-config /etc/vigil/agent.json]
  vigil-agent update [-config /etc/vigil/agent.json] [-unit vigil-agent.service]   (run by vigil-agent-update.service)`

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/vigil/agent.json", "agent config file")
	server := fs.String("server", "", "server URL (enroll)")
	token := fs.String("token", "", "enrollment token from the dashboard (enroll)")
	unit := fs.String("unit", "vigil-agent.service", "update: the agent's systemd unit")
	verify := fs.Bool("verify", false, "version: compare this binary with the published release")
	args := os.Args[2:]
	if os.Args[1] == "fallback" {
		if len(args) == 0 || args[0] != "test" {
			fmt.Fprintln(os.Stderr, usage)
			os.Exit(2)
		}
		args = args[1:]
	}
	fs.Parse(args)

	switch os.Args[1] {
	case "version":
		fmt.Println(agent.Version)
		if *verify {
			msg, err := release.Verify("vigil-agent", agent.Version)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(msg)
		}
	case "fallback":
		// A wrong webhook would otherwise show only during a real outage.
		cfg := mustConfig(*cfgPath)
		if cfg.Fallback == nil {
			log.Fatal("no fallback in " + *cfgPath)
		}
		host, _ := os.Hostname()
		if err := notify.Deliver(*cfg.Fallback, notify.Message{Severity: "info", Text: "vigil fallback test from " + host}); err != nil {
			log.Fatalf("FAIL  fallback (%s): %v", cfg.Fallback.Type, err)
		}
		fmt.Printf("ok    fallback (%s), told after %d minutes without the server\n", cfg.Fallback.Type, cfg.FallbackMinutes)
	case "update":
		if err := agent.ApplyUpdate(mustConfig(*cfgPath), *unit); err != nil {
			log.Fatal(err)
		}
	case "enroll":
		cfg := mustConfig(*cfgPath)
		if *server == "" {
			*server = cfg.Server
		}
		if *server == "" || *token == "" {
			log.Fatal("enroll needs -server and -token")
		}
		id, err := agent.Enroll(cfg, *server, *token)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("enrolled as %s\n", id.AgentID)
	case "run":
		cfg := mustConfig(*cfgPath)
		if os.Geteuid() != 0 {
			log.Fatal("vigil-agent must run as root")
		}
		a, err := agent.New(cfg)
		if err != nil {
			log.Fatal(err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := a.Run(ctx); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}

func mustConfig(path string) *agent.Config {
	cfg, err := agent.LoadConfig(path)
	if err != nil {
		log.Fatal(err)
	}
	return cfg
}
