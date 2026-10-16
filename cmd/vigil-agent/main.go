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
)

const usage = `usage:
  vigil-agent run    [-config /etc/vigil/agent.json]
  vigil-agent enroll [-config /etc/vigil/agent.json] -server URL -token TOKEN
  vigil-agent version`

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
	fs.Parse(os.Args[2:])

	switch os.Args[1] {
	case "version":
		fmt.Println(agent.Version)
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
