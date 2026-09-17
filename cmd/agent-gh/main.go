package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"agent-gh/internal/agentgh"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := agentgh.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "agent-gh: %v\n", err)
		os.Exit(1)
	}
}
