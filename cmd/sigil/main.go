package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"sigil/internal/sigil"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := sigil.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "sigil: %v\n", err)
		os.Exit(1)
	}
}
