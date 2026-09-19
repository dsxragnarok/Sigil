package main

import (
	"context"
	"errors"
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
		var exitError *sigil.ExitError
		if errors.As(err, &exitError) {
			os.Exit(exitError.Code)
		}
		fmt.Fprintf(os.Stderr, "sigil: %v\n", err)
		os.Exit(1)
	}
}
