// Package provider defines the M1 credential-oriented provider contract.
//
// The broker resolves a role to a provider identity, asks the provider to
// prepare a short-lived credential, and executes under it. The Operation
// abstraction for typed native operations arrives in M4; M1 stays
// credential-oriented.
package provider

import (
	"context"

	"sigil/internal/provider/github"
)

// CredentialRequest asks for a short-lived credential for one identity
// acting on one repository.
type CredentialRequest = github.CredentialRequest

// Credential is a short-lived broker-local credential. It never crosses IPC,
// never touches disk, and never appears in logs or error strings.
type Credential = github.Credential

// Binding maps a role to its provider identity. Every field is explicit.
type Binding = github.Binding

// Provider mints short-lived credentials inside the broker.
type Provider interface {
	Name() string
	ResolveIdentity(ctx context.Context, binding Binding) (github.Identity, error)
	Prepare(ctx context.Context, req CredentialRequest) (Credential, error)
}
