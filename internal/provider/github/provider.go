package github

import (
	"context"
	"time"

	"sigil/internal/secret"
)

// CredentialRequest asks for a short-lived credential for one identity
// acting on one repository.
type CredentialRequest struct {
	Identity   string
	Repository string
}

// Credential is a short-lived broker-local credential. It never crosses IPC,
// never touches disk, and never appears in logs or error strings.
type Credential struct {
	Token     string
	ExpiresAt time.Time
}

// Binding maps a role to its provider identity. Every field is explicit:
// there are no role-specific defaults or fallbacks.
type Binding struct {
	Name           string
	ClientID       string
	PrivateKeyRef  string
	InstallationID int64
}

// Identity is a resolved, validated provider identity.
type Identity struct {
	Name           string
	ClientID       string
	InstallationID int64
}

// Provider mints GitHub App installation credentials. It is broker-owned:
// only sigild constructs it, with broker-fixed configuration.
type Provider struct {
	Secrets  secret.Store
	Cache    *InstallationCache
	API      *Client
	Bindings map[string]Binding
}

// NewProvider builds a broker-owned provider. cacheDir and bindings are fixed
// at daemon startup and cannot be redirected by client environment.
func NewProvider(secrets secret.Store, cacheDir string, bindings map[string]Binding) *Provider {
	return &Provider{
		Secrets:  secrets,
		Cache:    NewInstallationCache(cacheDir),
		API:      NewClient(),
		Bindings: bindings,
	}
}

// Name returns the provider name for audit records.
func (p *Provider) Name() string { return "github" }

// ResolveIdentity validates a binding and returns its identity. An empty
// ClientID is an error: every identity must declare its configuration
// explicitly.
func (p *Provider) ResolveIdentity(ctx context.Context, binding Binding) (Identity, error) {
	if binding.Name == "" {
		return Identity{}, errorf("binding name is required")
	}
	if binding.ClientID == "" {
		return Identity{}, errorf("binding %q: client_id is required", binding.Name)
	}
	if binding.PrivateKeyRef == "" {
		return Identity{}, errorf("binding %q: private_key_path is required", binding.Name)
	}
	keyPEM, err := p.Secrets.Get(ctx, binding.PrivateKeyRef)
	if err != nil {
		return Identity{}, errorf("binding %q: load private key: %v", binding.Name, err)
	}
	if _, err := ParseRSAPrivateKey(keyPEM); err != nil {
		return Identity{}, errorf("binding %q: parse private key: %v", binding.Name, err)
	}
	return Identity{Name: binding.Name, ClientID: binding.ClientID, InstallationID: binding.InstallationID}, nil
}

// Prepare mints a repository-scoped installation token for the named
// identity. Token material is returned only to the broker caller.
func (p *Provider) Prepare(ctx context.Context, req CredentialRequest) (Credential, error) {
	binding, ok := p.Bindings[req.Identity]
	if !ok {
		return Credential{}, errorf("unknown identity %q", req.Identity)
	}
	identity, err := p.ResolveIdentity(ctx, binding)
	if err != nil {
		return Credential{}, err
	}
	keyPEM, err := p.Secrets.Get(ctx, binding.PrivateKeyRef)
	if err != nil {
		return Credential{}, errorf("load private key: %v", err)
	}
	key, err := ParseRSAPrivateKey(keyPEM)
	if err != nil {
		return Credential{}, errorf("parse private key: %v", err)
	}
	appJWT, err := CreateAppJWT(identity.ClientID, key, time.Now())
	if err != nil {
		return Credential{}, errorf("create app JWT: %v", err)
	}
	installationID := identity.InstallationID
	if installationID == 0 && req.Repository != "" {
		installationID, err = p.Cache.Get(req.Identity, req.Repository)
		if err != nil {
			return Credential{}, err
		}
	}
	if installationID == 0 {
		if req.Repository == "" {
			return Credential{}, errorf("no repository supplied for installation discovery")
		}
		installationID, err = p.API.FindInstallation(ctx, appJWT, req.Repository)
		if err != nil {
			return Credential{}, err
		}
		if err := p.Cache.Put(req.Identity, req.Repository, installationID); err != nil {
			return Credential{}, err
		}
	}
	var repos []string
	if req.Repository != "" {
		_, name, err := SplitRepository(req.Repository)
		if err != nil {
			return Credential{}, err
		}
		repos = []string{name}
	}
	token, expires, err := p.API.CreateInstallationToken(ctx, appJWT, installationID, repos...)
	if err != nil {
		return Credential{}, err
	}
	clearBytes(keyPEM)
	return Credential{Token: token, ExpiresAt: expires}, nil
}

// WithInstallationOverride returns a copy that pins one identity to an
// explicitly supplied installation ID, skipping discovery. Used only for the
// trusted admin path (--installation-id); each request gets its own bindings
// map so concurrent executions never race.
func (p *Provider) WithInstallationOverride(role string, id int64) *Provider {
	bindings := make(map[string]Binding, len(p.Bindings)+1)
	for name, binding := range p.Bindings {
		bindings[name] = binding
	}
	binding := bindings[role]
	binding.InstallationID = id
	bindings[role] = binding
	clone := *p
	clone.Bindings = bindings
	return &clone
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
