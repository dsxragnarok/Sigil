# Sigil Architecture

## 1. Purpose

Sigil is a delegated identity and authorization broker for autonomous agents.

Its job is to let an agent act through a narrowly scoped external identity without giving that agent the long-lived credential that owns the identity. The first provider is GitHub, using separate GitHub Apps for roles such as `reviewer`, `implementer`, and `tester`.

The long-term model is broader than GitHub: Sigil should bind an agent session to a role, resolve that role to provider-specific identities, enforce policy, obtain short-lived credentials, perform authenticated operations, and record what happened.

The core security rule is:

> An agent may use an identity assigned to its session, but it may not select or escalate to a stronger identity itself.

## 2. Current state: M0

The current implementation is a local GitHub delegation helper.

```text
sigil exec <role> -- <gh|git> ...
        |
        +-- load <role>.json
        +-- load GitHub App private key
        +-- create GitHub App JWT
        +-- discover/cache installation ID
        +-- mint repository-scoped installation token
        +-- launch trusted gh/git binary with GH_TOKEN
```

M0 already provides useful security properties:

- role-neutral configuration through `<role>.json` files;
- GitHub App authentication with short-lived installation tokens;
- repository token scoping when a target repository is known;
- no token persistence;
- private keys remain in the Sigil process rather than being printed or passed on the command line;
- trusted binary resolution instead of trusting caller `PATH`;
- environment hardening for Git and SSH;
- blocking of dangerous Git flags and configuration overrides;
- process-local GitHub credential delegation through `gh`;
- installation ID caching without caching credentials.

M0 is intentionally preserved as the compatibility baseline. The next milestones should extract the existing logic behind stronger trust boundaries rather than rewrite it from scratch.

## 3. Target architecture

```text
                         TRUSTED SIDE

                  +-----------------------+
                  | Human / Council / Pi  |
                  | trusted launcher      |
                  +-----------+-----------+
                              |
                     create role session
                              |
                              v
                    +-------------------+
                    |      sigild       |
                    |  trusted broker   |
                    +-------------------+
                    | Session Manager   |
                    | Policy Engine     |
                    | Secret Store      |
                    | Audit Log         |
                    | Provider Layer    |
                    | Command Runner    |
                    +---------+---------+
                              |
             +----------------+----------------+
             |                |                |
             v                v                v
         GitHub App        GitLab          Forgejo
         provider          provider        provider
             |
             v
       external service


                         AGENT SIDE

                  +-----------------------+
                  | reviewer / tester /   |
                  | implementer / future  |
                  +-----------+-----------+
                              |
                       opaque session
                              |
                              v
                         +---------+
                         |  sigil  |
                         |   CLI   |
                         +----+----+
                              |
                        Unix socket
                              |
                              v
                           sigild
```

The architectural center of gravity is `sigild`, not the CLI. `sigil` is a thin client and agent-facing interface to the broker.

## 4. Trust boundaries

### 4.1 Trusted launcher

A trusted launcher is a human shell, Council, Pi, or another orchestrator that is allowed to assign a role to a new agent session.

It may request:

```text
role = reviewer
repository = dsxragnarok/council
expiry = 2h
```

The launcher is trusted to choose the role. The spawned agent is not.

### 4.2 Agent process

The agent process is considered untrusted with respect to credentials and role selection.

The agent may:

- request operations allowed by its session;
- invoke compatibility commands through Sigil;
- read operation output.

The agent must not be able to:

- read provider private keys;
- mint provider credentials directly;
- change its role;
- expand repository scope;
- retrieve a stronger role's credentials;
- bypass policy by selecting another provider identity.

### 4.3 Broker process

`sigild` is the local trust anchor.

It owns:

- provider private keys and other long-lived secrets;
- role-to-identity bindings;
- policy evaluation;
- session state;
- provider token minting;
- command execution in compatibility mode;
- audit records.

Only `sigild` should need access to long-lived secrets after M1.

## 5. Components

### 5.1 `sigil`

The `sigil` binary is the user- and agent-facing CLI.

Primary responsibilities:

- connect to the local broker;
- submit requests;
- stream stdout/stderr and exit status;
- create role-bound sessions when invoked by a trusted launcher;
- expose compatibility and, later, native typed operations.

It should not load provider private keys after M1.

### 5.2 `sigild`

`sigild` is the privileged local broker.

Primary responsibilities:

- authenticate local clients;
- create and validate sessions;
- resolve session -> role -> provider binding -> identity;
- enforce repository and capability scope;
- load secrets through the secret-store abstraction;
- mint short-lived provider credentials;
- execute compatibility commands without returning credentials to the caller;
- write structured audit records.

### 5.3 Session manager

Sessions bind an agent to authority granted by a trusted launcher.

A session should contain at least:

```go
type Session struct {
    ID        string
    Role      string
    CreatedAt time.Time
    ExpiresAt time.Time
    Scope     Scope
}

type Scope struct {
    Providers    []string
    Repositories []string
}
```

Properties:

- opaque random identifier;
- short-lived;
- role-bound;
- non-upgradable;
- revocable;
- optionally repository-bound;
- never interprets user-controlled role overrides after creation.

The agent receives only a session reference, for example:

```text
SIGIL_SESSION=78b0a5...
SIGIL_SOCKET=/path/to/sigil.sock
```

### 5.4 Policy engine

Provider permissions are the outer security boundary. Sigil policy is a narrower inner boundary.

Example capability model:

```text
reviewer
  github.repo.read
  github.pr.read
  github.pr.comment
  github.pr.review
  github.checks.read

implementer
  github.repo.read
  github.repo.write
  github.pr.read
  github.pr.write
  github.issue.comment
  github.checks.read

tester
  github.repo.read
  github.pr.read
  github.checks.read
  github.checks.write
```

An explicit deny should take precedence over allow.

Example:

```text
github.pr.merge -> DENY
```

Even if the underlying provider credential technically permits the operation, Sigil may reject it.

### 5.5 Identity model

Roles and provider identities are separate concepts.

```text
Role
  reviewer
      |
      v
Provider binding
  github
      |
      v
Identity
  dsxreviewer
```

This allows one role to map to different identities on different providers:

```text
reviewer
  GitHub  -> dsxreviewer
  GitLab  -> dsx-reviewer
  Forgejo -> reviewer-bot
```

The role is the authorization concept. The provider identity is an implementation detail of that authorization.

### 5.6 Provider layer

Provider-specific authentication belongs behind an interface rather than in the core broker.

Conceptually:

```go
type Provider interface {
    Name() string
    ResolveIdentity(ctx context.Context, binding Binding) (Identity, error)
    Prepare(ctx context.Context, identity Identity, operation Operation) (Credential, error)
}
```

Initial package layout:

```text
internal/provider/
  provider.go
  github/
    provider.go
    jwt.go
    installation.go
    token.go
```

Future providers:

```text
internal/provider/gitlab/
internal/provider/forgejo/
```

The core broker should not know about GitHub App JWTs, installation IDs, or PEM formats.

### 5.7 Secret store

Long-lived credentials should be accessed through an abstraction:

```go
type SecretStore interface {
    Get(ctx context.Context, ref string) ([]byte, error)
}
```

Initial backend:

```text
file:/path/to/private-key.pem
```

Possible future backends:

```text
keychain:github/dsxreviewer
remote:...
```

Provider code should receive secret material from the store rather than opening arbitrary paths directly.

### 5.8 Runner

The current `runner.go` hardening is valuable and should be preserved.

The runner is responsible for compatibility-mode execution of `gh` and `git` while minimizing credential leakage and shell escape opportunities.

Existing protections should remain part of the architecture:

- only trusted system binary directories are searched;
- `gh` and `git` are explicitly selected rather than arbitrary commands;
- Git global/system config is suppressed;
- Git SSH configuration is pinned;
- pagers/editors are neutralized;
- dangerous Git flags are rejected;
- Git configuration overrides are restricted to a safe allowlist;
- GitHub HTTPS auth is process-local;
- tokens are passed only in the child environment.

The major M1 change is ownership: `sigild`, not the agent-facing `sigil` process, should execute the child command and inject the short-lived credential.

## 6. Compatibility mode and native operations

### 6.1 Compatibility mode

Compatibility mode preserves the current agent ergonomics:

```bash
sigil exec -- gh pr review 42 ...
sigil exec -- git push ...
```

The flow becomes:

```text
agent
  -> sigil
  -> sigild
  -> policy/session validation
  -> mint provider credential
  -> execute trusted gh/git
  -> return stdout/stderr/exit code
```

The agent never receives the token directly.

Compatibility mode provides broad functionality quickly because coding agents already understand `gh` and `git`.

### 6.2 Native typed operations

Compatibility execution is difficult to authorize precisely because arbitrary CLI arguments can map to many provider operations.

Sigil should therefore gain typed native operations over time, for example:

```text
pull_request.read
pull_request.comment
pull_request.review
checks.publish
repository.push
```

A typed request can be evaluated directly by the policy engine:

```text
session role: reviewer
operation: github.pr.review
repo: dsxragnarok/council
pr: 42
```

This is a stronger security model than trying to infer intent from arbitrary `gh api` invocations.

Compatibility mode remains useful even after native operations exist, but native operations should become the preferred path for security-sensitive actions.

## 7. Git and SSH handling

Git needs separate treatment because agents require unrestricted local Git operations while remote authentication must remain delegated.

Agents should continue to be able to run local operations such as:

```text
git status
git diff
git add
git commit
```

Remote GitHub authentication should flow through Sigil.

Target model:

```text
git push
  -> Git credential helper
  -> Sigil
  -> session validation
  -> provider credential
```

For agent sessions:

- personal `GH_TOKEN` / `GITHUB_TOKEN` variables should be removed;
- personal GitHub CLI state should be isolated;
- `SSH_AUTH_SOCK` should be removed where appropriate;
- GitHub SSH remotes may need to be rewritten or redirected to HTTPS for delegated auth;
- the existing Git argument hardening remains enforced in compatibility mode.

The goal is not to disable Git. The goal is to prevent remote operations from silently falling back to the human user's personal identity.

## 8. Local transport

Use HTTP+JSON over a Unix-domain socket for local broker communication.

Example socket:

```text
~/.local/run/sigil/sigil.sock
```

Reasons:

- simple Go implementation using `net/http`;
- easy unit and integration testing;
- no custom binary protocol;
- straightforward migration to HTTPS for a remote broker later;
- keeps transport separate from provider and policy logic.

Initial API shape may include:

```text
POST /v1/sessions
GET  /v1/sessions/{id}
POST /v1/exec
POST /v1/operations
```

M1 does not need the final remote API. It needs only enough structure to separate the CLI from the trusted broker cleanly.

## 9. Audit model

Audit is a first-class feature, not optional logging.

Each delegated operation should produce a structured record similar to:

```json
{
  "time": "2026-09-18T22:30:14Z",
  "session": "8ddf...",
  "role": "reviewer",
  "provider": "github",
  "identity": "dsxreviewer",
  "repository": "dsxragnarok/council",
  "operation": "pull_request.review",
  "result": "success",
  "duration_ms": 643
}
```

Never record:

- provider tokens;
- JWTs;
- private keys;
- authorization headers;
- raw secret-store values.

The audit log should answer:

> Which session used which delegated authority to perform what operation, against which resource, and when?

## 10. Isolation and threat model

Sigil should distinguish two deployment modes explicitly.

### 10.1 Soft isolation

Typical workstation mode:

```text
same OS user
PATH/environment isolation
personal tokens removed from child environment
Sigil broker used for delegated credentials
```

This protects well against accidental credential use and ordinary agent behavior, but it is not a complete hostile-process boundary.

If an unrestricted agent runs as the same Unix user that can read the user's SSH keys, keychain data, config files, or broker secrets, it may be able to bypass Sigil.

### 10.2 Hard isolation

Strong boundary:

```text
sandbox / dedicated Unix user / VM / container
no personal credentials visible
Sigil is the only permitted delegated identity path
```

Hard isolation is required if agents are treated as actively hostile rather than merely untrusted.

The architecture should never claim that a `PATH` shim, environment cleanup, or broker alone provides hard isolation when the agent still has unrestricted access to the same host identity.

## 11. Repository structure target

The current implementation can be evolved toward:

```text
Sigil/
  cmd/
    sigil/
      main.go
    sigild/
      main.go

  internal/
    audit/
    broker/
    config/
    identity/
    policy/
    provider/
      provider.go
      github/
        provider.go
        jwt.go
        installation.go
        token.go
    runner/
    secret/
    session/
    transport/
      unix/

  documentation/
    architecture.md
    implementation-plan.md
    threat-model.md        # later

  go.mod
  README.md
```

This is a direction, not a requirement to reorganize everything in one commit. Package extraction should follow milestone needs and preserve existing tests.

## 12. Future remote and MCP model

Once local broker semantics are stable, the same core can support a hosted broker:

```text
local today:
sigil -> unix:///sigil.sock -> sigild

remote later:
sigil -> https://sigil.example.com -> Sigil broker

ChatGPT / MCP later:
MCP adapter -> Sigil broker -> provider identities
```

Remote exposure should come after sessions, policy, audit, and local secret ownership are well defined. The remote transport should reuse the same broker abstractions rather than introduce a separate authorization model.

## 13. Design principles

1. **Role assignment is trusted; agent role selection is not.**
2. **Long-lived credentials belong to the broker, never to the agent.**
3. **Short-lived credentials should be scoped as narrowly as the provider allows.**
4. **Provider permissions and Sigil policy are separate enforcement layers.**
5. **Roles, identities, and providers are separate concepts.**
6. **Compatibility execution is useful but not the final policy model.**
7. **Existing runner hardening should be preserved and moved behind stronger boundaries.**
8. **Auditability is a core product feature.**
9. **Local soft isolation must not be described as a hostile-process sandbox.**
10. **The local broker model should be correct before adding remote/MCP exposure.**
