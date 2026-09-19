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

Two M0 details are temporary bootstrap artifacts rather than target architecture:

- `config.go` contains a reviewer-specific default Client ID when `reviewer.json` omits `client_id`;
- the agent-facing CLI currently loads config, reads private keys, and writes installation cache state itself.

Both must disappear from the agent-facing path in M1. M0 is intentionally preserved only as the behavioral compatibility baseline.

## 3. Target architecture

```text
                         TRUSTED SIDE

                  +-----------------------+
                  | Human / Council / Pi  |
                  | trusted launcher      |
                  +-----------+-----------+
                              |
                     launcher/admin path
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
                    agent Unix socket
                              |
                              v
                           sigild
```

The architectural center of gravity is `sigild`, not the CLI. `sigil` is a thin client. Role assignment and session creation use a launcher/admin path that is distinct from the agent execution path.

## 4. Trust boundaries

### 4.1 Trusted launcher

A trusted launcher is a human shell, Council, Pi, or another orchestrator that is allowed to assign a role to a new agent session.

It may request:

```text
role = reviewer
repository = dsxragnarok/council
expiry = 1h
```

The launcher is trusted to choose the role. The spawned agent is not.

Launcher-only operations must not be exposed on the ordinary agent socket. M1 introduces a separate launcher/admin socket, `sigil-admin.sock`; M2 uses that socket for `POST /v1/sessions`. The agent receives only `sigil.sock` and its opaque session ID.

A separate socket is an authority-separation mechanism, not a hostile-process boundary by itself. If launcher and agent run unrestricted as the same Unix UID, the agent may still be able to locate and connect to the admin socket. Strong enforcement therefore requires the hard-isolation deployment described in §10.2.

### 4.2 Agent process

The agent process is considered untrusted with respect to credentials and role selection.

The agent may:

- request operations allowed by its session;
- invoke compatibility commands through Sigil;
- stream command stdin and read operation stdout/stderr.

The agent must not be able to:

- read provider private keys in a hard-isolation deployment;
- mint provider credentials directly;
- change its role;
- expand repository scope;
- create arbitrary sessions through the agent socket;
- retrieve a stronger role's credentials;
- bypass policy by selecting another provider identity.

### 4.3 Broker process

`sigild` is the local trust anchor.

It owns:

- provider private keys and other long-lived secrets;
- role-to-identity bindings;
- all role/provider configuration loading;
- installation/cache state and cache writes;
- policy evaluation;
- session state;
- provider token minting;
- command execution in compatibility mode;
- audit records.

After M1, the CLI must not read `SIGIL_CONFIG_DIR`, `SIGIL_CACHE_DIR`, role files, private keys, or installation cache state. Configuration and cache paths are broker startup concerns only.

In a hard-isolation deployment, filesystem ownership and ACLs must make long-lived secrets readable only by the broker identity. In same-user workstation mode, this ownership property cannot be enforced against an unrestricted process with the same UID; that mode is explicitly only an accidental-misuse boundary.

## 5. Components

### 5.1 `sigil`

The `sigil` binary is the user- and agent-facing CLI.

Primary responsibilities:

- connect to the appropriate local broker socket;
- submit validated requests;
- stream stdin/stdout/stderr and exit status;
- request role-bound sessions only when operating as a trusted launcher through the admin socket;
- expose compatibility and, later, native typed operations.

It should not load provider private keys, role configuration, or installation cache state after M1.

### 5.2 `sigild`

`sigild` is the privileged local broker.

Primary responsibilities:

- authenticate or separate local client authority by transport;
- create and validate sessions;
- resolve session -> role -> provider binding -> identity;
- enforce repository and capability scope;
- load secrets through the secret-store abstraction;
- mint short-lived provider credentials;
- execute compatibility commands without returning credentials to the caller;
- write structured audit records;
- own runtime directories, temporary execution state, configuration, and caches.

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
    Revoked   bool
}

type Scope struct {
    Providers    []string
    Repositories []string
}
```

M2 storage is deliberately simple: an in-memory map protected by a mutex. Broker restart invalidates every session.

Session properties:

- ID is 32 bytes from `crypto/rand`, hex encoded to 64 characters;
- default TTL is 1 hour;
- creation and expiry are based on broker time, not caller-supplied timestamps;
- the in-process monotonic clock is used for TTL enforcement so wall-clock rollback does not extend authority;
- role-bound and non-upgradable;
- repository/provider scope cannot be widened;
- revocation, expiry, unknown IDs, and ambiguous state fail closed.

The agent receives only a session reference, for example:

```text
SIGIL_SESSION=78b0a5...
SIGIL_SOCKET=/path/to/sigil.sock
```

The agent does not receive `SIGIL_ADMIN_SOCKET` or any launcher credential.

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

M1 deliberately uses a credential-oriented request contract:

```go
type CredentialRequest struct {
    Identity   string
    Repository string
}

type Provider interface {
    Name() string
    ResolveIdentity(ctx context.Context, binding Binding) (Identity, error)
    Prepare(ctx context.Context, req CredentialRequest) (Credential, error)
}
```

The `Operation` abstraction is introduced in M4 when native typed operations exist. M1 must not prematurely diverge into an operation-oriented provider contract.

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

The current `runner.go` hardening is valuable and should be preserved, but M1 changes who owns execution.

**Locked execution model: Option A.** For remote Git operations, `sigild` itself spawns the trusted `git` executable. The agent never invokes a broker credential helper and never receives a bearer token.

The runner is responsible for compatibility-mode execution of `gh` and `git` while minimizing credential leakage and command-execution escape paths.

Required controls:

- only trusted system binary directories are searched;
- `gh` and `git` are explicitly selected rather than arbitrary commands;
- caller `PATH` is ignored;
- caller `HOME`, GitHub CLI configuration, and personal token environment are not trusted;
- `GH_CONFIG_DIR` points to a fresh broker-owned empty temporary directory for every execution;
- `GH_HOST`, `GH_TOKEN`, `GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN`, and variables matching `GITHUB_*_TOKEN` are stripped before the broker injects its own credential;
- Git global/system config is suppressed;
- Git SSH configuration is pinned;
- pagers/editors are neutralized;
- dangerous Git flags and unsafe config overrides are rejected;
- the working directory is explicit, canonicalized, must exist, and must fall under a broker/session-approved workspace root;
- Git hooks are disabled for every broker-spawned Git process with `-c core.hooksPath=/dev/null`;
- credentials are never placed in argv, IPC responses, logs, or persistent files;
- child processes run in their own process group so timeout cancellation can terminate the entire tree.

The review proposed additionally injecting a global Git `--no-hooks` flag. Current Git does not define `--no-hooks` as a global option; the supported all-hooks suppression mechanism is `-c core.hooksPath=/dev/null`. Sigil must enforce the security intent rather than emit an unsupported argument. Command-specific no-hook/no-verify flags may be added only where Git documents them and they provide defense in depth.

If the runner internally uses `gh auth git-credential` to satisfy HTTPS authentication for the broker-spawned `git`, that helper is an implementation detail inside the sanitized child environment. It is not an agent-facing credential path and must use the isolated `GH_CONFIG_DIR` so personal GitHub CLI OAuth state cannot be consulted.

## 6. Compatibility mode and native operations

### 6.1 Compatibility mode

Compatibility mode preserves familiar ergonomics while changing the trust path.

M1 trusted/admin compatibility invocation:

```bash
sigil exec reviewer -- gh pr review 42 ...
sigil exec implementer -- git push ...
```

M2 agent invocation:

```bash
sigil exec -- gh pr review 42 ...
sigil exec -- git push ...
```

M2 flow:

```text
agent
  -> sigil
  -> sigild agent socket
  -> session/policy validation
  -> mint provider credential
  -> sigild spawns trusted gh/git
  -> chunked stdout/stderr/exit frames
```

The agent never receives the token directly.

M1 explicit role selection is an administrative compatibility path, not a role-isolation boundary for an untrusted same-user agent. Role integrity for agents begins with M2 sessions.

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

Git needs separate treatment because agents require unrestricted local Git operations while authenticated remote operations must remain delegated.

Agents should continue to run local Git directly for operations such as:

```text
git status
git diff
git add
git commit
```

Remote operations requiring delegated GitHub authority go through Sigil:

```text
agent
  -> sigil exec -- git push ...
  -> sigild
  -> validate session/repository/working_dir
  -> mint repository-scoped GitHub App token
  -> spawn trusted git inside sanitized environment
  -> HTTPS authentication occurs inside that broker-owned process tree
  -> stream result back to agent
```

There is no agent-facing Git credential-helper hop. Any helper used by the broker-spawned Git process is internal to the runner and cannot return the token to the agent.

For agent sessions:

- personal `GH_TOKEN`, `GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN`, and `GITHUB_*_TOKEN` variables are removed;
- personal GitHub CLI state is isolated through a fresh `GH_CONFIG_DIR`;
- broker execution should use an empty temporary `HOME` where practical rather than inheriting the human user's home directory;
- `SSH_AUTH_SOCK` is removed from broker child execution;
- GitHub SSH remotes must not silently fall back to the human user's SSH identity; delegated remote Git should use the broker-managed HTTPS path;
- `-c core.hooksPath=/dev/null` is injected for every broker-spawned Git command;
- existing Git argument hardening remains enforced in compatibility mode.

The goal is not to disable Git. The goal is to prevent remote operations from silently falling back to the human user's personal identity or executing repository-controlled hooks inside `sigild`.

## 8. Local transport

Use HTTP over Unix-domain sockets with chunked streaming for execution requests. Do not implement a throwaway buffered-JSON execution transport first.

Sockets:

```text
Linux / XDG:
  $XDG_RUNTIME_DIR/sigil/sigil.sock
  $XDG_RUNTIME_DIR/sigil/sigil-admin.sock

macOS fallback:
  ~/.local/state/sigil/sigil.sock
  ~/.local/state/sigil/sigil-admin.sock
```

The runtime directory is created under `umask 0077`. M1 uses an owner-only runtime directory by default. Hard-isolation deployments may use explicit group/ACL rules for the agent socket while keeping the admin socket launcher-only.

Reasons for HTTP over Unix sockets:

- simple Go implementation using `net/http`;
- easy unit and integration testing;
- transport remains separate from provider and policy logic;
- the same broker service layer can later be exposed through authenticated HTTPS.

### 8.1 Chunked execution stream

`POST /v1/exec` uses `Transfer-Encoding: chunked` in both directions and an application framing layer so stdin, stdout, stderr, process exit, and broker errors are unambiguous.

Use newline-delimited JSON frames (`application/x-ndjson`) so arbitrary stream bytes can be base64 encoded without inventing a second binary protocol.

Request frames:

```json
{"type":"meta","working_dir":"/work/repo","repository":"dsxragnarok/council","command":["git","push"],"timeout_seconds":120}
{"type":"stdin","data":"<base64 bytes>"}
{"type":"stdin_eof"}
```

M1 admin execution may include `role` in the metadata frame. M2 agent execution replaces role selection with `session_id`.

Response frames:

```json
{"type":"stdout","data":"<base64 bytes>"}
{"type":"stderr","data":"<base64 bytes>"}
{"type":"exit","code":0}
```

A target command failure is **not** a broker transport failure: if `gh` or `git` starts successfully and exits non-zero, HTTP remains `200 OK` and the final `exit` frame carries the non-zero code. Authentication, request validation, internal broker, provider, or runner-start failures use an appropriate non-2xx HTTP status; unexpected broker failures use 5xx.

The transport must enforce explicit limits rather than buffering unbounded data. Initial defaults:

- maximum 256 command arguments;
- maximum 64 KiB aggregate argument bytes;
- maximum 64 KiB metadata frame;
- maximum 1 MiB individual stream frame;
- maximum 64 MiB stdin per execution;
- maximum 64 MiB combined stdout/stderr per execution;
- default execution timeout 120 seconds.

On timeout or client cancellation, `sigild` sends `SIGTERM` to the child process group, waits a short grace period (default 5 seconds), then sends `SIGKILL` to the process group if anything remains.

### 8.2 API separation

Initial shape:

```text
agent socket:
  GET  /v1/health
  POST /v1/exec                 # M2+: requires session

admin socket:
  POST /v1/exec                 # M1 trusted explicit-role compatibility
  POST /v1/sessions             # M2
  GET  /v1/sessions/{id}        # M2
  DELETE /v1/sessions/{id}      # M2
```

An agent must never be able to create a session through the ordinary agent socket.

## 9. Audit model

Audit is a first-class feature, not optional logging.

Default path:

```text
$XDG_STATE_HOME/sigil/audit.jsonl
```

with fallback:

```text
~/.local/state/sigil/audit.jsonl
```

Requirements:

- broker-owned;
- containing directory mode `0700` by default;
- file mode `0600`;
- opened append-only;
- JSONL, one immutable event per line;
- no secret values;
- audit availability is fail-closed for delegated operations.

Before a consequential operation starts, the broker must be able to append its attempt record. If the audit file cannot be opened, appended, or synchronized, the operation is denied. If writing the completion record fails after a command has already executed, the broker surfaces the failure and stops accepting further delegated operations until audit health is restored.

Each delegated operation should produce structured records containing fields similar to:

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

Sigil has two explicitly different deployment modes. Documentation and acceptance criteria must not blur them.

### 10.1 Same-user workstation mode — accidental-misuse defense

Typical development workstation mode:

```text
human, sigild, and agent may share one Unix UID
agent receives only sigil.sock + SIGIL_SESSION
personal token environment stripped from broker children
personal gh config isolated from broker children
Sigil broker used for delegated credentials
```

Owner-only socket/runtime permissions protect against other local users, not against another process with the same UID.

Consequences:

- an unrestricted same-user agent may be able to read `~/.config/sigil/*.pem` if those files are readable by that UID;
- it may be able to locate `sigil-admin.sock` even if the launcher does not advertise it;
- it may access the human user's unrelated credentials outside Sigil;
- file mode `0600` cannot distinguish the human, broker, and agent when all are the same UID.

Therefore same-user mode is useful for preventing accidental identity fallback and ordinary agent misuse, but it is **not** a hostile-process security boundary.

### 10.2 Hard isolation — security boundary

Strong deployment:

```text
agent sandbox / dedicated Unix user / VM / container
            |
            | only agent data socket exposed
            v
        sigild under dedicated broker identity
            |
            +-- private keys/config/cache/audit readable only by broker
            +-- admin socket exposed only to trusted launcher identity/boundary
```

Hard isolation requires at least one OS-enforced boundary that prevents the agent from reading broker secrets or reaching launcher-only authority. Examples include:

- dedicated `sigild` system user plus file ownership/ACLs and carefully scoped socket group/ACL access;
- container/sandbox boundary that mounts only `sigil.sock` into the agent environment;
- VM boundary with the broker as the only delegated identity service.

In hard-isolation mode, private key ownership, admin-socket reachability, personal SSH credentials, and human GitHub CLI state must be enforced by OS/container policy rather than convention.

The architecture must never claim that a `PATH` shim, environment cleanup, owner-only same-user socket, or broker process alone provides hard isolation.

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
2. **Launcher/admin authority is separate from agent execution authority.**
3. **Long-lived credentials belong to the broker boundary, never to the agent transport.**
4. **Short-lived credentials should be scoped as narrowly as the provider allows.**
5. **Provider permissions and Sigil policy are separate enforcement layers.**
6. **Roles, identities, and providers are separate concepts.**
7. **`sigild` owns configuration, caches, secrets, compatibility execution, and audit state.**
8. **Remote Git authentication is performed by broker-spawned Git, not by an agent credential-helper path.**
9. **Repository-controlled hooks must not execute inside the broker process tree.**
10. **Compatibility execution is useful but not the final policy model.**
11. **Auditability is a core product feature and delegated actions fail closed when audit is unavailable.**
12. **Same-user mode is accidental-misuse defense, not hostile-process isolation.**
13. **The local broker model should be correct before adding remote/MCP exposure.**
