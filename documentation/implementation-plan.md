# Sigil Implementation Plan

## 1. Roadmap

Sigil will evolve from the current local GitHub App delegation helper into a role-bound identity and authorization broker.

Milestones:

```text
M0  Local GitHub App delegation                    DONE
M1  sigild broker + Unix socket
M2  role-bound sessions + sigil run
M3  capabilities + repository scope + audit
M4  native provider operations
M5  GitLab + Forgejo providers
M6  remote broker + MCP integration
```

The implementation should preserve the existing GitHub authentication and runner hardening. The plan is an extraction and trust-boundary refactor, not a rewrite.

---

# M0 — Local GitHub App delegation

**Status: complete / current baseline**

Current behavior:

```bash
sigil exec reviewer -- gh pr view 1
sigil exec implementer -- git push ...
sigil exec tester -- gh api ...
```

Current capabilities include:

- role-specific JSON configuration;
- GitHub App Client ID + private key authentication;
- GitHub App JWT generation;
- installation discovery and installation ID caching;
- repository-scoped installation token creation where possible;
- short-lived token injection into a child `gh` or `git` process;
- trusted binary lookup;
- hardened Git argument validation;
- Git/SSH/global-config suppression;
- process-local GitHub HTTPS credential helper;
- tests around cache, config, JWT, GitHub client, CLI, and runner behavior.

Known M0 bootstrap artifacts that must not become architectural dependencies:

- `config.go` contains a reviewer-specific fallback `ReviewerClientID`; M1 removes this fallback and requires every role config/provider binding to supply its identity explicitly;
- `cli.go` reads `SIGIL_CONFIG_DIR` and `SIGIL_CACHE_DIR`, loads role config/private keys, and writes `installations.json`; in M1 the CLI becomes a dumb proxy and `sigild` alone owns those operations;
- only `reviewer.example.json` existed at the start of this hardening pass; equivalent implementer and tester examples are added so the role-neutral claim is represented in the repository.

M0 remains the behavioral compatibility reference for all later milestones, not the security model for untrusted same-user agents.

---

# M1 — Trusted `sigild` broker and Unix socket

## Goal

Move long-lived credentials, role configuration, cache ownership, token minting, and compatibility command execution out of the agent-facing CLI into a trusted broker process.

After M1:

```text
trusted/admin caller
  -> sigil CLI
  -> sigil-admin.sock
  -> sigild
  -> load role config/private key
  -> mint GitHub credential
  -> run gh/git
  -> chunked stdout/stderr/exit stream
```

The caller never receives the GitHub token directly from the broker.

M1 retains explicit role selection only as a **trusted/admin compatibility path**. It is not an agent role-isolation boundary. Untrusted agents use role-bound sessions beginning in M2. Adversarial child-output secrecy is out of scope for M1 (see Section 1.2 Framing and M2 prerequisites).

## 1.1 Add `cmd/sigild`

Create:

```text
cmd/sigild/main.go
```

Responsibilities:

- start the local broker;
- create/listen on Unix-domain sockets;
- set `umask 0077` before creating runtime directories, sockets, lock files, temporary homes, or other broker-owned files;
- enforce single-instance broker ownership;
- safely clean stale sockets;
- initialize config, provider, runner, broker, and audit dependencies;
- handle clean shutdown;
- surface startup errors clearly.

Runtime paths:

```text
Linux / XDG:
  $XDG_RUNTIME_DIR/sigil/sigil.sock
  $XDG_RUNTIME_DIR/sigil/sigil-admin.sock
  $XDG_RUNTIME_DIR/sigil/sigild.lock

macOS fallback:
  ~/.local/state/sigil/sigil.sock
  ~/.local/state/sigil/sigil-admin.sock
  ~/.local/state/sigil/sigild.lock
```

Do not use `~/.local/run` as the fallback.

### Single-instance and stale-socket rules

1. create/open the runtime directory under `umask 0077`;
2. acquire a non-blocking exclusive `flock` on `sigild.lock`;
3. if the lock cannot be acquired, fail with `sigild already running` rather than deleting sockets;
4. only after the lock is held, inspect existing socket paths;
5. if a socket accepts a connection or otherwise appears live, fail rather than replacing it;
6. if it is stale, unlink it and create a new socket;
7. hold the lock for the lifetime of the daemon;
8. unlink owned socket paths on graceful shutdown.

Default same-user mode keeps the runtime directory owner-only. Hard-isolation deployments may use explicit group/ACL rules for `sigil.sock` while keeping `sigil-admin.sock` launcher-only.

## 1.2 Add local transport package

Target package:

```text
internal/transport/unix/
```

Use HTTP over Unix sockets with **chunked streaming from the first M1 implementation**. Do not build a temporary buffered JSON execution protocol.

M1 admin endpoint:

```text
POST /v1/exec    # sigil-admin.sock only; explicit role allowed
```

The ordinary agent socket is reserved for session-bound execution beginning in M2. It may expose `/v1/health` in M1, but must not accept arbitrary role-selecting execution.

### Framing

Use `Transfer-Encoding: chunked` and newline-delimited JSON frames (`application/x-ndjson`). Binary stream data is base64 encoded in frames.

Initial request frames:

```json
{"type":"meta","role":"reviewer","repository":"dsxragnarok/council","installation_id":0,"working_dir":"/work/council","command":["gh","pr","view","1"],"timeout_seconds":120}
{"type":"stdin","data":"<base64 bytes>"}
{"type":"stdin_eof"}
```

Initial response frames:

```json
{"type":"stdout","data":"<base64 bytes>"}
{"type":"stderr","data":"<base64 bytes>"}
{"type":"exit","code":0}
```

Stream requirements:

- stdin is forwarded incrementally to the child process;
- stdout and stderr remain distinct;
- preserve frame order as emitted by each stream, without claiming a total ordering between stdout and stderr;
- the final success-path frame is exactly one `exit` frame;
- credentials are never placed in broker-originated frames (metadata, error, exit) or logs; child stdout and stderr frames are scrubbed per-stream of the exact raw token as defense in depth against accidental echo. Adversarial child-output secrecy (cross-stream reconstruction or encoded exfiltration by code inheriting `GH_TOKEN`) is out of scope for M1.

### Request and stream bounds

Initial defaults:

```text
max command arguments              256
max aggregate argument bytes       64 KiB
max metadata frame                 64 KiB
max individual stream frame        1 MiB
max stdin per execution            64 MiB
max stdout+stderr per execution    64 MiB
default execution timeout          120 s
termination grace period           5 s
```

Limits should be constants/configurable broker policy, not client-controlled expansion knobs.

`working_dir` requirements:

- required for repository-sensitive `git` execution;
- must be absolute;
- canonicalize with symlink resolution before execution;
- must exist and be a directory;
- must fall under a broker/session-approved workspace root;
- reject paths that cannot be resolved safely.

### Timeout and process-tree termination

The runner starts `gh`/`git` in a separate process group. On timeout, client cancellation, or broker cancellation:

1. send `SIGTERM` to the process group;
2. wait the grace period (default 5 seconds);
3. send `SIGKILL` to the process group if any process remains;
4. return the appropriate broker/exit result without leaking credentials.

### Error model

Distinguish transport/broker failure from target-command failure:

- malformed request, authentication/authority failure, invalid working directory, provider failure, or inability to start the child -> non-2xx HTTP response;
- unexpected broker failure -> 5xx HTTP response;
- `gh` or `git` starts successfully but exits non-zero -> HTTP `200 OK` with final `{"type":"exit","code":N}` frame.

Do not convert an ordinary target exit code into a 5xx broker failure.

## 1.3 Extract broker orchestration

Create:

```text
internal/broker/
```

Move orchestration currently performed by `internal/sigil/cli.go` into a broker service.

Conceptual API:

```go
type ExecRequest struct {
    Role           string // M1 admin path only; removed from agent request in M2
    Repository     string
    InstallationID int64
    WorkingDir     string
    Command        []string
    Timeout        time.Duration
}

type Broker interface {
    Exec(ctx context.Context, req ExecRequest, io IO) error
}
```

Broker flow:

1. validate transport authority and request;
2. validate/canonicalize working directory;
3. load role/provider binding from broker-owned configuration;
4. resolve repository scope;
5. obtain provider credential;
6. invoke hardened runner;
7. stream process result;
8. zero/drop credential references as soon as practical.

### Config/cache ownership

M1 makes ownership explicit:

- `sigild` alone loads role/provider config;
- `sigild` alone reads private-key references;
- `sigild` alone reads/writes installation cache state;
- the CLI does not read `SIGIL_CONFIG_DIR` or `SIGIL_CACHE_DIR`;
- client-supplied environment cannot redirect broker config/cache paths;
- broker config/cache locations are fixed at daemon startup.

## 1.4 Extract GitHub provider

Move GitHub-specific logic into:

```text
internal/provider/github/
```

Suggested files:

```text
provider.go
jwt.go
installation.go
token.go
```

Preserve current behavior and tests from:

- `github.go`;
- `jwt.go`;
- GitHub-related cache behavior.

M1 provider contract is credential-oriented and must match the architecture:

```go
type CredentialRequest struct {
    Identity   string
    Repository string
}

type Credential struct {
    Token     string
    ExpiresAt time.Time
}

type Provider interface {
    Name() string
    ResolveIdentity(ctx context.Context, binding Binding) (Identity, error)
    Prepare(ctx context.Context, req CredentialRequest) (Credential, error)
}
```

Do **not** introduce `Operation` into the provider interface in M1. Transition to operation-oriented requests in M4 when native operations exist.

The token must remain broker-local.

## 1.5 Extract secret loading

Create:

```text
internal/secret/
```

Initial interface:

```go
type Store interface {
    Get(ctx context.Context, ref string) ([]byte, error)
}
```

Initial implementation:

```text
file:
```

Migrate private-key loading behind this interface while preserving current permission checks.

Remove the reviewer-specific Client ID fallback during this extraction. Every identity must declare its Client ID/config explicitly.

M1 does not need macOS Keychain support yet.

Security wording must remain precise: moving key loading to `sigild` means the **architecture** no longer hands keys to the CLI. Same-UID file permissions do not prevent an unrestricted same-user agent from opening those key files itself. Enforced key secrecy requires the hard-isolation deployment in `architecture.md` §10.2.

## 1.6 Preserve and strengthen runner hardening

Move or retain existing `runner.go` behavior behind:

```text
internal/runner/
```

**Locked execution model: `sigild` spawns remote `git` directly.** Do not add an agent-facing credential-helper architecture.

Regression requirements:

- only `gh` and `git` accepted in compatibility mode;
- caller `PATH` not trusted;
- trusted directories checked for unsafe permissions;
- dangerous Git flags rejected;
- unsafe Git configuration overrides rejected;
- global/system Git config suppressed;
- SSH config pinned;
- pagers/editors neutralized;
- no credential in argv;
- no credential written to disk;
- repository-scoped installation token retained where possible.

New M1 requirements:

### GitHub CLI/personal identity isolation

For every broker-spawned `gh` or `git` process:

- create a fresh broker-owned temporary execution home under `umask 0077`;
- set `HOME` to that temporary home where compatible;
- set `GH_CONFIG_DIR` to a fresh empty broker-owned directory within it;
- remove `GH_HOST`;
- remove caller `GH_TOKEN`;
- remove caller `GITHUB_TOKEN`;
- remove `GH_ENTERPRISE_TOKEN`;
- remove every environment variable matching `GITHUB_*_TOKEN`;
- remove `SSH_AUTH_SOCK`;
- inject only the broker-minted credential needed by the child;
- delete temporary execution state after the child exits.

This prevents `gh` from reading `~/.config/gh/hosts.yml` and silently falling back to a human OAuth token if App authentication fails.

### Git hook suppression

For every broker-spawned Git command, inject:

```text
git -c core.hooksPath=/dev/null ...
```

before caller-controlled Git arguments.

This is mandatory even if the repository is trusted. Repository-controlled hooks must never execute inside the `sigild` process tree.

The review proposed also injecting a global `--no-hooks` Git flag. Current Git does not define such a global option, so M1 must not emit it unconditionally. The supported all-hooks control is `core.hooksPath=/dev/null`. Command-specific documented no-hook/no-verify flags may be added as defense in depth where applicable.

### Working-directory isolation

The runner must receive an already validated canonical `working_dir` from the broker and set `cmd.Dir` explicitly. It must never inherit the daemon's current working directory or accept Git `-C`, `--git-dir`, or `--work-tree` as an alternate path escape.

### Process lifecycle

- create a separate process group;
- enforce the broker timeout;
- kill the process tree using `SIGTERM` -> grace -> `SIGKILL`;
- close stdin on `stdin_eof`;
- stop streaming after the final exit/error condition.

### Required tests

Add explicit regression tests proving:

- `GH_CONFIG_DIR` is fresh and empty;
- inherited `HOME` is not used for GitHub CLI credentials;
- `GH_HOST`, `GH_TOKEN`, `GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN`, and `GITHUB_*_TOKEN` values are scrubbed;
- `SSH_AUTH_SOCK` is absent;
- `-c core.hooksPath=/dev/null` is injected ahead of caller Git arguments;
- a malicious `.git/hooks/pre-push` or equivalent fixture does not execute;
- `working_dir` outside allowed roots is denied;
- symlink escape from an allowed root is denied after canonicalization;
- timed-out grandchildren are terminated, not orphaned;
- no credential appears in argv, temp files, stdout/stderr, or error strings.

## 1.7 Convert `sigil exec` into a dumb client

M1 trusted/admin behavior:

```bash
sigil exec reviewer -- gh ...
```

The CLI:

- parses user-facing arguments;
- connects to `sigil-admin.sock`;
- sends metadata/stream frames;
- streams stdin;
- renders stdout/stderr;
- exits with the target exit code when an `exit` frame is received.

The CLI must not:

- load role config;
- read private keys;
- mint JWTs/tokens;
- discover installations;
- read/write `installations.json`;
- honor `SIGIL_CONFIG_DIR` or `SIGIL_CACHE_DIR` as client overrides.

Provide a clear error if the broker is unavailable:

```text
sigil: broker unavailable: start sigild or configure SIGIL_SOCKET
```

For admin commands, use `SIGIL_ADMIN_SOCKET` only in trusted launcher environments. Do not export it into agent environments.

## 1.8 Broker startup strategy

M1 may support either:

- explicitly running `sigild`; or
- optional `sigil daemon start` / `sigil daemon stop` commands.

Do not auto-spawn the broker invisibly in the first implementation unless lifecycle, lock ownership, socket cleanup, and shutdown behavior are defined and tested.

## 1.9 M1 testing

### Unit tests

Add tests for:

- runtime path selection including macOS fallback;
- `umask`/permission expectations where testable;
- single-instance lock behavior;
- stale socket cleanup only after lock acquisition;
- refusal to replace a live socket;
- chunked frame parsing/encoding;
- argument, metadata, stream, and payload limits;
- working-directory validation/canonicalization;
- broker request validation;
- provider credential acquisition;
- secret store path/permission rules;
- runner hardening and environment isolation;
- timeout/process-group termination;
- errors never include token/private-key content.

### Integration tests

Use a fake provider and controlled test runner to verify:

```text
sigil CLI -> sigil-admin.sock -> sigild -> provider -> runner
```

Verify that:

- in legitimate use, client process never receives provider token;
- token does not appear in broker-originated request/response frames;
- direct appearances in child stdout/stderr are scrubbed per-stream as defense in depth against accidental echo;
- cross-stream bearer fragmentation by adversarial child code is tested and documented as an M1 limitation (see M2 prerequisites);
- role config is resolved only by broker;
- client `SIGIL_CONFIG_DIR` / `SIGIL_CACHE_DIR` cannot redirect daemon state;
- streamed stdin reaches the child;
- stdout/stderr frames propagate incrementally;
- target non-zero exit is HTTP 200 + non-zero exit frame;
- broker/internal failure uses non-2xx/5xx as appropriate;
- malformed frames and limit violations fail closed;
- hook suppression and GH config isolation are active in the real runner path.

### Live GitHub smoke test

Optional/manual test using `dsxreviewer`:

```bash
sigil exec reviewer -- gh pr view 1 -R dsxragnarok/council
```

Then perform a harmless PR operation and verify attribution remains `dsxreviewer[bot]`.

## 1.10 M1 acceptance criteria

M1 is complete when all of the following are true:

- `sigild` owns its runtime directory under `umask 0077`;
- single-instance lock and stale-socket handling are tested;
- `sigil-admin.sock` exists for trusted explicit-role execution;
- agent socket does not expose arbitrary role-selecting execution;
- `sigil exec <role>` talks to `sigild` instead of loading keys itself;
- only `sigild` code loads GitHub App private keys/config/cache state;
- documentation explicitly states same-UID processes may still read broker files unless OS isolation prevents it;
- GitHub installation tokens are minted only inside `sigild`;
- tokens are not returned to `sigil` or written to disk;
- HTTP execution is chunked and supports streamed stdin/stdout/stderr;
- target exit codes are distinct from broker transport errors;
- default 120-second timeout kills the whole child process tree;
- `GH_CONFIG_DIR`/temporary `HOME` prevent fallback to personal GitHub CLI state;
- personal token environment is scrubbed;
- broker-spawned Git always disables repository hooks with `core.hooksPath=/dev/null`;
- validated `working_dir` cannot escape approved workspace roots;
- reviewer/implementer/tester configs are explicit and role-neutral;
- per-stream output redaction is defense in depth against accidental echo, while adversarial child-output secrecy is documented as out of scope for M1 and a hard prerequisite before M2 exposes compatibility execution to untrusted agents;
- all automated tests pass;
- README/documentation is updated for broker startup and trusted/admin usage.

---

# M2 — Role-bound sessions and `sigil run`

## Goal

Remove role selection from the untrusted agent and separate launcher authority from agent execution authority.

### Hard prerequisite: Credential isolation before untrusted compatibility execution

In M1, compatibility execution injects `GH_TOKEN` into the child process environment, where repo-local Git configuration (such as `alias.* = "!..."`, custom filter drivers, or diff drivers) can execute shell commands that inherit the token. Independent stream redactors cannot prevent an adversarial child from fragmenting or encoding the token across output streams or exfiltrating over network.

Therefore, **M2 must not expose the M1 compatibility execution path unchanged to untrusted agents**. Before compatibility execution is made available to untrusted sessions, M2 requires either:
1. **Credential helper isolation**: `sigild` acts as an out-of-process credential helper for `git` so that `GH_TOKEN` is never placed into the child process environment; or
2. **Native typed operations**: the broker executes provider operations directly rather than delegating command execution to a subprocess with raw credentials.

Trusted launcher:

```bash
sigil run \
  --role reviewer \
  --repo dsxragnarok/council \
  -- codex ...
```

Agent environment:

```text
SIGIL_SESSION=<opaque-id>
SIGIL_SOCKET=<agent-socket-path>
```

Agent command:

```bash
sigil exec -- gh pr view 42
```

There is no agent-controlled role flag, no admin socket path, and no session-creation credential in the agent environment.

## 2.1 Session manager

Create:

```text
internal/session/
```

Initial storage:

```text
in-memory map[string]Session behind sync.RWMutex / sync.Mutex
```

No persistence in M2. Daemon restart invalidates every session.

Session ID generation:

```go
raw := make([]byte, 32)
_, err := crypto_rand.Read(raw)
id := hex.EncodeToString(raw) // 64 hex chars
```

Session fields:

- 32-byte cryptographically random opaque ID, hex encoded;
- role;
- creation time;
- expiration time;
- repository scope;
- provider scope;
- revocation state;
- approved workspace roots if needed by execution policy.

TTL rules:

- default TTL: 1 hour;
- broker chooses timestamps; client does not submit absolute creation/expiry times;
- requested TTL may only reduce authority unless an explicit broker maximum permits more;
- use the broker's in-process monotonic time component for expiry decisions so wall-clock rollback cannot extend a live session;
- expiry comparison ambiguity fails closed.

Session rules:

- role cannot be changed after creation;
- repository/provider/workspace scope cannot be widened;
- expired sessions fail closed;
- revoked sessions fail closed;
- unknown sessions fail closed;
- lookup and revocation are synchronized so a revoked session cannot race back into valid state;
- revocation is fail-closed: once revocation is requested/recorded, no new operation may start under that session.

## 2.2 Launcher-authenticated session endpoints

Authority separation is explicit from M1 onward.

Admin socket only:

```text
POST   /v1/sessions
GET    /v1/sessions/{id}
DELETE /v1/sessions/{id}
```

Agent socket:

```text
POST /v1/exec
```

`POST /v1/exec` accepts a session ID, not a role.

### Launcher authentication mechanism

M2 uses **socket separation as the local launcher authority mechanism**:

- `sigil-admin.sock` accepts session creation/revocation and trusted explicit-role compatibility operations;
- `sigil.sock` accepts session-bound agent execution only;
- `sigil run` connects to the admin socket before spawning the agent;
- the spawned agent receives only `SIGIL_SOCKET` and `SIGIL_SESSION`;
- `SIGIL_ADMIN_SOCKET` is never inherited by the agent;
- session endpoints are not registered on `sigil.sock`.

Security boundary statement:

- in same-user unsandboxed mode, socket separation prevents accidental/API misuse but does not stop an actively hostile process with the same UID from discovering the admin socket;
- hard role/session isolation requires the deployment boundary from `architecture.md` §10.2, where the admin socket is not reachable from the agent identity/container/VM;
- do not claim owner-only `0700`/`0600` permissions distinguish two processes running under the same UID.

This is a deliberate design decision, not an unresolved TODO.

## 2.3 Implement `sigil run`

`sigil run` should:

1. operate as a trusted launcher command;
2. connect to `sigil-admin.sock`;
3. request a session for the selected role/repository/workspace scope;
4. construct a sanitized child environment;
5. set only `SIGIL_SESSION` and `SIGIL_SOCKET` for Sigil authority;
6. ensure `SIGIL_ADMIN_SOCKET` is absent;
7. remove personal GitHub token variables;
8. remove or replace personal GitHub CLI configuration where the agent environment is intended to be isolated;
9. optionally remove `SSH_AUTH_SOCK` based on the deployment profile;
10. launch the requested agent command;
11. revoke/end the session when the process exits unless explicitly configured otherwise.

`sigil run` does not pass the provider token, role config, App private key, or admin authority into the child.

## 2.4 Compatibility migration

Human/trusted use may temporarily retain:

```bash
sigil exec reviewer -- ...
```

but it uses `sigil-admin.sock` and is documented as trusted/admin-only.

Agent-facing documentation and orchestrator integration use role-bound sessions exclusively:

```bash
sigil exec -- ...
```

Eventually explicit-role `exec` can be removed or retained only as an administrative command.

## 2.5 M2 testing

Add tests proving:

- session IDs are exactly 32 random bytes encoded as 64 hex characters;
- no predictable/colliding test RNG is used in production path;
- concurrent lookup/revoke is race-safe;
- daemon restart invalidates sessions;
- default TTL is 1 hour;
- broker time, not client timestamps, controls expiry;
- monotonic TTL is not extended by wall-clock rollback in testable clock abstraction;
- expired/revoked/unknown sessions fail closed;
- `POST /v1/sessions` does not exist on the agent socket;
- agent-side `/v1/exec` rejects a role field;
- session scope cannot be widened by exec metadata;
- `sigil run` does not expose `SIGIL_ADMIN_SOCKET`;
- hard-isolation integration fixture cannot reach the admin socket from the agent boundary where platform CI permits.

## 2.6 M2 acceptance criteria

- Council/Pi/human can launch a role-bound agent session through the admin socket;
- agent can call `sigil exec -- ...` with no role argument;
- agent socket cannot create, mutate, or revoke sessions;
- agent cannot request another role through exec metadata;
- repository-bound session cannot operate against another repository;
- workspace-bound session cannot escape approved working roots;
- expired/revoked session is denied;
- broker restart invalidates existing sessions;
- role private keys remain broker-side architecturally, with hard filesystem enforcement documented as a separate-user/container requirement;
- environment strips personal GitHub token variables;
- tests prove role and scope are immutable from the agent API.

---

# M3 — Capability policy, repository scoping, and audit

## Goal

Add Sigil-native authorization on top of provider-native permissions and make delegated operations auditable by default.

## 3.1 Policy package

Create:

```text
internal/policy/
```

Introduce canonical capabilities such as:

```text
github.repo.read
github.repo.write
github.pr.read
github.pr.comment
github.pr.review
github.pr.write
github.pr.merge
github.checks.read
github.checks.write
```

Rules:

- default deny;
- explicit deny overrides allow;
- policy evaluated against session role + provider + resource;
- repository scope checked independently of provider token scope.

## 3.2 Role configuration redesign

Move toward provider bindings rather than role files that directly encode GitHub credential details.

Conceptually:

```toml
[identities.github.dsxreviewer]
type = "github_app"
client_id = "..."
private_key = "file:..."

[roles.reviewer.github]
identity = "dsxreviewer"
repositories = ["dsxragnarok/council"]
capabilities = [
  "github.repo.read",
  "github.pr.read",
  "github.pr.comment",
  "github.pr.review",
  "github.checks.read"
]
```

Migration may support existing JSON configs until the new format is stable, but there must be no role-specific hardcoded identity defaults.

## 3.3 Structured audit

Create:

```text
internal/audit/
```

Default audit path:

```text
$XDG_STATE_HOME/sigil/audit.jsonl
```

fallback:

```text
~/.local/state/sigil/audit.jsonl
```

Requirements:

- broker-owned;
- containing directory mode `0700` by default;
- file mode `0600`;
- opened append-only;
- JSONL;
- fail closed when audit is unavailable.

Record:

- timestamp;
- session ID or stable truncated/hash representation;
- role;
- provider;
- identity;
- repository/resource;
- operation;
- allow/deny/result;
- duration;
- process exit status where relevant.

Never record tokens, JWTs, private keys, authorization headers, or raw secret-store values.

Fail-closed behavior:

- before a consequential delegated operation, append/sync an attempt record;
- if that write fails, deny the operation;
- append the completion/result record after execution;
- if completion logging fails after the target already executed, surface the audit failure and stop accepting further delegated operations until audit health is restored.

## 3.4 Compatibility-command policy

For `sigil exec -- gh ...`, begin with coarse policy categories only where classification is reliable.

Reviewer role must explicitly blacklist these high-risk top-level `gh` command families in compatibility mode:

```text
gh auth
gh secret
gh api
gh workflow
gh run
gh cache
gh extension
```

Rationale:

- `auth` can mutate or expose authentication state;
- `secret` manages repository/environment/organization secrets;
- `api` bypasses typed intent classification;
- `workflow` / `run` can trigger or manipulate automation with broader effects;
- `cache` mutates Actions cache state;
- `extension` introduces arbitrary external command execution.

The blacklist is defense in depth, not a substitute for native typed operations. Unknown/unclassifiable high-risk compatibility commands should fail closed for restricted roles.

## 3.5 M3 acceptance criteria

- default-deny policy engine exists;
- roles have explicit capabilities;
- repository scope enforced by Sigil independently of GitHub;
- explicit deny works;
- structured audit record emitted for every broker operation;
- audit file ownership/mode/path is enforced;
- delegated writes fail closed when audit is unavailable;
- secrets never appear in audit output;
- reviewer compatibility path denies `auth`, `secret`, `api`, `workflow`, `run`, `cache`, and `extension`;
- reviewer cannot use Sigil policy path to perform repository-write or merge capability;
- tester cannot gain implementer capability;
- automated tests cover allow, deny, scope violation, expiry, blacklist behavior, audit failure, and audit redaction.

---

# M4 — Native provider operations

## Goal

Reduce dependence on arbitrary `gh` command interpretation by introducing typed operations that Sigil can authorize precisely.

## 4.1 Operation model

Introduce the `Operation` abstraction here, not in M1:

```go
type Operation struct {
    Provider   string
    Capability string
    Resource   Resource
    Parameters any
}
```

Provider preparation may now evolve from `CredentialRequest{Identity, Repository}` to an operation-aware contract where needed. Preserve compatibility adapters during the transition.

Initial native GitHub operations should focus on existing role workflows:

### Reviewer

- read PR metadata;
- read PR diff;
- add PR conversation comment;
- add inline review comment;
- submit COMMENT review;
- submit REQUEST_CHANGES review;
- submit APPROVE review;
- read checks/statuses.

### Implementer

- read repository/PR state;
- create/update branch content or authenticated Git push path;
- create/update PR;
- respond to review comments.

### Tester

- read PR/head SHA;
- create Check Run;
- update Check Run;
- publish annotations/results;
- read Actions/check state.

## 4.2 Native CLI/API

Possible CLI shape:

```bash
sigil pr view 42
sigil pr comment 42 --body-file comment.md
sigil pr review 42 --request-changes --body-file review.md
sigil checks publish ...
```

The exact UX can evolve. The architectural requirement is typed broker operations with explicit capability mapping.

## 4.3 Compatibility mode remains

Do not remove compatibility `gh`/`git` execution immediately.

Mark it as:

```text
compatibility path
```

and prefer native operations for actions that require strong policy guarantees.

## 4.4 M4 acceptance criteria

- typed operation request model exists;
- reviewer core workflow can be performed without arbitrary `gh` execution;
- tester can publish a real GitHub Check through native provider code;
- each operation maps to one or more explicit Sigil capabilities;
- policy decisions do not depend on parsing shell text for native operations;
- compatibility mode remains functional.

---

# M5 — GitLab and Forgejo providers

## Goal

Prove that Sigil is a provider-neutral delegated identity broker rather than a GitHub-specific wrapper.

## 5.1 Provider contracts

Stabilize provider interfaces based on the GitHub implementation before adding new backends.

Avoid forcing GitHub concepts such as installation IDs into the provider-neutral API.

## 5.2 GitLab provider

Support an appropriate GitLab bot/project/application identity mechanism.

Map Sigil capabilities to GitLab operations.

## 5.3 Forgejo provider

Support Forgejo API/token identity mechanism.

Map the same role concepts where practical.

## 5.4 Role/provider bindings

One role may map to multiple provider identities:

```text
reviewer
  github  -> dsxreviewer
  gitlab  -> dsx-reviewer
  forgejo -> reviewer-bot
```

## 5.5 M5 acceptance criteria

- provider-neutral broker code does not import GitHub-specific authentication concepts;
- at least one representative read and write/review operation works on GitLab;
- at least one representative read and write/review operation works on Forgejo;
- role/session/policy logic is reused unchanged across providers;
- audit records identify provider and provider identity consistently.

---

# M6 — Remote broker and MCP integration

## Goal

Allow authorized remote clients to use Sigil without moving long-lived provider credentials onto those clients.

Potential users:

- hosted Council/Pi agents;
- remote developer machines;
- ChatGPT custom app/MCP integration when product support permits;
- automation services.

## 6.1 Remote transport

Reuse broker semantics over HTTPS rather than inventing a second authorization model.

```text
local:
sigil -> Unix socket -> sigild

remote:
sigil -> HTTPS -> Sigil broker
```

Add strong client authentication before exposing any remote write path.

Candidates may include:

- mutual TLS;
- OAuth/OIDC-based client identity;
- signed short-lived client credentials.

Do not expose a remotely reachable broker with only an opaque session ID as authentication.

## 6.2 MCP adapter

MCP should be an adapter over typed native operations, not a direct shell-execution interface.

Example tools:

```text
get_pull_request
get_pull_diff
submit_review
reply_to_review_comment
publish_check
```

The adapter should call the same broker policy engine used by local clients.

## 6.3 Approval model

For interactive clients such as ChatGPT, preserve explicit approval opportunities for consequential writes where appropriate.

Sigil itself should still enforce policy regardless of client UI confirmation.

## 6.4 M6 acceptance criteria

- broker can run over authenticated HTTPS;
- local and remote transports use the same broker/service layer;
- MCP adapter exposes typed operations only;
- remote client never receives provider long-lived secret;
- remote client does not need provider App private key;
- audit records distinguish local and remote callers;
- authentication, authorization, replay resistance, and revocation are documented and tested.

---

# Cross-cutting engineering rules

## Preserve tests during extraction

Each refactor should move behavior with tests rather than recreate it later.

Existing runner security tests are especially important and should remain regression gates throughout M1-M4.

## Fail closed

Authentication, launcher authority, session, provider, policy, scope, audit availability, path validation, and transport ambiguity should fail closed.

Do not silently fall back to:

- the user's personal GitHub CLI credentials;
- SSH agent credentials;
- a broader installation token;
- a default stronger role;
- an unvalidated working directory;
- an unaudited delegated operation.

## Keep provider credentials out of logs and IPC

Never serialize or log:

- GitHub App private keys;
- App JWTs;
- installation tokens;
- authorization headers;
- future provider equivalents.

## Maintain least privilege at two layers

1. Provider identity permissions should be minimal.
2. Sigil capabilities should be narrower or equal to provider permissions.

## Separate same-user convenience from hard isolation

Tests and documentation must use precise language:

- same-UID workstation mode prevents accidental credential fallback and API misuse;
- it does not make a secret file unreadable to another process with that UID;
- hard isolation requires an OS/container/VM boundary and restricted admin-socket reachability.

## Avoid premature remote complexity

M1-M4 should optimize for a correct local trust model.

Remote and MCP support comes only after:

- broker ownership of config/cache/secrets;
- daemon lifecycle hygiene;
- launcher/admin authority separation;
- immutable role sessions;
- repository/workspace scoping;
- capability policy;
- fail-closed auditability;
- typed provider operations.

---

# Immediate next work

The next implementation target is **M1**.

Recommended sequence:

1. add runtime-path helper with XDG/macOS fallback and `umask 0077`;
2. add single-instance `flock` and safe stale-socket cleanup;
3. create `cmd/sigild` with `sigil.sock` + `sigil-admin.sock` lifecycle;
4. implement chunked NDJSON transport with streamed stdin/stdout/stderr, limits, and explicit error semantics using a fake broker;
5. extract current orchestration from `internal/sigil/cli.go` into `internal/broker`, moving config/cache ownership into the daemon;
6. move GitHub authentication into `internal/provider/github` using `CredentialRequest{Identity, Repository}`;
7. move private-key loading behind `internal/secret` and remove `ReviewerClientID` fallback;
8. move runner behind `internal/runner`, adding temporary `HOME`/`GH_CONFIG_DIR`, token env scrubbing, validated `working_dir`, process groups/timeouts, and mandatory `core.hooksPath=/dev/null`;
9. convert `sigil exec <role>` into an admin-socket streaming client with no config/cache/key access;
10. add integration tests proving credentials, personal `gh` state, repository hooks, and process descendants cannot escape the broker controls being claimed;
11. add/verify reviewer, implementer, and tester example configs;
12. run a live `dsxreviewer` smoke test against `dsxragnarok/council`;
13. update README and freeze M1 before starting the M2 session engine.

M1 should remain deliberately narrow: **establish the daemon trust boundary and execution hygiene first. M2 then binds agents to immutable role authority.**
