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

M0 remains the compatibility reference for all later milestones.

---

# M1 — Trusted `sigild` broker and Unix socket

## Goal

Move long-lived credentials and GitHub token minting out of the agent-facing CLI into a trusted broker process.

After M1:

```text
agent
  -> sigil CLI
  -> Unix socket
  -> sigild
  -> load private key
  -> mint GitHub credential
  -> run gh/git
  -> return stdout/stderr/exit status
```

The caller never receives the GitHub token.

M1 may retain explicit role selection for compatibility. Trusted role-bound sessions are M2.

## 1.1 Add `cmd/sigild`

Create:

```text
cmd/sigild/main.go
```

Responsibilities:

- start the local broker;
- create/listen on a Unix-domain socket;
- ensure safe socket permissions;
- initialize config, provider, runner, and broker dependencies;
- handle clean shutdown;
- surface startup errors clearly.

Default socket target:

```text
$XDG_RUNTIME_DIR/sigil/sigil.sock
```

with a safe fallback when `XDG_RUNTIME_DIR` is unavailable, for example an owner-only directory under the user's home or platform-appropriate runtime location.

The socket directory and socket must not be writable by other users.

## 1.2 Add local transport package

Target package:

```text
internal/transport/unix/
```

Use HTTP+JSON over a Unix socket.

Initial endpoint:

```text
POST /v1/exec
```

Initial request shape:

```json
{
  "role": "reviewer",
  "repository": "dsxragnarok/council",
  "installation_id": 0,
  "command": ["gh", "pr", "view", "1"]
}
```

Initial response model should support:

- process exit code;
- broker-level error;
- stdout/stderr streaming or bounded capture.

Prefer streaming if implementation complexity remains reasonable. If M1 uses buffered output first, enforce explicit output limits and document them.

Do not include provider credentials in transport messages.

## 1.3 Extract broker orchestration

Create:

```text
internal/broker/
```

Move the orchestration currently performed by the CLI into a broker service.

Conceptual API:

```go
type ExecRequest struct {
    Role           string
    Repository     string
    InstallationID int64
    Command        []string
}

type Broker interface {
    Exec(ctx context.Context, req ExecRequest, io IO) error
}
```

Broker flow:

1. validate request;
2. load role/provider binding;
3. resolve repository scope;
4. obtain provider credential;
5. invoke hardened runner;
6. return process result;
7. zero/drop credential references as soon as practical.

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

Introduce a provider abstraction only as far as M1 needs it. Avoid speculative complexity.

Suggested high-level interface:

```go
type CredentialRequest struct {
    Identity   string
    Repository string
}

type Credential struct {
    Token     string
    ExpiresAt time.Time
}
```

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

Migrate private-key loading behind this interface while preserving the current permission checks.

M1 does not need macOS Keychain support yet.

## 1.6 Preserve runner hardening

Move or retain existing `runner.go` behavior behind:

```text
internal/runner/
```

Do not weaken existing controls.

Regression requirements:

- only `gh` and `git` accepted in compatibility mode;
- caller `PATH` not trusted;
- trusted directories checked for unsafe permissions;
- dangerous Git flags rejected;
- unsafe Git configuration overrides rejected;
- global/system Git config suppressed;
- SSH config pinned;
- pagers/editors neutralized;
- process-local credential helper preserved;
- no credential in argv;
- no credential written to disk;
- repository-scoped installation token retained where possible.

The key M1 difference is that the runner executes inside `sigild`, not inside the agent-facing CLI.

## 1.7 Convert `sigil exec` into a client

Current:

```bash
sigil exec reviewer -- gh ...
```

M1 behavior should remain user-compatible where practical, but the CLI sends the request to `sigild` rather than loading keys or minting credentials itself.

`sigil` should no longer require read access to GitHub App private keys.

Provide a clear error if the broker is unavailable:

```text
sigil: broker unavailable: start sigild or configure SIGIL_SOCKET
```

## 1.8 Broker startup strategy

M1 may support either:

- explicitly running `sigild`; or
- optional `sigil daemon start` / `sigil daemon stop` commands.

Do not auto-spawn a privileged broker invisibly in the first implementation unless lifecycle behavior is well defined.

## 1.9 M1 testing

Add tests for:

### Unit tests

- Unix socket path validation;
- socket permission validation;
- transport request validation;
- broker request validation;
- provider credential acquisition;
- secret store path/permission rules;
- runner regression suite;
- errors never include token/private-key content.

### Integration tests

Use a fake provider and fake runner to verify:

```text
sigil CLI -> Unix socket -> sigild -> provider -> runner
```

Verify that:

- client process never receives provider token;
- token does not appear in request/response body;
- role config is resolved only by broker;
- stdout/stderr/exit status propagate correctly;
- broker rejects malformed command requests;
- socket rejects access from inappropriate filesystem permissions where testable.

### Live GitHub smoke test

Optional/manual test using `dsxreviewer`:

```bash
sigil exec reviewer -- gh pr view 1 -R dsxragnarok/council
```

Then post or read a harmless PR operation and verify attribution remains `dsxreviewer[bot]`.

## 1.10 M1 acceptance criteria

M1 is complete when all of the following are true:

- `sigild` exists and listens on an owner-only Unix socket;
- `sigil exec` talks to `sigild` instead of loading keys itself;
- only `sigild` needs read access to GitHub App private keys;
- GitHub installation tokens are minted only inside `sigild`;
- tokens are not returned to `sigil` or written to disk;
- existing `gh` and `git` functionality still works;
- existing runner hardening remains covered by tests;
- current reviewer/implementer/tester role configuration remains usable;
- all automated tests pass;
- README/documentation is updated for broker startup and usage.

---

# M2 — Role-bound sessions and `sigil run`

## Goal

Remove role selection from the untrusted agent.

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
SIGIL_SOCKET=<socket-path>
```

Agent command:

```bash
sigil exec -- gh pr view 42
```

There is no agent-controlled role flag.

## 2.1 Session manager

Create:

```text
internal/session/
```

Session fields:

- cryptographically random opaque ID;
- role;
- creation time;
- expiration time;
- repository scope;
- provider scope;
- revocation status.

Session rules:

- role cannot be changed after creation;
- repository scope cannot be widened;
- expired sessions fail closed;
- revoked sessions fail closed;
- unknown sessions fail closed.

## 2.2 Add session endpoints

Likely endpoints:

```text
POST /v1/sessions
GET  /v1/sessions/{id}
DELETE /v1/sessions/{id}
POST /v1/exec
```

`POST /v1/exec` accepts session ID rather than role.

## 2.3 Implement `sigil run`

`sigil run` should:

1. request a session from the broker;
2. construct a sanitized child environment;
3. set `SIGIL_SESSION` and `SIGIL_SOCKET`;
4. remove personal GitHub token variables;
5. isolate GitHub CLI configuration where practical;
6. optionally remove `SSH_AUTH_SOCK`;
7. launch the requested agent command;
8. revoke/end the session when the process exits unless configured otherwise.

## 2.4 Compatibility migration

Human/trusted use may temporarily retain:

```bash
sigil exec reviewer -- ...
```

but agent-facing documentation and orchestrator integration should use role-bound sessions.

Eventually explicit-role `exec` can become an administrative/trusted-only compatibility command or be removed.

## 2.5 M2 acceptance criteria

- Council/Pi/human can launch a role-bound agent session;
- agent can call `sigil exec -- ...` with no role argument;
- agent cannot request another role through the session API;
- repository-bound session cannot operate against another repository;
- expired/revoked session is denied;
- role private keys remain broker-only;
- environment strips personal GitHub token variables;
- tests prove role and scope are immutable from the agent side.

---

# M3 — Capability policy, repository scoping, and audit

## Goal

Add Sigil-native authorization on top of provider-native permissions.

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

Migration should support existing JSON configs until the new format is stable.

## 3.3 Structured audit

Create:

```text
internal/audit/
```

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

Never record tokens, JWTs, private keys, or authorization headers.

## 3.4 Compatibility-command policy

For `sigil exec -- gh ...`, begin with coarse policy categories where reliable classification is possible.

Do not pretend arbitrary `gh api` is strongly typed authorization.

Unknown/unclassifiable high-risk commands should either:

- be denied for restricted roles; or
- remain explicitly documented as compatibility-mode residual risk.

## 3.5 M3 acceptance criteria

- default-deny policy engine exists;
- roles have explicit capabilities;
- repository scope enforced by Sigil independently of GitHub;
- explicit deny works;
- structured audit record emitted for every broker operation;
- secrets never appear in audit output;
- reviewer cannot use Sigil policy path to perform repository-write or merge capability;
- tester cannot gain implementer capability;
- automated tests cover allow, deny, scope violation, expiry, and audit redaction.

---

# M4 — Native provider operations

## Goal

Reduce dependence on arbitrary `gh` command interpretation by introducing typed operations that Sigil can authorize precisely.

## 4.1 Operation model

Introduce:

```go
type Operation struct {
    Provider   string
    Capability string
    Resource   Resource
    Parameters any
}
```

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

Authentication, session, provider, policy, and scope ambiguity should fail closed.

Do not silently fall back to:

- the user's personal GitHub CLI credentials;
- SSH agent credentials;
- a broader installation token;
- a default stronger role.

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

## Avoid premature remote complexity

M1-M4 should optimize for a correct local trust model.

Remote and MCP support comes only after:

- broker ownership of secrets;
- immutable role sessions;
- repository scoping;
- capability policy;
- auditability;
- typed provider operations.

---

# Immediate next work

The next implementation target is **M1**.

Recommended first sequence:

1. create `cmd/sigild`;
2. create Unix socket transport with a fake broker;
3. extract current orchestration from `internal/sigil/cli.go` into `internal/broker`;
4. move GitHub authentication into `internal/provider/github` without changing behavior;
5. move runner behind `internal/runner` while retaining all existing tests;
6. move private-key loading behind `internal/secret`;
7. convert `sigil exec` into a Unix-socket client;
8. add integration tests proving credentials stay broker-side;
9. run a live `dsxreviewer` smoke test against `dsxragnarok/council`;
10. update README and freeze M1 behavior before starting sessions.

M1 should be kept deliberately narrow: **separate the trust boundary first; add role-bound authority in M2.**
