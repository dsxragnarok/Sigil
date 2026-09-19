# Sigil

Sigil is a delegated identity and authorization broker for autonomous agents.

Its job is to let an agent act through a narrowly scoped external identity without giving that agent the long-lived credential that owns the identity. The first provider is GitHub, using separate GitHub Apps for roles such as `reviewer`, `implementer`, and `tester`.

The core security rule is:

> An agent may use an identity assigned to its session, but it may not select or escalate to a stronger identity itself.

## Architecture (M1)

Long-lived credentials, role configuration, cache state, token minting, and
command execution live in the trusted broker daemon `sigild`. The `sigil`
CLI is a dumb streaming client that talks to the broker over Unix sockets and
never sees tokens, keys, or cache state.

```text
trusted/admin caller
  -> sigil CLI
  -> sigil-admin.sock
  -> sigild
  -> load role config/private key
  -> mint GitHub credential
  -> run gh/git (hardened, isolated)
  -> chunked stdout/stderr/exit stream
```

Explicit role selection (`sigil exec reviewer -- ...`) is a
**trusted/admin compatibility path**, not an agent isolation boundary.
Untrusted agents use role-bound sessions beginning in M2. Never export
`SIGIL_ADMIN_SOCKET` into agent environments.

## Build and install

Requirements: Go 1.23 or newer, `gh`, and `git`.

```bash
go test ./...
go build -o sigil ./cmd/sigil
go build -o sigild ./cmd/sigild
install -m 755 sigil sigild ~/.local/bin/
```

## Start the broker

```bash
sigild --workspace-root ~/Workspace &
```

Options:

```text
--config-dir      broker-owned role configs (default ~/.config/sigil)
--cache-dir       broker-owned cache (default ~/.cache/sigil)
--runtime-dir     socket/lock dir override (default $XDG_RUNTIME_DIR/sigil,
                  fallback ~/.local/state/sigil)
--workspace-root  approved working root, repeatable
                  (also SIGIL_WORKSPACE_ROOTS; default $HOME)
```

Only one daemon owns the runtime at a time: a second start fails with
`sigild already running`. Stale sockets are reclaimed only after the instance
lock is held; a live socket is never replaced. Sockets are removed on
graceful shutdown.

## Configure roles

Create `~/.config/sigil/reviewer.json` (see `reviewer.example.json`,
`implementer.example.json`, `tester.example.json`):

```json
{
  "client_id": "Iv23liYTtTwOvyDhpyK0",
  "private_key_path": "~/.config/sigil/dsxreviewer.private-key.pem",
  "default_repository": "dsxragnarok/council"
}
```

Every role binding must declare its `client_id` and `private_key_path`
explicitly. There are no role-specific defaults. Lock down both files:

```bash
chmod 600 ~/.config/sigil/reviewer.json
chmod 600 ~/.config/sigil/dsxreviewer.private-key.pem
```

The broker accepts PKCS#1 and PKCS#8 RSA PEM keys. It rejects a private key
readable by group or other users. Only `sigild` reads these files;
`SIGIL_CONFIG_DIR` and `SIGIL_CACHE_DIR` have no effect on the CLI.

## Use it (trusted/admin)

With the daemon running:

```bash
sigil exec reviewer -- gh pr view 1
sigil exec reviewer --repo dsxragnarok/council -- gh pr view 1
sigil exec reviewer -- gh pr view 1 -R dsxragnarok/council
```

For GitHub HTTPS operations, `git` runs with a broker-internal credential
path. It does not change global Git config.

```bash
sigil exec reviewer -- git ls-remote https://github.com/dsxragnarok/council.git
```

`git` execution requires the current directory to fall under a
broker-approved workspace root; paths are symlink-canonicalized and rejected
otherwise. The CLI exits with the target command's exit code. If the daemon
is down you get:

```text
sigil: broker unavailable: start sigild or configure SIGIL_ADMIN_SOCKET
```

On the first run for a repository, `sigild` asks GitHub for the App
installation ID and caches only that numeric ID in the broker-owned cache.
Set `installation_id` in the role config or pass `--installation-id` to skip
discovery.

If no repository can be resolved — from `--repo`, a `gh -R/--repo` flag, or
`default_repository` — the broker refuses the request instead of minting a
broad token. Always supply a repository so installation tokens stay
repository-scoped.

## Add another role later

Create `~/.config/sigil/implementer.json` or `tester.json` with that App's
`client_id`, `private_key_path`, and optional `default_repository` or
`installation_id`, then restart `sigild` so it loads the new binding. The
command shape stays the same:

```bash
sigil exec implementer -- gh pr create ...
```

## Security notes

- The private key stays in the broker process. Only the broker-spawned `gh`
  or `git` process receives the short-lived token, via environment.
- The broker does not return the GitHub token in IPC frames, logs, or error
  strings. `gh auth` disclosure commands (`gh auth token`, `gh auth status
  --show-token`, etc.) are rejected before minting or execution. Child stdout
  and stderr are scrubbed of the raw bearer as defense in depth against
  accidental echo. Per-stream scrubbing is not a secrecy boundary against
  adversarial code that can fragment or transform the bearer across streams;
  adversarial child-output secrecy is explicitly out of scope for M1.
- In legitimate use, the caller never receives the GitHub token directly from the broker.
- Binary resolution ignores caller `PATH` and searches only trusted system
  directories (`/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin`, `/bin`).
  The child process runs with this sanitized `PATH`.
- Every execution gets a fresh broker-owned `HOME` and an empty
  `GH_CONFIG_DIR`, so a failed App authentication can never fall back to a
  human `gh` OAuth identity. `GH_HOST`, `GH_TOKEN`, `GITHUB_TOKEN`,
  `GH_ENTERPRISE_TOKEN`, `GITHUB_*_TOKEN`, and `SSH_AUTH_SOCK` from the caller
  are scrubbed before the broker credential is injected.
- Every broker-spawned `git` runs with `-c core.hooksPath=/dev/null` ahead of
  caller arguments: repository-controlled hooks never execute inside the
  broker tree. This is not complete repository-code isolation: repository-local
  Git config (`.git/config`, attributes) is still read, and repo-local aliases
  or helpers prefixed with `!` execute shell commands (for example a repo-local
  `.git/config` with `[alias] sigil-leak = "!evil"` then `git sigil-leak`,
  `core.pager`, `core.fsmonitor`, `filter.*`, `diff.*.command`,
  `merge.*.driver`). Caller `-c alias.*` overrides are already rejected by
  argument validation; the residual vector is repo-local config. Child
  stdout/stderr is scrubbed of the broker bearer so direct recovery via output
  frames is blocked, but repo-local execution inherits `GH_TOKEN` in its
  environment and could exfiltrate via network or cross-stream fragmentation.
  Treat untrusted checkouts as residual risk until M2 constrains these vectors.
  M2 must not inherit the M1 compatibility path unchanged if token secrecy is
  still a security goal. Inspect repo-local `.git/config` and `.gitattributes`
  before running against untrusted workdirs, or run from outside the untrusted
  tree.
- Dangerous `git` arguments are blocked, including `--upload-pack`,
  `--receive-pack`, `--exec`, `--exec-path`, `--template`, `--git-dir`,
  `--work-tree`, `--config-env`, `--config`, and `-C` (except for
  `git commit -C <commit>` message reuse). Flag `-u` is blocked before
  subcommands and for `git clone`. Configuration overrides via `-c` are
  restricted to an allowlist of safe families (`user.*`, `pull.*`, `push.*`,
  `branch.*`, `commit.*`, `tag.*`, `log.*`, `format.*`, `status.*`, `init.*`,
  `advice.*`, `color.*`, and safe `core.*` line-ending configs).
- Git and SSH configurations are pinned with `GIT_CONFIG_NOSYSTEM=1`,
  `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`, and
  `GIT_SSH_COMMAND=ssh -F /dev/null`. Pagers and editors are pinned with
  `GIT_PAGER=cat`, `PAGER=cat`, `GIT_EDITOR=true`, and
  `GIT_SEQUENCE_EDITOR=true`, and git runs with `--no-pager`.
- Executions run in their own process group with a 120-second default
  timeout: on timeout the whole tree gets `SIGTERM`, then `SIGKILL` after a
  5-second grace period.
- Target exit terminates request-input consumption: `stdin_eof` is not required
  once the child has exited. Stdin frames are consumed and validated on demand
  while the target runs. Framing errors observed while feeding the target fail
  closed (HTTP 400), while unconsumed input following target exit is discarded.
- Same-user workstation mode prevents accidental credential fallback and API
  misuse. It does **not** make broker files unreadable to another process
  with the same UID. Enforced key secrecy requires a hard-isolation
  deployment (separate broker user/container plus restricted admin-socket
  reachability).

## Manual live smoke test (optional, needs real credentials)

```bash
sigil exec reviewer -- gh pr view 1 -R dsxragnarok/council
```

Then perform a harmless PR operation and verify attribution remains
`dsxreviewer[bot]`. Automated suites never depend on live credentials.
