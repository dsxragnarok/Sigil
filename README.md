# agent-gh

`agent-gh` mints a short-lived token for a GitHub App role, puts it in the child process as `GH_TOKEN`, and runs `gh` or `git`. It does not print or persist the token. App JWTs expire after nine minutes. GitHub installation tokens expire after one hour.

The first role is `reviewer`, backed by the `dsxreviewer` GitHub App. Each future role gets its own JSON config and private key.

## Build and install

Requirements: Go 1.23 or newer, `gh`, and `git`.

```bash
go test ./...
go build -o agent-gh ./cmd/agent-gh
install -m 755 agent-gh ~/.local/bin/agent-gh
```

## Configure reviewer

Create `~/.config/agent-gh/reviewer.json`:

```json
{
  "client_id": "Iv23liYTtTwOvyDhpyK0",
  "private_key_path": "~/.config/agent-gh/dsxreviewer.private-key.pem",
  "default_repository": "dsxragnarok/council"
}
```

Copy the GitHub App private key to the named path, then lock down both files:

```bash
chmod 600 ~/.config/agent-gh/reviewer.json
chmod 600 ~/.config/agent-gh/dsxreviewer.private-key.pem
```

The helper accepts PKCS#1 and PKCS#8 RSA PEM keys. It rejects a private key readable by group or other users.

## Use it

The configured default repository makes this enough:

```bash
agent-gh exec reviewer -- gh pr view 1
```

You can select a repository on either side of `--`:

```bash
agent-gh exec reviewer --repo dsxragnarok/council -- gh pr view 1
agent-gh exec reviewer -- gh pr view 1 -R dsxragnarok/council
```

For GitHub HTTPS operations, `git` runs with a process-local credential helper that delegates to `gh`. It does not change global Git config.

```bash
agent-gh exec reviewer -- git ls-remote https://github.com/dsxragnarok/council.git
```

On the first run for a repository, `agent-gh` asks GitHub for the App installation ID and caches only that numeric ID in `~/.cache/agent-gh/installations.json`. Set `installation_id` in the role config or pass `--installation-id` to skip discovery.

`AGENT_GH_CONFIG_DIR` and `AGENT_GH_CACHE_DIR` override the default directories. This is useful for isolated automation.

## Add another role later

Create `~/.config/agent-gh/implementer.json` or `tester.json` with that App's `client_id`, `private_key_path`, and optional `default_repository` or `installation_id`. The command shape stays the same:

```bash
agent-gh exec implementer -- gh pr create ...
```

## Security notes

- The private key stays in the parent helper process.
- Only the spawned `gh` or `git` process receives `GH_TOKEN`.
- Tokens never enter command-line arguments, cache files, or helper output.
- Binary resolution ignores caller `PATH` and searches only trusted system directories (`/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin`, `/bin`). The child process runs with this sanitized `PATH`.
- Dangerous `git` arguments are blocked, including `--upload-pack`, `--receive-pack`, `--exec`, `--exec-path`, `--template`, `--git-dir`, `--work-tree`, `--config-env`, `--config`, and `-C` (except for `git commit -C <commit>` message reuse). Flag `-u` is blocked before subcommands and for `git clone`. Configuration overrides via `-c` are restricted to an allowlist of safe families (`user.*`, `pull.*`, `push.*`, `branch.*`, `commit.*`, `tag.*`, `log.*`, `format.*`, `status.*`, `init.*`, `advice.*`, `color.*`, and safe `core.*` line-ending configs).
- Git and SSH configurations are pinned with `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`, and `GIT_SSH_COMMAND=ssh -F /dev/null`. Pagers and editors are pinned with `GIT_PAGER=cat`, `PAGER=cat`, `GIT_EDITOR=true`, and `GIT_SEQUENCE_EDITOR=true`, and git runs with `--no-pager`. `HOME` remains available for `gh` state.
- Residual risk: Running `agent-gh` inside an untrusted repository working directory still honors repo-local `.git/config` and `.gitattributes` hooks (such as external diff drivers `diff.external`, filter drivers `filter.*.smudge`, or merge drivers `merge.*.driver`). For maximum safety against untrusted local repositories, invoke `agent-gh` outside untrusted working directories or inspect the repository's `.git/config` and `.gitattributes` beforehand.
- `AGENT_GH_CONFIG_DIR` and `AGENT_GH_CACHE_DIR` belong to the trusted invoker environment. `agent-gh` prints a warning to stderr when either variable is active.
- If an installation token is minted without a target repository, `agent-gh` prints a warning to stderr because GitHub grants access across all installation repositories.
- The requested child command controls its own output. Do not run commands such as `gh auth token` that intentionally print credentials.

