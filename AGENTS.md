# Sigil

Sigil is a delegated identity and authorization broker for autonomous agents.

Its job is to let an agent act through a narrowly scoped external identity without giving that agent the long-lived credential that owns the identity. The first provider is GitHub, using separate GitHub Apps for roles such as `reviewer`, `implementer`, and `tester`.

The long-term model is broader than GitHub: Sigil should bind an agent session to a role, resolve that role to provider-specific identities, enforce policy, obtain short-lived credentials, perform authenticated operations, and record what happened.

The core security rule is:

> An agent may use an identity assigned to its session, but it may not select or escalate to a stronger identity itself.

## Agent skills

### Issue tracker

Issues live in GitHub Issues for `dsxragnarok/Sigil`. See `documentation/agents/issue-tracker.md`.

### Triage labels

Default five canonical roles (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `documentation/agents/triage-labels.md`.

### Domain docs

Single-context (`CONTEXT.md` + `documentation/adr/` at repo root). See `documentation/agents/domain.md`.

### Branches and Worktrees Conventions

- worktrees live in `scratch/worktree/<branch-name>`
- branch naming scheme: `<issue-name>-<short-desc>`
