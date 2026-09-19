# Sigil

Delegated identity and authorization broker that lets autonomous agents act through narrowly scoped external identities without holding the long-lived credentials behind them.

## Language

### Identity and authority

**Role**:
An authorization concept naming what an agent may do, such as reviewer, implementer, or tester.
_Avoid_: identity, provider identity, GitHub App

**Provider**:
An external system where delegated authority is exercised, starting with GitHub.
_Avoid_: backend, integration

**Provider Identity**:
A provider-side account a role acts through, such as a reviewer bot.
_Avoid_: role, personal account, human user

**Provider Binding**:
The mapping from a role to its identity on a specific provider.
_Avoid_: role config, credential

**Session**:
A broker-created grant binding one agent to one role with fixed scope and expiry.
_Avoid_: token, login, API key

**Capability**:
A fine-grained Sigil-native permission evaluated against session role, provider, and resource.
_Avoid_: provider permission, scope

**Repository Scope**:
The set of repositories a session may touch, enforced independently of provider token scope.
_Avoid_: token repositories, installation repositories

**Launcher**:
The trusted party allowed to assign a role to a new session, such as a human shell or orchestrator.
_Avoid_: agent

**Agent**:
The untrusted process that may only act through the authority of its assigned session.
_Avoid_: launcher, bot

**Broker**:
The trusted daemon owning secrets, sessions, policy, credential minting, execution, and audit.
_Avoid_: CLI, helper, server

### Credentials

**Long-Lived Credential**:
Provider-owned secret material held only by the broker, such as a GitHub App private key.
_Avoid_: token, session

**Short-Lived Credential**:
A narrowly scoped temporary credential the broker mints for one delegated action.
_Avoid_: password, API key, session ID

**Secret Store**:
The abstraction through which the broker loads long-lived credential material.
_Avoid_: config file, keychain

### Execution and audit

**Compatibility Mode**:
Broker execution of familiar provider CLI or Git commands under coarse authorization.
_Avoid_: native operation, shell passthrough

**Native Operation**:
A typed broker action mapped to explicit capabilities, such as submitting a review.
_Avoid_: CLI command, raw API call

**Delegated Operation**:
Any provider action the broker performs under session authority.
_Avoid_: local command, direct access

**Audit Event**:
An immutable record of which session used which authority against which resource and with what result.
_Avoid_: log line, trace

### Deployment

**Workspace Root**:
An approved local directory tree a session is allowed to execute in.
_Avoid_: working directory, cwd

**Same-User Mode**:
A workstation deployment where broker, launcher, and agent share one OS user; accidental-misuse defense only.
_Avoid_: sandbox, isolation

**Hard Isolation**:
A deployment with an OS or container boundary keeping broker secrets and launcher authority unreachable from the agent.
_Avoid_: file permissions, owner-only mode
