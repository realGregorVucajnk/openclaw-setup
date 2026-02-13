# CLAUDE.md

**Document version:** 1.1 · **Last updated:** 2026-02-14

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

This is an **ops/deployment documentation repo** for an OpenClaw AI agent gateway running on a dedicated Ubuntu 25.10 server. There is no application source code here — only deployment guides and configuration references.

**OpenClaw** connects a messaging channel to an LLM provider and runs agent tasks inside Docker sandbox containers. It runs as a systemd service under a locked `openclaw-svc` system user.

## Repo Structure

| File | Purpose |
|---|---|
| `README.md` | Entry point — security preamble, prerequisites, glossary |
| `HLA.md` | High-level architecture: network topology, security layers, data flow, systemd hardening |
| `SECURITY.md` | Verification checklists, supply chain trust, backup/recovery, incident response |
| `openclaw-deployment-guide.md` | Full step-by-step deployment guide (Phases 1–10), maintenance, emergency procedures |
| `CLAUDE.md` | This file — quick reference for operations and gotchas |

For version stamps and the full server file map, see `HLA.md` (§ Version Stamps, Appendix A).

## Running Commands as the openclaw-svc User

The `openclaw-svc` user is a locked system account (no password, no direct login). All CLI commands require this pattern:

```bash
sudo -u openclaw-svc bash -c '
  cd ~
  export PATH=$HOME/.npm-global/bin:$PATH
  <COMMAND>
'
```

## Common Operations

```bash
# Service management
sudo systemctl start|stop|restart|status openclaw.service

# Live logs
sudo journalctl -u openclaw.service -f

# Error logs from last hour
sudo journalctl -u openclaw.service -p err --since "1h ago"

# Security audit
sudo -u openclaw-svc bash -c 'cd ~ && export PATH=$HOME/.npm-global/bin:$PATH && openclaw security audit --deep'

# systemd hardening score (target: 5.8 MEDIUM)
sudo systemd-analyze security openclaw.service

# Verify gateway binds to loopback only
sudo ss -tlnp | grep 18789

# Verify SOUL.md integrity
sudo sha256sum -c /var/lib/openclaw-soul-baseline.sha256

# Session verification (run before any firewall changes)
who -m                    # Verify connection is from Tailscale IP (100.x.y.z)
ss -tnp | grep ssh        # Should return empty if using Tailscale SSH
```

## Critical Gotchas

These were discovered during deployment and will silently break the service if violated:

- **`gateway run` not `start --foreground`**: The ExecStart command must be `openclaw gateway run`. The subcommand `gateway start --foreground` does not exist — `gateway start` daemonizes and returns immediately, making systemd think the service crashed.
- **No WatchdogSec**: OpenClaw does not implement `sd_notify(WATCHDOG=1)`. Adding `WatchdogSec` kills healthy processes.
- **No ProtectHome=tmpfs**: Using `ProtectHome=tmpfs` with `BindPaths=/home/openclaw-svc` causes immediate exit. Use `ReadWritePaths=/home/openclaw-svc` instead.
- **No MemoryDenyWriteExecute**: V8 JIT requires W+X memory pages. This directive kills Node.js instantly.
- **No SystemCallFilter**: Node.js needs syscalls outside `@system-service`. Only `SystemCallArchitectures=native` is safe.
- **No empty CapabilityBoundingSet**: Too restrictive for Docker socket communication. Omit entirely.
- **No RestrictNamespaces**: Blocks Docker container creation.
- **Gateway token alignment**: `gateway.auth.token` and `gateway.remote.token` must be identical. Mismatched values cause "unauthorized: gateway token mismatch" on all CLI commands.
- **StartLimitIntervalSec placement**: Goes in `[Unit]`, NOT `[Service]`. Wrong placement is silently ignored.
- **NodeSource removes UFW**: Removing Ubuntu's `nodejs` package to install NodeSource Node 22 also removes `ufw`. Always reinstall UFW after the Node.js swap.
- **sudo-rs**: Ubuntu 25.10 uses `sudo-rs` (Rust reimplementation) by default. Some sudo flags behave differently.
- **`controlUi.allowInsecureAuth` must be `false`**: If the control UI is enabled, `gateway.controlUi.allowInsecureAuth` must be `false`. When `true`, token-only HTTP auth is allowed — anyone who intercepts the token gets full gateway control, including host-level command execution via `tools.elevated`. This is the most common CRITICAL finding in `openclaw security audit --deep`.

## Admin Access

**Traditional SSH is disabled.** Admin access to the server is exclusively via Tailscale SSH:

```bash
tailscale ssh youruser@your-server
```

No sshd service runs on the host. Port 22 is not open.

## Security Constraints

- Gateway binds to `127.0.0.1:18789` only — never `0.0.0.0`
- Tailscale Funnel must remain OFF (gateway is tailnet-internal only)
- SOUL.md is root-owned with 444 permissions — do not modify without updating the sha256 baseline
- Secrets live in `/home/openclaw-svc/.openclaw/openclaw.json` and `/home/openclaw-svc/.openclaw/credentials/` — never commit or expose them
- Token rotation: update BOTH `gateway.auth.token` AND `gateway.remote.token`, then restart

## Pending Tasks

See the "Remaining TODO" section in `openclaw-deployment-guide.md`.

## Update Procedure

See `openclaw-deployment-guide.md` Phase 9 for the full update procedure with rollback guidance.

Quick reference:

```bash
sudo systemctl stop openclaw.service
sudo -u openclaw-svc bash -c '
  export PATH=$HOME/.npm-global/bin:$PATH
  npm install -g openclaw@<new-version>
  openclaw --version
  openclaw doctor
  openclaw security audit --fix
'
sudo systemctl start openclaw.service
```
