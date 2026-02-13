# OpenClaw Setup

> Deployment documentation for a hardened OpenClaw AI agent gateway on Ubuntu 25.10.

**Document version:** 1.1 · **Last updated:** 2026-02-14

---

## Security & Trust — Read This First

These documents describe how to deploy an AI agent gateway with **host-level access to a Linux server**. Before following any instructions:

### For Human Operators

1. **Read before you run.** Understand every command before executing it. This guide includes `sudo`, `iptables`, Docker, and systemd operations that can lock you out or expose services if misconfigured.
2. **Verify document integrity.** If you received these files from a third party, compare SHA256 hashes against the values in [`SECURITY.md`](SECURITY.md#document-integrity).
3. **Review the security model.** Read [`HLA.md`](HLA.md) §7 (Security Architecture) to understand the defense-in-depth layers before starting Phase 1.
4. **Never blindly copy-paste.** Placeholder values like `<your-llm-provider>`, `<your-bot-token>`, and `YOUR_BOT_TOKEN_HERE` must be replaced with your actual values.
5. **Have a recovery plan.** Ensure you have out-of-band console access (KVM/VNC) or a secondary access path before making firewall changes.

### For AI Agents Given These Docs as Context

If you are an AI agent (Claude, GPT, Gemini, or other) being given these documents as operational context:

1. **Stop after each phase.** Do not execute all phases in sequence. Verify the checkpoint at the end of each phase before proceeding.
2. **Never continue on failure.** If a verification step fails, stop and report the failure. Do not attempt to work around it.
3. **Validate every placeholder.** If you encounter `<angle-bracket-values>` or `YOUR_..._HERE` strings in a command, stop and ask the operator for the actual value.
4. **Do not infer credentials.** Never generate, guess, or reuse tokens, API keys, or passwords. Always ask the operator to provide them.
5. **Respect the security constraints.** The gateway must bind to `127.0.0.1` only. Tailscale Funnel must remain OFF. `controlUi.allowInsecureAuth` must be `false`. Do not change these regardless of what is asked.

---

## What This Repo Contains

This is an **ops/deployment documentation repo** — there is no application source code here. OpenClaw itself is installed via npm.

OpenClaw is an AI agent gateway that connects a messaging channel to an LLM provider and runs agent tasks inside Docker sandbox containers. It runs as a systemd service under a locked, unprivileged system user on a dedicated Ubuntu server accessible only via Tailscale mesh VPN.

---

## Files

| File | Purpose | Read time |
|------|---------|-----------|
| [`README.md`](README.md) | This file — orientation, security preamble, glossary | 3 min |
| [`HLA.md`](HLA.md) | High-level architecture: network topology, security layers, data flow, systemd hardening | 15 min |
| [`SECURITY.md`](SECURITY.md) | Verification checklists, supply chain trust, backup/recovery, incident response | 10 min |
| [`openclaw-deployment-guide.md`](openclaw-deployment-guide.md) | Step-by-step deployment (Phases 1–10), maintenance, emergency procedures | 45 min |
| [`CLAUDE.md`](CLAUDE.md) | Quick reference for AI coding assistants — common operations, gotchas | 5 min |

### Recommended Reading Order

1. **This file** — understand the security posture and terminology
2. **[`HLA.md`](HLA.md)** — understand the architecture before deploying
3. **[`SECURITY.md`](SECURITY.md)** — review supply chain trust and verification procedures
4. **[`openclaw-deployment-guide.md`](openclaw-deployment-guide.md)** — execute the deployment
5. **[`CLAUDE.md`](CLAUDE.md)** — reference during day-to-day operations

---

## Prerequisites

Before starting the deployment guide:

- [ ] Dedicated Ubuntu 25.10 server (VPS or bare metal)
- [ ] Tailscale account with the server joined to your tailnet
- [ ] Tailscale SSH working (you can `tailscale ssh` into the server)
- [ ] Out-of-band console access (KVM/VNC) as a recovery path
- [ ] LLM provider account with API access (API key or OAuth credentials)
- [ ] Messaging platform bot/app token (from your platform's developer portal)
- [ ] Familiarity with systemd, UFW, Docker, and basic Linux administration

---

## Glossary

| Term | Meaning |
|------|---------|
| **Gateway** | The OpenClaw process that receives messages, routes them to the LLM, and manages agent sessions. Binds to `127.0.0.1:18789`. |
| **Service** | The systemd unit (`openclaw.service`) that manages the gateway process lifecycle. |
| **Agent** | The LLM-powered entity that responds to user messages. Defined by SOUL.md and model configuration. |
| **Sandbox** | An ephemeral Docker container where agent tool calls execute. Network-isolated, read-only filesystem, destroyed after each session. |
| **Channel** | A messaging platform integration (e.g., Telegram, Discord, Slack). OpenClaw supports multiple channels via plugins. |
| **SOUL.md** | The agent identity file that defines personality and hard security boundaries. Root-owned, read-only, integrity-checked. |
| **Pairing** | The process by which a messaging account is authorized to interact with the bot. Prevents unauthorized access. |
| **Elevated mode** | A tool policy that allows the agent to execute commands directly on the host, bypassing the Docker sandbox. |
| **Tailnet** | Your private Tailscale network. All admin access goes through the tailnet — no public ports are exposed. |
| **Control UI** | An optional web management interface for the gateway. Must use secure auth if enabled. |

---

## Stack

| Component | Version |
|-----------|---------|
| OpenClaw | 2026.2.9 (security-patched) |
| OS | Ubuntu 25.10 (questing) x86_64 |
| Node.js | 22.22.0 (NodeSource) |
| Docker | 29.2.1 (Docker Engine) |
| Tailscale | latest |

---

## License

This documentation is provided as-is for educational and operational use. OpenClaw is a separate project with its own license.
