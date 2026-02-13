# OpenClaw — High-Level Architecture

> **System:** OpenClaw AI Agent Gateway on dedicated Ubuntu 25.10 server
> **Document version:** 1.1 · **Last updated:** 2026-02-14

This document describes the architecture of the OpenClaw deployment in progressive
detail — from bird's-eye overview down to individual security layers. It documents
the **target state** (post user-rename to `openclaw-svc`). No secrets, tokens,
or credentials appear anywhere in this document.

---

## 1. System Overview

```
                        ┌───────────────────────────────┐
                        │         INTERNET              │
                        │  ┌─────────┐  ┌────────────┐  │
                        │  │Messaging│  │ LLM        │  │
                        │  │Channel  │  │ Provider   │  │
                        │  └────▲────┘  └─────▲──────┘  │
                        └───────┼─────────────┼─────────┘
                                │  HTTPS/443  │
                        ┌───────┼─────────────┼─────────┐
                        │       │  Tailscale  │         │
                        │       │  Mesh VPN   │         │
                        │  100.x.y.z (tailscale0)       │
                        └───────┼─────────────┼─────────┘
                                │             │
┌───────────────────────────────┼─────────────┼─────────────────────────┐
│                     Ubuntu 25.10 Host                                 │
│                                                                       │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │  UFW Firewall  │  DOCKER-USER iptables  │  Loopback Binding   │   │
│   └────────────────────────────────────────────────────────────────┘   │
│                                                                       │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │  systemd: openclaw.service                                     │   │
│   │  User: openclaw-svc (locked system account)                  │   │
│   │  ┌──────────────────────────────────────┐                      │   │
│   │  │  OpenClaw Gateway (Node.js)          │                      │   │
│   │  │  Listening: 127.0.0.1:18789          │                      │   │
│   │  │  Model: <provider/model-id>          │                      │   │
│   │  │  Channel: <your-channel>             │                      │   │
│   │  └──────────┬───────────────────────────┘                      │   │
│   └─────────────┼──────────────────────────────────────────────────┘   │
│                 │                                                      │
│   ┌─────────────▼──────────────────────────────────────────────────┐   │
│   │  Docker Engine                                                  │   │
│   │  ┌──────────┐ ┌──────────┐ ┌──────────┐                        │   │
│   │  │ Sandbox  │ │ Sandbox  │ │ Sandbox  │  (per-session, ephemeral│   │
│   │  │Container │ │Container │ │Container │   network=none)         │   │
│   │  └──────────┘ └──────────┘ └──────────┘                        │   │
│   └────────────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────────┘
```

### Version Stamps

| Component  | Version                              |
|------------|--------------------------------------|
| OS         | Ubuntu 25.10 (questing) x86_64       |
| Node.js    | 22.22.0 (NodeSource)                 |
| Docker     | 29.2.1 (Docker Engine)               |
| OpenClaw   | 2026.2.9 (security-patched)           |
| Tailscale  | latest (IP: 100.x.y.z)               |

### One-Paragraph Description

OpenClaw is an AI agent gateway that connects a messaging channel to an LLM
provider. Users interact with the bot via direct messages. The gateway
receives messages via outbound HTTPS long-polling (no inbound webhooks), routes
them to the configured LLM for inference, and optionally executes agent tasks
inside ephemeral Docker sandbox containers with network isolation. The entire
system runs as a single systemd service under a locked, unprivileged system user
on a dedicated Ubuntu server accessible only via Tailscale mesh VPN.

---

## 2. Network Architecture

### 2.1 Network Flow Diagram

```
                              OUTBOUND ONLY
                        ┌─────────────────────────┐
                        │                         │
                        ▼                         ▼
               ┌────────────────┐       ┌──────────────────┐
               │  Messaging     │       │  LLM Provider    │
               │  Channel API   │       │  API             │
               │  :443          │       │  :443            │
               │                │       │                  │
               └────────────────┘       └──────────────────┘
                        ▲                         ▲
                        │    HTTPS (TLS 1.3)      │
                        │                         │
┌───────────────────────┼─────────────────────────┼───────────────────┐
│                       │   Ubuntu 25.10 Host     │                   │
│                       │                         │                   │
│  ┌────────────────────┼─────────────────────────┼────────────────┐  │
│  │  eth0 / wlan       │                         │                │  │
│  │  (public NIC)      │   outbound allowed      │                │  │
│  │  UFW: deny inbound ┘                         │                │  │
│  └───────────────────────────────────────────────┘                │  │
│                                                                   │  │
│  ┌──────────────────────────────────────────────┐                 │  │
│  │  tailscale0 (100.x.y.z)                      │                 │  │
│  │  Tailscale SSH: admin access (replaces sshd) │  ◄── Admin      │  │
│  │  UFW: allow in on tailscale0                 │      Only       │  │
│  └──────────────────────────────────────────────┘                 │  │
│                                                                   │  │
│  ┌──────────────────────────────────────────────┐                 │  │
│  │  lo (127.0.0.1)                              │                 │  │
│  │  Gateway: 127.0.0.1:18789                    │  ◄── Local      │  │
│  │  Not reachable from any external interface   │      Only       │  │
│  └──────────────────────────────────────────────┘                 │  │
└───────────────────────────────────────────────────────────────────┘
```

### 2.2 Inbound Access

| Source           | Interface   | Port/Protocol       | Purpose            |
|------------------|-------------|---------------------|--------------------|
| Tailscale peers  | tailscale0  | Tailscale SSH       | Admin shell access |
| Tailscale peers  | tailscale0  | All (UFW allowed)   | Tailnet services   |
| Public internet  | eth0        | **NONE** (all denied) | Blocked by UFW   |

**Traditional SSH (port 22) is disabled.** Admin access is exclusively via
Tailscale SSH, which authenticates against the tailnet ACL — no passwords, no
exposed ports.

### 2.3 Outbound Connections

| Destination                              | Port | Protocol | Purpose                    |
|------------------------------------------|------|----------|----------------------------|
| `<messaging-api-endpoint>`               | 443  | HTTPS    | Messaging channel API (long-poll) |
| `<llm-api-endpoint>`                     | 443  | HTTPS    | LLM inference API          |
| registry.npmjs.org                       | 443  | HTTPS    | npm package updates        |
| deb.nodesource.com, download.docker.com  | 443  | HTTPS    | APT package updates        |
| login.tailscale.com, controlplane.ts.net | 443  | HTTPS    | Tailscale coordination     |

### 2.4 Firewall Stack

Three independent layers enforce network policy:

```
  Packet arrives ──►  UFW (iptables INPUT chain)
                          │
                          ├── deny all incoming (default)
                          └── allow in on tailscale0
                          │
                      DOCKER-USER chain (iptables)
                          │
                          ├── ACCEPT established/related
                          ├── ACCEPT from tailscale0
                          ├── ACCEPT from loopback
                          └── DROP everything else
                          │
                      Application binding
                          │
                          └── Gateway binds 127.0.0.1 only
                              (unreachable from any NIC)
```

**Egress filtering** is recommended in addition to inbound rules. The deployment
guide documents two outbound policies: a permissive default (`allow outgoing`)
and a hardened allowlist (`deny outgoing` with explicit rules for HTTPS, DNS,
and Tailscale coordination). The hardened policy prevents data exfiltration if
the agent or host is compromised.

### 2.5 Port Table

| Port  | Bind Address   | Process        | Reachable From             |
|-------|----------------|----------------|----------------------------|
| 18789 | 127.0.0.1      | openclaw gw    | localhost only              |
| 22    | disabled       | sshd (stopped) | nowhere (Tailscale SSH)    |

Tailscale Funnel: **OFF** (gateway is tailnet-internal only, never public).

---

## 3. User & Permission Model

### 3.1 User Hierarchy

```
  root
    │
    ├── youruser  (human admin)
    │     Groups: sudo, docker
    │     Access: Tailscale SSH
    │     Can: sudo, systemctl, edit configs
    │
    └── openclaw-svc  (system service account)
          Groups: docker, openclaw-svc
          Shell: /bin/bash (locked — no password, no direct login)
          Home: /home/openclaw-svc (mode 700)
          Can: run openclaw gateway, access Docker socket
          Cannot: sudo, ssh, login directly
```

### 3.2 Why a Locked System User?

The `openclaw-svc` account has no password and cannot be logged into directly
(`passwd -l`). This provides:

- **Least privilege:** the gateway process owns only its own files
- **No interactive access:** compromising the process doesn't grant a login shell
- **Clear audit trail:** all admin actions go through the admin user with sudo

### 3.3 Group Memberships

| User             | Groups                           | Purpose                        |
|------------------|----------------------------------|--------------------------------|
| youruser         | sudo, docker                     | Admin operations               |
| openclaw-svc   | docker, openclaw-svc           | Docker socket for sandboxes    |

### 3.4 File Ownership Patterns

| Path                                          | Owner                | Mode | Why                                |
|-----------------------------------------------|----------------------|------|------------------------------------|
| `/home/openclaw-svc/`                       | openclaw-svc       | 700  | Service home, no other access      |
| `/home/openclaw-svc/.openclaw/`             | openclaw-svc       | 700  | Config dir                         |
| `/home/openclaw-svc/.openclaw/openclaw.json`| openclaw-svc       | 600  | Contains secrets                   |
| `/home/openclaw-svc/.openclaw/SOUL.md`      | root:openclaw-svc  | 444  | Read-only agent identity           |
| `/home/openclaw-svc/.openclaw/credentials/` | openclaw-svc       | 700  | API keys and tokens                |

### 3.5 Admin Access Pattern

All CLI commands targeting the service user require:

```bash
sudo -u openclaw-svc bash -c '
  cd ~
  export PATH=$HOME/.npm-global/bin:$PATH
  <COMMAND>
'
```

---

## 4. Service Architecture

### 4.1 Startup Sequence

```
  System Boot
      │
      ▼
  network-online.target  ──►  Waits for network
      │
      ▼
  docker.service  ──────────►  Docker daemon starts
      │                        (Requires=docker.service)
      ▼
  openclaw.service
      │
      ├── User=openclaw-svc, Group=openclaw-svc
      ├── WorkingDirectory=/home/openclaw-svc
      ├── Environment:
      │     HOME=/home/openclaw-svc
      │     PATH=~/.npm-global/bin:/usr/local/sbin:...
      │     NODE_ENV=production
      │     OPENCLAW_DISABLE_BONJOUR=1
      ├── EnvironmentFile=-/home/openclaw-svc/.openclaw/.env
      │
      ▼
  ExecStart: openclaw gateway run
      │
      ├── Loads openclaw.json (gateway config, model, channels)
      ├── Loads SOUL.md (agent identity and boundaries)
      ├── Binds HTTP gateway to 127.0.0.1:18789
      ├── Starts messaging channel long-poll loop
      └── Ready to accept messages
```

### 4.2 Restart Behavior

```
  Process exits
      │
      ├── Exit code 0 (clean shutdown) ──► stays stopped
      │
      └── Non-zero exit (crash/error)
            │
            ▼
          Restart=on-failure
          RestartSec=10  (wait 10 seconds)
            │
            ▼
          Restart attempt
            │
            ├── Success ──► running again
            │
            └── Failure ──► retry up to 5 times in 300 seconds
                             (StartLimitBurst=5, StartLimitIntervalSec=300)
                             │
                             └── After 5 failures ──► service enters "failed" state
                                                      Manual intervention required
```

### 4.3 Resource Limits

| Limit      | Value  | Purpose                             |
|------------|--------|-------------------------------------|
| MemoryMax  | 2 GB   | Hard OOM kill boundary              |
| MemoryHigh | 1.5 GB | Throttle trigger before OOM         |
| TasksMax   | 512    | Prevent fork bombs                  |
| LimitNOFILE| 4096   | Max open file descriptors           |

### 4.4 systemd Hardening — What Works and What Doesn't

The service file applies all compatible hardening directives, achieving a
**5.8 MEDIUM** security score (`systemd-analyze security`).

**Active hardening:**

| Directive                  | Effect                                    |
|----------------------------|-------------------------------------------|
| NoNewPrivileges=yes        | Process cannot gain new privileges        |
| PrivateTmp=yes             | Isolated /tmp namespace                   |
| PrivateDevices=yes         | No access to physical devices             |
| DevicePolicy=closed        | Deny device node creation                 |
| ProtectSystem=strict       | Entire filesystem read-only except allowed|
| ProtectKernelModules=yes   | Cannot load kernel modules                |
| ProtectKernelTunables=yes  | Cannot modify /proc/sys                   |
| ProtectKernelLogs=yes      | Cannot read kernel log buffer             |
| ProtectControlGroups=yes   | Cannot modify cgroups                     |
| ProtectClock=yes           | Cannot change system clock                |
| ProtectHostname=yes        | Cannot change hostname                    |
| RestrictAddressFamilies    | Only IPv4, IPv6, Unix, Netlink sockets    |
| RestrictRealtime=yes       | Cannot acquire realtime scheduling        |
| RestrictSUIDSGID=yes       | Cannot create SUID/SGID files             |
| LockPersonality=yes        | Cannot change execution domain            |
| SystemCallArchitectures    | native only (no 32-bit compat)            |

**Intentionally omitted (breaks Node.js or Docker):**

| Directive                   | Why it breaks things                      |
|-----------------------------|-------------------------------------------|
| MemoryDenyWriteExecute=yes  | V8 JIT requires W+X memory pages          |
| ProtectHome=tmpfs           | Causes immediate gateway exit with BindPaths |
| CapabilityBoundingSet=      | Empty set blocks Docker socket access     |
| RestrictNamespaces=yes      | Blocks Docker container creation          |
| SystemCallFilter=@system-service | Node.js needs syscalls outside this set|

### 4.5 Critical Command Gotcha

The ExecStart command **must** be `openclaw gateway run`, not
`gateway start --foreground`. The `gateway start` subcommand daemonizes and
returns immediately, causing systemd to think the service crashed.

---

## 5. Data Flow: Message Lifecycle

### 5.1 Sequence Diagram

```
  User                Messaging          Gateway            LLM             Docker
  (client)            Servers          (localhost)          Provider        Sandbox
    │                    │                  │                   │              │
    │  Send message      │                  │                   │              │
    ├───────────────────►│                  │                   │              │
    │                    │                  │                   │              │
    │                    │  Long-poll resp  │                   │              │
    │                    │◄─── poll ────────┤                   │              │
    │                    ├────────────────►│                   │              │
    │                    │  (new message)   │                   │              │
    │                    │                  │                   │              │
    │                    │                  │  Inference req    │              │
    │                    │                  ├──────────────────►│              │
    │                    │                  │                   │              │
    │                    │                  │  Response (may    │              │
    │                    │                  │◄──────────────────┤              │
    │                    │                  │  include tool     │              │
    │                    │                  │  calls)           │              │
    │                    │                  │                   │              │
    │                    │                  │                   │              │
    │                    │                  │  [If tool call]   │              │
    │                    │                  ├──────────────────────────────────►│
    │                    │                  │  Execute in sandbox              │
    │                    │                  │◄──────────────────────────────────┤
    │                    │                  │  (result)                        │
    │                    │                  │                   │              │
    │                    │                  │  [Feed result     │              │
    │                    │                  │   back to model]  │              │
    │                    │                  ├──────────────────►│              │
    │                    │                  │◄──────────────────┤              │
    │                    │                  │                   │              │
    │                    │  Send reply      │                   │              │
    │                    │◄────────────────┤                   │              │
    │  Display reply     │                  │                   │              │
    │◄───────────────────┤                  │                   │              │
    │                    │                  │                   │              │
```

### 5.2 Long-Polling vs Webhooks

OpenClaw uses **long-polling** to receive messages from the messaging channel:

| Aspect             | Long-Polling (used)               | Webhook (not used)                 |
|--------------------|-----------------------------------|------------------------------------|
| Direction          | Gateway polls channel outbound    | Channel pushes to gateway inbound  |
| Open ports needed  | None                              | HTTPS port must be public          |
| TLS certificate    | Not needed                        | Required on your endpoint          |
| Firewall config    | Outbound HTTPS only               | Must allow inbound connections     |
| Security posture   | No attack surface                 | Exposes an HTTP endpoint           |
| Latency            | Slightly higher (poll interval)   | Near-instant                       |

Long-polling is the correct choice here because:
- The gateway has **no public-facing ports** — inbound webhooks would require
  exposing an endpoint
- Security is maximized by having **zero inbound attack surface**
- The small latency increase is irrelevant for a personal assistant bot

### 5.3 What Happens at Each Step

1. **User sends message** — typed in the messaging client
2. **Channel stores message** — held on the messaging platform's servers
3. **Gateway polls** — HTTPS long-poll request to the messaging API
4. **Message received** — gateway processes the message, checks pairing
5. **Inference request** — message + SOUL.md context sent to LLM provider API
6. **Model responds** — may include text response and/or tool calls
7. **Tool execution** — if tools are invoked, they run inside a Docker sandbox
8. **Result fed back** — tool output returned to the LLM for final response
9. **Reply sent** — HTTPS call back to the messaging channel API
10. **User sees reply** — displayed in the messaging client

---

## 6. Docker Sandbox Architecture

### 6.1 Isolation Model

```
┌──────────────────────────────────────────────────────────┐
│  Host: Ubuntu 25.10                                       │
│                                                           │
│  Docker Engine (dockerd)                                  │
│  └── /var/run/docker.sock (openclaw-svc has access      │
│                            via docker group)              │
│                                                           │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  Sandbox Container (per session)                     │ │
│  │                                                      │ │
│  │  Network:        none (no network access)            │ │
│  │  Filesystem:     readOnlyRoot=true                   │ │
│  │  Workspace:      mounted read-only                   │ │
│  │  PID namespace:  isolated                            │ │
│  │  User:           unprivileged (inside container)     │ │
│  │                                                      │ │
│  │  ulimits:                                            │ │
│  │    nproc  = 256  (max processes)                     │ │
│  │    nofile = 1024 (max open files)                    │ │
│  │                                                      │ │
│  │  Lifecycle: created on session start                 │ │
│  │             destroyed on session end                 │ │
│  └──────────────────────────────────────────────────────┘ │
│                                                           │
│  Docker daemon defaults (/etc/docker/daemon.json):        │
│    Log rotation: 10MB x 3 files per container             │
│    Default ulimits: nofile=1024, nproc=256                 │
└──────────────────────────────────────────────────────────┘
```

### 6.2 Container Lifecycle

```
  User sends message requiring tool execution
      │
      ▼
  Gateway receives tool call from LLM
      │
      ▼
  Docker: create container
    ├── Image: openclaw-sandbox:bookworm-slim
    ├── Network: none
    ├── ReadOnlyRootfs: true
    ├── Workspace: bind mount (read-only)
    └── Ulimits applied
      │
      ▼
  Execute tool inside container
    ├── File reads, code execution, etc.
    └── Stdout/stderr captured
      │
      ▼
  Gateway collects result
      │
      ▼
  Docker: remove container
    └── Container and any writable layers destroyed
```

### 6.3 Configuration

| Setting                                  | Value      | Effect                            |
|------------------------------------------|------------|-----------------------------------|
| agents.defaults.sandbox.mode             | all        | Every tool runs sandboxed         |
| agents.defaults.sandbox.scope            | session    | One container per chat session    |
| agents.defaults.sandbox.docker.network   | none       | No network inside sandbox         |
| agents.defaults.sandbox.workspaceAccess  | ro         | Workspace is read-only            |
| agents.defaults.sandbox.docker.readOnlyRoot | true    | Root filesystem is read-only      |

### 6.4 What Sandboxes Prevent

- **Network exfiltration:** `network=none` prevents the sandbox from calling
  any external service
- **Filesystem escape:** read-only root + read-only workspace prevent writes
- **Resource abuse:** ulimits cap processes and file descriptors
- **Persistence:** ephemeral containers leave no state behind

---

## 7. Security Architecture

### 7.1 Defense-in-Depth Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: NETWORK                                                │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  No public-facing ports (UFW deny incoming)                 │ │
│  │  Admin access via Tailscale SSH only                        │ │
│  │  Gateway binds 127.0.0.1 (loopback only)                   │ │
│  │  Tailscale Funnel: OFF                                      │ │
│  ├─────────────────────────────────────────────────────────────┤ │
│  │  Layer 2: FIREWALL                                          │ │
│  │  ┌─────────────────────────────────────────────────────────┐│ │
│  │  │  UFW: deny inbound default                              ││ │
│  │  │  DOCKER-USER: DROP default (iptables)                   ││ │
│  │  │  Only loopback + tailscale0 accepted                    ││ │
│  │  ├─────────────────────────────────────────────────────────┤│ │
│  │  │  Layer 3: HOST OS                                       ││ │
│  │  │  ┌─────────────────────────────────────────────────────┐││ │
│  │  │  │  Unattended security upgrades                       │││ │
│  │  │  │  fail2ban (sshd jail — legacy, before SSH disabled) │││ │
│  │  │  │  sudo-rs (Rust sudo reimplementation)               │││ │
│  │  │  ├─────────────────────────────────────────────────────┤││ │
│  │  │  │  Layer 4: PROCESS ISOLATION (systemd)               │││ │
│  │  │  │  ┌─────────────────────────────────────────────────┐│││ │
│  │  │  │  │  Locked service user (no login, no sudo)        ││││ │
│  │  │  │  │  NoNewPrivileges, PrivateTmp, PrivateDevices    ││││ │
│  │  │  │  │  ProtectSystem=strict, ProtectKernel*           ││││ │
│  │  │  │  │  Memory limits (2GB max), TasksMax=512          ││││ │
│  │  │  │  ├─────────────────────────────────────────────────┤│││ │
│  │  │  │  │  Layer 5: APPLICATION                           ││││ │
│  │  │  │  │  ┌─────────────────────────────────────────────┐│││││
│  │  │  │  │  │  Gateway auth (token-based)                 ││││││
│  │  │  │  │  │  Channel pairing mode (DM whitelist)        ││││││
│  │  │  │  │  │  Tool deny list (gateway, nodes blocked)    ││││││
│  │  │  │  │  │  Elevated mode disabled                     ││││││
│  │  │  │  │  │  Sensitive data redaction in logs           ││││││
│  │  │  │  │  ├─────────────────────────────────────────────┤│││││
│  │  │  │  │  │  Layer 6: AGENT IDENTITY (SOUL.md)          ││││││
│  │  │  │  │  │  ┌─────────────────────────────────────────┐││││││
│  │  │  │  │  │  │  Root-owned, 444 permissions            │││││││
│  │  │  │  │  │  │  Security boundaries (hardcoded rules)  │││││││
│  │  │  │  │  │  │  sha256 baseline integrity check        │││││││
│  │  │  │  │  │  │  Weekly cron verification               │││││││
│  │  │  │  │  │  ├─────────────────────────────────────────┤││││││
│  │  │  │  │  │  │  Layer 7: SANDBOX (Docker)              │││││││
│  │  │  │  │  │  │  network=none, readOnlyRoot, ro mount   │││││││
│  │  │  │  │  │  │  Ephemeral per-session containers       │││││││
│  │  │  │  │  │  └─────────────────────────────────────────┘││││││
│  │  │  │  │  └─────────────────────────────────────────────┘│││││
│  │  │  │  └─────────────────────────────────────────────────┘││││
│  │  │  └─────────────────────────────────────────────────────┘│││
│  │  └─────────────────────────────────────────────────────────┘││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 7.2 All Security Layers Enumerated

| #  | Layer                    | Mechanism                                       |
|----|--------------------------|--------------------------------------------------|
| 1  | Network perimeter        | No public ports, UFW deny incoming               |
| 2  | Admin access             | Tailscale SSH only (no sshd, no port 22)         |
| 3  | Firewall (UFW)           | Default deny incoming, allow outgoing            |
| 4  | Firewall (DOCKER-USER)   | iptables DROP default, allow lo + tailscale0     |
| 5  | Loopback binding         | Gateway on 127.0.0.1:18789, not 0.0.0.0          |
| 6  | OS hardening             | Unattended upgrades, fail2ban, sudo-rs           |
| 7  | Process isolation        | systemd hardening (17 active directives)         |
| 8  | Least privilege          | Locked user, no sudo, docker group only          |
| 9  | Gateway authentication   | Token-based auth for API access                  |
| 10 | Channel policy           | Messaging pairing mode, no groups, no config DMs |
| 11 | Agent boundaries         | SOUL.md with hardcoded security rules            |
| 12 | Sandbox isolation        | Docker: network=none, readOnlyRoot, ephemeral    |

### 7.3 SOUL.md Integrity Chain

```
  Deployment
      │
      ▼
  SOUL.md written ──► chown root:openclaw-svc
                  ──► chmod 444 (read-only for everyone)
      │
      ▼
  sha256sum ──► /var/lib/openclaw-soul-baseline.sha256
      │
      ▼
  Weekly cron (/etc/cron.weekly/openclaw-soul-check)
      │
      ├── sha256sum matches ──► silent (no action)
      │
      └── sha256sum differs ──► logger WARNING to syslog
```

The SOUL.md file cannot be modified by the `openclaw-svc` user (root-owned,
read-only). If an attacker gains code execution as the service user, they
cannot alter the agent's security boundaries. Any unauthorized change is
detected within 7 days by the weekly cron check.

### 7.4 Messaging Channel Security Posture

The messaging channel integration has minimal attack surface:

- **No inbound ports:** long-polling means no webhook endpoint to attack
- **Pairing required:** unknown users cannot interact with the bot
- **DM only:** group chats are disabled (`groupPolicy: disabled`)
- **No config writes:** messages cannot change gateway configuration
- **Privacy mode:** if your messaging platform supports it, enable privacy mode to ignore group messages

### 7.5 Tailscale ACL Requirements

Tailscale ACLs control which devices on your tailnet can reach the server. The default "allow all" policy is too permissive for a production deployment.

**Minimum requirements:**
- Only admin devices should have SSH access to the server
- The server should be tagged (e.g., `tag:openclaw-server`) for policy targeting
- SSH should be restricted to non-root users
- Default deny is implicit — anything not explicitly allowed is blocked

See [`SECURITY.md`](SECURITY.md) §4 for a recommended ACL template and Funnel verification procedures.

### 7.6 Backup & Disaster Recovery

The deployment produces several stateful artifacts that must be backed up for recovery:
- **Secrets** (gateway token, API credentials) — encrypted backup required
- **Configuration** (systemd unit, Docker daemon, UFW rules) — can be reconstructed from this guide but backup saves time
- **SOUL.md** and its integrity baseline — low sensitivity, easy to restore

See [`SECURITY.md`](SECURITY.md) §5 for the full backup procedure and recovery steps.

---

## 8. Maintenance & Monitoring

### 8.1 Automated Tasks

| Schedule | Job                                   | Location                                  |
|----------|---------------------------------------|-------------------------------------------|
| Weekly   | Deep security audit                   | `/etc/cron.weekly/openclaw-security-audit` |
| Weekly   | SOUL.md sha256 integrity check        | `/etc/cron.weekly/openclaw-soul-check`     |
| Auto     | Unattended security upgrades (apt)    | `/etc/apt/apt.conf.d/50unattended-upgrades`|

### 8.2 Log Access

```bash
# Live log stream
sudo journalctl -u openclaw.service -f

# Errors from last hour
sudo journalctl -u openclaw.service -p err --since "1h ago"

# Full log since last boot
sudo journalctl -u openclaw.service -b

# Grep for specific events
sudo journalctl -u openclaw.service --no-pager | grep "<keyword>"
```

### 8.3 Health Checks

```bash
# Service status
sudo systemctl status openclaw.service

# Gateway port binding (must show 127.0.0.1:18789)
sudo ss -tlnp | grep 18789

# systemd security score (target: 5.8 MEDIUM)
sudo systemd-analyze security openclaw.service

# SOUL.md integrity
sudo sha256sum -c /var/lib/openclaw-soul-baseline.sha256

# OpenClaw internal diagnostics
sudo -u openclaw-svc bash -c '
  cd ~ && export PATH=$HOME/.npm-global/bin:$PATH
  openclaw doctor
'

# Deep security audit
sudo -u openclaw-svc bash -c '
  cd ~ && export PATH=$HOME/.npm-global/bin:$PATH
  openclaw security audit --deep
'
```

### 8.4 Update Procedure

```
  1. Stop service     ──► sudo systemctl stop openclaw.service
  2. Upgrade package  ──► npm install -g openclaw@<new-version>
  3. Verify version   ──► openclaw --version
  4. Run diagnostics  ──► openclaw doctor
  5. Security audit   ──► openclaw security audit --fix
  6. Start service    ──► sudo systemctl start openclaw.service
  7. Verify running   ──► sudo systemctl status openclaw.service
```

### 8.5 Credential Rotation Schedule

| Credential            | Frequency    | Notes                              |
|-----------------------|--------------|------------------------------------|
| Gateway auth token    | Quarterly    | Update both auth.token and remote.token |
| Messaging bot token   | On compromise| Revoke in your platform's developer portal, create new |
| LLM API key           | Quarterly    | Rotate in your LLM provider's console |
| LLM OAuth tokens      | Automatic    | Self-refreshing; re-login if expired |

---

## Appendix A: File Map

| Path (on server)                                        | Owner              | Mode | Purpose                      |
|---------------------------------------------------------|--------------------|------|------------------------------|
| `/etc/systemd/system/openclaw.service`                  | root               | 644  | systemd unit file            |
| `/home/openclaw-svc/.openclaw/openclaw.json`          | openclaw-svc     | 600  | Main config (contains secrets)|
| `/home/openclaw-svc/.openclaw/SOUL.md`                | root:openclaw-svc| 444  | Agent identity & boundaries  |
| `/home/openclaw-svc/.openclaw/.env`                   | openclaw-svc     | 600  | Environment overrides        |
| `/home/openclaw-svc/.openclaw/credentials/`           | openclaw-svc     | 700  | API credentials directory    |
| `/home/openclaw-svc/.npm-global/bin/openclaw`         | openclaw-svc     | 755  | OpenClaw binary              |
| `/etc/docker/daemon.json`                               | root               | 644  | Docker daemon config         |
| `/var/lib/openclaw-soul-baseline.sha256`                | root               | 644  | SOUL.md integrity baseline   |
| `/etc/cron.weekly/openclaw-security-audit`              | root               | 755  | Weekly security audit script |
| `/etc/cron.weekly/openclaw-soul-check`                  | root               | 755  | Weekly SOUL.md integrity check|

## Appendix B: Deployment Gotchas

Hard-won lessons from the initial deployment — violating any of these will
silently break the service:

1. **`gateway run` not `start --foreground`** — `gateway start` daemonizes,
   causing systemd to detect a crash
2. **No WatchdogSec** — OpenClaw doesn't implement `sd_notify(WATCHDOG=1)`
3. **No ProtectHome=tmpfs** — causes immediate exit with BindPaths
4. **No MemoryDenyWriteExecute** — V8 JIT requires W+X memory
5. **No SystemCallFilter** — Node.js needs syscalls outside `@system-service`
6. **No empty CapabilityBoundingSet** — blocks Docker socket
7. **No RestrictNamespaces** — blocks Docker container creation
8. **Gateway tokens must match** — `gateway.auth.token` and
   `gateway.remote.token` must be identical
9. **StartLimitIntervalSec in [Unit]** — silently ignored if placed in [Service]
10. **NodeSource removes UFW** — always reinstall UFW after swapping Node.js
11. **sudo-rs quirks** — Ubuntu 25.10 uses Rust sudo; some flags differ
