# Security Verification & Trust Model

> Pre-deployment verification, supply chain trust, backup/recovery, and incident response.

**Document version:** 1.0 · **Last updated:** 2026-02-14

---

## 1. Document Integrity

Verify the integrity of these documentation files before following them. Generate current hashes and compare against a trusted source:

```bash
sha256sum README.md HLA.md openclaw-deployment-guide.md CLAUDE.md SECURITY.md
```

If you received these files from a third party, compare the output against hashes published in the original repository or provided by the document author through a separate channel.

---

## 2. Pre-Deployment Verification Checklist

Run through this checklist before starting Phase 1 of the deployment guide. Each item should be confirmed independently.

### Server Environment

- [ ] Ubuntu version is 25.10 (questing): `lsb_release -a`
- [ ] Server is joined to your Tailscale tailnet: `tailscale status`
- [ ] Tailscale SSH is working: `tailscale ssh youruser@your-server`
- [ ] Out-of-band console access is available (KVM/VNC) — test it now, not during a lockout
- [ ] No unexpected users exist: `cat /etc/passwd | grep -v nologin | grep -v false`
- [ ] No unexpected services are listening: `sudo ss -tlnp`

### Network

- [ ] Server's public IP is known (for verifying UFW blocks it)
- [ ] Tailscale IP is assigned: `tailscale ip -4`
- [ ] No existing UFW rules conflict: `sudo ufw status verbose`

### Accounts & Access

- [ ] You can `sudo` on the server
- [ ] Your SSH keys (or Tailscale identity) are the only authorized access method

---

## 3. Supply Chain Verification

The deployment guide imports GPG keys for two third-party package repositories. Verify the key fingerprints before trusting packages signed by them.

### NodeSource GPG Key

The deployment guide imports the NodeSource signing key to install Node.js 22.x:

```bash
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
  | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
```

**After importing, verify the fingerprint:**

```bash
gpg --no-default-keyring --keyring /etc/apt/keyrings/nodesource.gpg --list-keys --keyid-format long
```

Expected fingerprint (as of 2026-02): `9FD3B784BC1C6FC31A8A0A1C1655A0AB68576280`

Verify this fingerprint against the [NodeSource documentation](https://github.com/nodesource/distributions#manual-installation) before proceeding.

### Docker GPG Key

The deployment guide imports the Docker signing key:

```bash
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
```

**After importing, verify the fingerprint:**

```bash
gpg --no-default-keyring --keyring /etc/apt/keyrings/docker.gpg --list-keys --keyid-format long
```

Expected fingerprint (as of 2026-02): `9DC858229FC7DD38854AE2D88D81803C0EBFCD88`

Verify this fingerprint against the [Docker documentation](https://docs.docker.com/engine/install/ubuntu/#set-up-the-repository).

### General Supply Chain Hygiene

- Never pipe `curl` output directly to `bash` or `sh` without reviewing the script first
- Pin package versions in production (`openclaw@2026.2.9`, not `openclaw@latest`)
- After importing any GPG key, verify its fingerprint against the publisher's official documentation
- Review `/etc/apt/sources.list.d/` to ensure only expected repositories are configured

---

## 4. Tailscale ACL Configuration

Tailscale ACLs control which devices on your tailnet can access which services. The deployment guide assumes Tailscale is configured, but ACLs must be explicitly set.

### Recommended ACL Policy

Configure this in the [Tailscale admin console](https://login.tailscale.com/admin/acls) (Access Controls):

```jsonc
{
  "acls": [
    // Admin access: your devices can SSH to the server
    {
      "action": "accept",
      "src": ["autogroup:admin"],
      "dst": ["tag:openclaw-server:*"]
    },
    // Deny all other access to the server
    // (implicit — Tailscale denies by default)
  ],

  "tagOwners": {
    "tag:openclaw-server": ["autogroup:admin"]
  },

  "ssh": [
    // Allow admin SSH to the server (Tailscale SSH, not port 22)
    {
      "action": "accept",
      "src": ["autogroup:admin"],
      "dst": ["tag:openclaw-server"],
      "users": ["autogroup:nonroot"]
    }
  ]
}
```

### Key Points

- **Tag the server** with `tag:openclaw-server` in the Tailscale admin console
- **Restrict SSH** to `autogroup:admin` (your admin account) — no one else should have SSH access
- **`autogroup:nonroot`** ensures SSH lands as your user, not root
- **Default deny** is implicit in Tailscale ACLs — anything not explicitly allowed is blocked
- **Review ACLs quarterly** or after adding new devices to your tailnet

### Tailscale Funnel Verification

Tailscale Funnel exposes services to the public internet. It must remain **OFF** for the OpenClaw gateway.

**Manual check:**

```bash
tailscale funnel status
# Expected: "No serve config" or empty funnel list
```

**Automated check (recommended cron):**

```bash
sudo tee /etc/cron.daily/openclaw-funnel-check << 'EOF'
#!/bin/bash
# Alert if Tailscale Funnel is accidentally enabled
if tailscale funnel status 2>&1 | grep -qi "funnel on\|AllowFunnel"; then
    logger -t openclaw-security "CRITICAL: Tailscale Funnel is ON — gateway may be publicly exposed!"
fi
EOF
sudo chmod 755 /etc/cron.daily/openclaw-funnel-check
```

---

## 5. Backup & Disaster Recovery

### What to Back Up

| Item | Path | Sensitivity | Backup Method |
|------|------|-------------|---------------|
| OpenClaw config | `/home/openclaw-svc/.openclaw/openclaw.json` | **SECRET** — contains gateway token | Encrypted backup only |
| Credentials directory | `/home/openclaw-svc/.openclaw/credentials/` | **SECRET** — API keys | Encrypted backup only |
| SOUL.md | `/home/openclaw-svc/.openclaw/SOUL.md` | Low — identity file, no secrets | Git or plain copy |
| SOUL.md baseline hash | `/var/lib/openclaw-soul-baseline.sha256` | Low | Git or plain copy |
| systemd unit file | `/etc/systemd/system/openclaw.service` | Low | Git or plain copy |
| Docker daemon config | `/etc/docker/daemon.json` | Low | Git or plain copy |
| UFW rules | `sudo ufw status verbose` output | Low | Save to file |
| iptables rules | `/etc/iptables/rules.v4` | Low | Included in iptables-persistent |
| Cron scripts | `/etc/cron.weekly/openclaw-*`, `/etc/cron.daily/openclaw-*` | Low | Git or plain copy |
| Tailscale ACLs | Tailscale admin console | Low | Screenshot or export |

### Backup Procedure

```bash
# Create encrypted backup of secrets
BACKUP_DIR="/tmp/openclaw-backup-$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Non-secret configs
sudo cp /etc/systemd/system/openclaw.service "$BACKUP_DIR/"
sudo cp /etc/docker/daemon.json "$BACKUP_DIR/"
sudo cp /var/lib/openclaw-soul-baseline.sha256 "$BACKUP_DIR/"
sudo cp /home/openclaw-svc/.openclaw/SOUL.md "$BACKUP_DIR/"
sudo cp /etc/cron.weekly/openclaw-* "$BACKUP_DIR/" 2>/dev/null
sudo cp /etc/cron.daily/openclaw-* "$BACKUP_DIR/" 2>/dev/null
sudo ufw status verbose > "$BACKUP_DIR/ufw-rules.txt"
sudo iptables -L DOCKER-USER -n -v > "$BACKUP_DIR/docker-user-iptables.txt"

# Secret configs (encrypt before transferring off-server)
sudo cp /home/openclaw-svc/.openclaw/openclaw.json "$BACKUP_DIR/openclaw.json.secret"
sudo cp -r /home/openclaw-svc/.openclaw/credentials/ "$BACKUP_DIR/credentials.secret/" 2>/dev/null

# Encrypt secrets
tar -czf "$BACKUP_DIR/secrets.tar.gz" -C "$BACKUP_DIR" openclaw.json.secret credentials.secret/
gpg --symmetric --cipher-algo AES256 "$BACKUP_DIR/secrets.tar.gz"
rm -f "$BACKUP_DIR/secrets.tar.gz" "$BACKUP_DIR/openclaw.json.secret"
rm -rf "$BACKUP_DIR/credentials.secret/"

echo "Backup at: $BACKUP_DIR"
echo "Transfer secrets.tar.gz.gpg to a secure off-server location"
```

### Recovery Procedure

1. Provision a fresh Ubuntu 25.10 server
2. Join it to your Tailscale tailnet
3. Follow the deployment guide from Phase 1
4. At Phase 2 (after creating the `openclaw-svc` user), restore secrets:

```bash
# Decrypt and restore
gpg --decrypt secrets.tar.gz.gpg | tar -xzf - -C /tmp/restore/
sudo cp /tmp/restore/openclaw.json.secret /home/openclaw-svc/.openclaw/openclaw.json
sudo cp -r /tmp/restore/credentials.secret/* /home/openclaw-svc/.openclaw/credentials/
sudo chown -R openclaw-svc:openclaw-svc /home/openclaw-svc/.openclaw/
sudo chmod 600 /home/openclaw-svc/.openclaw/openclaw.json
sudo chmod 700 /home/openclaw-svc/.openclaw/credentials/
rm -rf /tmp/restore/
```

5. Continue the deployment guide from Phase 5 (security hardening) onward

---

## 6. Credential Compromise Response

If you suspect any credential has been compromised:

### Immediate Actions (Do All)

```bash
# 1. Stop the gateway immediately
sudo systemctl stop openclaw.service

# 2. Kill any lingering processes
sudo pkill -u openclaw-svc

# 3. Capture logs for investigation
sudo journalctl -u openclaw.service --since "7 days ago" > /tmp/openclaw-incident-$(date +%Y%m%d).log

# 4. Check SOUL.md integrity
sudo sha256sum -c /var/lib/openclaw-soul-baseline.sha256

# 5. Check for unauthorized file changes
sudo find /home/openclaw-svc -newer /home/openclaw-svc/.openclaw/openclaw.json -ls

# 6. Check for rogue containers
sudo docker ps -a | grep openclaw
```

### Credential-Specific Rotation

| Credential | Rotation Steps |
|------------|---------------|
| **Gateway token** | Generate new: `openssl rand -hex 32`. Update both `gateway.auth.token` and `gateway.remote.token`. Restart service. |
| **Messaging bot token** | Revoke in your messaging platform's developer portal. Create a new bot/token. Update channel config. Restart service. |
| **LLM API key** | Revoke in your LLM provider's console. Generate new key. Update credentials. Restart service. |
| **LLM OAuth** | Revoke sessions in your LLM provider's console. Re-authenticate: `openclaw models auth login`. |
| **Tailscale** | Remove the compromised node from your tailnet. Re-join with a fresh auth key. Review ACLs. |
| **1Password SA token** (if using Appendix B) | Revoke the service account in 1Password console. Create a new SA with the same vault permissions. Update `/etc/openclaw/bootstrap.env` with the new token. Restart service. |

### Post-Rotation

```bash
# Re-run security audit
sudo -u openclaw-svc bash -c '
  cd ~ && export PATH=$HOME/.npm-global/bin:$PATH
  openclaw security audit --deep --fix
'

# Restart and verify
sudo systemctl start openclaw.service
sudo systemctl status openclaw.service
```

---

## 7. Incident Response Decision Tree

```
Incident detected
    │
    ├── Service won't start
    │     ├── Check logs: sudo journalctl -u openclaw.service -n 100
    │     ├── Check config syntax: openclaw doctor
    │     ├── Check token alignment: auth.token == remote.token?
    │     └── Check systemd: systemd-analyze security openclaw.service
    │
    ├── Unexpected API charges
    │     ├── Stop service immediately
    │     ├── Check session history: openclaw sessions list
    │     ├── Rotate LLM API key
    │     ├── Review rate limits in LLM provider console
    │     └── Restart with tighter tool policies
    │
    ├── SOUL.md integrity failure
    │     ├── Stop service immediately
    │     ├── Investigate: who modified it? (check auth.log, journal)
    │     ├── Restore from backup or re-deploy SOUL.md
    │     ├── Regenerate sha256 baseline
    │     └── Full security audit
    │
    ├── Unauthorized pairing attempt
    │     ├── Check pairing logs in journal
    │     ├── Deny the pairing: openclaw pairing deny <channel> <CODE>
    │     ├── Review paired devices: openclaw pairing list
    │     └── Consider rotating the messaging bot token
    │
    ├── Suspected host compromise
    │     ├── Stop service, kill processes (see §6 above)
    │     ├── Capture logs and forensic state
    │     ├── Rotate ALL credentials
    │     ├── Review Tailscale ACLs and device list
    │     ├── Consider full server rebuild from backup
    │     └── Full security audit post-recovery
    │
    └── Tailscale access lost
          ├── Use out-of-band console (KVM/VNC) if available
          ├── Check Tailscale status: tailscale status (from console)
          ├── Re-authenticate if needed: tailscale up
          └── See deployment guide Phase 10 for recovery options
```

---

## 8. 1Password Verification (If Using Appendix B)

These checks apply only if you've externalized secrets to 1Password per `openclaw-deployment-guide.md` Appendix B.

### Bootstrap Token Protection

- [ ] Bootstrap token file exists: `ls -la /etc/openclaw/bootstrap.env`
- [ ] Permissions are `root:root 0400`: `stat -c '%U:%G %a' /etc/openclaw/bootstrap.env`
- [ ] File is not world-readable: permissions must be `400`, not `444` or `644`
- [ ] The `openclaw-svc` user cannot read it directly: `sudo -u openclaw-svc cat /etc/openclaw/bootstrap.env` (must fail with "Permission denied")

### Service Account Permissions

- [ ] Service account has READ-only access to exactly one vault (the agent's vault)
- [ ] Service account cannot access other vaults: `sudo bash -c 'source /etc/openclaw/bootstrap.env && op vault list'` (must show only the agent's vault)

### Secret Resolution

- [ ] Service starts successfully with `op run`: `sudo systemctl status openclaw.service`
- [ ] No plaintext secrets in `openclaw.json` (if using Approach A): `sudo grep -c 'MANAGED_BY_1PASSWORD' /home/openclaw-svc/.openclaw/openclaw.json`
- [ ] systemd drop-in is loaded: `sudo systemctl cat openclaw.service` (should show `1password.conf` contents)

### Failure Recovery

- [ ] Documented procedure for restoring secrets to disk if 1Password is unreachable
- [ ] Bootstrap token is included in encrypted backup procedure (§5)

---

## 9. Security Review Schedule

| Frequency | Action |
|-----------|--------|
| **Daily** | Automated Tailscale Funnel check (cron) |
| **Weekly** | Automated deep security audit + SOUL.md integrity check (cron) |
| **Monthly** | Review Tailscale ACLs and device list. Review paired messaging accounts. |
| **Quarterly** | Rotate gateway token and LLM API key. Review UFW and iptables rules. |
| **On change** | Run `openclaw security audit --deep` after any config change, upgrade, or credential rotation |
| **On incident** | Full incident response per §7 above |
