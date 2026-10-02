# infrastructures

Config-as-code for the homelab: Ansible for the machines, Komodo for the apps, SOPS with age for secrets.

> **Status: scaffold.** Nothing here deploys anything yet. Deployment, rebuild and restore steps are added as they start working; until then they're marked pending.

## Layout

| Folder | What it owns |
|---|---|
| `ansible/` | The Proxmox host, the containers, the OS inside each one, and the three apps that aren't in Docker (GitLab, Jellyfin, Nextcloud). Runs from your Mac. |
| `komodo/` | Komodo's own settings: servers, the resource sync, the 5-minute deploy job. |
| `stacks/<project>/` | One folder per Compose project as it runs today: `compose.yaml`, `komodo.toml`, and `secrets.sops.env` where it has secrets. Flat, not grouped by machine. |

This repo is public. Every secret in it is SOPS-encrypted; nothing secret is ever committed in plain text.

## Setup on a fresh clone

Checked with sops 3.12.2, age 1.3.1, gitleaks 8.30.0, ansible-core 2.20.1 and ansible-lint 26.1.1.

```sh
git config core.hooksPath .githooks   # every clone: turns on the secret checks
cd ansible && ansible-galaxy collection install -r requirements.yml -p collections
```

## Secret checks

`.githooks/pre-commit` refuses a commit when:
- gitleaks finds a possible secret in the staged changes;
- a staged `*.sops.*` file has any plaintext value or no SOPS metadata. It checks the staged copy, so encrypting a file after `git add` doesn't help: stage it again;
- a file that must never be committed is staged (`.env`, `secrets.env`, key files, Terraform state, `cryptkey`), or anything contains ansible-vault data.

After changing the hook, check it by hand with fake values only. Each of these must be refused:
1. a plaintext `x.sops.env` containing `DB_PASS=fake`;
2. a private key: `ssh-keygen -t ed25519 -N '' -f deploy_key`, then stage `deploy_key`;
3. `y.sops.env` staged in plaintext, then encrypted with `sops -e -i` without staging it again.

A valid encrypted `.sops.yaml` and `.sops.env` must still commit cleanly. GitHub push protection is the second line of defence if the hook is ever skipped.

## Secrets

Two age keys, set in `.sops.yaml` (the first matching rule wins):

| Key | Lives in | Opens |
|---|---|---|
| `admin` | your Mac (`~/.config/sops/age/keys.txt`, via `SOPS_AGE_KEY_FILE`), Bitwarden, one offline copy | everything |
| `lab` | stored encrypted as `lab_age_key` in `ansible/group_vars/all/secrets.sops.yml`; Ansible puts it on each Komodo agent machine (pending, Phase 3) | the encrypted files under `stacks/`, except `stacks/komodo/` |

**Editing a secret:** `sops <file>` opens it decrypted in your editor and encrypts it again on save. Create a new secrets file the same way, at its final path, so the right rule picks its keys.

**Opaque config files:** a whole config file that names things or holds keys is committed as one encrypted value, `NAME.sops.yaml` (`tools/sops-blob new|edit`). The Komodo agent decrypts it before a deploy (`komodo-decrypt-files`) into `.decrypted/`, which the compose file bind-mounts read-only. The hook and the tests refuse the plaintext twin.

**Where the secrets came from:** moved from ansible-vault on 2026-09-29, with values unchanged: 58 keys, the disk key (`cryptkey_b64`, base64), AdGuard's config (encrypted) and `crypttab` (plaintext: device paths and a key-file path only). 33 keys weren't carried over: Oracle-Arm, the workstation, thanos and kubernetes groups, `mysql_db`, and values nothing uses or that belong to guests that no longer exist. App values are provisional until Phase 3 compares them with what's running.

**If a key leaks:**
1. Make a new key and put it in `.sops.yaml`.
2. Run `sops rotate -i --rm-age <leaked key> --add-age <new key> <file>` on every file the leaked key could open. This gives each file a new data key; `sops updatekeys` alone isn't enough, because the leaked key could still recover the old data key from git history.
3. Change the secret values themselves, then commit and push: the old values stay readable in the history.
4. Put the new key where it lives: `admin` in `keys.txt`, Bitwarden and the offline copy; `lab` by re-running Ansible's `base` role (pending).

## GitLab, Jellyfin and Nextcloud: what a rebuild gives back

The `gitlab`, `jellyfin` and `nextcloud` roles put the software and its config files back; they don't restore data. Ansible on a fresh container gives you a working install with empty content.

- **GitLab and Jellyfin:** GitLab's data (`/var/opt/gitlab`) and Jellyfin's library database and settings (`/var/lib/jellyfin`, `/etc/jellyfin`) live only on the container's root disk. Only a CT dump restores them. A fresh install gives empty apps.
- **Nextcloud fallback:** the role installs the stack and, only if `/var/www/nextcloud/occ` is missing, the 30.0.4 code (sha256 checked). It never touches `config.php`, the data folder or `/var/lib/mysql`. Then restore a database dump if there is one; if not, run `occ maintenance:install` and `occ files:scan --all`. Shares, calendars and contacts are lost that way.

## Proxy: what a rebuild gives back

The `proxy`, `node_exporter` and `base` roles put the files Caddy reads back; Komodo runs the stack (`stacks/proxy/compose.yaml` and `Dockerfile`, from its own clone), so Ansible places neither.

- **What Ansible delivers:** `prometheus-node-exporter` on :9100, and under `/opt/caddy/` the `conf/Caddyfile` from `stacks/proxy/`, the empty `data/` and `config/` folders, and `.env` (from `host_vars/proxy/secrets.sops.yml`, root-only). The Caddyfile holds no secret: the Cloudflare token and the ACME email come from `.env` as `{env.CF_API_TOKEN}` and `{env.ACME_EMAIL}`.
- **First start (one-off, ad hoc, before Komodo owns it):** from a clone of the repo, `cd stacks/proxy && docker compose -p proxy up -d --build` (the compose file's `.env` is `/opt/caddy/.env`, an absolute path). It builds the pinned Caddy 2.8.4 with the Cloudflare DNS and caddy2-filter plugins. With an empty `data/` Caddy asks Let's Encrypt for a new `*.ahlooii.com` wildcard by DNS-01, which takes one to three minutes.
- **Changing the Caddyfile:** run `--tags proxy`; the handler reloads Caddy in the running container. A changed `.env` (a new token) needs a Komodo redeploy of `proxy` (or `up -d` from its clone): an env file is read only when the container is created.
- **Secrets:** the two keys in `.env` are `CF_API_TOKEN` and `ACME_EMAIL`. Caddy's certificate and ACME account (`/opt/caddy/data`) are not in the repo; they are re-issued on their own.
- **Container:** Ubuntu 24.04 with Docker 29 needs the raw key `lxc.mount.entry: /dev/null sys/module/apparmor/parameters/enabled none bind 0 0` in the inventory, as on `apps`, or `docker run` fails on the AppArmor check.

## Drift snapshot and heartbeats

**Pending:** code and templates exist (`roles/proxmox_host/files/config-snapshot.py`, `files/job-heartbeat`, `tasks/snapshot.yml`, `tasks/monitoring.yml`); nothing has run on the host. `heartbeats_enabled`/`snapshot_enabled` (`host_vars/proxmox/main.yml`, both `false`) keep both task files out of every run, including a plain `--check`, so the missing secrets below never break an ordinary pass; the commissioning step flips them to `true`, at which point each still `assert`s its own secrets are set and fails loudly if they're not. The nightly timer installs disabled (`snapshot_timer_enabled: false`); Phase 6 enables it and accepts the first successful scheduled run as the baseline.

**What's collected (sanitized, then pushed to a private repo):** per machine, installed packages, enabled/active systemd units, crontabs, and (where `docker: true`) running Compose projects' config files and image identities; on the Proxmox host also the non-secret `/etc/pve` guest/cluster config (an allowlist, never `priv/` or any key material), network config, fstab, crypttab, SnapRAID/sanoid config; everywhere, the `snapshot_paths` explicitly declared per machine in `host_vars/<machine>/main.yml` (AdGuard, Caddy, Samba, GitLab, Jellyfin's XMLs, the host's `sanoid.sh`/`lxc_off.sh`). Every credential-shaped value (passwords, tokens, keys, API secrets, session/signing keys, connection-string userinfo, bcrypt/argon hashes) is redacted before anything touches disk; gitleaks re-checks the whole sanitized candidate before it's committed.

**Never collected:** `.env`/`secrets.env`/`*.sops.*`, private keys and certificates, credential files, the disk's LUKS key file (resolved from `/etc/crypttab`), this tool's own config and workspace, `/etc/shadow`, resolved container environments, app databases, and arbitrary home directories. Nextcloud's `config.php` is deliberately excluded (PHP, rewritten by the app itself). A file that should never be there failing to redact cleanly aborts the whole run rather than committing a partial, misleading snapshot.

**Handling a drift alert:** every notification means the live configuration no longer matches what's declared. Three responses, depending on which is true:
1. **The change is wanted:** declare it — edit the Ansible role/template or the Komodo stack definition so the repo describes the new, intended state, then commit. The next snapshot should then show no diff.
2. **The change is unwanted:** undo it by re-running the relevant Ansible role, or by redeploying the stack through Komodo, so the machine goes back to matching the repo. Never hand-edit the live file and call it fixed; that's exactly the drift this exists to catch.
3. **The setting only exists in a database** (an app's own admin UI, not a file): the snapshot can't see or restore it. Recovery relies on that app's own data backup (Phase 5), not on this repo.

**SOPS keys to add** (admin-only, `host_vars/proxmox/secrets.sops.yml`; `sops ansible/host_vars/proxmox/secrets.sops.yml`):
| Key | Used by |
|---|---|
| `snapshot_deploy_key` | config-snapshot's push access to the private `infrastructures-snapshot` repo (write-only, scoped to that one repo) |
| `snapshot_gotify_token` | the `config-snapshot` app's token in Gotify, for the drift notification |
| `healthchecks_ping_key` | job-heartbeat's ping key for every check in `heartbeat_checks` |
| `healthchecks_api_key` *(optional)* | a read-write healthchecks.io API key; lets Ansible create/reconcile the checks by slug instead of someone doing it by hand |

**New host root-crontab lines (now in SOPS's `secret_crontabs_b64`, no longer pending, but not deployed until `heartbeats_enabled` is flipped):** schedules unchanged, each wrapped in `job-heartbeat` so a missed or failed run alerts externally:
```
0 0 * * 6 /usr/local/bin/job-heartbeat snapraid -- python3 /opt/snapraid-runner/snapraid-runner.py -c ~/.snapraid-runner.conf
*/5 * * * * /usr/local/bin/job-heartbeat sanoid -- bash /root/scripts/sanoid.sh
```
Before this change the lines were the same commands without the wrapper, and SnapRAID's also ended in `&& curl … <self-hosted ping URL>`. Only the `job-heartbeat` prefix is new (decision 6 also drops SnapRAID's existing ping to the self-hosted Healthchecks instance, which the hosted check replaces). The other three existing host cron jobs (`chmod`, `lxc_off.sh`, a Saturday `rename…` job) get no heartbeat (decision 16). The `base` role asserts that a crontab mentioning `job-heartbeat` is only deployed when `heartbeats_enabled` is true, since otherwise the wrapper would be missing and these jobs would silently stop.

## Not working yet

Deploying anything (the Ansible roles, Komodo), rebuilding from scratch, and backups and restores. Each section is added here once it has been shown to work.
