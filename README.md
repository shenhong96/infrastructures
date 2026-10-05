# infrastructures

Config-as-code for the homelab: Ansible for the machines, Komodo for the apps, SOPS with age for secrets.

> **Status: scaffold.** Nothing here deploys anything yet. Deployment, rebuild and restore steps are added as they start working; until then they're marked pending.

## Layout

| Folder | What it owns |
|---|---|
| `ansible/` | The Proxmox host, the containers, the OS inside each one, and the three apps that aren't in Docker (GitLab, Jellyfin, Nextcloud). Runs from your Mac. |
| `komodo/` | Komodo's own settings: servers, the resource sync, the 5-minute deploy job. |
| `cloudflare/` | The Cloudflare zone: DNS, the geoblock rule, the tunnel and Access. Terraform Cloud plans it after a merge that touches it; you confirm the apply there. |
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

## Monitoring: the telemetry agent

Every machine runs the same Grafana Alloy agent from `stacks/monitoring/`; it sends to Prometheus and Loki on the Proxmox host (`stacks/host-monitoring/`), and the Grafana there shows the **Homelab · Machines & containers** dashboard. So far on `vpn`.

- **What it collects:** the machine (CPU, memory, disks, network, load, pressure, from the node_exporter built into Alloy: no separate exporter), each Docker container (CPU, memory against its limit, network, uptime, OOM kills), every container's logs, and its own health. Every series and log line carries `host`, `host_kind` and `vmid`.
- **Why it runs with the machine's network, processes, `/proc`, `/sys` and `/`:** so the numbers are the machine's, not the Alloy container's. Inside an LXC the `/proc` bind carries lxcfs, so memory and CPU are the LXC's share. Containers that share a network (host, or another container's) each show that network's total.
- **Why every 60s when the panels draw at 5 minutes:** Prometheus forgets a series 5 minutes after its last sample, so a 5-minute scrape would leave gaps.
- **Adding a machine:** add `stacks/monitoring/hosts/<name>.yaml` and a `[[stack]]` named `monitoring-<name>` in `stacks/monitoring/komodo.toml`; `tests/test_monitoring.py` checks the two match. If the machine is in the `node_exporter` group, take it out and remove the package once: `ansible <name> -m apt -a "name=prometheus-node-exporter,prometheus-node-exporter-collectors state=absent purge=true"` (from `ansible/`).
- **Adding a signal:** a new file in `stacks/monitoring/modules/` with one `declare` block, one block in `config.alloy`, and its `config_files` entry on every stack.
- **Changing a dashboard:** edit `tools/build_dashboards.py`, run it, commit the JSON. Grafana won't save an edit made in its UI.
- **Keeping a container's logs out:** give it the label `homelab.logs=false`.
- **Next, roughly in order:** the other machines (`apps` replaces `monitoring-apps`, `gitlab` and `nextcloud` replace Promtail, then `proxy` and the `node_exporter` role with it); the Proxmox host with `prometheus-pve-exporter` for every guest; machine logs from the journal; per-container disk I/O; Grafana alerts (an agent stale for 10 minutes, a disk over 90%, an OOM kill). Each but the first needs a policy exception.

## Cloudflare

`cloudflare/` is applied by Terraform Cloud (org `ahlooii`, workspace `cloudflare`), never from a laptop: a merge that touches it starts a plan, and nothing changes until you confirm it there. PRs get no plan, on purpose: a plan runs with the Cloudflare token, so it only runs on merged code.

- The API token and the Access email lists are workspace variables in Terraform Cloud. Proxied-origin IPs, emails and tokens always come from variables, never from code.
- The tunnel token and the Access service token are sensitive outputs: read them from the workspace's latest state in Terraform Cloud.
- The tunnel is the only way in to what it fronts: don't add a direct route around it.

## Not working yet

Deploying anything (the Ansible roles, Komodo), rebuilding from scratch, and backups and restores. Each section is added here once it has been shown to work.
