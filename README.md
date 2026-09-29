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

## Not working yet

Deploying anything (the Ansible roles, Komodo), rebuilding from scratch, and backups and restores. Each section is added here once it has been shown to work.
