# Working on this repo

This repo is public and runs a homelab: a merge to `main` is live within minutes.

- Work on a branch and open a pull request against `main`. Never merge, turn on auto-merge or push to `main`: GitHub refuses, and only the owner merges.
- Every PR gets two checks. `ci` runs the tests (`python -m unittest discover tests`), `ansible-lint ansible/`, the playbook syntax check and `docker compose config` for each stack. `gate` is the security check, run from `main`'s code; its comment on the PR lists what blocks and what to look at. Watch both checks after every push, and fix what blocks; never work around a rule.
- A change to the gate's own files (`.github/`, `policy/`, `.githooks/`, `komodo/`, `.sops.yaml`, `.gitleaks*`, `.gitattributes`, Ansible's config, inventory, `known_hosts`, collections and plugin folders, and the `semaphore` and `github` roles) needs the owner's `gate-change` label. Say so in the PR description; never add the label yourself. Any push takes it off again.
- Your GitHub token can't push files under `.github/workflows/`: GitHub refuses them. Describe a workflow change in the PR instead.
- Never commit a secret. Secrets are SOPS-encrypted `*.sops.*` files, and editing them needs the owner's laptop: describe the change in the PR instead.
- Compose settings that reach the host (`privileged`, `docker.sock`, host system paths, host namespaces, `cap_add`, `devices`) are blocked unless `policy/exceptions.toml` lists them, and that file is a gate file.
- After a merge, Komodo deploys the changed stacks and Semaphore applies the Ansible tags `base`, `samba`, `gitlab`, `jellyfin`, `nextcloud`, `proxy` and `node_exporter`, each within 5 minutes. Changes under the other tags (the gate's summary says "Needs a laptop run") still need a laptop run. Terraform Cloud applies `cloudflare/` on merge; its speculative plan on the PR shows what will change.
