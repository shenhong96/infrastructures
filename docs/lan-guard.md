# Proxmox LAN guard: complete, staged source enforcement

This is optional defense in depth, **not** a replacement for diag's authenticated
transport or a guarantee against physical LAN devices. It is off by default.
The existing cluster firewall must already be enabled on the iptables backend;
the host firewall remains off and Docker FORWARD must remain ACCEPT. The tool
never changes sysctls, restarts guests, starts stopped guests, flushes tables or
changes the host firewall. Changes are laptop-run only.

## 1. Read-only inventory

Use the focused playbook, not the broad host role. From `ansible/`:

```sh
ansible-playbook diag-security.yml -e diag_security_action=guard-inspect \
  -e diag_security_maintenance_ack=true
```

`guard-inspect` executes the checked-in helper without installing or writing any
file on the target. It prints a JSON skeleton containing the exact package
version, all CT/QEMU IDs including stopped 117/401, full NIC strings, MACs and
hashes of existing guest firewalls. No credential/configuration bodies or guest
descriptions are printed. Save the JSON from its result as an owner-only local
manifest. Do not mistake discovery for policy: empty address arrays, `REVIEW`
actions and false review flags deliberately cannot be applied.

Review each actual guest, extra NIC, namespace/router/floating address and CT118
Docker source requirement; inspect guest IPv6 including privacy addresses. VM107
and VM401 need their actual reserved addresses/leases and probe/reboot behavior,
not an address guessed from PVE config. All live guest IDs and NICs must appear;
no exclusion can qualify for global enablement.

## 2. Owner-reviewed manifest

Use the generated full NIC strings/MACs, not the example below. Make every guest
`action: enroll` and fill its source policies. Example shape only:

```json
{
  "pve_firewall_version": "EXACT_INSTALLED_DPKG_VERSION",
  "compiled_rules_verified": false,
  "guests": [
    {
      "vmid": "101",
      "kind": "ct",
      "action": "enroll",
      "existing_firewall_sha256": null,
      "nics": {
        "net0": {
          "config": "FULL_ORIGINAL_NIC_STRING_FROM_INSPECT",
          "mac": "EXACT_OBSERVED_MAC",
          "ipv4": ["192.168.9.153/32"],
          "ipv6": [],
          "dhcp": false,
          "ipv6_reviewed": true,
          "egress_sources_reviewed": true
        }
      }
    }
  ]
}
```

Supply the **whole** object, not just its guests, in a private variable file:

```yaml
proxmox_host_lan_guard_manifest:
  # paste the reviewed manifest fields here as YAML, or use JSON variable syntax
```

`existing_firewall_sha256` must match the reviewed existing file (or be null for
absent). This authorizes replacing VM401's disabled policy or other owner rules,
so review every such replacement. Subsequent runs accept the exact generated
file, allowing idempotency without weakening the initial adoption guard. Unknown
new rules, NIC/MAC/bridge/VLAN changes, extra IDs and duplicate allowed addresses
are refused. Per-interface lists only accept host /32 and /128 entries, not a
whole /24. PVE implicit CT addresses must also appear in policy. CT dynamic IPv6
`auto`/`dhcp` is refused until a stable source policy exists; empty IPv6 means no
explicit global IPv6 allowance, **not** that IPv6 was disabled by this tool. PVE
may add the NIC-derived link-local address implicitly. IPv6 privacy addresses and
NDP exceptions must be included in the later live tests.

For **121**, set `preserve_firewall: true` and its current secure `121.fw` hash.
The tool will not generate an open policy for it; default DROP, enable, MAC and
IP filtering must all remain present. Changes to its firewall hash require a new
reviewed manifest. It is not an unenforced exclusion; the existing role owns its
narrow policy.

For **QEMU**, `kind: vm`, use the full actual `virtio=...`/`e1000=...` etc NIC
string from `qm config`; specify the exact stable IPv4 and IPv6 addresses.
For DHCP set `dhcp: true`, require a fixed reservation/lease, then explicitly set
`dhcp_lease_reviewed: true` and `arp_probe_reviewed: true`. If installed-version
lab testing shows zero-source IPv4 ARP probes are required, explicitly set
`allow_arp_probe: true`. Only that reviewed DHCP case adds `0.0.0.0/32` to its
interface set. It also permits source 0 at IP layer, so it is not a generic
exception to copy to every guest. Never add a whole subnet to accommodate DHCP.
Older/newer pve-firewall versions differ in empty-set ARP behavior; this code
requires nonempty normal host lists and separately compiles the installed code.

## 3. Check, enroll, then separately enable

No `--limit`, `--tags`, or automatic guest restart:

```sh
ansible-playbook diag-security.yml -e @/absolute/private/guard-vars.yml \
  -e diag_security_maintenance_ack=true -e diag_security_action=guard-check
ansible-playbook diag-security.yml -e @/absolute/private/guard-vars.yml \
  -e diag_security_maintenance_ack=true -e diag_security_action=guard-apply
```

`guard-check` is read-only. `guard-apply` validates the **whole** manifest before
writing any NIC/firewall, then saves an exact mode-0600 operation backup under
`/var/lib/proxmox-lan-guard/backups/`. It preserves full NIC definitions, changing
only `firewall=1` via `pct set`/`qm set`. Any guest whose flag must change (110,
116, 107 in the supplied snapshot) must already be stopped; the script refuses
to interrupt a running guest. **Required step:** `ansible/inventory.yml` is the
source of truth for NIC flags, so first add `firewall=1` to every `pct` `net*`
line of each enrolled inventory-managed CT (CT110/116 still lack it; 118 and 121
already have it). `guard-check/apply/enable` refuse until it is there, because the
ordinary `lxc` adoption would otherwise revert the flag. No firewall-file marker
is trusted for this: a GUI edit can drop it. Remove `firewall=1` from inventory
only after rolling back that guest's enrollment. The guard also detects subsequent
drift; it is not an admission controller for unrelated PVE operators or new guest
starts.

Enabling a guest firewall/IP filter can affect traffic immediately, even while
cluster `ebtables: 0`; ACCEPT policies do not bypass MAC/IP source restrictions.
Plan the stopped-guest/service window accordingly. Guests with existing rules
must not have their required behavior silently erased by an unreviewed hash.

After enrollment, inspect `pve-firewall compile`, bridge attachment and actual
IP/IPv6 source sets. Verify DHCP reservation, renew/reboot and ARP probes, CT118
Docker egress, each guest service and all expected source addresses. Then set
`compiled_rules_verified: true` only after installed-version review, and run:

```sh
ansible-playbook diag-security.yml -e @/absolute/private/guard-vars.yml \
  -e diag_security_maintenance_ack=true -e diag_security_action=guard-enable
```

`guard-enable` refuses if enrollment still has pending changes. It calls the
installed Perl compiler with an **in-memory** `ebtables=1` override and checks
expected per-interface ARP allows/drop, MAC and source-filter output before
writing that one option in cluster.fw. No iptables/nftables backend switch or host
firewall change occurs. Existing cluster content is preserved. The normal host
firewall task only writes cluster.fw when it is absent (first install) and never
resets an existing file's ebtables or emergency `enable: 0`.

A successful compilation is not proof of packet traversal: after PVE reconciles,
inspect `ebtables-save`, `iptables-save`, `ip6tables-save`, `ipset list`,
`pve-firewall status`, per-NIC attachment/counters and actual traffic. Repeat after
a reboot/approved Ansible run. Docker's chain order and kernel bridge netfilter
are live acceptance requirements, not properties a mocked unit test can prove.

## 4. Per-operation rollback

The tool reports the exact JSON backup path **before** its first config mutation.
Keep that handle in the maintenance log. If a write fails half-way, targets still
at their original value are safe no-ops during rollback. Changed-by-someone-else
targets are refused before any rollback write. Restoring a NIC flag requires its
guest to be stopped. On the Proxmox console, using that exact returned path:

```sh
python3 /usr/local/sbin/lan-guard rollback \
  --backup /var/lib/proxmox-lan-guard/backups/EXACT_RETURNED_HANDLE.json
```

The role installs the rollback helper after successful operations; if an initial
apply fails before that installation, copy/run this PR's
`ansible/roles/proxmox_host/files/lan_guard.py` from the laptop. Backups contain
only network config/firewall policies and are protected owner-only. A rollback
only touches targets in its backup; it never flushes whole tables. Roll back
`guard-enable` first if disabling the new ARP layer, then the selected enrollment
operation. Newly created guest firewall files are removed only when that exact
operation recorded them absent. Reconcile desired manifest/inventory afterward
so a subsequent apply cannot recreate the failed policy.

For host/bridge failure only, use the console emergency procedure in
[diag-security.md](diag-security.md): cluster `enable: 0`, verify reconciliation,
then both bridge-netfilter sysctls to zero, with the explicit loss-of-isolation
warning. Do not use that global escape for a simple individual guest problem.

The isolated, nonpersistent spoofing test and remaining physical-LAN limits are
also in that runbook. No spoofing packets, guest changes or live rule tests were
run while preparing this PR.
