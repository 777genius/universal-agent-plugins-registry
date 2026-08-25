# Observer operations

This is the preflight and deployment checklist for one **fresh, disposable,
Linux x86-64 observer host**. It is not an upgrade procedure. Use only fresh
dedicated test identities and synthetic disposable Git roots. Never copy Mac
authentication, a saved home, cookies, tokens, or client profiles to this host,
and never point an observer client at a real project.

## 1. Freeze and verify the inputs

Set the approved 40-hex commit supplied with the release record; do not use a
branch name. Work from an offline-delivered checkout and record command output
in a non-secret change ticket.

```sh
SOURCE_ROOT=/opt/uap-observer
REVIEWED_COMMIT=<approved-40-hex-commit>
test "$(git -C "$SOURCE_ROOT" rev-parse HEAD)" = "$REVIEWED_COMMIT"
test -z "$(git -C "$SOURCE_ROOT" status --porcelain --untracked-files=all)"
git -C "$SOURCE_ROOT" fsck --no-dangling
(cd "$SOURCE_ROOT" && sha256sum -c deploy/uap-observer-runtime.sha256)
```

Record `REVIEWED_COMMIT`, the runtime-manifest digest, and the deployment input
digests below. Do not record the signing key or profile contents.

```sh
sha256sum "$SOURCE_ROOT/deploy/uap-observer-runtime.sha256" \
  /root/uap-observer-adapter-config.json /root/uap-observer.json \
  /root/Caddyfile /root/caddy_2.11.4_linux_amd64.tar.gz \
  /root/uap-observer-egress-allowlist.json
```

The Caddy archive must be the official Linux amd64 v2.11.4 archive with SHA-256
`527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9`.
The adapter config must validate against
`deploy/uap-observer-adapter-config.schema.json`. The protected input tree and
installer-managed deployment files are:

| Artifact | Installed path | Mode |
| --- | --- | --- |
| Git, Codex, Cursor, Kiro native executables | `/opt/uap-observer-inputs/bin/{git,codex,cursor,kiro}` | root-owned `0755` regular files |
| ChatGPT app binding and projection receipt | `/opt/uap-observer-inputs/chatgpt/{app-binding.json,projection-receipt.json}` | `root:uap-observer-adapter-config`, `0640` |
| independently captured external-PR evidence | `/opt/uap-observer-inputs/external-pr-evidence.json` | `root:uap-observer-adapter-config`, `0640` |
| operator-approved proxy FQDN allowlist | `/opt/uap-observer-current/etc/uap-observer-egress-allowlist.json` | `root:root`, `0644`, one-link regular file |
| repository proxy executable | `/opt/uap-observer-current/libexec/uap-observer-egress-proxy` | `root:root`, `0755`, one-link regular file |
| repository proxy units | `/opt/uap-observer-current/systemd/` and `/etc/systemd/system/uap-observer-egress-proxy.{socket,service}` | `root:root`, `0644`, one-link regular files |

The proxy executable and units are repository source/runtime-closure files, not
separate operator inputs. The installer copies and verifies them. Do not stage
or copy units into `/etc/systemd/system` manually.

There may be no other entries under `/opt/uap-observer-inputs`; directories
must be root-owned and not group/other-writable. Every file must have one hard
link, no path may be a symlink, and every `sha256:` in the adapter config must
match its bytes. The external PR record must validate against
`tests/e2e/schemas/external-pr-evidence.schema.json`, identify a genuinely
external unmerged PR, and bind its successful head checks to the exact release
and Directory identity. A local fork simulation is not sufficient.

Build that exact tree from the approved, digest-recorded input directory. The
group creation is safe before the idempotent installer creates the remaining
service identities.

```sh
getent group uap-observer-adapter-config >/dev/null || \
  groupadd --system uap-observer-adapter-config
install -d -o root -g root -m 0755 /opt/uap-observer-inputs \
  /opt/uap-observer-inputs/bin /opt/uap-observer-inputs/chatgpt
for name in git codex cursor kiro; do
  install -o root -g root -m 0755 "/root/approved-inputs/$name" \
    "/opt/uap-observer-inputs/bin/$name"
done
for name in app-binding.json projection-receipt.json; do
  install -o root -g uap-observer-adapter-config -m 0640 \
    "/root/approved-inputs/$name" "/opt/uap-observer-inputs/chatgpt/$name"
done
install -o root -g uap-observer-adapter-config -m 0640 \
  /root/approved-inputs/external-pr-evidence.json \
  /opt/uap-observer-inputs/external-pr-evidence.json
python3 -m jsonschema -i /root/uap-observer-adapter-config.json \
  "$SOURCE_ROOT/deploy/uap-observer-adapter-config.schema.json"
sha256sum /opt/uap-observer-inputs/bin/* \
  /opt/uap-observer-inputs/chatgpt/* \
  /opt/uap-observer-inputs/external-pr-evidence.json
```

Use exact, approved Linux client binaries at the paths above, not wrappers.
Create authentication independently on this disposable host with dedicated
test accounts. For each pinned binary, use a separate empty root such as
`/root/profile-seeds/{codex,cursor,kiro}`, set `HOME`, `XDG_CONFIG_HOME`, and
`XDG_CACHE_HOME` inside that root, and additionally set `CODEX_HOME` inside the
Codex root. Never share a profile between clients.

Exercise one real, non-secret network request from **each exact pinned binary**
with `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` set to the approved test proxy
and `NO_PROXY` empty. During this preflight, block direct Internet egress for
the login process and retain sanitized proxy connection metadata plus the
binary SHA-256 and exit result. A successful version-only command is not a
proxy test. Stop if any client bypasses or ignores the proxy.

Use only the clients' supported fresh-host login paths: Codex supports
`codex login --device-auth`; Cursor supports `NO_OPEN_BROWSER=1 login`
(invoke the pinned Cursor executable's `login` command) and API-key
automation; Kiro supports its remote device flow and `KIRO_API_KEY` headless
mode. API keys may be supplied only transiently to the login/preflight process:
never put them in a script, image, adapter config, service environment, or
evidence. Prefer device flow for the persistent test profile. Confirm that the
three completed seed trees contain only that client's disposable-host profile,
then make the seed directories and entries root-owned and non-group/other-
writable before provisioning.

The installed profiles are isolated at
`/var/lib/uap-observer/profiles/{codex,cursor,kiro}` with client-specific
ownership, `0700` directories, and `0600` files. The helper refuses a non-empty
destination. Do not use any seed exported from a Mac or normal workstation,
and never bake credentials into the source checkout or protected input tree.

The operator must provide the proxy allowlist as an immutable deployment input,
not derive it during installation. It is canonical JSON with exactly
`schema_version` set to `1` and a non-empty `hosts` array of bytewise-sorted,
unique, exact lowercase ASCII FQDNs. The JSON has no extra keys or insignificant
whitespace and ends with one LF. Hosts have no ports, URLs, IP literals, leading
dots, or wildcards. The set must equal the HTTPS hosts in the final adapter and
observer configs; the installer checks that equality. Review the current
provider-owned host list for Codex, Cursor, Kiro, GitHub, and the configured
ChatGPT MCP before approving it; redirects and CDN hosts are separate exact
entries and are never implicitly trusted. Record this exact tuple in the change
ticket:

```text
EGRESS_ALLOWLIST=/root/uap-observer-egress-allowlist.json
EGRESS_SHA256=sha256:<64-lowercase-hex>
EGRESS_ALLOWLIST_MODE=0:0:644:1
```

Validate it only after checking its recorded digest, ownership, mode, link
count, and canonical form. The repository socket listens only on
`127.0.0.2:8766`; the repository service reads the closure copy of that exact
input, fails closed on malformed or unlisted CONNECT targets, resolves names
itself, and provides no transparent or direct-fallback mode.

```sh
test "$(stat -c '%u:%g:%a:%h' "$EGRESS_ALLOWLIST")" = \
  "$EGRESS_ALLOWLIST_MODE"
test "sha256:$(sha256sum "$EGRESS_ALLOWLIST" | cut -d' ' -f1)" = \
  "$EGRESS_SHA256"
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  "$SOURCE_ROOT/deploy/uap-observer-egress-proxy.py" \
  --config "$EGRESS_ALLOWLIST" --validate-config
```

For each exact pinned client, perform the earlier real-request proxy preflight
with `HTTP_PROXY=http://127.0.0.2:8766`,
`HTTPS_PROXY=http://127.0.0.2:8766`, `ALL_PROXY=http://127.0.0.2:8766`, and
an explicitly empty `NO_PROXY`. Repeat once with the proxy stopped while the
operator-managed host firewall rejects the process's direct egress; the request
must fail. A client passes only if the running-proxy request appears
in sanitized proxy connection metadata and the stopped-proxy request cannot use
a direct path. Every observed provider hostname must already be an exact host in
the final configured set. On any discrepancy, stop, revise and re-review the
configs and allowlist together, re-digest them, and repeat every preflight;
never add an allowlist-only exception or direct fallback to make it pass.

## 2. Identity, network, and GitHub

Generate a new root Ed25519 key on this host. Store canonical base64 of its raw
32-byte private value at `/etc/uap-observer-ed25519.key`, owned by root with
mode `0600` and one hard link. Put canonical base64 of the corresponding raw
32-byte public value in `deploy/uap-observer.json`'s
`public_key_base64`; keep key ID `uap-stable-launch-2026-08`. Publish only this
non-secret identity tuple:

```sh
umask 077
python3 - <<'PY'
import base64, os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

private = Ed25519PrivateKey.generate()
key_path = Path("/etc/uap-observer-ed25519.key")
with key_path.open("xb") as stream:
    stream.write(base64.b64encode(private.private_bytes_raw()) + b"\n")
    stream.flush()
    os.fsync(stream.fileno())
os.chmod(key_path, 0o600)
public = base64.b64encode(private.public_key().public_bytes_raw()).decode()
Path("/root/uap-observer-public-key.txt").write_text(public + "\n")
PY
PUBLIC_KEY="$(tr -d '\n' </root/uap-observer-public-key.txt)"
jq --arg public_key "$PUBLIC_KEY" \
  '.public_key_base64 = $public_key' \
  "$SOURCE_ROOT/deploy/uap-observer.json" >/root/uap-observer.json
chmod 0644 /root/uap-observer.json
test "$(stat -c '%u:%g:%a:%h' /etc/uap-observer-ed25519.key)" = "0:0:600:1"
```

Run this only where pinned `cryptography` is already available, and never print
or copy the private value. Record the public file's value and key ID together.

```text
STABLE_LAUNCH_OBSERVER_KEY_ID=uap-stable-launch-2026-08
STABLE_LAUNCH_OBSERVER_ED25519_PUBLIC_KEY=<44-character-base64-public-key>
```

In repository variables, set those two values. In the protected
`stable-launch-e2e` environment, set
`STABLE_LAUNCH_OBSERVER_ENDPOINT=https://<observer-fqdn>/v1/stable-launch/observe`
and require the intended human reviewer. Do not create a GitHub secret for any
of these non-secret values. Confirm the `directory-publication` protections and
that the reusable protected job has `id-token: write`; the observer policy
accepts only `push`, `schedule`, and `workflow_dispatch` from the exact main-ref
workflow identity.

Replace `observer.example.invalid` in a copy of `deploy/Caddyfile` with the
public observer FQDN. Create public A (and AAAA only when IPv6 is actually
routed) DNS records before starting Caddy. In the operator-managed host
firewall, permit inbound TCP 80/443, restrict SSH to the administration source,
permit the proxy's required outbound DNS/HTTPS, and reject every direct Internet
path from observer and client processes. Do not expose port 8765 or 8766. The
repository does not install UID-, cgroup-, or service-identity firewall rules,
so do not claim that a service account alone provides this isolation: select,
document, and test concrete firewall mechanics for the host. Separately,
installer-created systemd drop-ins apply `IPAddressDeny=any` with only the
required loopback allowances to the observer and runner services; those unit
controls do not replace the host firewall. Cloud images with
`manage_etc_hosts: true` overwrite `/etc/hosts`, so do not use a local hosts
entry as persistent DNS configuration.

## 3. Install and start

First compute the three `sha256:` arguments from the final adapter, observer,
and Caddy configs. As root, run the reviewed installer exactly once:

```sh
ADAPTER_SHA256="sha256:$(sha256sum /root/uap-observer-adapter-config.json | cut -d' ' -f1)"
OBSERVER_SHA256="sha256:$(sha256sum /root/uap-observer.json | cut -d' ' -f1)"
CADDY_SHA256="sha256:$(sha256sum /root/Caddyfile | cut -d' ' -f1)"
"$SOURCE_ROOT/deploy/uap-observer-install.sh" "$SOURCE_ROOT" \
  /root/uap-observer-adapter-config.json "$ADAPTER_SHA256" \
  /root/uap-observer.json "$OBSERVER_SHA256" \
  /root/caddy_2.11.4_linux_amd64.tar.gz \
  /root/Caddyfile "$CADDY_SHA256" \
  "$EGRESS_ALLOWLIST" "$EGRESS_SHA256"
```

The installer does not enable or start anything. After it succeeds, provision
each isolated profile with the installed helper's two-pass digest check:

```sh
for client in codex cursor kiro; do
  digest="$(/usr/local/libexec/uap-observer-provision-profile \
    --client "$client" --root-owned-seed "/root/profile-seeds/$client" \
    --seed-digest show)"
  /usr/local/libexec/uap-observer-provision-profile \
    --client "$client" --root-owned-seed "/root/profile-seeds/$client" \
    --seed-digest "$digest"
done
```

After the signing key, isolated profiles, firewall rules, and immutable proxy
inputs exist, start the proxy socket first and prove its listener and service
health before starting the four repository units:

```sh
systemctl daemon-reload
systemctl enable --now uap-observer-egress-proxy.socket
systemctl is-active uap-observer-egress-proxy.socket
ss -lntp | grep -E '127\.0\.0\.2:8766([[:space:]]|$)'
! ss -lntp | grep -E '(0\.0\.0\.0|\[::\]|:::):8766([[:space:]]|$)'
curl --silent --show-error --output /dev/null --connect-timeout 10 --max-time 30 \
  --proxy http://127.0.0.2:8766 "https://<reviewed-allowlisted-health-fqdn>/"
systemctl is-active uap-observer-egress-proxy.service
systemctl enable --now uap-observer-runner.socket \
  uap-observer-signer.service uap-observer.service \
  uap-observer-caddy.service
systemctl is-active uap-observer-runner.socket uap-observer-signer.service \
  uap-observer.service uap-observer-caddy.service
systemctl --failed
curl --fail --silent --show-error --output /dev/null \
  "https://<observer-fqdn>/v1/stable-launch/observe" || test "$?" -eq 22
ss -lnt | grep -E '127\.0\.0\.1:8765|127\.0\.0\.2:8766|:80 |:443 '
! ss -lnt | grep -E '(0\.0\.0\.0|\[::\]|:::):876(5|6)([[:space:]]|$)'
```

The proxy probe accepts any origin HTTP status; it deterministically checks the
CONNECT tunnel and TLS without requiring an arbitrary root path to return 2xx.
The unauthenticated observer probe is expected to be rejected; it proves only
TLS and routing. Health is complete only when the proxy socket/service and all
four repository units are active, `127.0.0.1:8765` and `127.0.0.2:8766` are the
only 8765/8766 listeners, Caddy owns the public listener, direct client egress
is rejected, and a protected workflow gets a signed bundle whose public key
and key ID match the repository variables.

## 4. Operate one evidence run

Before approving the protected job, obtain its challenge, run ID/attempt,
catalog SHA, canonical request digest, scenario-contract digest, and fresh
pseudonymous identity/root IDs through the release-coordinator channel. Create
the root consent record with `/usr/local/libexec/uap-observer-attest-consent`;
choose only `read-only` or `synthetic` and `fresh-dedicated-identity` (or `none`)
as true for this disposable run.

```sh
/usr/local/libexec/uap-observer-attest-consent \
  --challenge <64-hex> --run-id <decimal> --run-attempt <decimal> \
  --catalog-sha <40-hex> --request-digest sha256:<64-hex> \
  --scenario-contract-digest sha256:<64-hex> \
  --identity-id <fresh-pseudonymous-64-hex> \
  --logical-root-id <fresh-pseudonymous-64-hex> \
  --operation-mode synthetic --auth-origin fresh-dedicated-identity
```

For ChatGPT, use only the configured dedicated test app and the public
Cloudflare Docs MCP. After visually confirming consent, UI activation, the
read-only runtime result, no secrets, and no real-project access, run
`/usr/local/libexec/uap-observer-attest-chatgpt` with the exact challenge,
run/attempt, app ID, and request digest. Create this human attestation no more
than **five minutes before** the observer will consume it; never pre-stage it.
Pass `yes` only for facts the human actually observed. Both helpers use
exclusive, challenge-specific files and intentionally accept no free-form text.

```sh
/usr/local/libexec/uap-observer-attest-chatgpt \
  --challenge <64-hex> --run-id <decimal> --run-attempt <decimal> \
  --app-id plugin_asdk_app_<32-hex> --request-digest sha256:<64-hex> \
  --consent yes --ui-activation yes --runtime-observed yes \
  --read-only yes --no-secrets yes --no-real-project yes
```

Approve the `stable-launch-e2e` environment only after consent and the external
PR evidence are ready. Preserve the GitHub run URL/attempt, immutable artifact
names and digests, observer key ID/public key, unit status, installed closure
identity, and sanitized failure/status output. Never archive the private key,
profile trees, auth material, raw client output, or absolute local paths as
evidence.

## 5. Failure and rollback

On a failed first install, keep services stopped and retain the installer output
and recovery journal; rerun the same reviewed command to complete its built-in
recovery. On a runtime or proxy failure, record sanitized unit status, remove
the host from DNS/load balancing, stop Caddy and the observer before stopping
the proxy, and keep the failed GitHub gate red:

```sh
systemctl stop uap-observer-caddy.service uap-observer.service \
  uap-observer-runner.socket uap-observer-runner.service \
  uap-observer-signer.service
systemctl stop uap-observer-egress-proxy.socket \
  uap-observer-egress-proxy.service
! ss -lnt | grep -E ':(80|443|8765|8766)([[:space:]]|$)'
```

Do not bypass OIDC, reuse consent/attestations, edit the installed closure or
proxy allowlist in place, relax the no-direct-egress firewall policy, or
substitute fixture evidence. Proxy rollback means restore the last independently
reviewed source commit and allowlist tuple (including its recorded digest and
mode) on a new disposable host; do not keep this host serving while changing
those inputs.

The current installer supports a fresh host only. If
`/opt/uap-observer-current` exists, it accepts only byte-identical inputs and
verifies that closure; it does not upgrade, switch to another closure, or
provide a post-deployment downgrade. Rollback for a changed release is therefore
to return DNS to the last independently healthy host (if one exists) and dispose
this test host. Build and verify another fresh disposable host for every change.
