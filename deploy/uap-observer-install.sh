#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install_lib="$script_dir/uap-observer-install-lib.sh"
test "$(sha256sum "$install_lib" | cut -d' ' -f1)" = 5f48bda0a127dd37790192d5597055cc25105298f5d1c8bedf3246c7e805bf23
. "$install_lib"

if [ "$(id -u)" -ne 0 ]; then
  echo "installer must run as root" >&2
  exit 1
fi

usage='usage: uap-observer-install.sh SOURCE_ROOT ADAPTER_CONFIG ADAPTER_SHA256 OBSERVER_CONFIG OBSERVER_SHA256 CADDY_2.11.4_LINUX_AMD64_ARCHIVE CADDY_CONFIG CADDY_CONFIG_SHA256'
stage_root=/opt/uap-observer-source.new
runtime_manifest_digest=e9ed2c4b131c8a8f8c120b7c2c6ed37b058a6ce78858c1f59c2f3add0f7feec5
caddy_archive_digest=527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9
closure_digest=
closure_stage=
closure_final=
activation_started=0
activation_complete=0
systemd_mutation_started=0
closure_published=0
install -d -o root -g root -m 0755 /run/lock
exec 9>/run/lock/uap-observer-install.lock
flock -n 9 || { echo "another observer install is active" >&2; exit 1; }

# Recovery is deliberately before even requiring, opening, hashing, or
# otherwise validating caller-controlled arguments.  A retry after power loss
# must be able to restore the fixed system state with every input unavailable.
if [ ! -e /opt/uap-observer-current ] && [ ! -L /opt/uap-observer-current ]; then
  recover_observer_install "$stage_root" /opt/uap-observer-closures /opt/uap-observer-current /etc/systemd/system systemctl
fi

untrusted_source_root=${1:-/opt/uap-observer}
untrusted_adapter_config=${2:?$usage}
adapter_config_digest=${3:?$usage}
untrusted_observer_config=${4:?$usage}
observer_config_digest=${5:?$usage}
untrusted_caddy_archive=${6:?$usage}
untrusted_caddy_config=${7:?$usage}
caddy_config_digest=${8:?$usage}
install_identity=$(observer_install_input_identity \
  "$untrusted_source_root" "$runtime_manifest_digest" \
  "$untrusted_adapter_config" "$adapter_config_digest" \
  "$untrusted_observer_config" "$observer_config_digest" \
  "$untrusted_caddy_archive" "$caddy_archive_digest" \
  "$untrusted_caddy_config" "$caddy_config_digest")
if [ -e /opt/uap-observer-current ] || [ -L /opt/uap-observer-current ]; then
  observer_validate_no_partial_paths
  observer_validate_completed_closure /opt/uap-observer-closures /opt/uap-observer-current "$install_identity"
  installed_target=$(readlink /opt/uap-observer-current)
  installed_closure="/opt/$installed_target"
  observer_validate_installed_closure_sources "$installed_closure" "$untrusted_source_root" \
    "$untrusted_adapter_config" "$untrusted_observer_config" "$untrusted_caddy_config" \
    46c161d23bdf457a9cd08be7a088e9ed8431dae2a84a2d5e84765b0aa6d6360b \
    977e59a8c2d8b7df845d136aaf514a52243529cb7ca22602d1fd2af4d0a77ddf \
    b7105518e3ed1c0761f232e44fc09345535533c9cb0abf0e12809416c7ac64d9
  observer_validate_installed_accounts_and_state
  observer_validate_protected_inputs "$installed_closure"
  echo "observer files already installed; verified identical immutable closure"
  exit 0
fi
test ! -e "$stage_root"
install -d -o root -g root -m 0700 "$stage_root"
cleanup() {
  status=${1:-1}
  trap - EXIT HUP INT TERM
  rollback_ok=1
  if [ "$systemd_mutation_started" -eq 1 ] && [ "$activation_complete" -eq 0 ]; then
    set +e
    restore_observer_systemd "$systemd_backup" /etc/systemd/system
    restore_status=$?
    if [ "$restore_status" -eq 0 ]; then observer_sync_tree /etc/systemd/system; restore_status=$?; fi
    systemctl daemon-reload
    reload_status=$?
    if [ "$restore_status" -ne 0 ] || [ "$reload_status" -ne 0 ]; then rollback_ok=0; fi
    set -e
  fi
  if [ "$rollback_ok" -eq 0 ]; then
    echo "observer rollback incomplete; durable recovery journal retained" >&2
  else
    observer_cleanup_partial_paths
    test -z "$closure_stage" || rm -rf "$closure_stage"
    if [ "$closure_published" -eq 1 ] && [ "$activation_complete" -eq 0 ]; then
      rm -rf "$closure_final"
    fi
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'exit 1' HUP INT TERM

install -D -o root -g root -m 0444 "$untrusted_source_root/deploy/uap-observer-runtime.sha256" "$stage_root/deploy/uap-observer-runtime.sha256"
test "$(sha256sum "$stage_root/deploy/uap-observer-runtime.sha256" | cut -d' ' -f1)" = "$runtime_manifest_digest"
while read -r expected relative extra; do
  test -z "${extra:-}"
  case "$expected:$relative" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*:[A-Za-z0-9._-]*) ;;
    *) echo "invalid runtime closure entry" >&2; exit 1 ;;
  esac
  case "/$relative/" in */../*|*/./*|//* ) echo "unsafe runtime closure path" >&2; exit 1 ;; esac
  test -f "$untrusted_source_root/$relative"
  test ! -L "$untrusted_source_root/$relative"
  install -D -o root -g root -m 0444 "$untrusted_source_root/$relative" "$stage_root/$relative"
done < "$stage_root/deploy/uap-observer-runtime.sha256"
install -o root -g root -m 0400 "$untrusted_adapter_config" "$stage_root/adapter-config.json"
install -o root -g root -m 0644 "$untrusted_observer_config" "$stage_root/observer-config.json"
install -o root -g root -m 0400 "$untrusted_caddy_archive" "$stage_root/caddy_2.11.4_linux_amd64.tar.gz"
test "$(sha256sum "$stage_root/caddy_2.11.4_linux_amd64.tar.gz" | cut -d' ' -f1)" = "527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9"
test "$(tar -tzf "$stage_root/caddy_2.11.4_linux_amd64.tar.gz" | sort | tr '\n' ' ')" = "LICENSE README.md caddy "
tar -xOf "$stage_root/caddy_2.11.4_linux_amd64.tar.gz" caddy > "$stage_root/caddy"
chown root:root "$stage_root/caddy"
chmod 0500 "$stage_root/caddy"
install -o root -g root -m 0400 "$untrusted_caddy_config" "$stage_root/Caddyfile"
(cd "$stage_root" && sha256sum -c deploy/uap-observer-runtime.sha256)
source_root=$stage_root
adapter_config=$stage_root/adapter-config.json
observer_config=$stage_root/observer-config.json
caddy_binary=$stage_root/caddy
caddy_config=$stage_root/Caddyfile
runner_source="$source_root/observer/fixed_runner.py"
adapter_source="$source_root/observer/fixed_adapters.py"
runner_digest=46c161d23bdf457a9cd08be7a088e9ed8431dae2a84a2d5e84765b0aa6d6360b
adapter_digest=977e59a8c2d8b7df845d136aaf514a52243529cb7ca22602d1fd2af4d0a77ddf
caddy_digest=b7105518e3ed1c0761f232e44fc09345535533c9cb0abf0e12809416c7ac64d9

test -f "$runner_source"
test "$(sha256sum "$runner_source" | cut -d' ' -f1)" = "$runner_digest"
test "$(sha256sum "$adapter_source" | cut -d' ' -f1)" = "$adapter_digest"
test "sha256:$(sha256sum "$adapter_config" | cut -d' ' -f1)" = "$adapter_config_digest"
test "sha256:$(sha256sum "$observer_config" | cut -d' ' -f1)" = "$observer_config_digest"
test "$(sha256sum "$caddy_binary" | cut -d' ' -f1)" = "$caddy_digest"
test "$(sha256sum "$source_root/caddy_2.11.4_linux_amd64.tar.gz" | cut -d' ' -f1)" = "$caddy_archive_digest"
test "$("$caddy_binary" version | awk '{print $1}')" = "v2.11.4"
test "sha256:$(sha256sum "$caddy_config" | cut -d' ' -f1)" = "$caddy_config_digest"
test "$(uname -s):$(uname -m)" = "Linux:x86_64"
test "$(stat -c '%u:%a' "$adapter_config")" = "0:400"
! grep -q REPLACE_WITH "$observer_config"
! grep -q observer.example.invalid "$caddy_config"
(cd "$source_root" && sha256sum -c deploy/uap-observer-runtime.sha256)

getent group uap-observer-signer-ipc >/dev/null || groupadd --system uap-observer-signer-ipc
getent group uap-observer-runner-ipc >/dev/null || groupadd --system uap-observer-runner-ipc
getent group uap-observer-adapter-config >/dev/null || groupadd --system uap-observer-adapter-config
install -d -o root -g root -m 0755 /var/empty
for identity in codex cursor kiro control; do
  getent group "uap-observer-$identity" >/dev/null || groupadd --system "uap-observer-$identity"
  id "uap-observer-$identity" >/dev/null 2>&1 || useradd --system --gid "uap-observer-$identity" --home-dir "/var/empty/uap-observer-$identity" --shell /usr/sbin/nologin "uap-observer-$identity"
  usermod -a -G uap-observer-adapter-config "uap-observer-$identity"
  install -d -o "uap-observer-$identity" -g "uap-observer-$identity" -m 0700 "/var/empty/uap-observer-$identity"
done
getent group uap-observer >/dev/null || groupadd --system uap-observer
getent group caddy >/dev/null || groupadd --system caddy
id caddy >/dev/null 2>&1 || useradd --system --gid caddy --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy
id uap-observer >/dev/null 2>&1 || useradd --system --gid uap-observer --home-dir /nonexistent --shell /usr/sbin/nologin uap-observer
usermod -a -G uap-observer-signer-ipc,uap-observer-runner-ipc uap-observer

identity_uids=
identity_gids=
for identity in codex cursor kiro control; do
  account="uap-observer-$identity"
  uid=$(id -u "$account")
  gid=$(id -g "$account")
  test "$uid" -ne 0
  test "$(getent passwd "$account" | cut -d: -f6)" = "/var/empty/$account"
  shell=$(getent passwd "$account" | cut -d: -f7)
  case "$shell" in /usr/sbin/nologin|/sbin/nologin|/bin/false) ;; *) echo "adapter login shell differs" >&2; exit 1;; esac
  test "$(getent group "$account" | cut -d: -f3)" = "$gid"
  test "$(stat -c '%u:%g:%a' "/var/empty/$account")" = "$uid:$gid:700"
  groups=$(id -G "$account")
  config_gid=$(getent group uap-observer-adapter-config | cut -d: -f3)
  test "$(printf '%s\n' $groups | sort -n | tr '\n' ' ')" = "$(printf '%s\n' "$gid" "$config_gid" | sort -n | uniq | tr '\n' ' ')"
  case " $identity_uids " in *" $uid "*) echo "adapter UIDs are not distinct" >&2; exit 1;; esac
  case " $identity_gids " in *" $gid "*) echo "adapter GIDs are not distinct" >&2; exit 1;; esac
  identity_uids="$identity_uids $uid"
  identity_gids="$identity_gids $gid"
done

for unit in uap-observer.service uap-observer-signer.service uap-observer-runner.service uap-observer-runner.socket uap-observer-caddy.service; do
  if systemctl is-active --quiet "$unit"; then
    echo "stop observer services before installing a new immutable closure" >&2
    exit 1
  fi
done

install -d -o root -g root -m 0711 /var/lib/uap-observer
install -d -o uap-observer -g uap-observer -m 0700 /var/lib/uap-observer/state
install -d -o root -g root -m 0711 /var/lib/uap-observer/jobs /var/lib/uap-observer/workspaces /var/lib/uap-observer/profiles
for client in codex cursor kiro; do
  install -d -o "uap-observer-$client" -g "uap-observer-$client" -m 0700 "/var/lib/uap-observer/profiles/$client" "/var/lib/uap-observer/workspaces/$client"
done
install -d -o root -g root -m 0755 /var/lib/uap-observer-human
install -d -o root -g uap-observer-control -m 0750 /var/lib/uap-observer-human/pending
install -d -o root -g root -m 0700 /var/lib/uap-observer-human/consumed
install -d -o root -g root -m 0700 /var/lib/uap-observer-human/reserved
install -d -o root -g root -m 0755 /var/lib/uap-observer-consent
install -d -o root -g uap-observer-adapter-config -m 0750 /var/lib/uap-observer-consent/pending
install -d -o root -g root -m 0700 /var/lib/uap-observer-consent/consumed
install -d -o root -g root -m 0700 /var/lib/uap-observer-consent/reserved
install -d -o caddy -g caddy -m 0700 /var/lib/caddy /var/log/caddy

test ! -e /opt/uap-observer-venv.new
python3 -m venv /opt/uap-observer-venv.new
/opt/uap-observer-venv.new/bin/python -m pip install --require-hashes --no-deps -r "$source_root/observer/requirements.lock"
/opt/uap-observer-venv.new/bin/python -m jsonschema -i "$adapter_config" "$source_root/deploy/uap-observer-adapter-config.schema.json"
PYTHONPATH="$source_root" /opt/uap-observer-venv.new/bin/python -c 'import json,sys; from observer.fixed_adapters import validate_config; validate_config(json.load(open(sys.argv[1], encoding="utf-8")))' "$adapter_config"
PYTHONPATH="$source_root" /opt/uap-observer-venv.new/bin/python -c 'import sys; from pathlib import Path; from observer.config import Config; Config.load(Path(sys.argv[1]))' "$observer_config"

# Resolve only the reviewed service hosts at install time. The resulting hosts
# file and cgroup-BPF allowlist remove runtime DNS and arbitrary IP egress from
# the observer and adapter runner.
python3 - "$adapter_config" "$observer_config" "$stage_root/hosts" "$stage_root/egress-addresses" <<'PY'
import ipaddress,json,socket,sys
from pathlib import Path
from urllib.parse import urlsplit
adapter=json.load(open(sys.argv[1], encoding="utf-8"))
observer=json.load(open(sys.argv[2], encoding="utf-8"))
urls=[item["endpoint"] for item in adapter["matrix"]]
urls += [adapter["chatgpt"]["mcp_endpoint"], observer["jwks_url"], observer["github_api_url"]]
host_values={urlsplit(url).hostname for url in urls}
if None in host_values:
    raise SystemExit("observer egress hostname is invalid")
hosts=sorted(host_values)
resolved={}
for host in hosts:
    values=sorted({str(ipaddress.ip_address(item[4][0])) for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    if not values:
        raise SystemExit("observer egress hostname did not resolve")
    resolved[host]=values
Path(sys.argv[3]).write_text("127.0.0.1 localhost\n::1 localhost\n" + "".join(f"{address} {host}\n" for host in hosts for address in resolved[host]))
Path(sys.argv[4]).write_text("".join(f"{address}\n" for values in resolved.values() for address in values))
PY
chown root:root "$stage_root/hosts" "$stage_root/egress-addresses"
chmod 0444 "$stage_root/hosts" "$stage_root/egress-addresses"

test ! -e /opt/uap-observer-runtime.new
install -d -o root -g root -m 0755 /opt/uap-observer-runtime.new/observer /opt/uap-observer-runtime.new/tests/e2e/schemas
for source in "$source_root"/observer/*.py; do
  install -o root -g root -m 0444 "$source" "/opt/uap-observer-runtime.new/observer/$(basename "$source")"
done
for source in "$source_root"/tests/e2e/schemas/*.schema.json; do
  install -o root -g root -m 0444 "$source" "/opt/uap-observer-runtime.new/tests/e2e/schemas/$(basename "$source")"
done
install -o root -g root -m 0555 "$source_root/deploy/uap-observer-signer.py" /opt/uap-observer-runtime.new/uap-observer-signer.py

install -d -o root -g root -m 0755 /usr/local/libexec
install -d -o root -g root -m 0755 /usr/local/bin
install -o root -g root -m 0755 "$runner_source" /usr/local/libexec/uap-observer-runner.new
test "$(sha256sum /usr/local/libexec/uap-observer-runner.new | cut -d' ' -f1)" = "$runner_digest"
install -o root -g root -m 0555 "$adapter_source" /usr/local/libexec/uap-observer-fixed-adapter.new
for name in runtime notion chatgpt consent; do
  test ! -e "/usr/local/libexec/uap-observer-adapter-$name.new"
  ln /usr/local/libexec/uap-observer-fixed-adapter.new "/usr/local/libexec/uap-observer-adapter-$name.new"
done
install -o root -g root -m 0555 "$source_root/deploy/uap-observer-attest-chatgpt.py" /usr/local/libexec/uap-observer-attest-chatgpt.new
install -o root -g root -m 0555 "$source_root/deploy/uap-observer-attest-consent.py" /usr/local/libexec/uap-observer-attest-consent.new
install -o root -g root -m 0555 "$source_root/deploy/uap-observer-provision-profile.py" /usr/local/libexec/uap-observer-provision-profile.new
install -o root -g root -m 0755 "$caddy_binary" /usr/local/bin/caddy.new
install -o root -g root -m 0644 "$observer_config" /etc/uap-observer.json.new
install -o root -g uap-observer-adapter-config -m 0640 "$adapter_config" /etc/uap-observer-adapter-config.json.new
installed_adapter_config_digest="sha256:$(sha256sum /etc/uap-observer-adapter-config.json.new | cut -d' ' -f1)"
/opt/uap-observer-venv.new/bin/python - "$adapter_digest" "$installed_adapter_config_digest" <<'PY'
import json,sys
artifacts = {
    "runtime-attestations.json": "runtime", "notion-oauth-attestations.json": "notion",
    "chatgpt-cloudflare-attestation.json": "chatgpt", "consent.json": "consent",
}
value = {
    "schema_version": 1,
    "config": {"path": "/opt/uap-observer-current/etc/uap-observer-adapter-config.json", "sha256": sys.argv[2]},
    "artifacts": {
        artifact: {"path": f"/opt/uap-observer-current/libexec/uap-observer-adapter-{name}", "sha256": "sha256:" + sys.argv[1]}
        for artifact, name in artifacts.items()
    },
}
with open("/etc/uap-observer-adapters.json.new", "x", encoding="utf-8") as stream:
    json.dump(value, stream, sort_keys=True, separators=(",", ":"))
PY
chown root:root /etc/uap-observer-adapters.json.new
chmod 0644 /etc/uap-observer-adapters.json.new

install -d -o root -g root -m 0755 /etc/caddy
install -o root -g caddy -m 0640 "$caddy_config" /etc/caddy/Caddyfile.new
systemd_stage="$stage_root/systemd"
install -d -o root -g root -m 0700 "$systemd_stage/uap-observer.service.d" "$systemd_stage/uap-observer-runner.service.d"
for unit in uap-observer.service uap-observer-signer.service uap-observer-runner.service uap-observer-runner.socket uap-observer-caddy.service; do
  install -o root -g root -m 0644 "$source_root/deploy/$unit" "$systemd_stage/$unit"
done
for service in uap-observer uap-observer-runner; do
  {
    printf '%s\n' '[Service]' 'IPAddressDeny=any'
    if [ "$service" = uap-observer ]; then printf '%s\n' 'IPAddressAllow=127.0.0.0/8 ::1/128'; fi
    while read -r address; do printf 'IPAddressAllow=%s\n' "$address"; done < "$stage_root/egress-addresses"
    if [ "$service" = uap-observer-runner ]; then
      python3 - "$adapter_config" <<'PY'
import grp,hashlib,json,os,stat,sys
from pathlib import Path
value=json.load(open(sys.argv[1], encoding="utf-8"))
expected=["/opt/uap-observer-inputs/bin/git","/opt/uap-observer-inputs/bin/codex","/opt/uap-observer-inputs/bin/cursor","/opt/uap-observer-inputs/bin/kiro","/opt/uap-observer-inputs/chatgpt/app-binding.json","/opt/uap-observer-inputs/chatgpt/projection-receipt.json","/opt/uap-observer-inputs/external-pr-evidence.json"]
config_gid=grp.getgrnam("uap-observer-adapter-config").gr_gid
paths=[value["git"]["binary"], *(item["binary"] for item in value["clients"].values()), value["chatgpt"]["app_binding_path"], value["chatgpt"]["projection_receipt_path"], value["external_pr_evidence"]["path"]]
if sorted(set(paths)) != sorted(expected): raise SystemExit("adapter bind paths differ from literal dedicated allowlist")
if any(value["clients"][client]["binary"] != f"/opt/uap-observer-inputs/bin/{client}" for client in ("codex","cursor","kiro")): raise SystemExit("adapter client binary differs from its literal dedicated path")
digests={value["git"]["binary"]:value["git"]["sha256"], **{item["binary"]:item["sha256"] for item in value["clients"].values()}, value["chatgpt"]["app_binding_path"]:value["chatgpt"]["app_binding_sha256"], value["chatgpt"]["projection_receipt_path"]:value["chatgpt"]["projection_receipt_sha256"], value["external_pr_evidence"]["path"]:value["external_pr_evidence"]["sha256"]}
for path in sorted(set(paths)):
    candidate=Path(path)
    if candidate.resolve(strict=True) != candidate: raise SystemExit("adapter input path traverses a symlink")
    dedicated=Path("/opt/uap-observer-inputs")
    if dedicated not in candidate.parents: raise SystemExit("adapter input escaped its dedicated root")
    for parent in (dedicated, *[item for item in candidate.parents if dedicated in item.parents]):
        parent_info=os.lstat(parent)
        if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
            raise SystemExit("adapter input parent is not root-controlled")
        if not parent_info.st_mode & stat.S_IXOTH and not (parent_info.st_gid == config_gid and parent_info.st_mode & stat.S_IXGRP):
            raise SystemExit("adapter input parent is not accessible to the reviewed identities")
    info=os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
        raise SystemExit("adapter input is not an immutable root-owned regular file")
    expected_mode=0o755 if candidate.parent == Path("/opt/uap-observer-inputs/bin") else 0o640
    if stat.S_IMODE(info.st_mode) != expected_mode or (expected_mode == 0o640 and info.st_gid != config_gid):
        raise SystemExit("adapter input mode or group differs")
    actual="sha256:"+hashlib.sha256(open(path,"rb").read()).hexdigest()
    if actual != digests[path]: raise SystemExit("adapter input digest differs")
    print(f"BindReadOnlyPaths={path}")
PY
    fi
  } > "$systemd_stage/$service.service.d/egress.conf"
  chown root:root "$systemd_stage/$service.service.d/egress.conf"
  chmod 0644 "$systemd_stage/$service.service.d/egress.conf"
done

(cd /opt/uap-observer-runtime.new && /opt/uap-observer-venv.new/bin/python -c 'import cryptography,jsonschema; import observer.http_server')
test "$(sha256sum /usr/local/libexec/uap-observer-runner.new | cut -d' ' -f1)" = "$runner_digest"
test "$(sha256sum /usr/local/libexec/uap-observer-fixed-adapter.new | cut -d' ' -f1)" = "$adapter_digest"
test "$(sha256sum /usr/local/bin/caddy.new | cut -d' ' -f1)" = "$caddy_digest"
test "$(/usr/local/bin/caddy.new version | awk '{print $1}')" = "v2.11.4"
/usr/local/bin/caddy.new validate --config /etc/caddy/Caddyfile.new --adapter caddyfile
adapter_inode=$(stat -c '%d:%i' /usr/local/libexec/uap-observer-fixed-adapter.new)
for name in runtime notion chatgpt consent; do
  test "$(stat -c '%d:%i' "/usr/local/libexec/uap-observer-adapter-$name.new")" = "$adapter_inode"
done
for unit in uap-observer.service uap-observer-signer.service uap-observer-runner.service uap-observer-runner.socket uap-observer-caddy.service; do
  cmp "$source_root/deploy/$unit" "$systemd_stage/$unit"
done
cmp "$observer_config" /etc/uap-observer.json.new
cmp "$adapter_config" /etc/uap-observer-adapter-config.json.new
cmp "$caddy_config" /etc/caddy/Caddyfile.new

# Build one immutable, complete version. No consumer references it until the
# single current-pointer rename below.
install -d -o root -g root -m 0755 /opt/uap-observer-closures
closure_stage="/opt/uap-observer-closures/.new-$$"
test ! -e "$closure_stage"
test ! -e "$closure_final"
install -d -o root -g root -m 0755 "$closure_stage/libexec" "$closure_stage/bin" "$closure_stage/etc"
install -d -o root -g root -m 0755 "$closure_stage/systemd/uap-observer.service.d" "$closure_stage/systemd/uap-observer-runner.service.d"
for unit in uap-observer.service uap-observer-signer.service uap-observer-runner.service uap-observer-runner.socket uap-observer-caddy.service; do
  install -o root -g root -m 0644 "$systemd_stage/$unit" "$closure_stage/systemd/$unit"
done
for service in uap-observer uap-observer-runner; do
  install -o root -g root -m 0644 "$systemd_stage/$service.service.d/egress.conf" "$closure_stage/systemd/$service.service.d/egress.conf"
done
mv /opt/uap-observer-venv.new "$closure_stage/venv"
mv /opt/uap-observer-runtime.new "$closure_stage/runtime"
mv /usr/local/libexec/uap-observer-runner.new "$closure_stage/libexec/uap-observer-runner"
mv /usr/local/libexec/uap-observer-fixed-adapter.new "$closure_stage/libexec/uap-observer-fixed-adapter"
for name in runtime notion chatgpt consent; do
  mv "/usr/local/libexec/uap-observer-adapter-$name.new" "$closure_stage/libexec/uap-observer-adapter-$name"
done
mv /usr/local/libexec/uap-observer-attest-chatgpt.new "$closure_stage/libexec/uap-observer-attest-chatgpt"
mv /usr/local/libexec/uap-observer-attest-consent.new "$closure_stage/libexec/uap-observer-attest-consent"
mv /usr/local/libexec/uap-observer-provision-profile.new "$closure_stage/libexec/uap-observer-provision-profile"
mv /usr/local/bin/caddy.new "$closure_stage/bin/caddy"
mv /etc/uap-observer.json.new "$closure_stage/etc/uap-observer.json"
mv /etc/uap-observer-adapter-config.json.new "$closure_stage/etc/uap-observer-adapter-config.json"
mv /etc/uap-observer-adapters.json.new "$closure_stage/etc/uap-observer-adapters.json"
mv /etc/caddy/Caddyfile.new "$closure_stage/etc/Caddyfile"
mv "$stage_root/hosts" "$closure_stage/etc/hosts"
printf '%s\n' 'complete-v1' > "$closure_stage/.complete"
printf '%s\n' "$install_identity" > "$closure_stage/.install-identity"
apply_observer_closure_modes "$closure_stage"
observer_sync_tree "$closure_stage"
closure_digest=$(observer_closure_identity "$closure_stage")
closure_final="/opt/uap-observer-closures/$closure_digest"
test ! -e "$closure_final"
unit_validation="$stage_root/unit-validation"
install -d -o root -g root -m 0700 "$unit_validation"
for unit in uap-observer.service uap-observer-signer.service uap-observer-runner.service uap-observer-runner.socket uap-observer-caddy.service; do
  sed "s|/opt/uap-observer-current|$closure_stage|g" "$systemd_stage/$unit" > "$unit_validation/$unit"
done
systemd-analyze verify "$unit_validation"/*.service "$unit_validation"/*.socket
PYTHONPATH="$closure_stage/runtime" "$closure_stage/venv/bin/python" - "$closure_stage" "$runner_digest" "$adapter_digest" <<'PY'
import grp,hashlib,sys
from pathlib import Path
from observer.config import Config
from observer.fixed_runner import Adapter, ARTIFACT_ORDER, ReviewedRunner, read_owned_regular
from observer.runner import SocketRunner
root=Path(sys.argv[1])
Config.load(root / "etc/uap-observer.json")
SocketRunner(Path("/run/unused-validation.sock"), root / "libexec/uap-observer-runner", "sha256:" + sys.argv[2], 840)
gid=grp.getgrnam("uap-observer-adapter-config").gr_gid
config=root / "etc/uap-observer-adapter-config.json"
encoded=read_owned_regular(config, 4 << 20, owner_uid=0, exact_mode=0o640, group_gid=gid)
config_digest="sha256:" + hashlib.sha256(encoded).hexdigest()
adapters=tuple(Adapter(name, root / f"libexec/uap-observer-adapter-{kind}", "sha256:" + sys.argv[3], config, config_digest) for name,kind in zip(ARTIFACT_ORDER,("runtime","notion","chatgpt","consent")))
ReviewedRunner(adapters, Path("/var/lib/uap-observer/jobs"))
PY
systemd_backup="$stage_root/systemd-backup"
journal_observer_systemd "$systemd_backup" /etc/systemd/system
observer_sync_tree "$systemd_backup"
printf '%s\n' "$closure_digest" > "$stage_root/closure-digest"
chown root:root "$stage_root/closure-digest"
chmod 0600 "$stage_root/closure-digest"
sync -f "$stage_root/closure-digest"
printf '%s\n' rollback-required > "$stage_root/rollback-required"
chown root:root "$stage_root/rollback-required"
chmod 0600 "$stage_root/rollback-required"
sync -f "$stage_root/rollback-required"
sync -f "$stage_root"
mv "$closure_stage" "$closure_final"
closure_stage=
closure_published=1
sync -f /opt/uap-observer-closures
systemd_mutation_started=1
activate_observer_systemd "$systemd_stage" /etc/systemd/system
observer_sync_tree /etc/systemd/system
reload_observer_systemd systemctl
activation_started=1
ln -s "uap-observer-closures/$closure_digest" /opt/uap-observer-current.new
mv -T /opt/uap-observer-current.new /opt/uap-observer-current
sync -f /opt
activation_complete=1
echo "observer files installed; provision the root key and reviewed adapters before enabling services"
