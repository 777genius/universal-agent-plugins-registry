#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "installer must run as root" >&2
  exit 1
fi

untrusted_source_root=${1:-/opt/uap-observer}
usage='usage: uap-observer-install.sh SOURCE_ROOT ADAPTER_CONFIG ADAPTER_SHA256 OBSERVER_CONFIG OBSERVER_SHA256 CADDY_2.11.4_LINUX_AMD64_ARCHIVE CADDY_CONFIG CADDY_CONFIG_SHA256'
untrusted_adapter_config=${2:?$usage}
adapter_config_digest=${3:?$usage}
untrusted_observer_config=${4:?$usage}
observer_config_digest=${5:?$usage}
untrusted_caddy_archive=${6:?$usage}
untrusted_caddy_config=${7:?$usage}
caddy_config_digest=${8:?$usage}
stage_root=/opt/uap-observer-source.new
closure_digest=63c40563730d6dc3ad672d26fbde32e38017529597f97efd1a55871ecb2d23da
activation_started=0
activation_complete=0
activated_paths=
test ! -e "$stage_root"
install -d -o root -g root -m 0700 "$stage_root"
cleanup() {
  status=${1:-1}
  trap - EXIT HUP INT TERM
  if [ "$activation_started" -eq 1 ] && [ "$activation_complete" -eq 0 ]; then
    set +e
    for destination in $activated_paths; do
      rm -rf "$destination"
      if [ -e "$destination.previous" ] || [ -L "$destination.previous" ]; then
        mv "$destination.previous" "$destination"
      fi
    done
    systemctl daemon-reload
    set -e
  fi
  rm -rf /opt/uap-observer-source.new /opt/uap-observer-venv.new /opt/uap-observer-runtime.new
  rm -rf "/opt/uap-observer-closures/.new-$closure_digest"
  rm -f /opt/uap-observer-current.new
  rm -f /usr/local/libexec/uap-observer-runner.new /usr/local/libexec/uap-observer-fixed-adapter.new \
    /usr/local/libexec/uap-observer-attest-chatgpt.new /usr/local/libexec/uap-observer-attest-consent.new /usr/local/libexec/uap-observer-provision-profile.new \
    /usr/local/bin/caddy.new /etc/uap-observer.json.new /etc/uap-observer-adapter-config.json.new \
    /etc/uap-observer-adapters.json.new /etc/caddy/Caddyfile.new \
    /etc/systemd/system/uap-observer-runner.service.d/egress.conf.new \
    /etc/systemd/system/uap-observer.service.d/egress.conf.new
  for name in runtime notion chatgpt consent; do rm -f "/usr/local/libexec/uap-observer-adapter-$name.new"; done
  for unit in uap-observer.service uap-observer-signer.service uap-observer-runner.service uap-observer-runner.socket uap-observer-caddy.service; do rm -f "/etc/systemd/system/$unit.new"; done
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'exit 1' HUP INT TERM

activate() {
  staged=$1
  destination=$2
  if [ -e "$destination" ] || [ -L "$destination" ]; then
    mv "$destination" "$destination.previous"
  fi
  activated_paths="$destination $activated_paths"
  mv "$staged" "$destination"
}
install -D -o root -g root -m 0444 "$untrusted_source_root/deploy/uap-observer-runtime.sha256" "$stage_root/deploy/uap-observer-runtime.sha256"
test "$(sha256sum "$stage_root/deploy/uap-observer-runtime.sha256" | cut -d' ' -f1)" = "$closure_digest"
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
runner_digest=8be5c091aa02182522f975f121c857469d340f55db9a6f0d84170986fc52667c
adapter_digest=97ffd6b54e08ce245d2dfa9690ac442abe35e77f1be63f03d56882468d15da82
caddy_digest=b7105518e3ed1c0761f232e44fc09345535533c9cb0abf0e12809416c7ac64d9
caddy_archive_digest=527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9

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
install -d -o root -g root -m 0755 /var/lib/uap-observer-consent
install -d -o root -g uap-observer-adapter-config -m 0750 /var/lib/uap-observer-consent/pending
install -d -o root -g root -m 0700 /var/lib/uap-observer-consent/consumed
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
for unit in uap-observer.service uap-observer-signer.service uap-observer-runner.service uap-observer-runner.socket uap-observer-caddy.service; do
  install -o root -g root -m 0644 "$source_root/deploy/$unit" "/etc/systemd/system/$unit.new"
done
for service in uap-observer uap-observer-runner; do
  install -d -o root -g root -m 0755 "/etc/systemd/system/$service.service.d"
  {
    printf '%s\n' '[Service]' 'IPAddressDeny=any'
    if [ "$service" = uap-observer ]; then printf '%s\n' 'IPAddressAllow=127.0.0.0/8 ::1/128'; fi
    while read -r address; do printf 'IPAddressAllow=%s\n' "$address"; done < "$stage_root/egress-addresses"
  } > "/etc/systemd/system/$service.service.d/egress.conf.new"
  chown root:root "/etc/systemd/system/$service.service.d/egress.conf.new"
  chmod 0644 "/etc/systemd/system/$service.service.d/egress.conf.new"
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
  cmp "$source_root/deploy/$unit" "/etc/systemd/system/$unit.new"
done
cmp "$observer_config" /etc/uap-observer.json.new
cmp "$adapter_config" /etc/uap-observer-adapter-config.json.new
cmp "$caddy_config" /etc/caddy/Caddyfile.new

# Build one immutable, complete version. No consumer references it until the
# single current-pointer rename below.
install -d -o root -g root -m 0755 /opt/uap-observer-closures
closure_stage="/opt/uap-observer-closures/.new-$closure_digest"
closure_final="/opt/uap-observer-closures/$closure_digest"
test ! -e "$closure_stage"
test ! -e "$closure_final"
install -d -o root -g root -m 0755 "$closure_stage/libexec" "$closure_stage/bin" "$closure_stage/etc"
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
printf '%s\n' "$closure_digest" > "$closure_stage/.complete"
chown -R root "$closure_stage"
chmod -R a-w "$closure_stage"
mv "$closure_stage" "$closure_final"

# Unit definitions are stable bootstrap files; all release-varying paths flow
# through the immutable closure pointer.
for unit in uap-observer.service uap-observer-signer.service uap-observer-runner.service uap-observer-runner.socket uap-observer-caddy.service; do
  mv "/etc/systemd/system/$unit.new" "/etc/systemd/system/$unit"
done
for service in uap-observer uap-observer-runner; do
  mv "/etc/systemd/system/$service.service.d/egress.conf.new" "/etc/systemd/system/$service.service.d/egress.conf"
done
systemctl daemon-reload
activation_started=1
ln -s "uap-observer-closures/$closure_digest" /opt/uap-observer-current.new
mv -T /opt/uap-observer-current.new /opt/uap-observer-current
activation_complete=1
echo "observer files installed; provision the root key and reviewed adapters before enabling services"
