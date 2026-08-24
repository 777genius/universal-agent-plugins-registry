#!/bin/sh

# Shared, testable installer primitives. The caller supplies only disposable
# roots in tests; production calls use the fixed system paths.

observer_units='uap-observer.service uap-observer-signer.service uap-observer-runner.service uap-observer-runner.socket uap-observer-caddy.service'

# This is the authoritative inventory of every temporary name created by the
# installer.  Both retry cleanup and the identical-install trust check consume
# it so a newly added staging path cannot silently escape one of them.
observer_partial_paths() {
  printf '%s\n' \
    /opt/uap-observer-source.new \
    /opt/uap-observer-venv.new \
    /opt/uap-observer-runtime.new \
    /opt/uap-observer-current.new \
    /usr/local/libexec/uap-observer-runner.new \
    /usr/local/libexec/uap-observer-fixed-adapter.new \
    /usr/local/libexec/uap-observer-attest-chatgpt.new \
    /usr/local/libexec/uap-observer-attest-consent.new \
    /usr/local/libexec/uap-observer-provision-profile.new \
    /usr/local/bin/caddy.new \
    /etc/uap-observer.json.new \
    /etc/uap-observer-adapter-config.json.new \
    /etc/uap-observer-adapters.json.new \
    /etc/caddy/Caddyfile.new \
    /opt/uap-observer-closures/.new-* \
    /usr/local/libexec/uap-observer-adapter-*.new
}

observer_validate_no_partial_paths() {
  inventory=${1:-observer_partial_paths}
  for partial in $("$inventory"); do
    test ! -e "$partial"
    test ! -L "$partial"
  done
}

observer_cleanup_partial_paths() {
  inventory=${1:-observer_partial_paths}
  for partial in $("$inventory"); do
    if [ -e "$partial" ] || [ -L "$partial" ]; then rm -rf -- "$partial"; fi
  done
}

# Recovery owns the journal directory and removes it only after every other
# cleanup and durability operation has succeeded.
observer_cleanup_recovery_partials() {
  inventory=${1:-observer_partial_paths}
  cleaned_parents=
  for partial in $("$inventory"); do
    test "$partial" = /opt/uap-observer-source.new && continue
    parent=$(dirname "$partial")
    case " $cleaned_parents " in *" $parent "*) ;; *) cleaned_parents="$cleaned_parents $parent";; esac
    if [ -e "$partial" ] || [ -L "$partial" ]; then
      rm -rf -- "$partial" || return 1
    fi
  done
  for parent in $cleaned_parents; do observer_sync_directory "$parent" || return 1; done
}

observer_validate_first_install_closures_root() {
  closures_root=$1
  expected_owner=${2:-0:0}
  if [ ! -e "$closures_root" ] && [ ! -L "$closures_root" ]; then return 0; fi
  test -d "$closures_root" || return 1
  test ! -L "$closures_root" || return 1
  test "$(stat -c '%u:%g:%a' "$closures_root")" = "$expected_owner:755" || return 1
  test -z "$(find "$closures_root" -mindepth 1 -maxdepth 1 -print -quit)"
}

observer_closure_identity() {
  python3 - "$1" <<'PY'
import hashlib,os,stat,sys
from pathlib import Path
root=Path(sys.argv[1])
identity=hashlib.sha256()
paths=sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
regular={}
for path in paths:
    info=path.lstat()
    if stat.S_ISREG(info.st_mode):
        regular.setdefault((info.st_dev,info.st_ino),[]).append(path.relative_to(root).as_posix())
adapter_paths={f"libexec/uap-observer-adapter-{name}" for name in ("runtime","notion","chatgpt","consent")}
adapter_paths.add("libexec/uap-observer-fixed-adapter")
for inode,members in regular.items():
    members.sort()
    info=(root/members[0]).lstat()
    actual=set(members)
    if actual == adapter_paths:
        if info.st_nlink != 5: raise SystemExit("adapter hardlink set has an external link")
    elif len(members) != 1 or info.st_nlink != 1:
        raise SystemExit("closure regular file has unexpected hardlink topology")
groups=[set(members) for members in regular.values() if adapter_paths & set(members)]
if groups != [adapter_paths]: raise SystemExit("adapter paths are not one exact hardlink set")
for path in paths:
    info=path.lstat(); relative=path.relative_to(root).as_posix().encode()
    kind=b"d" if stat.S_ISDIR(info.st_mode) else b"f" if stat.S_ISREG(info.st_mode) else b"l" if stat.S_ISLNK(info.st_mode) else b"?"
    identity.update(b"\0".join((relative,kind,str(stat.S_IMODE(info.st_mode)).encode(),str(info.st_uid).encode(),str(info.st_gid).encode()))+b"\0")
    if kind == b"f":
        # Canonical path equivalence classes bind topology without hashing raw,
        # filesystem-specific inode numbers.
        topology="=".join(regular[(info.st_dev,info.st_ino)]).encode()
        identity.update(b"links\0"+topology+b"\0"+hashlib.sha256(path.read_bytes()).digest())
    elif kind == b"l": identity.update(os.readlink(path).encode())
    elif kind == b"?": raise SystemExit("closure contains a special file")
print(identity.hexdigest())
PY
}

observer_install_input_identity() {
  source_root=$1
  runtime_manifest_digest=$2
  adapter_config=$3
  adapter_config_digest=$4
  observer_config=$5
  observer_config_digest=$6
  caddy_archive=$7
  caddy_archive_digest=$8
  caddy_config=$9
  shift 9
  caddy_config_digest=$1
  manifest="$source_root/deploy/uap-observer-runtime.sha256"
  test -d "$source_root"
  test ! -L "$source_root"
  test -f "$manifest"
  test ! -L "$manifest"
  test "$(sha256sum "$manifest" | cut -d' ' -f1)" = "$runtime_manifest_digest"
  while read -r expected relative extra; do
    test -z "${extra:-}"
    case "$expected:$relative" in
      [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*:[A-Za-z0-9._-]*) ;;
      *) echo "invalid runtime closure entry" >&2; return 1 ;;
    esac
    case "/$relative/" in */../*|*/./*|//* ) echo "unsafe runtime closure path" >&2; return 1 ;; esac
    test -f "$source_root/$relative"
    test ! -L "$source_root/$relative"
  done < "$manifest"
  (cd "$source_root" && sha256sum -c deploy/uap-observer-runtime.sha256 >/dev/null)
  for input in "$adapter_config" "$observer_config" "$caddy_archive" "$caddy_config"; do
    test -f "$input"
    test ! -L "$input"
  done
  actual_adapter="sha256:$(sha256sum "$adapter_config" | cut -d' ' -f1)"
  actual_observer="sha256:$(sha256sum "$observer_config" | cut -d' ' -f1)"
  actual_archive="sha256:$(sha256sum "$caddy_archive" | cut -d' ' -f1)"
  actual_caddy="sha256:$(sha256sum "$caddy_config" | cut -d' ' -f1)"
  test "$actual_adapter" = "$adapter_config_digest"
  test "$actual_observer" = "$observer_config_digest"
  test "$actual_archive" = "sha256:$caddy_archive_digest"
  test "$actual_caddy" = "$caddy_config_digest"
  printf '%s\n' \
    "runtime-manifest sha256:$runtime_manifest_digest" \
    "adapter-config $actual_adapter" \
    "observer-config $actual_observer" \
    "caddy-archive $actual_archive" \
    "caddy-config $actual_caddy" | sha256sum | cut -d' ' -f1
}

observer_validate_completed_closure() {
  closures_root=$1
  current_pointer=$2
  expected_install_identity=$3
  expected_owner=${4:-0:0}
  systemd_root=${5:-/etc/systemd/system}
  config_gid=${6:-$(getent group uap-observer-adapter-config | cut -d: -f3)}
  caddy_gid=${7:-$(getent group caddy | cut -d: -f3)}
  test -n "$config_gid"
  test -n "$caddy_gid"
  test -d "$closures_root"
  test ! -L "$closures_root"
  test "$(stat -c '%u:%g:%a' "$closures_root")" = "$expected_owner:755"
  test -L "$current_pointer"
  test "$(stat -c '%u:%g:%a' "$current_pointer")" = "$expected_owner:777"
  target=$(readlink "$current_pointer")
  digest=${target#uap-observer-closures/}
  printf '%s\n' "$digest" | grep -Eq '^[0-9a-f]{64}$' || {
    echo "observer current pointer is invalid" >&2
    return 1
  }
  test "$target" = "uap-observer-closures/$digest"
  closure="$closures_root/$digest"
  test "$(find "$closures_root" -mindepth 1 -maxdepth 1 -printf '%f\n')" = "$digest"
  test -d "$closure"
  test ! -L "$closure"
  test "$(stat -c '%u:%g:%a' "$closure")" = "$expected_owner:755"
  for marker in .complete .install-identity; do
    test -f "$closure/$marker"
    test ! -L "$closure/$marker"
    test "$(stat -c '%u:%g:%a' "$closure/$marker")" = "$expected_owner:644"
  done
  test "$(cat "$closure/.complete")" = complete-v1
  test "$(cat "$closure/.install-identity")" = "$expected_install_identity"
  actual_identity=$(observer_closure_identity "$closure")
  test "$actual_identity" = "$digest"
  test "$(stat -c '%u:%g:%a:%h' "$closure/etc/uap-observer-adapter-config.json")" = "0:$config_gid:640:1"
  test "$(stat -c '%u:%g:%a:%h' "$closure/etc/Caddyfile")" = "0:$caddy_gid:640:1"
  test -d "$systemd_root"
  test ! -L "$systemd_root"
  test "$(stat -c '%u:%g:%a' "$systemd_root")" = "$expected_owner:755"
  for unit in $observer_units; do
    installed="$systemd_root/$unit"
    reviewed="$closure/systemd/$unit"
    test -f "$installed"
    test ! -L "$installed"
    test "$(stat -c '%h' "$installed")" = 1
    test "$(stat -c '%u:%g:%a' "$installed")" = "$expected_owner:644"
    cmp "$reviewed" "$installed"
  done
  for service in uap-observer uap-observer-runner; do
    installed="$systemd_root/$service.service.d"
    reviewed="$closure/systemd/$service.service.d/egress.conf"
    test -d "$installed"
    test ! -L "$installed"
    test "$(stat -c '%u:%g:%a' "$installed")" = "$expected_owner:755"
    test "$(find "$installed" -mindepth 1 -maxdepth 1 -printf '%f\n')" = egress.conf
    test -f "$installed/egress.conf"
    test ! -L "$installed/egress.conf"
    test "$(stat -c '%h' "$installed/egress.conf")" = 1
    test "$(stat -c '%u:%g:%a' "$installed/egress.conf")" = "$expected_owner:644"
    cmp "$reviewed" "$installed/egress.conf"
  done
  expected_observer_paths=$(printf '%s\n' $observer_units uap-observer.service.d uap-observer-runner.service.d | sort)
  actual_observer_paths=$(find "$systemd_root" -mindepth 1 -maxdepth 1 -name 'uap-observer*' -printf '%f\n' | sort)
  test "$actual_observer_paths" = "$expected_observer_paths"
}

observer_validate_installed_accounts_and_state() {
  observer_runtime=${1:-/opt/uap-observer-current/runtime}
  PYTHONPATH="$observer_runtime" python3 - <<'PY'
import grp,os,pwd,stat
from pathlib import Path
from observer.fixed_runner import reviewed_service_identities

services=reviewed_service_identities()
identities=[services[name][:2] for name in ("codex","cursor","kiro","control")]
observer_uid,observer_gid,_=services["observer"]
caddy_uid,caddy_gid,_=services["caddy"]

def directory(path,uid,gid,mode):
    info=os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode:
        raise SystemExit(f"installed state directory {path} differs")

directory("/var/empty",0,0,0o755)
for suffix,(uid,gid) in zip(("codex","cursor","kiro","control"),identities):
    directory(f"/var/empty/uap-observer-{suffix}",uid,gid,0o700)
directory("/var/lib/uap-observer",0,0,0o711)
directory("/var/lib/uap-observer/state",observer_uid,observer_gid,0o700)
for name in ("jobs","workspaces","profiles"): directory(f"/var/lib/uap-observer/{name}",0,0,0o711)
for suffix,(uid,gid) in zip(("codex","cursor","kiro"),identities):
    directory(f"/var/lib/uap-observer/profiles/{suffix}",uid,gid,0o700)
    directory(f"/var/lib/uap-observer/workspaces/{suffix}",uid,gid,0o700)
directory("/var/lib/uap-observer-human",0,0,0o755)
directory("/var/lib/uap-observer-human/pending",0,identities[3][1],0o750)
for name in ("consumed","reserved"): directory(f"/var/lib/uap-observer-human/{name}",0,0,0o700)
config_gid=grp.getgrnam("uap-observer-adapter-config").gr_gid
directory("/var/lib/uap-observer-consent",0,0,0o755)
directory("/var/lib/uap-observer-consent/pending",0,config_gid,0o750)
for name in ("consumed","reserved"): directory(f"/var/lib/uap-observer-consent/{name}",0,0,0o700)
directory("/var/lib/caddy",caddy_uid,caddy_gid,0o700)
directory("/var/log/caddy",caddy_uid,caddy_gid,0o700)
PY
}

observer_validate_protected_inputs() {
  closure=$1
  observer_runtime=${2:-$closure/runtime}
  protected_root=${3:-/opt/uap-observer-inputs}
  PYTHONPATH="$observer_runtime" python3 - "$closure/etc/uap-observer-adapter-config.json" "$protected_root" <<'PY'
import sys
from pathlib import Path
from observer.fixed_runner import validate_adapter_input_access
validate_adapter_input_access(Path(sys.argv[1]),protected_root=Path(sys.argv[2]))
PY
}

observer_validate_installed_closure_sources() {
  closure=$1
  source_root=$2
  adapter_config=$3
  observer_config=$4
  caddy_config=$5
  runner_digest=$6
  adapter_digest=$7
  caddy_digest=$8
  cmp "$observer_config" "$closure/etc/uap-observer.json"
  cmp "$adapter_config" "$closure/etc/uap-observer-adapter-config.json"
  cmp "$caddy_config" "$closure/etc/Caddyfile"
  test "$(sha256sum "$closure/libexec/uap-observer-runner" | cut -d' ' -f1)" = "$runner_digest"
  test "$(sha256sum "$closure/libexec/uap-observer-fixed-adapter" | cut -d' ' -f1)" = "$adapter_digest"
  test "$(sha256sum "$closure/bin/caddy" | cut -d' ' -f1)" = "$caddy_digest"
  for source in "$source_root"/observer/*.py; do
    cmp "$source" "$closure/runtime/observer/$(basename "$source")"
  done
  for source in "$source_root"/tests/e2e/schemas/*.schema.json; do
    cmp "$source" "$closure/runtime/tests/e2e/schemas/$(basename "$source")"
  done
  cmp "$source_root/deploy/uap-observer-signer.py" "$closure/runtime/uap-observer-signer.py"
  cmp "$source_root/deploy/uap-observer-attest-chatgpt.py" "$closure/libexec/uap-observer-attest-chatgpt"
  cmp "$source_root/deploy/uap-observer-attest-consent.py" "$closure/libexec/uap-observer-attest-consent"
  cmp "$source_root/deploy/uap-observer-provision-profile.py" "$closure/libexec/uap-observer-provision-profile"
  for unit in $observer_units; do cmp "$source_root/deploy/$unit" "$closure/systemd/$unit"; done
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$closure/runtime" "$closure/venv/bin/python" -B -c 'import cryptography,jsonschema; import observer.http_server'
  python3 - "$closure/etc/uap-observer-adapter-config.json" "$closure/etc/uap-observer-adapters.json" "$adapter_digest" <<'PY'
import hashlib,json,sys
config_path,adapters_path,adapter_digest=sys.argv[1:]
config_digest="sha256:"+hashlib.sha256(open(config_path,"rb").read()).hexdigest()
artifacts={"runtime-attestations.json":"runtime","notion-oauth-attestations.json":"notion","chatgpt-cloudflare-attestation.json":"chatgpt","consent.json":"consent"}
expected={"schema_version":1,"config":{"path":"/opt/uap-observer-current/etc/uap-observer-adapter-config.json","sha256":config_digest},"artifacts":{artifact:{"path":f"/opt/uap-observer-current/libexec/uap-observer-adapter-{name}","sha256":"sha256:"+adapter_digest} for artifact,name in artifacts.items()}}
if json.load(open(adapters_path,encoding="utf-8")) != expected: raise SystemExit("installed adapter registry differs")
PY
}

observer_sync_tree() {
  python3 - "$1" <<'PY'
import os,stat,sys
from pathlib import Path
root=Path(sys.argv[1])
directories=[]
for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
    info=path.lstat()
    if stat.S_ISREG(info.st_mode):
        descriptor=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    elif stat.S_ISDIR(info.st_mode): directories.append(path)
    elif not stat.S_ISLNK(info.st_mode): raise SystemExit("durability tree contains a special file")
directories.append(root)
for path in directories:
    descriptor=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
PY
}

observer_sync_directory() {
  python3 - "$1" <<'PY'
import os,sys
descriptor=os.open(sys.argv[1],os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW)
try: os.fsync(descriptor)
finally: os.close(descriptor)
PY
}

observer_cleanup_committed_stage_payload() {
  stage=$1
  for item in "$stage"/* "$stage"/.[!.]* "$stage"/..?*; do
    if [ ! -e "$item" ] && [ ! -L "$item" ]; then continue; fi
    case "${item##*/}" in
      journal-resolved) continue ;;
    esac
    rm -rf -- "$item" || return 1
  done
  observer_sync_directory "$stage" || return 1
}

observer_mark_recovery_resolved() {
  stage=$1
  python3 - "$stage" <<'PY'
import os,secrets,sys
stage=sys.argv[1]
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW
directory=os.open(stage,flags)
temporary=f".journal-resolved-{os.getpid()}-{secrets.token_hex(16)}"
try:
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600,dir_fd=directory)
    try:
        os.write(descriptor,b"resolved-v1\n")
        os.fchown(descriptor,0,0)
        os.fchmod(descriptor,0o600)
        os.fsync(descriptor)
    finally: os.close(descriptor)
    os.rename(temporary,"journal-resolved",src_dir_fd=directory,dst_dir_fd=directory)
    os.fsync(directory)
finally:
    try: os.unlink(temporary,dir_fd=directory)
    except FileNotFoundError: pass
    os.close(directory)
PY
}

apply_observer_closure_modes() {
  closure=$1
  config_group=${2:-uap-observer-adapter-config}
  caddy_group=${3:-caddy}
  chown -R root "$closure"
  find "$closure" -type d -exec chmod 0755 {} +
  find "$closure" -type f -perm /0111 -exec chmod 0755 {} +
  find "$closure" -type f ! -perm /0111 -exec chmod 0644 {} +
  chmod 0640 "$closure/etc/uap-observer-adapter-config.json" "$closure/etc/Caddyfile"
  chown "root:$config_group" "$closure/etc/uap-observer-adapter-config.json"
  chown "root:$caddy_group" "$closure/etc/Caddyfile"
  chmod 0755 "$closure/libexec/uap-observer-runner" "$closure/libexec/uap-observer-fixed-adapter"
  for name in runtime notion chatgpt consent; do
    chmod 0755 "$closure/libexec/uap-observer-adapter-$name"
  done
  test "$(stat -c '%u:%g:%a' "$closure/etc/uap-observer.json")" = '0:0:644'
  test "$(stat -c '%u:%g:%a:%h' "$closure/etc/uap-observer-adapter-config.json")" = "0:$(getent group "$config_group" | cut -d: -f3):640:1"
  test "$(stat -c '%u:%g:%a:%h' "$closure/etc/Caddyfile")" = "0:$(getent group "$caddy_group" | cut -d: -f3):640:1"
  test "$(stat -c '%u:%g:%a' "$closure/etc/uap-observer-adapters.json")" = '0:0:644'
  test "$(stat -c '%u:%g:%a' "$closure/libexec/uap-observer-runner")" = '0:0:755'
  test -z "$(find "$closure" \( -type d -o -type f \) -perm /0022 -print -quit)"
}

observer_validate_systemd_topology() {
  python3 - "$1" <<'PY'
import os,stat,sys
from pathlib import Path
root=Path(sys.argv[1])
info=root.lstat()
if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022):
    raise SystemExit("systemd root is unsafe")
units=("uap-observer.service","uap-observer-signer.service","uap-observer-runner.service","uap-observer-runner.socket","uap-observer-caddy.service")
dropins=("uap-observer.service.d","uap-observer-runner.service.d")
allowed=set(units+dropins)
actual={item.name for item in root.iterdir() if item.name.startswith("uap-observer")}
if actual - allowed: raise SystemExit("systemd observer inventory contains an unexpected target")
for name in units+dropins:
    path=root/name
    try: item=path.lstat()
    except FileNotFoundError: continue
    if (item.st_uid != 0 or item.st_gid != 0
            or (not stat.S_ISLNK(item.st_mode) and item.st_mode & 0o022)):
        raise SystemExit("systemd target is not root-controlled")
    if name in units:
        if stat.S_ISREG(item.st_mode):
            if item.st_nlink != 1: raise SystemExit("systemd regular target has unsafe link count")
        elif not stat.S_ISLNK(item.st_mode):
            raise SystemExit("systemd unit target has unsafe type")
        continue
    if not stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode):
        raise SystemExit("systemd drop-in directory is unsafe")
    for current,dirs,files in os.walk(path,followlinks=False):
        for child_name in dirs+files:
            child_info=(Path(current)/child_name).lstat()
            if child_info.st_uid != 0 or child_info.st_gid != 0 or child_info.st_mode & 0o022:
                raise SystemExit("systemd drop-in is not root-controlled")
            if stat.S_ISLNK(child_info.st_mode) or not (stat.S_ISDIR(child_info.st_mode) or stat.S_ISREG(child_info.st_mode)):
                raise SystemExit("systemd drop-in contains unsafe topology")
            if stat.S_ISREG(child_info.st_mode) and child_info.st_nlink != 1:
                raise SystemExit("systemd drop-in regular file has unsafe link count")
PY
}

journal_observer_systemd() {
  backup=$1
  systemd_root=$2
  test ! -e "$backup"
  observer_validate_systemd_topology "$systemd_root" || return 1
  install -d -o root -g root -m 0700 "$backup" "$backup/items"
  : > "$backup/manifest"
  chown root:root "$backup/manifest"
  chmod 0600 "$backup/manifest"
  index=0
  for relative in $observer_units uap-observer.service.d uap-observer-runner.service.d; do
    target="$systemd_root/$relative"
    if [ -e "$target" ] || [ -L "$target" ]; then
      cp -a "$target" "$backup/items/$index"
      printf 'present %s %s\n' "$index" "$relative" >> "$backup/manifest"
    else
      printf 'missing %s %s\n' "$index" "$relative" >> "$backup/manifest"
    fi
    index=$((index + 1))
  done
}

validate_observer_systemd_journal() {
  backup=$1
  test -d "$backup" || return 1
  test ! -L "$backup" || return 1
  test -d "$backup/items" || return 1
  test ! -L "$backup/items" || return 1
  test -f "$backup/manifest" || return 1
  test ! -L "$backup/manifest" || return 1
  test "$(stat -c '%u:%g:%a' "$backup")" = 0:0:700 || return 1
  test "$(stat -c '%u:%g:%a' "$backup/items")" = 0:0:700 || return 1
  test "$(stat -c '%u:%g:%a:%h' "$backup/manifest")" = 0:0:600:1 || return 1
  expected_index=0
  expected_names="$observer_units uap-observer.service.d uap-observer-runner.service.d"
  seen_items=
  while read -r state index relative extra; do
    test -z "${extra:-}" || return 1
    test "$index" = "$expected_index" || return 1
    expected_relative=$(printf '%s\n' $expected_names | sed -n "$((expected_index + 1))p")
    test "$relative" = "$expected_relative" || return 1
    case "$state" in
      present)
        test -e "$backup/items/$index" || test -L "$backup/items/$index" || return 1
        seen_items="$seen_items $index"
        ;;
      missing)
        test ! -e "$backup/items/$index" || return 1
        test ! -L "$backup/items/$index" || return 1
        ;;
      *) echo "installer recovery journal is invalid" >&2; return 1 ;;
    esac
    expected_index=$((expected_index + 1))
  done < "$backup/manifest"
  test "$expected_index" -eq 7 || return 1
  for item in "$backup"/items/*; do
    if [ -e "$item" ] || [ -L "$item" ]; then
      index=${item##*/}
      case " $seen_items " in *" $index "*) ;; *) echo "installer recovery journal is invalid" >&2; return 1;; esac
    fi
  done
  python3 - "$backup" <<'PY' || return 1
import os,stat,sys
from pathlib import Path
root=Path(sys.argv[1]); items=root/"items"
manifest=[line.split() for line in (root/"manifest").read_text().splitlines()]
present={index for state,index,_ in manifest if state == "present"}
actual={item.name for item in items.iterdir()}
if actual != present: raise SystemExit("installer recovery journal inventory differs")
for state,index,_ in manifest:
    if state != "present": continue
    path=items/index; info=path.lstat()
    if int(index) < 5:
        if stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1: raise SystemExit("journal target link count differs")
        elif not stat.S_ISLNK(info.st_mode): raise SystemExit("journal unit type differs")
    else:
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode): raise SystemExit("journal drop-in type differs")
        for current,dirs,files in os.walk(path,followlinks=False):
            for child_name in dirs+files:
                child=(Path(current)/child_name).lstat()
                if stat.S_ISLNK(child.st_mode) or not (stat.S_ISDIR(child.st_mode) or stat.S_ISREG(child.st_mode)):
                    raise SystemExit("journal drop-in topology differs")
                if stat.S_ISREG(child.st_mode) and child.st_nlink != 1:
                    raise SystemExit("journal drop-in link count differs")
PY
}

# Install one reviewed systemd entry without ever opening the destination.
# The only names created are exclusive entries in the destination directory;
# renameat2 protects the displaced name and rename atomically replaces any
# destination symlink raced in after validation.
observer_replace_systemd_entries() {
  systemd_root=$1
  shift
  python3 - "$systemd_root" "$@" <<'PY'
import ctypes,os,secrets,stat,sys
from pathlib import Path

root_path=sys.argv[1]
pairs=sys.argv[2:]
if not pairs or len(pairs) % 2: raise SystemExit("invalid systemd replacement arguments")
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW
rootfd=os.open(root_path,flags)
libc=ctypes.CDLL(None,use_errno=True)
renameat2=getattr(libc,"renameat2",None)
if renameat2 is None:
    raise SystemExit("renameat2 is required for safe systemd replacement")
renameat2.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
renameat2.restype=ctypes.c_int

def trusted(info: os.stat_result, *, link: bool = False) -> None:
    if info.st_uid != 0 or info.st_gid != 0 or (not link and info.st_mode & 0o022):
        raise PermissionError("systemd source is not root-controlled")

def exclusive_name(prefix: str) -> str:
    return f".{prefix}-{os.getpid()}-{secrets.token_hex(16)}"

def rename_noreplace(oldfd: int, old: str, newfd: int, new: str) -> None:
    if renameat2(oldfd,os.fsencode(old),newfd,os.fsencode(new),1) != 0:
        value=ctypes.get_errno()
        raise OSError(value,os.strerror(value),old)

def copy_entry(srcfd: int, srcname: str, dstfd: int, dstname: str) -> None:
    info=os.stat(srcname,dir_fd=srcfd,follow_symlinks=False)
    mode=info.st_mode
    if stat.S_ISREG(mode):
        trusted(info)
        if info.st_nlink != 1: raise PermissionError("systemd source has unsafe link count")
        infd=os.open(srcname,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=srcfd)
        outfd=os.open(dstname,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600,dir_fd=dstfd)
        try:
            if os.fstat(infd) != info: raise PermissionError("systemd source changed while copying")
            while True:
                block=os.read(infd,1 << 20)
                if not block: break
                view=memoryview(block)
                while view: view=view[os.write(outfd,view):]
            os.fchown(outfd,info.st_uid,info.st_gid)
            os.fchmod(outfd,stat.S_IMODE(mode))
            os.fsync(outfd)
        finally:
            os.close(outfd); os.close(infd)
    elif stat.S_ISDIR(mode):
        trusted(info)
        os.mkdir(dstname,0o700,dir_fd=dstfd)
        infd=os.open(srcname,flags,dir_fd=srcfd)
        outfd=os.open(dstname,flags,dir_fd=dstfd)
        try:
            if os.fstat(infd) != info: raise PermissionError("systemd source changed while copying")
            for child in os.listdir(infd): copy_entry(infd,child,outfd,child)
            os.fchown(outfd,info.st_uid,info.st_gid)
            os.fchmod(outfd,stat.S_IMODE(mode))
            os.fsync(outfd)
        finally:
            os.close(outfd); os.close(infd)
    elif stat.S_ISLNK(mode):
        trusted(info,link=True)
        os.symlink(os.readlink(srcname,dir_fd=srcfd),dstname,dir_fd=dstfd)
        os.chown(dstname,info.st_uid,info.st_gid,dir_fd=dstfd,follow_symlinks=False)
    else:
        raise PermissionError("systemd source has unsafe type")

def remove_entry(parentfd: int, child: str) -> None:
    info=os.stat(child,dir_fd=parentfd,follow_symlinks=False)
    if stat.S_ISDIR(info.st_mode):
        childfd=os.open(child,flags,dir_fd=parentfd)
        try:
            for nested in os.listdir(childfd): remove_entry(childfd,nested)
        finally: os.close(childfd)
        os.rmdir(child,dir_fd=parentfd)
    else:
        os.unlink(child,dir_fd=parentfd)

def replace(source_arg: str, name: str) -> None:
    if not name or "/" in name or name in (".",".."):
        raise ValueError("invalid systemd destination name")
    temporary=exclusive_name("uap-observer-new")
    displaced=exclusive_name("uap-observer-old")
    created=False
    moved=False
    try:
        if source_arg != "-":
            source=Path(source_arg)
            source_parent=os.open(source.parent,flags)
            try: copy_entry(source_parent,source.name,rootfd,temporary)
            finally: os.close(source_parent)
            created=True
        try:
            rename_noreplace(rootfd,name,rootfd,displaced)
            moved=True
        except FileNotFoundError:
            pass
        if created:
            os.rename(temporary,name,src_dir_fd=rootfd,dst_dir_fd=rootfd)
            created=False
        os.fsync(rootfd)
        if moved:
            remove_entry(rootfd,displaced)
            moved=False
            os.fsync(rootfd)
    except BaseException:
        if moved:
            try: rename_noreplace(rootfd,displaced,rootfd,name)
            except OSError: pass
        if created:
            try: remove_entry(rootfd,temporary)
            except OSError: pass
        raise

try:
    root_info=os.fstat(rootfd)
    trusted(root_info)
    if not stat.S_ISDIR(root_info.st_mode): raise PermissionError("systemd root is unsafe")
    stale=[name for name in os.listdir(rootfd) if name.startswith((".uap-observer-new-",".uap-observer-old-"))]
    for name in stale: remove_entry(rootfd,name)
    if stale: os.fsync(rootfd)
    fail_at=int(os.environ.get("UAP_OBSERVER_REPLACE_FAIL_AT") or 0)
    for index in range(0,len(pairs),2):
        replace(pairs[index],pairs[index+1])
        if fail_at == index // 2 + 1: raise SystemExit(1)
finally:
    os.close(rootfd)
PY
}

restore_observer_systemd() {
  backup=$1
  systemd_root=$2
  set -- "$systemd_root"
  while read -r state index relative; do
    if [ "$state" = present ]; then
      set -- "$@" "$backup/items/$index" "$relative"
    else
      set -- "$@" - "$relative"
    fi
  done < "$backup/manifest"
  observer_replace_systemd_entries "$@" || return 1
  observer_validate_systemd_topology "$systemd_root" || return 1
  while read -r state index relative; do
    target="$systemd_root/$relative"
    if [ "$state" = present ]; then
      diff -r --no-dereference "$backup/items/$index" "$target" >/dev/null || return 1
    else
      test ! -e "$target" && test ! -L "$target" || return 1
    fi
  done < "$backup/manifest"
}

recover_observer_install() {
  stage=$1
  closures_root=$2
  current_pointer=$3
  systemd_root=$4
  manager=$5
  cleanup_partials=${6:-observer_cleanup_recovery_partials}
  journal_committed=0
  journal_resolved=0
  if [ ! -e "$stage" ] && [ ! -L "$stage" ]; then
    # Retried even when a prior attempt removed the name but its parent fsync
    # failed.  This makes the removal durability step independently retryable.
    observer_sync_directory "$(dirname "$stage")"
    return
  fi
  if [ ! -d "$stage" ] || [ -L "$stage" ]; then
    echo "installer recovery journal is invalid" >&2
    return 1
  fi
  test "$(stat -c '%u:%g:%a' "$stage")" = 0:0:700 || {
    echo "installer recovery journal is invalid" >&2
    return 1
  }
  if [ -e "$stage/journal-resolved" ] || [ -L "$stage/journal-resolved" ]; then
    journal_committed=1
    journal_resolved=1
    test -f "$stage/journal-resolved" && test ! -L "$stage/journal-resolved" || return 1
    test "$(stat -c '%u:%g:%a:%h' "$stage/journal-resolved")" = 0:0:600:1 || return 1
    test "$(cat "$stage/journal-resolved")" = resolved-v1 || return 1
  elif [ ! -e "$stage/journal-committed" ] && [ ! -L "$stage/journal-committed" ]; then
    # The atomic marker is the sole durable proof that mutation could begin.
    # lstat traversal never follows a staged link outside this fixed tree.
    python3 - "$stage" <<'PY' || return 1
import os,stat,sys
from pathlib import Path
for current,dirs,files in os.walk(Path(sys.argv[1]),followlinks=False):
    for name in dirs+files:
        mode=(Path(current)/name).lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
            raise SystemExit("pre-commit staging tree contains an unsafe object")
PY
  else
    journal_committed=1
    test -f "$stage/journal-committed" && test ! -L "$stage/journal-committed" || return 1
    test "$(stat -c '%u:%g:%a:%h' "$stage/journal-committed")" = 0:0:600:1 || return 1
    test "$(cat "$stage/journal-committed")" = committed-v1 || return 1
    test -f "$stage/closure-digest" && test ! -L "$stage/closure-digest" || return 1
    test "$(stat -c '%u:%g:%a:%h' "$stage/closure-digest")" = 0:0:600:1 || return 1
    recovered_digest=$(cat "$stage/closure-digest")
    printf '%s\n' "$recovered_digest" | grep -Eq '^[0-9a-f]{64}$' || return 1
    validate_observer_systemd_journal "$stage/systemd-backup" || return 1
    test -d "$closures_root" && test ! -L "$closures_root" || return 1
    test "$(stat -c '%u:%g:%a' "$closures_root")" = 0:0:755 || return 1
    # A current pointer means activation crossed its commit point.  Recovery is
    # only permitted to accept the exact journaled closure in that case.
    if [ -e "$current_pointer" ] || [ -L "$current_pointer" ]; then
      test -L "$current_pointer" || return 1
      test "$(readlink "$current_pointer")" = "uap-observer-closures/$recovered_digest" || return 1
      test -d "$closures_root/$recovered_digest" || return 1
      test ! -L "$closures_root/$recovered_digest" || return 1
      observer_sync_directory "$(dirname "$current_pointer")" || return 1
    else
      restore_observer_systemd "$stage/systemd-backup" "$systemd_root" || return 1
      observer_sync_tree "$systemd_root" || return 1
      "$manager" daemon-reload || return 1
      candidate="$closures_root/$recovered_digest"
      if [ -e "$candidate" ] || [ -L "$candidate" ]; then rm -rf -- "$candidate" || return 1; fi
      observer_sync_tree "$closures_root" || return 1
    fi
    observer_mark_recovery_resolved "$stage" || return 1
    journal_resolved=1
  fi
  "$cleanup_partials" || return 1
  if [ "$journal_resolved" -eq 1 ]; then
    observer_cleanup_committed_stage_payload "$stage" || return 1
  fi
  rm -rf -- "$stage" || return 1
  observer_sync_directory "$(dirname "$stage")" || return 1
}

observer_install_failpoint() {
  observer_install_step=$((observer_install_step + 1))
  test "${UAP_OBSERVER_INSTALL_FAIL_AT:-}" != "$observer_install_step"
}

activate_observer_systemd() {
  staged=$1
  systemd_root=$2
  backup=${3:-}
  observer_install_step=0
  if [ -n "$backup" ]; then
    validate_observer_systemd_journal "$backup" || return 1
    while read -r state index relative; do
      target="$systemd_root/$relative"
      if [ "$state" = present ]; then
        diff -r --no-dereference "$backup/items/$index" "$target" >/dev/null || return 1
      else
        test ! -e "$target" && test ! -L "$target" || return 1
      fi
    done < "$backup/manifest"
  fi
  set -- "$systemd_root"
  for unit in $observer_units; do set -- "$@" "$staged/$unit" "$unit"; done
  for service in uap-observer uap-observer-runner; do
    set -- "$@" "$staged/$service.service.d" "$service.service.d"
  done
  UAP_OBSERVER_REPLACE_FAIL_AT=${UAP_OBSERVER_INSTALL_FAIL_AT:-} \
    observer_replace_systemd_entries "$@" || return 1
  observer_install_step=7
  validate_observer_systemd_inventory "$staged" "$systemd_root"
}

validate_observer_systemd_inventory() {
  reviewed=$1
  systemd_root=$2
  observer_validate_systemd_topology "$systemd_root" || return 1
  expected=$(printf '%s\n' $observer_units uap-observer.service.d uap-observer-runner.service.d | sort)
  actual=$(find "$systemd_root" -mindepth 1 -maxdepth 1 -name 'uap-observer*' -printf '%f\n' | sort)
  test "$actual" = "$expected" || return 1
  for relative in $observer_units uap-observer.service.d uap-observer-runner.service.d; do
    diff -r --no-dereference "$reviewed/$relative" "$systemd_root/$relative" >/dev/null || return 1
  done
}

reload_observer_systemd() {
  manager=$1
  "$manager" daemon-reload
  observer_install_failpoint || return 1
}
