#!/bin/sh

# Shared, testable installer primitives. The caller supplies only disposable
# roots in tests; production calls use the fixed system paths.

observer_units='uap-observer.service uap-observer-signer.service uap-observer-runner.service uap-observer-runner.socket uap-observer-caddy.service'

# Control data is never consumed through a pathname-opening utility.  The
# parent and object are pinned without following links and O_NOATIME keeps
# validation and recovery from becoming metadata mutations themselves.
observer_read_control_file() {
  python3 - "$1" <<'PY'
import os,stat,sys
path=os.path.abspath(sys.argv[1]); parent_path=os.path.dirname(path); name=os.path.basename(path)
dirflags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME
fileflags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME
parent_info=os.stat(parent_path,follow_symlinks=False); parent=os.open(parent_path,dirflags)
try:
    if os.fstat(parent)!=parent_info: raise PermissionError("control parent changed while opening")
    before=os.stat(name,dir_fd=parent,follow_symlinks=False); descriptor=os.open(name,fileflags,dir_fd=parent)
    try:
        if os.fstat(descriptor)!=before or not stat.S_ISREG(before.st_mode): raise PermissionError("control file changed while opening")
        while True:
            block=os.read(descriptor,1<<20)
            if not block: break
            os.write(1,block)
        if os.fstat(descriptor)!=before: raise PermissionError("control file changed while reading")
    finally: os.close(descriptor)
finally: os.close(parent)
PY
}

observer_read_symlink_neutral() {
  python3 - "$1" <<'PY'
import os,stat,sys
path=os.path.abspath(sys.argv[1]); parent_path=os.path.dirname(path); name=os.path.basename(path)
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME
parent_info=os.stat(parent_path,follow_symlinks=False); parent=os.open(parent_path,flags)
try:
    if os.fstat(parent)!=parent_info: raise PermissionError("symlink parent changed while opening")
    before=os.stat(name,dir_fd=parent,follow_symlinks=False)
    if not stat.S_ISLNK(before.st_mode): raise PermissionError("control symlink is unsafe")
    value=os.readlink(name,dir_fd=parent)
    os.utime(name,ns=(before.st_atime_ns,before.st_mtime_ns),dir_fd=parent,follow_symlinks=False)
    after=os.stat(name,dir_fd=parent,follow_symlinks=False)
    fields=lambda value:(value.st_dev,value.st_ino,stat.S_IFMT(value.st_mode),stat.S_IMODE(value.st_mode),value.st_uid,value.st_gid,value.st_atime_ns,value.st_mtime_ns,value.st_nlink)
    if fields(after)!=fields(before): raise PermissionError("control symlink changed while reading")
    os.write(1,os.fsencode(value))
finally: os.close(parent)
PY
}

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
  target=$(observer_read_symlink_neutral "$current_pointer")
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
  test "$(observer_read_control_file "$closure/.complete")" = complete-v1
  test "$(observer_read_control_file "$closure/.install-identity")" = "$expected_install_identity"
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
directory_flags=os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NOATIME
file_flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME
root=os.open(sys.argv[1],directory_flags)
def sync_tree(directory: int) -> None:
    children=[]
    for name in os.listdir(directory):
        info=os.stat(name,dir_fd=directory,follow_symlinks=False)
        if stat.S_ISREG(info.st_mode):
            descriptor=os.open(name,file_flags,dir_fd=directory)
            try:
                if os.fstat(descriptor) != info: raise PermissionError("durability file changed during traversal")
                os.fsync(descriptor)
            finally: os.close(descriptor)
        elif stat.S_ISDIR(info.st_mode):
            child=os.open(name,directory_flags,dir_fd=directory)
            if os.fstat(child) != info:
                os.close(child); raise PermissionError("durability directory changed during traversal")
            children.append(child)
        elif not stat.S_ISLNK(info.st_mode):
            raise SystemExit("durability tree contains a special file")
    for child in children:
        try: sync_tree(child)
        finally: os.close(child)
    os.fsync(directory)
try: sync_tree(root)
finally: os.close(root)
PY
}

observer_sync_directory() {
  python3 - "$1" <<'PY'
import os,sys
descriptor=os.open(sys.argv[1],os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NOATIME)
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
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME
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
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME
root_before=os.stat(sys.argv[1],follow_symlinks=False)
rootfd=os.open(sys.argv[1],flags)
info=os.fstat(rootfd)
if info!=root_before: raise PermissionError("systemd root changed while opening")
if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022):
    raise SystemExit("systemd root is unsafe")
units=("uap-observer.service","uap-observer-signer.service","uap-observer-runner.service","uap-observer-runner.socket","uap-observer-caddy.service")
dropins=("uap-observer.service.d","uap-observer-runner.service.d")
allowed=set(units+dropins)
actual={name for name in os.listdir(rootfd) if name.startswith("uap-observer")}
if actual - allowed: raise SystemExit("systemd observer inventory contains an unexpected target")

def validate_dropin(parentfd: int, name: str, before: os.stat_result) -> None:
    directory=os.open(name,flags,dir_fd=parentfd)
    try:
        info=os.fstat(directory)
        if info!=before: raise PermissionError("systemd drop-in changed while opening")
        for child_name in os.listdir(directory):
            child_info=os.stat(child_name,dir_fd=directory,follow_symlinks=False)
            if child_info.st_uid != 0 or child_info.st_gid != 0 or child_info.st_mode & 0o022:
                raise SystemExit("systemd drop-in is not root-controlled")
            if stat.S_ISDIR(child_info.st_mode):
                validate_dropin(directory,child_name,child_info)
            elif stat.S_ISREG(child_info.st_mode):
                if child_info.st_nlink != 1: raise SystemExit("systemd drop-in regular file has unsafe link count")
            else:
                raise SystemExit("systemd drop-in contains unsafe topology")
        if os.fstat(directory)!=info: raise PermissionError("systemd drop-in changed during traversal")
    finally: os.close(directory)

for name in units+dropins:
    try: item=os.stat(name,dir_fd=rootfd,follow_symlinks=False)
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
    validate_dropin(rootfd,name,item)
if os.fstat(rootfd)!=info: raise PermissionError("systemd root changed during traversal")
os.close(rootfd)
PY
}

observer_systemd_archive() {
  operation=$1
  backup=$2
  live=${3:-}
  python3 - "$operation" "$backup" "$live" <<'PY'
import base64,hashlib,json,os,secrets,stat,sys

operation,backup_path,live_path=sys.argv[1:]
names=("uap-observer.service","uap-observer-signer.service","uap-observer-runner.service","uap-observer-runner.socket","uap-observer-caddy.service","uap-observer.service.d","uap-observer-runner.service.d")
dirflags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME
fileflags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME

def open_directory(name,*,dir_fd=None):
    before=os.stat(name,dir_fd=dir_fd,follow_symlinks=False)
    descriptor=os.open(name,dirflags,dir_fd=dir_fd)
    if os.fstat(descriptor)!=before:
        os.close(descriptor); raise PermissionError("systemd directory changed while opening")
    return descriptor,before

def metadata(info):
    return {"type":stat.S_IFMT(info.st_mode),"mode":stat.S_IMODE(info.st_mode),"uid":info.st_uid,"gid":info.st_gid,"atime":info.st_atime_ns,"mtime":info.st_mtime_ns,"nlink":info.st_nlink}
def proc_link(parent,name): return f"/proc/self/fd/{parent}/{name}"
def xattrs(parent,name,info,descriptor=None):
    target=proc_link(parent,name) if stat.S_ISLNK(info.st_mode) else descriptor
    return [[base64.b64encode(os.fsencode(key)).decode(),base64.b64encode(os.getxattr(target,key,follow_symlinks=not stat.S_ISLNK(info.st_mode))).decode()] for key in sorted(os.listxattr(target,follow_symlinks=not stat.S_ISLNK(info.st_mode)))]
def set_xattrs(parent,name,info,values,descriptor=None):
    target=proc_link(parent,name) if stat.S_ISLNK(info.st_mode) else descriptor
    for encoded,value in values:
        key=os.fsdecode(base64.b64decode(encoded)); data=base64.b64decode(value)
        os.setxattr(target,key,data,follow_symlinks=not stat.S_ISLNK(info.st_mode))
def stable_link(parent,name,info):
    target=os.readlink(name,dir_fd=parent)
    os.utime(name,ns=(info.st_atime_ns,info.st_mtime_ns),dir_fd=parent,follow_symlinks=False)
    after=os.stat(name,dir_fd=parent,follow_symlinks=False)
    if metadata(after)!=metadata(info) or (after.st_dev,after.st_ino)!=(info.st_dev,info.st_ino):
        raise PermissionError("systemd symlink changed while reading")
    return target
def trusted(info,link=False):
    if info.st_uid!=0 or info.st_gid!=0 or (not link and info.st_mode&0o022): raise PermissionError("systemd target is not root-controlled")

def scan(parent,name,prefix,*,allow_link=True):
    info=os.stat(name,dir_fd=parent,follow_symlinks=False); mode=info.st_mode
    if stat.S_ISREG(mode):
        trusted(info); descriptor=os.open(name,fileflags,dir_fd=parent)
        try:
            if os.fstat(descriptor)!=info: raise PermissionError("systemd file changed while reading")
            info=os.fstat(descriptor); record=metadata(info); record["path"]=prefix
            digest=hashlib.sha256()
            while True:
                block=os.read(descriptor,1<<20)
                if not block: break
                digest.update(block)
            record["payload"]=digest.hexdigest(); record["xattrs"]=xattrs(parent,name,info,descriptor)
        finally: os.close(descriptor)
    elif stat.S_ISDIR(mode):
        trusted(info); descriptor,opened=open_directory(name,dir_fd=parent)
        try:
            if opened!=info: raise PermissionError("systemd directory changed while reading")
            info=os.fstat(descriptor); record=metadata(info); record["path"]=prefix
            record["xattrs"]=xattrs(parent,name,info,descriptor)
            children=[]
            for child in sorted(os.listdir(descriptor)):
                children.extend(scan(descriptor,child,prefix+"/"+child,allow_link=False))
            record["children"]=[child for child in sorted(os.listdir(descriptor))]
            if os.fstat(descriptor)!=info: raise PermissionError("systemd directory changed while reading")
        finally: os.close(descriptor)
        return [record]+children
    elif stat.S_ISLNK(mode):
        if not allow_link: raise PermissionError("systemd drop-in contains a symlink")
        trusted(info,True)
        record=metadata(info); record["path"]=prefix
        record["payload"]=stable_link(parent,name,info)
        record["xattrs"]=xattrs(parent,name,info)
        after=os.stat(name,dir_fd=parent,follow_symlinks=False)
        if metadata(after)!=metadata(info) or (after.st_dev,after.st_ino)!=(info.st_dev,info.st_ino): raise PermissionError("systemd symlink changed while reading")
    else: raise PermissionError("systemd target has unsafe type")
    if stat.S_ISREG(mode) and info.st_nlink!=1: raise PermissionError("systemd regular target has unsafe link count")
    return [record]

def copy(parent,name,destination,dstname,prefix,allow_link=True):
    info=os.stat(name,dir_fd=parent,follow_symlinks=False); mode=info.st_mode
    if stat.S_ISREG(mode):
        trusted(info)
        if info.st_nlink!=1: raise PermissionError("systemd regular target has unsafe link count")
        source=os.open(name,fileflags,dir_fd=parent); target=os.open(dstname,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600,dir_fd=destination)
        try:
            if os.fstat(source)!=info: raise PermissionError("systemd file changed while snapshotting")
            while True:
                block=os.read(source,1<<20)
                if not block: break
                view=memoryview(block)
                while view: view=view[os.write(target,view):]
            os.fchown(target,info.st_uid,info.st_gid); os.fchmod(target,stat.S_IMODE(mode)); set_xattrs(destination,dstname,info,xattrs(parent,name,info,source),target)
            os.utime(target,ns=(info.st_atime_ns,info.st_mtime_ns)); os.fsync(target)
        finally: os.close(target); os.close(source)
    elif stat.S_ISDIR(mode):
        trusted(info); source,opened=open_directory(name,dir_fd=parent); os.mkdir(dstname,0o700,dir_fd=destination); target,_=open_directory(dstname,dir_fd=destination)
        try:
            if opened!=info: raise PermissionError("systemd directory changed while snapshotting")
            info=os.fstat(source)
            for child in sorted(os.listdir(source)): copy(source,child,target,child,prefix+"/"+child,False)
            os.fchown(target,info.st_uid,info.st_gid); os.fchmod(target,stat.S_IMODE(mode)); set_xattrs(destination,dstname,info,xattrs(parent,name,info,source),target)
            os.utime(target,ns=(info.st_atime_ns,info.st_mtime_ns)); os.fsync(target)
            if os.fstat(source)!=info: raise PermissionError("systemd directory changed while snapshotting")
        finally: os.close(target); os.close(source)
    elif stat.S_ISLNK(mode):
        if not allow_link: raise PermissionError("systemd drop-in contains a symlink")
        trusted(info,True); target_text=stable_link(parent,name,info); attributes=xattrs(parent,name,info)
        after=os.stat(name,dir_fd=parent,follow_symlinks=False)
        if metadata(after)!=metadata(info) or (after.st_dev,after.st_ino)!=(info.st_dev,info.st_ino): raise PermissionError("systemd symlink changed while snapshotting")
        os.symlink(target_text,dstname,dir_fd=destination)
        os.chown(dstname,info.st_uid,info.st_gid,dir_fd=destination,follow_symlinks=False); set_xattrs(destination,dstname,info,attributes)
        os.utime(dstname,ns=(info.st_atime_ns,info.st_mtime_ns),dir_fd=destination,follow_symlinks=False)
    else: raise PermissionError("systemd target has unsafe type")

def read_file(directory,name):
    descriptor=os.open(name,fileflags,dir_fd=directory)
    try:
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_gid or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1: raise PermissionError("journal control file is unsafe")
        value=b""
        while True:
            block=os.read(descriptor,1<<20)
            if not block: break
            value+=block
        return value
    finally: os.close(descriptor)
def write_file(directory,name,data):
    descriptor=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600,dir_fd=directory)
    try: os.write(descriptor,data); os.fchown(descriptor,0,0); os.fchmod(descriptor,0o600); os.fsync(descriptor)
    finally: os.close(descriptor)
def load_archive():
    backup,info=open_directory(backup_path)
    if info.st_uid or info.st_gid or stat.S_IMODE(info.st_mode)!=0o700: raise PermissionError("journal root is unsafe")
    items,item_info=open_directory("items",dir_fd=backup)
    if item_info.st_uid or item_info.st_gid or stat.S_IMODE(item_info.st_mode)!=0o700: raise PermissionError("journal items are unsafe")
    manifest=read_file(backup,"manifest")
    identity=json.loads(read_file(backup,"identity.json"))
    expected_manifest=b"".join((b"present " if name in identity["present"] else b"missing ")+str(index).encode()+b" "+name.encode()+b"\n" for index,name in enumerate(names))
    if manifest!=expected_manifest or identity.get("version")!=1: raise PermissionError("installer recovery journal is invalid")
    return backup,items,identity,info,item_info

if operation=="create":
    parent_path=os.path.dirname(backup_path) or "."; leaf=os.path.basename(backup_path)
    parent,_=open_directory(parent_path); live,rootinfo=open_directory(live_path)
    created=False
    try:
        trusted(rootinfo)
        if not stat.S_ISDIR(rootinfo.st_mode): raise PermissionError("systemd root is unsafe")
        allowed=set(names); actual={name for name in os.listdir(live) if name.startswith("uap-observer")}
        if actual-allowed: raise PermissionError("systemd observer inventory contains an unexpected target")
        os.mkdir(leaf,0o700,dir_fd=parent); created=True; backup,_=open_directory(leaf,dir_fd=parent); os.mkdir("items",0o700,dir_fd=backup); items,_=open_directory("items",dir_fd=backup)
        try:
            present=[]; records=[]
            for index,name in enumerate(names):
                try: entry=os.stat(name,dir_fd=live,follow_symlinks=False)
                except FileNotFoundError: continue
                if index<5 and not (stat.S_ISREG(entry.st_mode) or stat.S_ISLNK(entry.st_mode)): raise PermissionError("systemd unit target has unsafe type")
                if index>=5 and not stat.S_ISDIR(entry.st_mode): raise PermissionError("systemd drop-in target has unsafe type")
                copy(live,name,items,str(index),name,index<5); present.append(name); records.extend(scan(live,name,name,allow_link=index<5))
            if os.fstat(live)!=rootinfo: raise PermissionError("systemd root changed while snapshotting")
            identity={"version":1,"present":present,"records":records}
            copied=[]
            for index,name in enumerate(names):
                if name in present: copied.extend(scan(items,str(index),name,allow_link=index<5))
            if copied!=records: raise PermissionError("journal snapshot identity differs")
            encoded=json.dumps(identity,sort_keys=True,separators=(",",":")).encode()+b"\n"
            manifest=b"".join((b"present " if name in present else b"missing ")+str(index).encode()+b" "+name.encode()+b"\n" for index,name in enumerate(names))
            write_file(backup,"manifest",manifest); write_file(backup,"identity.json",encoded); os.fsync(items); os.fsync(backup)
        finally: os.close(items); os.close(backup)
    except BaseException:
        if created:
            # The exclusive journal is uncommitted; the shell removes only this exact name.
            os.close(live); os.close(parent); raise
        raise
    finally:
        try: os.close(live)
        except OSError: pass
        try: os.close(parent)
        except OSError: pass
elif operation=="manifest":
    backup,items,identity,backup_info,item_info=load_archive()
    try:
        os.write(1,read_file(backup,"manifest"))
        if os.fstat(backup)!=backup_info or os.fstat(items)!=item_info: raise PermissionError("journal directory changed while reading")
    finally: os.close(items); os.close(backup)
elif operation in ("validate","compare"):
    backup,items,identity,backup_info,item_info=load_archive()
    try:
        actual=[]
        if set(os.listdir(items))!={str(names.index(name)) for name in identity["present"]}: raise PermissionError("journal inventory differs")
        for index,name in enumerate(names):
            if name in identity["present"]: actual.extend(scan(items,str(index),name,allow_link=index<5))
        if actual!=identity["records"]: raise PermissionError("journal payload differs")
        if operation=="compare":
            live,live_info=open_directory(live_path)
            try:
                current=[]
                for name in names:
                    try: os.stat(name,dir_fd=live,follow_symlinks=False)
                    except FileNotFoundError:
                        if name in identity["present"]: raise PermissionError("systemd target disappeared after journaling")
                    else:
                        if name not in identity["present"]: raise PermissionError("systemd target appeared after journaling")
                        current.extend(scan(live,name,name,allow_link=names.index(name)<5))
                if current!=identity["records"]: raise PermissionError("systemd target drifted after journaling")
                if os.fstat(live)!=live_info: raise PermissionError("systemd root changed while comparing")
            finally: os.close(live)
        if os.fstat(backup)!=backup_info or os.fstat(items)!=item_info: raise PermissionError("journal directory changed while validating")
    finally: os.close(items); os.close(backup)
else: raise SystemExit("invalid journal operation")
PY
  result=$?
  if [ "$operation" = create ] && [ "$result" -ne 0 ] && { [ -e "$backup" ] || [ -L "$backup" ]; }; then rm -rf -- "$backup"; fi
  return "$result"
}

journal_observer_systemd() { observer_systemd_archive create "$1" "$2"; }
validate_observer_systemd_journal() { observer_systemd_archive validate "$1"; }
observer_compare_systemd_journal() { observer_systemd_archive compare "$1" "$2"; }

# Install one reviewed systemd entry without ever opening the destination.
# The only names created are exclusive entries in the destination directory;
# renameat2 protects the displaced name and rename atomically replaces any
# destination symlink raced in after validation.
observer_replace_systemd_entries() {
  systemd_root=$1
  shift
  python3 - "$systemd_root" "$@" <<'PY'
import base64,ctypes,errno,hashlib,json,os,secrets,stat,sys
from pathlib import Path

root_path=sys.argv[1]
pairs=sys.argv[2:]
if not pairs or len(pairs) % 2: raise SystemExit("invalid systemd replacement arguments")
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME
root_lstat=os.stat(root_path,follow_symlinks=False)
rootfd=os.open(root_path,flags)
if os.fstat(rootfd)!=root_lstat: raise PermissionError("systemd root changed while opening")
source_parents={}
libc=ctypes.CDLL(None,use_errno=True)
renameat2=getattr(libc,"renameat2",None)
if renameat2 is None:
    raise SystemExit("renameat2 is required for safe systemd replacement")
renameat2.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
renameat2.restype=ctypes.c_int

# Use descriptor xattr operations for files/directories.  Linux has no fd for
# an unopened symlink, so its l*xattr operations use a stable /proc/self/fd
# parent and are bracketed by no-follow identity checks.  ENOTSUP while listing
# means that filesystem cannot store xattrs, and therefore has none to copy;
# any failure after a source xattr is observed is fatal.
flistxattr=libc.flistxattr; fgetxattr=libc.fgetxattr
fsetxattr=libc.fsetxattr; fremovexattr=libc.fremovexattr
llistxattr=libc.llistxattr; lgetxattr=libc.lgetxattr
lsetxattr=libc.lsetxattr; lremovexattr=libc.lremovexattr
flistxattr.argtypes=(ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t)
fgetxattr.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t)
fsetxattr.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int)
fremovexattr.argtypes=(ctypes.c_int,ctypes.c_char_p)
llistxattr.argtypes=(ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t)
lgetxattr.argtypes=(ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t)
lsetxattr.argtypes=(ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int)
lremovexattr.argtypes=(ctypes.c_char_p,ctypes.c_char_p)
for function in (flistxattr,fgetxattr,llistxattr,lgetxattr): function.restype=ctypes.c_ssize_t
for function in (fsetxattr,fremovexattr,lsetxattr,lremovexattr): function.restype=ctypes.c_int

unsupported_xattr_errors={errno.ENOTSUP,errno.EOPNOTSUPP,errno.ENOSYS}

def xattr_names(function, target) -> list[bytes]:
    while True:
        size=function(target,None,0)
        if size < 0:
            value=ctypes.get_errno()
            if value in unsupported_xattr_errors: return []
            raise OSError(value,os.strerror(value))
        if size == 0: return []
        buffer=ctypes.create_string_buffer(size)
        result=function(target,buffer,size)
        if result >= 0: return buffer.raw[:result].split(b"\0")[:-1]
        value=ctypes.get_errno()
        if value != errno.ERANGE: raise OSError(value,os.strerror(value))

def xattr_value(function, target, name: bytes) -> bytes:
    while True:
        size=function(target,name,None,0)
        if size < 0:
            value=ctypes.get_errno(); raise OSError(value,os.strerror(value),os.fsdecode(name))
        buffer=ctypes.create_string_buffer(max(1,size))
        result=function(target,name,buffer,size)
        if result >= 0: return buffer.raw[:result]
        value=ctypes.get_errno()
        if value != errno.ERANGE: raise OSError(value,os.strerror(value),os.fsdecode(name))

def set_xattr(function, target, name: bytes, value: bytes) -> None:
    buffer=ctypes.create_string_buffer(value,max(1,len(value)))
    if function(target,name,buffer,len(value),0) != 0:
        error=ctypes.get_errno(); raise OSError(error,os.strerror(error),os.fsdecode(name))

def sync_xattrs(src_names,src_get,src_target,dst_names,dst_get,dst_set,dst_remove,dst_target) -> None:
    source={name:xattr_value(src_get,src_target,name) for name in xattr_names(src_names,src_target)}
    destination=set(xattr_names(dst_names,dst_target))
    for name in destination-source.keys():
        if dst_remove(dst_target,name) != 0:
            error=ctypes.get_errno(); raise OSError(error,os.strerror(error),os.fsdecode(name))
    for name,value in source.items(): set_xattr(dst_set,dst_target,name,value)
    copied={name:xattr_value(dst_get,dst_target,name) for name in xattr_names(dst_names,dst_target)}
    if copied != source: raise OSError("systemd metadata xattrs differ after copy")

def sync_xattrs_fd(srcfd: int, dstfd: int) -> None:
    sync_xattrs(flistxattr,fgetxattr,srcfd,flistxattr,fgetxattr,fsetxattr,fremovexattr,dstfd)

def link_path(parentfd: int, name: str) -> bytes:
    return b"/proc/self/fd/"+str(parentfd).encode("ascii")+b"/"+os.fsencode(name)

def same_entry(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino and stat.S_IFMT(first.st_mode) == stat.S_IFMT(second.st_mode)

def exact_metadata(info: os.stat_result, copied: os.stat_result) -> bool:
    return (stat.S_IFMT(info.st_mode),stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid,info.st_atime_ns,info.st_mtime_ns,info.st_nlink) == (stat.S_IFMT(copied.st_mode),stat.S_IMODE(copied.st_mode),copied.st_uid,copied.st_gid,copied.st_atime_ns,copied.st_mtime_ns,copied.st_nlink)

def neutral_readlink(parentfd: int, name: str, info: os.stat_result) -> str:
    value=os.readlink(name,dir_fd=parentfd)
    os.utime(name,ns=(info.st_atime_ns,info.st_mtime_ns),dir_fd=parentfd,follow_symlinks=False)
    after=os.stat(name,dir_fd=parentfd,follow_symlinks=False)
    if not same_entry(info,after) or not exact_metadata(info,after):
        raise PermissionError("systemd symlink changed while reading")
    return value

def open_directory(name, *, dir_fd=None):
    before=os.stat(name,dir_fd=dir_fd,follow_symlinks=False)
    descriptor=os.open(name,flags,dir_fd=dir_fd)
    if os.fstat(descriptor)!=before:
        os.close(descriptor); raise PermissionError("systemd directory changed while opening")
    return descriptor,before

def sync_xattrs_link(srcfd: int, srcname: str, dstfd: int, dstname: str, info: os.stat_result) -> None:
    source=link_path(srcfd,srcname); destination=link_path(dstfd,dstname)
    before=os.stat(dstname,dir_fd=dstfd,follow_symlinks=False)
    if not same_entry(info,os.stat(srcname,dir_fd=srcfd,follow_symlinks=False)):
        raise PermissionError("systemd symlink source changed while copying")
    sync_xattrs(llistxattr,lgetxattr,source,llistxattr,lgetxattr,lsetxattr,lremovexattr,destination)
    if not same_entry(info,os.stat(srcname,dir_fd=srcfd,follow_symlinks=False)) or not same_entry(before,os.stat(dstname,dir_fd=dstfd,follow_symlinks=False)):
        raise PermissionError("systemd symlink changed while copying metadata")

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
        infd=os.open(srcname,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME,dir_fd=srcfd)
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
            sync_xattrs_fd(infd,outfd)
            os.utime(outfd,ns=(info.st_atime_ns,info.st_mtime_ns))
            os.fsync(outfd)
            if not exact_metadata(info,os.fstat(outfd)): raise OSError("systemd file metadata differs after copy")
        finally:
            os.close(outfd); os.close(infd)
    elif stat.S_ISDIR(mode):
        trusted(info)
        os.mkdir(dstname,0o700,dir_fd=dstfd)
        infd,opened=open_directory(srcname,dir_fd=srcfd)
        outfd,_=open_directory(dstname,dir_fd=dstfd)
        try:
            if opened != info: raise PermissionError("systemd source changed while copying")
            info=os.fstat(infd)
            for child in os.listdir(infd): copy_entry(infd,child,outfd,child)
            os.fchown(outfd,info.st_uid,info.st_gid)
            os.fchmod(outfd,stat.S_IMODE(mode))
            sync_xattrs_fd(infd,outfd)
            os.utime(outfd,ns=(info.st_atime_ns,info.st_mtime_ns))
            os.fsync(outfd)
            if not exact_metadata(info,os.fstat(outfd)): raise OSError("systemd directory metadata differs after copy")
            if os.fstat(infd) != info: raise PermissionError("systemd source changed while copying")
        finally:
            os.close(outfd); os.close(infd)
    elif stat.S_ISLNK(mode):
        trusted(info,link=True)
        os.symlink(neutral_readlink(srcfd,srcname,info),dstname,dir_fd=dstfd)
        os.chown(dstname,info.st_uid,info.st_gid,dir_fd=dstfd,follow_symlinks=False)
        sync_xattrs_link(srcfd,srcname,dstfd,dstname,info)
        os.utime(dstname,ns=(info.st_atime_ns,info.st_mtime_ns),dir_fd=dstfd,follow_symlinks=False)
        if not exact_metadata(info,os.stat(dstname,dir_fd=dstfd,follow_symlinks=False)):
            raise OSError("systemd symlink metadata differs after copy")
    else:
        raise PermissionError("systemd source has unsafe type")

def remove_entry(parentfd: int, child: str) -> None:
    info=os.stat(child,dir_fd=parentfd,follow_symlinks=False)
    if stat.S_ISDIR(info.st_mode):
        childfd,opened=open_directory(child,dir_fd=parentfd)
        try:
            if opened!=info: raise PermissionError("systemd directory changed while removing")
            info=os.fstat(childfd)
            for nested in os.listdir(childfd): remove_entry(childfd,nested)
            if not same_entry(info,os.fstat(childfd)): raise PermissionError("systemd directory changed while removing")
        finally: os.close(childfd)
        os.rmdir(child,dir_fd=parentfd)
    else:
        os.unlink(child,dir_fd=parentfd)

def fingerprint(parentfd: int, name: str, *, allow_link=True):
    info=os.stat(name,dir_fd=parentfd,follow_symlinks=False)
    common=(stat.S_IFMT(info.st_mode),stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid,info.st_atime_ns,info.st_mtime_ns,info.st_nlink)
    if stat.S_ISREG(info.st_mode):
        descriptor=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME,dir_fd=parentfd)
        try:
            if os.fstat(descriptor)!=info: raise PermissionError("systemd file changed while binding")
            digest=hashlib.sha256()
            while True:
                block=os.read(descriptor,1<<20)
                if not block: break
                digest.update(block)
            attrs=tuple((key,xattr_value(fgetxattr,descriptor,key)) for key in sorted(xattr_names(flistxattr,descriptor)))
            if os.fstat(descriptor)!=info: raise PermissionError("systemd file changed while binding")
            return common,digest.digest(),attrs
        finally: os.close(descriptor)
    if stat.S_ISDIR(info.st_mode):
        descriptor,opened=open_directory(name,dir_fd=parentfd)
        try:
            if opened!=info: raise PermissionError("systemd directory changed while binding")
            attrs=tuple((key,xattr_value(fgetxattr,descriptor,key)) for key in sorted(xattr_names(flistxattr,descriptor)))
            children=tuple((child,fingerprint(descriptor,child,allow_link=False)) for child in sorted(os.listdir(descriptor)))
            if os.fstat(descriptor)!=info: raise PermissionError("systemd directory changed while binding")
            return common,attrs,children
        finally: os.close(descriptor)
    if stat.S_ISLNK(info.st_mode) and allow_link:
        target=link_path(parentfd,name)
        attrs=tuple((key,xattr_value(lgetxattr,target,key)) for key in sorted(xattr_names(llistxattr,target)))
        return common,neutral_readlink(parentfd,name,info),attrs
    raise PermissionError("systemd topology changed while binding")

expected_records={}
expected_present=None
expected_inventory=None

def observer_inventory() -> set[str]:
    return {name for name in os.listdir(rootfd) if name.startswith("uap-observer")}

def journal_precondition() -> None:
    global expected_records,expected_present,expected_inventory
    backup_path=os.environ.get("UAP_OBSERVER_COMPARE_BACKUP")
    if not backup_path: return
    backup,_=open_directory(backup_path)
    try:
        control=os.open("identity.json",os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME,dir_fd=backup)
        try:
            encoded=b""
            while True:
                block=os.read(control,1<<20)
                if not block: break
                encoded+=block
            identity=json.loads(encoded)
        finally: os.close(control)
    finally: os.close(backup)
    expected=identity["records"]
    present=set(identity["present"])
    records=[]
    names=("uap-observer.service","uap-observer-signer.service","uap-observer-runner.service","uap-observer-runner.socket","uap-observer-caddy.service","uap-observer.service.d","uap-observer-runner.service.d")
    def attrs(parent,name,info,descriptor=None):
        if stat.S_ISLNK(info.st_mode):
            target=link_path(parent,name); names_=xattr_names(llistxattr,target); getter=lgetxattr
        else: target=descriptor; names_=xattr_names(flistxattr,target); getter=fgetxattr
        return [[base64.b64encode(key).decode(),base64.b64encode(xattr_value(getter,target,key)).decode()] for key in sorted(names_)]
    def visit(parent,name,path,allow_link=True,output=None):
        if output is None: output=records
        info=os.stat(name,dir_fd=parent,follow_symlinks=False); mode=info.st_mode
        if stat.S_ISREG(mode):
            descriptor=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME,dir_fd=parent)
            try:
                if os.fstat(descriptor)!=info: raise PermissionError("systemd target changed before replacement")
                info=os.fstat(descriptor)
                record={"path":path,"type":stat.S_IFMT(info.st_mode),"mode":stat.S_IMODE(info.st_mode),"uid":info.st_uid,"gid":info.st_gid,"atime":info.st_atime_ns,"mtime":info.st_mtime_ns,"nlink":info.st_nlink}
                digest=hashlib.sha256()
                while True:
                    block=os.read(descriptor,1<<20)
                    if not block: break
                    digest.update(block)
                record["payload"]=digest.hexdigest(); record["xattrs"]=attrs(parent,name,info,descriptor)
            finally: os.close(descriptor)
        elif stat.S_ISDIR(mode):
            descriptor,opened=open_directory(name,dir_fd=parent)
            try:
                if opened!=info: raise PermissionError("systemd directory changed before replacement")
                info=os.fstat(descriptor)
                record={"path":path,"type":stat.S_IFMT(info.st_mode),"mode":stat.S_IMODE(info.st_mode),"uid":info.st_uid,"gid":info.st_gid,"atime":info.st_atime_ns,"mtime":info.st_mtime_ns,"nlink":info.st_nlink}
                children=sorted(os.listdir(descriptor)); record["children"]=children; record["xattrs"]=attrs(parent,name,info,descriptor)
                output.append(record)
                for child in children: visit(descriptor,child,path+"/"+child,False,output)
                if os.fstat(descriptor)!=info: raise PermissionError("systemd directory changed before replacement")
            finally: os.close(descriptor)
            return
        elif stat.S_ISLNK(mode) and allow_link:
            record={"path":path,"type":stat.S_IFMT(mode),"mode":stat.S_IMODE(mode),"uid":info.st_uid,"gid":info.st_gid,"atime":info.st_atime_ns,"mtime":info.st_mtime_ns,"nlink":info.st_nlink}
            record["payload"]=neutral_readlink(parent,name,info)
            record["xattrs"]=attrs(parent,name,info)
            after=os.stat(name,dir_fd=parent,follow_symlinks=False)
            if not same_entry(info,after) or not exact_metadata(info,after): raise PermissionError("systemd symlink changed before replacement")
        else: raise PermissionError("systemd topology changed before replacement")
        output.append(record)
    for index,name in enumerate(names):
        try: os.stat(name,dir_fd=rootfd,follow_symlinks=False)
        except FileNotFoundError:
            if name in present: raise PermissionError("systemd target disappeared before replacement")
        else:
            if name not in present: raise PermissionError("systemd target appeared before replacement")
            visit(rootfd,name,name,index<5)
    if records!=expected: raise PermissionError("systemd target drifted immediately before replacement")
    expected_present=present
    expected_inventory=set(present)
    if observer_inventory()!=expected_inventory: raise PermissionError("systemd observer inventory changed before replacement")
    expected_records={name:[record for record in expected if record["path"]==name or record["path"].startswith(name+"/")] for name in present}

    globals()["capture_visit"]=visit

def validate_capture(name: str, displaced: str) -> None:
    captured=[]
    capture_visit(rootfd,displaced,name,names.index(name)<5,captured)
    if captured!=expected_records[name]:
        raise PermissionError("systemd destination raced after validation")

def replace(source_arg: str, name: str) -> None:
    if not name or "/" in name or name in (".",".."):
        raise ValueError("invalid systemd destination name")
    temporary=exclusive_name("uap-observer-new")
    displaced=exclusive_name("uap-observer-old")
    created=False
    moved=False
    installed=False
    baseline_missing=False
    baseline=None
    try:
        if expected_present is None:
            try: baseline=fingerprint(rootfd,name)
            except FileNotFoundError: baseline_missing=True
        if source_arg != "-":
            source=Path(source_arg)
            parent=os.fspath(source.parent)
            source_parent=source_parents.get(parent)
            if source_parent is None:
                source_parent,_=open_directory(parent)
                source_parents[parent]=source_parent
            copy_entry(source_parent,source.name,rootfd,temporary)
            created=True
        global precondition_done
        if not precondition_done:
            journal_precondition()
            precondition_done=True
        if expected_inventory is not None and observer_inventory()!=expected_inventory:
            raise PermissionError("systemd observer inventory changed before replacement")
        if expected_present is not None and name in expected_present:
            rename_noreplace(rootfd,name,rootfd,displaced)
            moved=True
            if observer_inventory()!=expected_inventory-{name}:
                raise PermissionError("systemd observer inventory changed before replacement")
            validate_capture(name,displaced)
        elif expected_present is not None and name not in expected_present:
            if os.path.lexists(link_path(rootfd,name)):
                raise PermissionError("systemd missing destination raced after validation")
        else:
            if baseline_missing:
                pass
            else:
                rename_noreplace(rootfd,name,rootfd,displaced)
                moved=True
                if observer_inventory()!=expected_inventory-{name}:
                    raise PermissionError("systemd observer inventory changed before replacement")
                if fingerprint(rootfd,displaced)!=baseline:
                    raise PermissionError("systemd destination raced after validation")
        if created:
            rename_noreplace(rootfd,temporary,rootfd,name)
            created=False
            installed=True
            if expected_inventory is not None: expected_inventory.add(name)
        os.fsync(rootfd)
        if moved:
            remove_entry(rootfd,displaced)
            moved=False
            if expected_inventory is not None and source_arg == "-": expected_inventory.discard(name)
            os.fsync(rootfd)
    except BaseException:
        if installed:
            try: remove_entry(rootfd,name); installed=False
            except OSError: pass
        if moved:
            try: rename_noreplace(rootfd,displaced,rootfd,name); moved=False
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
    precondition_done=False
    if not os.environ.get("UAP_OBSERVER_COMPARE_BACKUP"):
        expected_inventory=observer_inventory()
    for index in range(0,len(pairs),2):
        replace(pairs[index],pairs[index+1])
        if fail_at == index // 2 + 1: raise SystemExit(1)
finally:
    for source_parent in source_parents.values(): os.close(source_parent)
    os.close(rootfd)
PY
}

restore_observer_systemd() {
  backup=$1
  systemd_root=$2
  validate_observer_systemd_journal "$backup" || return 1
  journal_manifest=$(observer_systemd_archive manifest "$backup") || return 1
  set -- "$systemd_root"
  while read -r state index relative; do
    if [ "$state" = present ]; then
      set -- "$@" "$backup/items/$index" "$relative"
    else
      set -- "$@" - "$relative"
    fi
  done <<EOF
$journal_manifest
EOF
  observer_replace_systemd_entries "$@" || return 1
  observer_compare_systemd_journal "$backup" "$systemd_root"
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
    test "$(observer_read_control_file "$stage/journal-resolved")" = resolved-v1 || return 1
  elif [ ! -e "$stage/journal-committed" ] && [ ! -L "$stage/journal-committed" ]; then
    # The atomic marker is the sole durable proof that mutation could begin.
    python3 - "$stage" <<'PY' || return 1
import os,stat,sys
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME
root=os.open(sys.argv[1],flags)
def validate(directory):
    for name in os.listdir(directory):
        info=os.stat(name,dir_fd=directory,follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child=os.open(name,flags,dir_fd=directory)
            try:
                if os.fstat(child)!=info: raise PermissionError("pre-commit staging directory changed")
                validate(child)
            finally: os.close(child)
        elif not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
            raise SystemExit("pre-commit staging tree contains an unsafe object")
try: validate(root)
finally: os.close(root)
PY
  else
    journal_committed=1
    test -f "$stage/journal-committed" && test ! -L "$stage/journal-committed" || return 1
    test "$(stat -c '%u:%g:%a:%h' "$stage/journal-committed")" = 0:0:600:1 || return 1
    test "$(observer_read_control_file "$stage/journal-committed")" = committed-v1 || return 1
    test -f "$stage/closure-digest" && test ! -L "$stage/closure-digest" || return 1
    test "$(stat -c '%u:%g:%a:%h' "$stage/closure-digest")" = 0:0:600:1 || return 1
    recovered_digest=$(observer_read_control_file "$stage/closure-digest")
    printf '%s\n' "$recovered_digest" | grep -Eq '^[0-9a-f]{64}$' || return 1
    validate_observer_systemd_journal "$stage/systemd-backup" || return 1
    test -d "$closures_root" && test ! -L "$closures_root" || return 1
    test "$(stat -c '%u:%g:%a' "$closures_root")" = 0:0:755 || return 1
    # A current pointer means activation crossed its commit point.  Recovery is
    # only permitted to accept the exact journaled closure in that case.
    if [ -e "$current_pointer" ] || [ -L "$current_pointer" ]; then
      test -L "$current_pointer" || return 1
      test "$(observer_read_symlink_neutral "$current_pointer")" = "uap-observer-closures/$recovered_digest" || return 1
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
    observer_compare_systemd_journal "$backup" "$systemd_root" || return 1
  fi
  set -- "$systemd_root"
  for unit in $observer_units; do set -- "$@" "$staged/$unit" "$unit"; done
  for service in uap-observer uap-observer-runner; do
    set -- "$@" "$staged/$service.service.d" "$service.service.d"
  done
  # This second descriptor-only identity check is deliberately adjacent to
  # the replacement process, after all validation that could consume atime.
  if [ -n "$backup" ]; then observer_compare_systemd_journal "$backup" "$systemd_root" || return 1; fi
  UAP_OBSERVER_COMPARE_BACKUP=$backup \
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
  observer_compare_systemd_trees "$reviewed" "$systemd_root"
}

observer_compare_systemd_trees() {
  python3 - "$1" "$2" <<'PY'
import os,stat,sys
names=("uap-observer.service","uap-observer-signer.service","uap-observer-runner.service","uap-observer-runner.socket","uap-observer-caddy.service","uap-observer.service.d","uap-observer-runner.service.d")
dirflags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME
fileflags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME
def metadata(info): return (stat.S_IFMT(info.st_mode),stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid,info.st_atime_ns,info.st_mtime_ns,info.st_nlink)
def attributes(parent,name,info,descriptor=None):
    target=f"/proc/self/fd/{parent}/{name}" if stat.S_ISLNK(info.st_mode) else descriptor
    follow=not stat.S_ISLNK(info.st_mode)
    return {key:os.getxattr(target,key,follow_symlinks=follow) for key in os.listxattr(target,follow_symlinks=follow)}
def link(parent,name,info):
    value=os.readlink(name,dir_fd=parent)
    os.utime(name,ns=(info.st_atime_ns,info.st_mtime_ns),dir_fd=parent,follow_symlinks=False)
    after=os.stat(name,dir_fd=parent,follow_symlinks=False)
    if (after.st_dev,after.st_ino)!=(info.st_dev,info.st_ino) or metadata(after)!=metadata(info): raise PermissionError("systemd symlink changed during comparison")
    return value
def compare(first,name,second):
    left=os.stat(name,dir_fd=first,follow_symlinks=False); right=os.stat(name,dir_fd=second,follow_symlinks=False)
    if metadata(left)!=metadata(right): raise SystemExit("systemd metadata differs")
    if stat.S_ISREG(left.st_mode):
        a=os.open(name,fileflags,dir_fd=first); b=os.open(name,fileflags,dir_fd=second)
        try:
            if os.fstat(a)!=left or os.fstat(b)!=right: raise PermissionError("systemd file changed during comparison")
            if attributes(first,name,left,a)!=attributes(second,name,right,b): raise SystemExit("systemd xattrs differ")
            while True:
                one=os.read(a,1<<20); two=os.read(b,1<<20)
                if one!=two: raise SystemExit("systemd payload differs")
                if not one: break
        finally: os.close(b); os.close(a)
    elif stat.S_ISDIR(left.st_mode):
        a=os.open(name,dirflags,dir_fd=first); b=os.open(name,dirflags,dir_fd=second)
        try:
            if os.fstat(a)!=left or os.fstat(b)!=right: raise PermissionError("systemd directory changed during comparison")
            left=os.fstat(a); right=os.fstat(b)
            if attributes(first,name,left,a)!=attributes(second,name,right,b): raise SystemExit("systemd xattrs differ")
            children=sorted(os.listdir(a))
            if children!=sorted(os.listdir(b)): raise SystemExit("systemd topology differs")
            for child in children: compare(a,child,b)
            if os.fstat(a)!=left or os.fstat(b)!=right: raise PermissionError("systemd directory changed during comparison")
        finally: os.close(b); os.close(a)
    elif stat.S_ISLNK(left.st_mode):
        if link(first,name,left)!=link(second,name,right) or attributes(first,name,left)!=attributes(second,name,right): raise SystemExit("systemd symlink differs")
    else: raise SystemExit("systemd type differs")
first_before=os.stat(sys.argv[1],follow_symlinks=False); second_before=os.stat(sys.argv[2],follow_symlinks=False)
first=os.open(sys.argv[1],dirflags); second=os.open(sys.argv[2],dirflags)
try:
    if os.fstat(first)!=first_before or os.fstat(second)!=second_before: raise PermissionError("systemd root changed during comparison")
    for name in names: compare(first,name,second)
    if os.fstat(first)!=first_before or os.fstat(second)!=second_before: raise PermissionError("systemd root changed during comparison")
finally: os.close(second); os.close(first)
PY
}

reload_observer_systemd() {
  manager=$1
  "$manager" daemon-reload
  observer_install_failpoint || return 1
}
