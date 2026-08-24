#!/bin/sh

# Shared, testable installer primitives. The caller supplies only disposable
# roots in tests; production calls use the fixed system paths.

observer_units='uap-observer.service uap-observer-signer.service uap-observer-runner.service uap-observer-runner.socket uap-observer-caddy.service'

observer_closure_identity() {
  python3 - "$1" <<'PY'
import hashlib,os,stat,sys
from pathlib import Path
root=Path(sys.argv[1])
identity=hashlib.sha256()
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    info=path.lstat(); relative=path.relative_to(root).as_posix().encode()
    kind=b"d" if stat.S_ISDIR(info.st_mode) else b"f" if stat.S_ISREG(info.st_mode) else b"l" if stat.S_ISLNK(info.st_mode) else b"?"
    identity.update(b"\0".join((relative,kind,str(stat.S_IMODE(info.st_mode)).encode(),str(info.st_uid).encode(),str(info.st_gid).encode()))+b"\0")
    if kind == b"f": identity.update(hashlib.sha256(path.read_bytes()).digest())
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
  test -d "$systemd_root"
  test ! -L "$systemd_root"
  test "$(stat -c '%u:%g:%a' "$systemd_root")" = "$expected_owner:755"
  for unit in $observer_units; do
    installed="$systemd_root/$unit"
    reviewed="$closure/systemd/$unit"
    test -f "$installed"
    test ! -L "$installed"
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
    test "$(stat -c '%u:%g:%a' "$installed/egress.conf")" = "$expected_owner:644"
    cmp "$reviewed" "$installed/egress.conf"
  done
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

apply_observer_closure_modes() {
  closure=$1
  chown -R root "$closure"
  find "$closure" -type d -exec chmod 0755 {} +
  find "$closure" -type f -perm /0111 -exec chmod 0755 {} +
  find "$closure" -type f ! -perm /0111 -exec chmod 0644 {} +
  chmod 0640 "$closure/etc/uap-observer-adapter-config.json" "$closure/etc/Caddyfile"
  chmod 0755 "$closure/libexec/uap-observer-runner" "$closure/libexec/uap-observer-fixed-adapter"
  for name in runtime notion chatgpt consent; do
    chmod 0755 "$closure/libexec/uap-observer-adapter-$name"
  done
  test "$(stat -c '%u:%g:%a' "$closure/etc/uap-observer.json")" = '0:0:644'
  test "$(stat -c '%u:%a' "$closure/etc/uap-observer-adapter-config.json")" = '0:640'
  test "$(stat -c '%u:%g:%a' "$closure/etc/uap-observer-adapters.json")" = '0:0:644'
  test "$(stat -c '%u:%g:%a' "$closure/libexec/uap-observer-runner")" = '0:0:755'
  test -z "$(find "$closure" \( -type d -o -type f \) -perm /0022 -print -quit)"
}

journal_observer_systemd() {
  backup=$1
  systemd_root=$2
  test ! -e "$backup"
  install -d -m 0700 "$backup/items"
  : > "$backup/manifest"
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

restore_observer_systemd() {
  backup=$1
  systemd_root=$2
  while read -r state index relative; do
    target="$systemd_root/$relative"
    rm -rf "$target"
    if [ "$state" = present ]; then
      cp -a "$backup/items/$index" "$target"
    fi
  done < "$backup/manifest"
}

observer_install_failpoint() {
  observer_install_step=$((observer_install_step + 1))
  test "${UAP_OBSERVER_INSTALL_FAIL_AT:-}" != "$observer_install_step"
}

activate_observer_systemd() {
  staged=$1
  systemd_root=$2
  observer_install_step=0
  install -d -m 0755 "$systemd_root/uap-observer.service.d" "$systemd_root/uap-observer-runner.service.d"
  for unit in $observer_units; do
    mv "$staged/$unit" "$systemd_root/$unit"
    observer_install_failpoint || return 1
  done
  for service in uap-observer uap-observer-runner; do
    mv "$staged/$service.service.d/egress.conf" "$systemd_root/$service.service.d/egress.conf"
    observer_install_failpoint || return 1
  done
}

reload_observer_systemd() {
  manager=$1
  "$manager" daemon-reload
  observer_install_failpoint || return 1
}
