# AppArmor profile for BugFund sandboxes.
#
# Load on the host once:
#   sudo apparmor_parser -r execution_engine/isolation/apparmor.profile
# Then apply to containers via:
#   --security-opt apparmor=bugfund-sandbox
#
# Defense-in-depth on top of seccomp + dropped capabilities. Denies the
# container-escape primitives (mount, ptrace, namespace creation, raw block
# device access, kernel module loading) and confines network to what the
# seccomp/network policy already permits.

#include <tunables/global>

profile bugfund-sandbox flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,

  # Core filesystem: read-only access to system trees; write only to /tmp.
  /bin/               r,
  /usr/               r,
  /lib/               r,
  /lib64/             r,
  /etc/ld.so.cache    r,
  /etc/ld.so.conf     r,
  /etc/ld.so.conf.d/  r,
  /etc/passwd         r,
  /etc/nsswitch.conf  r,
  /srv/               r,           # the read-only target + PoV mounts
  /tmp/               rw,
  /dev/pts/           rw,
  /dev/null           rw,
  /dev/zero           rw,
  /dev/urandom        r,
  /dev/random         r,
  /proc/              r,
  /sys/               r,
  deny /proc/sysrq-trigger   rwklx,
  deny /proc/kcore           rwklx,
  deny /proc/mem             rwklx,

  # Read-only target tree is bind-mounted under /srv/target — never writable.
  deny /srv/target/**        wklx,

  # Hard-deny container-escape & kernel-attack surface.
  deny mount,
  deny umount,
  deny ptrace,
  deny capability sys_admin,        # blocks setns/pivot_root/mount
  deny capability sys_module,
  deny capability sys_ptrace,
  deny capability sys_rawio,
  deny capability sys_boot,
  deny capability mknod,
  deny capability setfcap,
  deny capability setpcap,

  # Exec only interpreters/binaries under standard paths.
  /usr/bin/python*        Pix,
  /usr/local/bin/python*  Pix,
  /bin/**                 Px,
  /usr/bin/**             Px,

  # Everything else not matched is denied by default (AppArmor default-deny).
}
