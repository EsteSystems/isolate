# Architecture

This document describes how isolate is built: its modules, the data it keeps, and what happens during each command. What isolate must guarantee, and what it deliberately leaves out, is specified in the [design documents](design/README.md).

isolate is a single command-line program for FreeBSD. It has no daemon and keeps no state apart from one small file per running instance.

## Overview

```
                      isolate <command>
   ┌────────┬─────────┬────────┬────────┬─────────┬─────────┐
   │  run   │ detect  │  list  │  stop  │  clean  │  check  │   main.zig
   └───┬────┴────┬────┴───┬────┴───┬────┴────┬────┴────┬────┘
       │         │        │        │         │         │
       ▼         ▼        └────────┼─────────┘         ▼
   caps.zig   detect.zig           ▼              syscheck.zig
   (parse     (ELF            registry.zig        (racct, VNET,
    .caps)     analysis)      (/var/run/isolate)   jails, root)
       │                           ▲
       ▼                           │
   freebsd.zig ────────────────────┘
   jail, mounts, user, rctl, VNET, cleanup
       │
       ▼
   FreeBSD: jail(2), nmount(2), rctl(2), libjail, pw(8), ifconfig(8)
```

## Source files

| File | Lines | Responsibility |
|---|---|---|
| `src/main.zig` | ~1270 | Argument parsing, the six commands, the fork between the jailed program and the process that waits for it, signal forwarding. |
| `src/freebsd.zig` | ~1450 | Everything that touches the system: instance directory, mounts, ephemeral user, jail creation, VNET, resource limits, privilege drop, cleanup and teardown. |
| `src/caps.zig` | ~880 | The `Capabilities` structure and the capability-file parser. |
| `src/detect.zig` | ~740 | ELF reading and the heuristics behind `isolate detect`. |
| `src/registry.zig` | ~430 | The on-disk registry of running instances. |
| `src/syscheck.zig` | ~240 | Kernel feature detection for `isolate check` and for warnings. |
| `src/c_api.zig` | ~40 | A shared `@cImport` of the libc headers `main.zig` uses. |
| `src/freebsd_proc.c` | ~25 | One function, the parent of a process, in C because `<sys/user.h>` cannot be imported into Zig 0.16. |
| `tests/scenarios.sh`, `tests/probe.c` | | End-to-end checks that create real jails; see "Tests". |

`freebsd.zig` and `syscheck.zig` compile only on FreeBSD. On other systems the program builds, and `detect`, `list` and the tests work, but `run` reports that it is not supported.

### Dependencies between modules

```
main.zig ──► caps.zig, detect.zig, registry.zig, c_api.zig
         ──► freebsd.zig, syscheck.zig        (FreeBSD only)

freebsd.zig ──► caps.zig, syscheck.zig, registry.zig (for the runtime directory path)

caps.zig, detect.zig, registry.zig, syscheck.zig ──► standard library and libc only
```

### External dependencies

isolate is a dynamically linked executable. At run time it uses:

| Dependency | Used for |
|---|---|
| `libc`, `libjail` (FreeBSD base) | System calls; `jailparam_*`, `jail_getid`, `jail_getname`. |
| `/usr/sbin/pw` | Creating and deleting the ephemeral user. |
| `/usr/sbin/pwd_mkdb` | Building the user database in the jail's `/etc`. |
| `/sbin/ifconfig` | Moving an interface into a VNET jail, configuring it, and taking it back. |
| `/sbin/devfs` | Hiding device nodes in the jail's `/dev`. |
| A kernel with jails, nullfs and devfs | Always. |
| `kern.racct.enable=1` | Resource limits. |
| A kernel with `VIMAGE` | `network_mode: vnet`. |

Building needs Zig 0.16.0 and nothing else.

## Data structures

### `Capabilities` (`caps.zig`)

The parsed capability file, plus command-line overrides.

```zig
pub const Capabilities = struct {
    allocator: Allocator,

    username: []const u8,              // "auto" or an existing user's name
    create_user: bool,                 // true for "auto"

    workspace_path: ?[]const u8,       // host directory mounted at /workspace
    network_config: NetworkConfig,     // mode, interface, ip_address

    network_rules: std.ArrayList(NetworkRule),  // parsed, not enforced
    file_rules: std.ArrayList(FileRule),

    env_vars: std.ArrayList(EnvVar),
    env_clear: bool,
    sysv_ipc: bool,                    // private System V IPC namespace

    limits: ResourceLimits,            // memory_bytes, max_processes, max_files
};

pub const NetworkMode = enum { inherit, none, vnet };
pub const FileRule = struct { path: []const u8, permissions: Permission };  // read, or read and write
pub const NetworkRule = struct { protocol: Protocol, address: []const u8, port: ?u16, direction: Direction };
```

`load()` returns a `ParseResult`: the capabilities and a list of problems (line number and message), one for every line that cannot be applied as written. `run` refuses a file with any.

### Jail state (`freebsd.zig`)

A process-wide structure holding what cleanup needs: the jail id, the ephemeral username and the jail root path. The child fills it in while setting up. Because parent and child are separate processes after `fork`, the child sends these three values to the parent over a pipe, and the parent stores them in its own copy.

### `Instance` (`registry.zig`)

```zig
pub const Instance = struct {
    name: []const u8,            // registry key; [A-Za-z0-9._-], at most 64 bytes
    pid: i32,                    // the jailed program
    manager_pid: i32,            // the `isolate run` process waiting for it
    jail_id: i32,
    jail_path: []const u8,       // /var/run/isolate/inst-XXXXXX/root
    username: []const u8,        // app-<pid>, or the existing user's name
    binary_path: []const u8,     // as given on the command line
    start_time: i64,             // seconds since the epoch
    workspace_path: ?[]const u8,
};

pub const InstanceState = enum { running, stopped, orphaned };
```

Reading an entry back yields an `InstanceInfo` with the same fields (minus the workspace) and a computed `state`.

### `CapabilityHint` (`detect.zig`)

```zig
pub const CapabilityHint = struct {
    description: []const u8,     // why: "Socket operations detected (server)"
    capability: []const u8,      // one or more capability-file lines
    confidence: u8,              // 0-100; used only to order the output
};
```

## On-disk layout

```
/var/run/isolate/                      created by root, 0755
├── <instance name>.json               registry entry, one per running instance
└── inst-XXXXXX/                       one per run, from mkdtemp(3)
    ├── root/                          the jail's root filesystem
    └── tmp/                           backs the jail's /tmp when a /tmp rule exists
```

Nothing is written anywhere else. In particular nothing is created under `/tmp`.

The jail root contains a copy of the program at `/<basename>`, a user database in `etc` holding root and the program's user, devfs at `dev`, and empty directories that the rules mount over. The full list is in [design/01-isolation.md](design/01-isolation.md).

## Execution flow

### `run`

```
main: parse arguments (options only before the binary)
      load <binary>.caps or -c file; apply -w and --vnet
      require root; refuse a name that is already registered
      fork ───────────────────────────────────────────────┐
                                                           │
  CHILD (becomes the program)              PARENT (waits and cleans up)
  ───────────────────────────              ────────────────────────────
  1 create user app-<pid>, or look up      a handle SIGINT, SIGTERM, SIGHUP:
    the named one                            first → signal the child
  2 mkdtemp /var/run/isolate/inst-XXXXXX     second → remove the jail
    mkdir root/                            b read jail id, username, path
  3 build the jail filesystem:               from the pipe; on a short read
      directories                            the child failed: report, exit
      nullfs  workspace → /workspace       c write the registry entry
      copy the binary to /<basename>         (exclusive; on failure stop the child)
      build the user database in etc/      d waitpid(child)
      mount devfs; hide all but a          e VNET: ifconfig <if> -vnet <jid>
        few nodes (devfs rule apply)         jail_remove
      nullfs  one mount per rule             unmount everything under the
  4 jail_set (create)                         instance directory, deepest first
      VNET: ifconfig <if> vnet <jid>         remove the directory tree
            ifconfig -j <jid> ... up         pw userdel app-<pid>
  5 rctl_add_rule per limit                  remove the jail's rctl rules
  6 jail_attach                            f delete the registry entry
    setgroups, setgid, setuid              g exit with the child's status
    set environment
  7 write jail id, username, path
    to the pipe
  8 closefrom(3); execv /<basename>
```

If any of the child's steps 1–6 fails, the child removes what it created and exits; it never writes to the pipe. That includes a rule whose path does not exist, a limit that cannot be applied, and a VNET interface that cannot be moved or configured: nothing asked for in the capability file is skipped.

Cleanup removes mounts by reading the kernel's mount table (`getmntinfo`) rather than from a list of expected mount points, and the directory removal uses `fts(3)` with `FTS_XDEV`, so it cannot descend into a filesystem that is still mounted.

### `stop` and `clean`

Both work from registry entries. Before acting on an entry they check that each value still describes something isolate created: the directory must be `/var/run/isolate/inst-XXXXXX`, the user must be named `app-<digits>`, and the jail's name must be `isolate-<pid>` for the recorded pid.

`clean` then looks past the registry: it walks the kernel's jail list, the instance directories and the password database for anything of isolate's that no entry accounts for. To tell an abandoned jail from one whose run is still setting up, it asks whether the jailed process still has a parent other than init. The steps are listed in [design/03-lifecycle.md](design/03-lifecycle.md).

### `list`

Reads every `*.json` in the registry directory and computes each instance's state: **running** if a jail with the recorded id exists (`jail_get`) or the recorded pid exists (`kill(pid, 0)`), **orphaned** if the pid does not exist, **stopped** otherwise.

### `detect`

```
open the file; read the ELF header and section headers
  ├─ .dynamic + .dynstr  → DT_NEEDED library names   → match against a table
  ├─ .dynsym  + .dynstr  → imported symbol names     → socket/bind, fork, open, ...
  ├─ .rodata, .data, .dynstr → printable strings     → /etc/..., /var/..., http://
  └─ file name                                       → match against a table
sort hints by confidence; drop exact duplicates
write the capability file: fixed defaults, then one commented block per hint
```

All reads are positional (`pread`). A file that is not ELF produces a warning and a file containing only the defaults. The tables and their limits are in [design/06-detection.md](design/06-detection.md).

### `check`

Reads `kern.racct.enable`, `kern.features.vimage`, `security.jail.jailed`, `kern.osreldate` and the effective uid, and prints a report. Exits non-zero only when running inside a jail.

## FreeBSD interfaces used

| Purpose | Interface |
|---|---|
| Create the jail | `jailparam_init/import/set` (libjail) with `JAIL_CREATE` |
| Enter the jail | `jail_attach(2)` |
| Remove the jail | `jail_remove(2)` |
| Check and list jails | `jail_get(2)` (with `lastjid` to iterate), `jail_getid`, `jail_getname` (libjail) |
| Restrict `/dev` | `fork` + `execv("/sbin/devfs")`: `rule apply hide`, then `unhide` per node |
| Find a process's parent | `sysctl(3)` `kern.proc.pid`, in `freebsd_proc.c` |
| Find isolate's users | `getpwent(3)` |
| Mount nullfs and devfs | `nmount(2)` |
| Unmount | `getmntinfo(3)`, `unmount(2)`, with `MNT_FORCE` as a fallback |
| Remove a directory tree | `fts(3)` with `FTS_PHYSICAL | FTS_XDEV` |
| Resource limits | `rctl_add_rule(2)`, `rctl_remove_rule(2)`, `rctl_get_rules(2)` |
| Create and delete the user | `fork` + `execv("/usr/sbin/pw")` |
| The jail's user database | `fork` + `execv("/usr/sbin/pwd_mkdb")` |
| VNET interface | `fork` + `execv("/sbin/ifconfig")`: `vnet`, `-j <jid> … up`, `-vnet` |
| Drop privileges | `setgroups(2)`, `setgid(2)`, `setuid(2)` |
| Start the program | `closefrom(2)`, `execv(2)` |

### Jail parameters

| Parameter | Value |
|---|---|
| `name` | `isolate-<pid>` |
| `path` | the jail root |
| `persist` | set |
| `allow.raw_sockets` | false |
| `allow.socket_af` | true |
| `allow.sysvipc` | false |
| `sysvshm`, `sysvsem`, `sysvmsg` | `new`, with `sysv_ipc: true` |
| `ip4`, `ip6` | `inherit` or `disable`, by network mode |
| `vnet` | `new`, in VNET mode (instead of `ip4`/`ip6`) |

### Resource limit rules

```
jail:isolate-<pid>:memoryuse:sigkill=<bytes>
jail:isolate-<pid>:maxproc:deny=<count>
jail:isolate-<pid>:openfiles:deny=<count>
```

## Errors

`freebsd.zig` reports failures with one error set:

```zig
pub const JailError = error{
    JailCreateFailed, JailAttachFailed, JailRemoveFailed, JailParamFailed,
    UserCreateFailed, UserDeleteFailed, UserNotFound,
    MountFailed, UnmountFailed, FilesystemSetupFailed,
    ResourceLimitFailed, ForkFailed, ExecFailed,
    PermissionDenied, OutOfMemory, InvalidPath,
};
```

Every failure during setup aborts the run and removes what was created; none is downgraded to a warning (design: ISO-11, LIM-5, NET-5). The capability file is checked the same way before anything is created: a file with a line that cannot be applied is refused (CAP-2).

Output goes to stdout and stderr through unbuffered, streaming writers, so that nothing is lost across `fork` and `execv` and so that redirected output interleaves correctly with the program's own.

## Tests

`zig build test` runs the unit tests of every module: 46 on FreeBSD, 36 elsewhere (the FreeBSD-only modules are skipped). They cover parsing of capability files and command lines, path and name validation, the registry, generated capability files, and small helpers. None of them creates a jail.

`tests/scenarios.sh` does. It needs FreeBSD and root, creates real jails, users, mounts, limits and an epair interface, and makes about 80 checks, each labelled with the invariant it demonstrates. It refuses to start on a host that already has isolate leftovers, and its last check is that it left none. Run it with `doas sh tests/scenarios.sh` after `zig build`.

## Measurements

Taken on one FreeBSD 15.1 virtual machine; they are indications, not guarantees.

| | Debug | ReleaseSafe | ReleaseSmall |
|---|---|---|---|
| Executable size | 5.5 MB | 4.1 MB | 0.27 MB |
| `isolate run` of a hello-world with five mounts, start to finish | 0.10–0.12 s | 0.06–0.08 s | not measured |

These were measured before `/dev` was restricted, which adds about a dozen `devfs` invocations per start. Most of the measured time is the two `pw` invocations that create and delete the ephemeral user: with `user: nobody` instead of `user: auto`, the same debug run takes 0.02–0.04 s.
