# 01 — Isolation

## Purpose

Contain an untrusted program: it runs in a jail whose filesystem isolate built for that run, as a user with no privileges, and sees nothing of the host except what the capability file names.

## Scope

- The jail and its parameters.
- The jail's root filesystem: what is created in it, what is mounted into it.
- The identity the program runs as.
- The environment, arguments and file descriptors the program receives.

## Out of scope

- **Kernel vulnerabilities and side channels.** isolate relies on the jail boundary being sound.
- **System-call filtering.** No Capsicum, no MAC policy.
- **Hiding part of a mounted directory.** A rule for `/usr/lib` exposes all of `/usr/lib`. To expose less, name a single file or a deeper directory.
- **Controlling execution per rule.** A rule is read-only or read-write. Whether a file under it can be executed is not something a rule decides.
- **Protecting the program from the host.** Root on the host can do anything to the jail.
- **Network access** is covered in [05-network.md](05-network.md); **resource limits** in [04-resource-limits.md](04-resource-limits.md).

## What a run creates

```
/var/run/isolate/                    root-owned, 0755
└── inst-XXXXXX/                     per run, from mkdtemp(3), 0755
    ├── root/                        the jail's root filesystem
    │   ├── <binary>                 copy of the program, 0755
    │   ├── etc/                     user database: root and the program's user only
    │   ├── dev/                     devfs, reduced to a few nodes
    │   ├── tmp/                     1777; the instance tmp if a /tmp rule exists
    │   ├── workspace/               nullfs mount of the -w directory, read-write
    │   ├── <rule path>              nullfs mount of each filesystem rule
    │   └── bin lib libexec usr/lib usr/local/lib var/log var/tmp var/run
    │                                empty directories unless a rule mounts them
    └── tmp/                         backs the jail's /tmp when a /tmp rule exists
```

The jail is created with these parameters. Everything else is the FreeBSD default, which means no nested jails and no mounting from inside the jail.

| Parameter | Value |
|---|---|
| `name` | `isolate-<pid of the jailed process>` |
| `path` | `/var/run/isolate/inst-XXXXXX/root` |
| `persist` | set |
| `allow.raw_sockets` | false |
| `allow.sysvipc` | false |
| `sysvshm`, `sysvsem`, `sysvmsg` | `new`, only with `sysv_ipc: true` |
| `allow.socket_af` | true |
| `ip4`, `ip6` / `vnet` | by network mode; see [05-network.md](05-network.md) |

The jail's `/dev` is a devfs mount on which isolate hides every node and then unhides `null`, `zero`, `full`, `random`, `urandom`, `stdin`, `stdout`, `stderr`, `fd` and `pts`.

The jail's `/etc` holds `master.passwd`, `passwd`, `pwd.db`, `spwd.db` and `group`, built with `pwd_mkdb(8)`. They contain two users, `root` and the one the program runs as, with no password hashes. FreeBSD's libc reads the `.db` files, not `passwd`, so without them a program cannot look up its own user.

## Invariants

"Tested" names the check in `tests/scenarios.sh` that demonstrates the invariant on FreeBSD 15.1.

| ID | Invariant | Status |
|---|---|---|
| ISO-1 | The program runs inside a jail whose root is a directory created for this run. It never runs against the host's root. | Holds (tested) |
| ISO-2 | The only host-backed paths in the jail are: each `filesystem:` rule, the workspace, devfs, and the instance tmp. | Holds (by inspection); the jail root's listing is tested. |
| ISO-3 | A rule without `w` is mounted read-only. | Holds (tested): a write under `/lib:r` fails with `EROFS`. |
| ISO-4 | The instance directory has an unpredictable name and lives under a directory only root can write. Nothing isolate creates as root is under a world-writable directory. | Holds (tested) |
| ISO-5 | The program runs with the uid and gid of its user and no other groups. | Holds (tested) |
| ISO-6 | The program never runs as uid 0. | Holds (tested): a `user:` that resolves to uid 0 is refused before anything is created. |
| ISO-7 | With `env_clear: true`, the program's environment contains only `USER`, `HOME`, `PATH`, `LD_LIBRARY_PATH`, `SHELL` and the file's `env:` entries. | Holds (tested) |
| ISO-8 | A `/tmp` rule never mounts the host's `/tmp`. It mounts a directory private to the instance. | Holds (tested) |
| ISO-9 | The jail's `/dev` exposes only the device nodes listed above. | Holds (tested): `mem`, `kmem`, `io`, `pci`, `bpf` and `geom.ctl` are absent. |
| ISO-10 | The program inherits no open file descriptors other than 0, 1 and 2. | Holds (tested): descriptors opened by the invoking shell are closed before `execv`. |
| ISO-11 | If something the capability file asks for cannot be set up, the run does not start, and nothing is left behind. | Holds (tested) for a rule whose path does not exist. A failed devfs mount, devfs restriction or any other mount takes the same path (by inspection). Related: LIM-5, NET-5. |
| ISO-12 | Inside the jail the program cannot create raw sockets, create jails or mount filesystems. It cannot use System V IPC unless the capability file sets `sysv_ipc: true`; then the jail has a System V namespace of its own, never the host's, and the kernel destroys it with the jail. | System V IPC: holds (tested): `shmget` fails by default, works when granted, and a segment the program leaves behind is gone after the run. The rest by inspection. |
| ISO-13 | The program receives exactly the arguments given after the binary on the command line. | Holds (tested) with 200 arguments, and with arguments that look like isolate's own options. |
| ISO-14 | The program can look up its own user and group by id and by name. The jail's user database names no other user of the host and holds no password hash, and the program cannot read `master.passwd` or `spwd.db`. | Holds (tested), for `user: auto` and for an existing user. |

## Default behaviour that is not an invariant

- **The environment is inherited unless `env_clear: true`.** The invoking shell's variables reach the program, with `USER`, `HOME`, `PATH`, `LD_LIBRARY_PATH` and `SHELL` overwritten.
- **`allow.socket_af` is true**, which permits socket address families other than IPv4, IPv6, UNIX and route. Whether that should be the case in `network_mode: none` has not been reviewed.
- **The program's working directory is the jail root**, as a consequence of `jail_attach(2)`.

## Success criteria

All of these, observed from inside the jail on a run with only library and `/bin` rules:

1. `id` reports a non-zero uid and exactly one group.
2. A path that no rule names (`/boot`, `/home`, `/root`, `/sbin`) does not exist.
3. Creating a file under a read-only rule fails with `EROFS`.
4. A file created in `/tmp` does not appear in the host's `/tmp`.
5. With `env_clear: true`, a variable exported in the invoking shell is absent.
6. `ls /dev` lists only the nodes named above.
7. No descriptor above 2 is open.
8. `getpwuid(getuid())` returns the program's user.
9. `shmget` fails unless the capability file sets `sysv_ipc: true`.

All nine pass.

## Failure criteria

Any one of these means isolation is broken:

- The program can read a host file that no rule, workspace or devfs mount covers.
- The program can write to a path mounted from a rule without `w`.
- The program runs as uid 0 or holds a group other than its own.
- Anything isolate creates as root is placed at a path another local user could have created or replaced.
- A user other than root can change what a run mounts, where it mounts it, or who it runs as.
- The program starts although part of its capability file could not be applied.

## Known gaps

- No test checks that two instances running at the same time cannot see each other's `/tmp`. Each has its own directory by construction.
- The copy of the binary in the jail root is owned by root and mode 0755; a program that expects to rewrite itself cannot.
- Restricting `/dev` runs `devfs(8)` once per visible node, which adds a dozen short-lived processes to every start.
