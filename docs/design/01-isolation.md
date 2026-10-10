# 01 — Isolation

## Purpose

Contain an untrusted program: it runs in a jail whose filesystem isolate built for that run, as a user with no privileges, and sees nothing of the host except what the capability file names.

## Scope

- The jail and its parameters.
- The jail's root filesystem: what is created in it, what is mounted into it.
- The identity the program runs as.
- The environment and arguments the program receives.

## Out of scope

- **Kernel vulnerabilities and side channels.** isolate relies on the jail boundary being sound.
- **System-call filtering.** No Capsicum, no MAC policy.
- **Hiding the contents of a mounted directory.** A rule for `/usr/lib` exposes all of `/usr/lib`. Rules are per directory, not per file (see [02-capability-file.md](02-capability-file.md)).
- **Protecting the program from the host.** Root on the host can do anything to the jail.
- **Network access** is covered in [05-network.md](05-network.md); **resource limits** in [04-resource-limits.md](04-resource-limits.md).

## What a run creates

```
/var/run/isolate/                    root-owned, 0755
└── inst-XXXXXX/                     per run, from mkdtemp(3), 0755
    ├── root/                        the jail's root filesystem
    │   ├── <binary>                 copy of the program, 0755
    │   ├── etc/passwd, etc/group    root and the program's user only
    │   ├── dev/                     devfs
    │   ├── tmp/                     1777; the instance tmp if a /tmp rule exists
    │   ├── workspace/               nullfs mount of the -w directory, read-write
    │   ├── <rule path>/             nullfs mount of each filesystem rule
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
| `allow.socket_af` | true |
| `ip4`, `ip6` / `vnet` | by network mode; see [05-network.md](05-network.md) |

## Invariants

| ID | Invariant | Status |
|---|---|---|
| ISO-1 | The program runs inside a jail whose root is a directory created for this run. It never runs against the host's root. | Holds (tested): with no rules, a dynamically linked program cannot find `/libexec/ld-elf.so.1`. |
| ISO-2 | The only host-backed paths in the jail are: each `filesystem:` rule, the workspace, devfs, and the instance tmp. | Holds (by inspection) |
| ISO-3 | A rule without `w` is mounted read-only. | Holds (by inspection). No test attempts a write. |
| ISO-4 | The instance directory has an unpredictable name and lives under a directory only root can write. Nothing isolate creates as root is under a world-writable directory. | Holds (tested) |
| ISO-5 | The program runs with the uid and gid of its user and no other groups. | Holds (tested): `id` in the jail shows one group, for `user: auto` and for `user: nobody`. |
| ISO-6 | The program never runs as uid 0. | **Violated**: `user: root` is looked up like any other name and accepted. By inspection; not tested. |
| ISO-7 | With `env_clear: true`, the program's environment contains only `USER`, `HOME`, `PATH`, `LD_LIBRARY_PATH`, `SHELL` and the file's `env:` entries. | Holds (tested) |
| ISO-8 | A `/tmp` rule never mounts the host's `/tmp`. It mounts a directory private to the instance. | Holds (tested) |
| ISO-9 | The jail's `/dev` exposes only the device nodes an unprivileged program needs (`null`, `zero`, `random`, `urandom`, `stdin`/`stdout`/`stderr`, `fd`, ptys). | **Violated** (tested): devfs is mounted with no ruleset, so every host node is listed, including `mem`, `kmem`, `io`, `bpf`, `pci` and `geom.ctl`. Access is still subject to their file permissions. |
| ISO-10 | The program inherits no open file descriptors other than 0, 1 and 2. | **Violated** (by inspection): nothing closes other descriptors before `execv`. |
| ISO-11 | If something the capability file asks for cannot be set up, the run does not start. | **Violated** (by inspection): a failed devfs mount or rule mount prints a warning and the run continues. Related: LIM-5, NET-5. |
| ISO-12 | Inside the jail the program cannot create raw sockets, use System V IPC, create jails or mount filesystems. | Holds (by inspection) |
| ISO-13 | The program receives exactly the arguments given after the binary on the command line. | **Violated** (tested): the argument vector holds 62 arguments; the rest are dropped without a message. A binary name longer than 254 bytes is an error. |

## Default behaviour that is not an invariant

- **The environment is inherited unless `env_clear: true`.** The invoking shell's variables reach the program, with `USER`, `HOME`, `PATH`, `LD_LIBRARY_PATH` and `SHELL` overwritten. Tested: a variable set in the invoking shell is visible in the jail.
- **`allow.socket_af` is true**, which permits socket address families other than IPv4, IPv6, UNIX and route. Whether that should be the case in `network_mode: none` has not been reviewed.
- **The program's working directory is the jail root**, as a consequence of `jail_attach(2)`.

## Success criteria

All of these, observed from inside the jail on a run with only `/lib`, `/usr/lib` and `/libexec` rules:

1. `id` reports a non-zero uid and exactly one group.
2. A path that no rule names (for example `/etc/master.passwd`, `/home`, `/usr/local`) does not exist.
3. Creating a file under a read-only rule fails with `EROFS`.
4. A file created in `/tmp` by one instance is not visible to another instance running at the same time.
5. With `env_clear: true`, a variable exported in the invoking shell is absent.
6. `ls /dev` lists only the nodes named in ISO-9.

Criteria 1, 2 and 5 pass today. Criterion 3 and 4 have not been run. Criterion 6 fails (ISO-9).

## Failure criteria

Any one of these means isolation is broken:

- The program can read a host file that no rule, workspace or devfs mount covers.
- The program can write to a path mounted from a rule without `w`.
- The program runs as uid 0 or holds a group other than its own.
- Anything isolate creates as root is placed at a path another local user could have created or replaced.
- A user other than root can change what a run mounts, where it mounts it, or who it runs as.

## Known gaps

Beyond the violated invariants above:

- No test checks ISO-3 (read-only mounts) or cross-instance `/tmp` separation.
- The copy of the binary in the jail root is owned by root and mode 0755; a program that expects to rewrite itself cannot. This is intended but undocumented elsewhere.
