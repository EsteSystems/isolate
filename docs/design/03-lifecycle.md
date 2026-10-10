# 03 — Lifecycle

## Purpose

Everything isolate creates for a run is removed when the run ends, however it ends, without touching anything else on the host. Running instances can be listed and stopped, and whatever a crashed run leaves behind can be found and removed.

## Scope

- `isolate run`: setup order, what the parent process does while the program runs, exit status, signals.
- The registry of running instances.
- `isolate list`, `isolate stop`, `isolate clean`.
- Cleanup, including after isolate itself is killed.

## Out of scope

- **Supervision.** isolate does not restart a program, run in the background, or start instances at boot.
- **Surviving a reboot.** A reboot ends every instance; nothing is restored.
- **Log management.** The program's output goes wherever isolate's own output goes.
- **Concurrent administration.** Two `isolate` commands acting on the same instance at once are not coordinated beyond what is described below.

## How a run proceeds

`isolate run` forks. The **child** becomes the program; the **parent** waits and cleans up.

Child, in order:

1. Create the ephemeral user (`user: auto`) or look up the named one.
2. Create the instance directory and the jail root.
3. Build the jail's filesystem: directories, workspace mount, copy of the binary, `passwd` and `group`, devfs, one mount per rule.
4. Create the jail. In VNET mode, move the interface in and configure it.
5. Add resource limits.
6. Attach to the jail, drop to the user, set the environment.
7. Send the jail id, username and jail path to the parent over a pipe.
8. `execv` the program.

If any of steps 1–6 fails, the child removes what it created and exits non-zero. The parent sees a short read on the pipe and reports the failure without touching anything.

Parent:

1. Install handlers for `SIGINT`, `SIGTERM` and `SIGHUP`.
2. Read the child's state from the pipe and write the registry entry.
3. Wait for the child.
4. Remove the jail, unmount everything under the instance directory, remove the directory, delete the ephemeral user, remove the jail's resource limits.
5. Delete the registry entry and exit with the child's status.

## The registry

One JSON file per instance, `/var/run/isolate/<name>.json`:

```json
{
  "name": "server-73d28d8b",
  "pid": 3561,
  "manager_pid": 3559,
  "jail_id": 23,
  "jail_path": "/var/run/isolate/inst-MeVxWG/root",
  "username": "app-3561",
  "binary_path": "./zig-out/examples/server",
  "start_time": 1760126400,
  "workspace_path": null
}
```

- `pid` is the jailed program. `manager_pid` is the `isolate run` process waiting for it.
- The name is the `-N` value, or `<workspace or binary basename>-<8 hex digits>`. It may contain letters, digits, `.`, `_` and `-`, must not start with `.`, and is at most 64 bytes.
- The directory is created by root with mode 0755. `isolate list` works unprivileged.

An instance is **running** if its jail exists or its `pid` exists, **orphaned** if neither does. Separately, an instance is **unmanaged** when its `manager_pid` no longer exists; that is what `stop` and `clean` act on.

## Commands

**`stop <name>`**

1. If the jail still belongs to the instance, send `SIGTERM` to the program and wait up to five seconds.
2. If the program is still running: without `-f`, report it and exit 1, leaving the instance registered. With `-f`, remove the jail, which kills everything inside it.
3. If the manager is alive, it performs the cleanup. Otherwise `stop` removes the jail, limits, instance directory and ephemeral user itself and deletes the registry entry.

**`clean`**

1. For every registered instance whose manager is gone: remove its jail, limits, instance directory and ephemeral user, and delete the entry.
2. Remove resource limits belonging to `isolate-*` jails that no longer exist.
3. Remove every `inst-*` directory that is not the jail root of a running instance.

## Invariants

| ID | Invariant | Status |
|---|---|---|
| LIF-1 | When `isolate run` returns, nothing of the instance remains: no jail, mount, instance directory, ephemeral user, resource limit or registry entry. This holds when the program exits, is killed, or isolate receives `SIGINT`, `SIGTERM` or `SIGHUP`. | Holds (tested) for normal exit, a killed program, and two `SIGTERM`s. `SIGINT` and `SIGHUP` by inspection. |
| LIF-2 | Whatever an `isolate run` leaves when it cannot clean up (it was killed with `SIGKILL`, or the host crashed) is removed by one `isolate clean`. | **Violated**. Holds (tested) when the registry entry survives. A jail or an `app-*` user with no registry entry is never found. After a reboot `/var/run` is empty, so every ephemeral user that existed at the time stays in the password database. |
| LIF-3 | Cleanup never deletes or changes host data outside the instance directory. Mounts are removed before the directory tree, and removal never crosses a mount point. | Holds (tested): a workspace and an extra read-write rule keep their files. |
| LIF-4 | `stop` and `clean` act only on things isolate created: a directory of the form `/var/run/isolate/inst-XXXXXX`, a user named `app-<digits>`, and a jail whose name is still `isolate-<pid>` for the recorded pid. Anything else in a registry entry is reported and skipped. | Holds (tested; unit tests `trustedInstanceDir…`, `isEphemeralUsername`) |
| LIF-5 | Only root can create or change registry entries. The registry is never read from a directory another user can write. | Holds (tested): an entry planted in `/tmp` is ignored, and a non-root user cannot write `/var/run/isolate`. |
| LIF-6 | `stop` never unregisters an instance whose program is still running, unless `-f` is given. | Holds (tested) |
| LIF-7 | `isolate run` exits with the program's exit status, or 128 plus the signal number if a signal ended it. | Holds (tested): 7 for `exit 7`, 137 for `SIGKILL`. |
| LIF-8 | The first termination signal to `isolate run` is passed to the program. The second removes the jail. In both cases isolate stays alive until it has cleaned up. | Holds (tested) with `SIGTERM` |
| LIF-9 | Instance names are unique among running instances. | **Violated** (by inspection): a second run with the same `-N` overwrites the first's registry entry, and whichever exits first deletes it. |
| LIF-10 | A registry entry is either absent or complete. | **Violated** (by inspection): the file is written in place, so a concurrent `list` can read a partial entry. It is then skipped, not misread. |

## Success criteria

After each of the following, the host has no `isolate-*` jail, no mount under `/var/run/isolate`, no `inst-*` directory, no `app-*` user, no `jail:isolate-*` resource limit and no registry entry:

1. A program that exits normally.
2. A program that is killed.
3. `SIGTERM` sent twice to `isolate run` while a program that ignores it is running.
4. `isolate stop -f` on such a program.
5. `kill -9` of the `isolate run` process, followed by `isolate clean`.

In every case, files in a mounted workspace and in a read-write rule directory are unchanged.

All five pass on FreeBSD 15.1.

## Failure criteria

- Any file outside the instance directory is deleted or modified by cleanup.
- A non-root user can cause `stop` or `clean` to remove or signal anything.
- `stop` reports success while the program is still running.
- A run leaves a jail, mount, user or limit behind and `clean` reports nothing to do.

The last one occurs today in the situation described under LIF-2.

## Known gaps

- **The scenarios above are not automated.** They exist as shell scripts run by hand on a test machine. `zig build test` covers parsing and path validation only; nothing in the repository creates a jail.
- Ephemeral usernames are `app-<pid>`. If a user of that name already exists (left by a crash), it is reused and then deleted.
- The jail is created with `persist`, so a jail outlives its last process until someone removes it. This is what makes LIF-2 matter.
- `stop` waits a fixed five seconds. It is not configurable.
