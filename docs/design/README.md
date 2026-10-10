# isolate design documents

These documents say what isolate must do, what it deliberately does not do, and how to tell whether it is doing it. They are the specification the code is measured against. [ARCHITECTURE.md](../ARCHITECTURE.md) describes how the code is built; these describe what it has to guarantee.

| Document | Covers |
|---|---|
| [01-isolation.md](01-isolation.md) | The jail, the user the program runs as, and what it can see of the host |
| [02-capability-file.md](02-capability-file.md) | The `.caps` format: every key, its meaning and its defaults |
| [03-lifecycle.md](03-lifecycle.md) | `run`, `stop`, `clean`, `list`, the registry, and cleanup |
| [04-resource-limits.md](04-resource-limits.md) | Memory, process and file-descriptor limits |
| [05-network.md](05-network.md) | Network modes, VNET, and the planned enforcement of network rules |
| [06-detection.md](06-detection.md) | `isolate detect` |

## Product scope

isolate runs **one program from the host, in one FreeBSD jail, with only the access a capability file declares**, and removes everything it created when the program ends.

**In scope**

- Running a host binary inside a jail built for that run, as an unprivileged user.
- A declarative capability file that states the program's filesystem access, network mode, resource limits and environment.
- Lifecycle management of running instances: list, stop, and cleanup after crashes.
- Generating a starting capability file from static analysis of a binary.

**Out of scope**

- **Any platform other than FreeBSD.** There is no Linux, macOS or Windows backend and none is planned in these documents.
- **Images, packaging and distribution.** isolate runs what is already on the host.
- **Orchestration.** No scheduling, clustering, remote API or metrics endpoint.
- **Supervision.** isolate does not daemonize, restart a program that exits, or start anything at boot. `isolate run` stays in the foreground for as long as the program runs.
- **Persistent jails.** Nothing survives the end of a run or a reboot.
- **Full-system jails.** No base system is installed in the jail; there is no `rc`, no package manager and no shell unless a rule mounts one.
- **Defending against the kernel.** A kernel vulnerability reachable from inside a jail is outside what isolate can prevent. isolate does no system-call filtering (no Capsicum, no MAC policy).

## Trust model

| Party | Trusted? | Consequence |
|---|---|---|
| The person invoking `isolate` as root | Yes | Command-line arguments are not treated as hostile. |
| The author of the capability file | Yes | The file is policy. It can grant any access root has. It is still validated, to catch mistakes. |
| The program being run | **No** | Everything in these documents exists to contain it. |
| Other local users of the host | **No** | They must not be able to influence what isolate does as root. |
| The contents of `/var/run/isolate` | Yes, because only root can write there | See [03-lifecycle.md](03-lifecycle.md), LIF-5. |

## How to read the invariants

Each document lists invariants with an identifier (`ISO-3`, `LIF-1`, …). An invariant is a statement that must be true of every run. Each one carries a status:

| Status | Meaning |
|---|---|
| **Holds (tested)** | Demonstrated on FreeBSD 15.1 by running the scenario described, or covered by a unit test. |
| **Holds (by inspection)** | Follows from reading the code. No test exercises it. |
| **Violated** | The code does not do this today. It is a defect to fix, not a description of intended behaviour. |
| **Planned** | A goal that has not been implemented. |

"Tested" means a manual scenario unless a unit test is named. The root-only scenarios are not yet automated and are not part of `zig build test`; see [03-lifecycle.md](03-lifecycle.md), "Known gaps".

Each document also has:

- **Success criteria** — observable results that must all be true for the area to be considered working.
- **Failure criteria** — observations any one of which means the area is broken, whatever else passes.

## Summary of violated invariants

These are the defects the design documents currently record. Each is described in its own document.

| ID | Defect |
|---|---|
| ISO-6 | `user: root` is accepted, so the program can run as uid 0 in the jail. |
| ISO-9 | Every host device node is visible in the jail's `/dev`. |
| ISO-10 | File descriptors open in the invoking process are inherited by the program. |
| ISO-11 | A failed mount is a warning; the run continues. |
| ISO-13 | Arguments beyond the 62nd are dropped without a message. |
| CAP-1 | `cpu:`, `network_default:`, `filesystem_default:`, the `x` permission, single-file rules and write-only rules are accepted and do nothing. |
| CAP-2 | Capability-file errors are shown only with `-v`, and never stop the run. |
| LIF-2 | `clean` cannot find a jail or an ephemeral user that has no registry entry. |
| LIF-9 | Two instances can be given the same name; the second overwrites the first's registry entry. |
| LIF-10 | Registry entries are written in place, so a reader can see a partial one. |
| LIM-5 | If limits cannot be applied, the run continues without them. |
| NET-5 | If VNET is requested and unavailable, the run falls back to the host's network. |
| DET-2 | `detect` writes rules that isolate does not apply. |

Planned, not yet built: NET-6 (enforcing `network:` rules with pf).
