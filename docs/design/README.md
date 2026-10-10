# isolate design documents

These documents say what isolate must do, what it deliberately does not do, and how to tell whether it is doing it. They are the specification the code is measured against. [ARCHITECTURE.md](../ARCHITECTURE.md) describes how the code is built; these describe what it has to guarantee.

| Document | Covers |
|---|---|
| [01-isolation.md](01-isolation.md) | The jail, the user the program runs as, and what it can see of the host |
| [02-capability-file.md](02-capability-file.md) | The `.caps` format: every key, its meaning and its defaults |
| [03-lifecycle.md](03-lifecycle.md) | `run`, `stop`, `clean`, `list`, the registry, and cleanup |
| [04-resource-limits.md](04-resource-limits.md) | Memory, process and file-descriptor limits |
| [05-network.md](05-network.md) | Network modes, VNET, and network rules enforced with pf |
| [06-detection.md](06-detection.md) | `isolate detect` |

## Product scope

isolate is a **sandbox launcher**: it runs one program that is already installed on the host, in one FreeBSD jail that contains only what a capability file lists, and removes everything it created when the program ends.

It is not a container runner. It does not package, ship or reproduce anything; the program and its libraries are the host's.

**In scope**

- Running a host binary inside a jail built for that run, as an unprivileged user.
- A declarative capability file that states the program's filesystem access, network mode and rules, resource limits and environment.
- Lifecycle management of running instances: list, stop, and cleanup after crashes.
- Generating a capability file that lists exactly the shared libraries a binary is linked against.

**Out of scope**

- **Any platform other than FreeBSD.** There is no Linux, macOS or Windows backend and none is planned in these documents.
- **Images, packaging and distribution.** isolate runs what is already on the host. A capability file is written for the host it runs on.
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
| **Holds (tested)** | Demonstrated on FreeBSD 15.1 by a check in `tests/scenarios.sh`, or covered by a unit test. |
| **Holds (by inspection)** | Follows from reading the code. No test exercises it. |
| **Violated** | The code does not do this today. It is a defect to fix, not a description of intended behaviour. |
| **Planned** | A goal that has not been implemented. |

"Tested" means a check in `tests/scenarios.sh` unless a unit test is named. That script creates real jails, so it needs FreeBSD and root and is run by hand; it is not part of `zig build test`.

Each document also has:

- **Success criteria** — observable results that must all be true for the area to be considered working.
- **Failure criteria** — observations any one of which means the area is broken, whatever else passes.

## Status

No invariant is currently recorded as violated.

Some refusals hold only by inspection because the test host cannot exercise them: LIM-5 (limits requested on a kernel without racct), the no-VNET half of NET-5, and the half of NET-6 that refuses network rules when pf is not ready. `tests/scenarios.sh` contains checks for the first and the last and runs them on a host that lacks racct or pf.

Each document ends with its known gaps: behaviour that is not an invariant but is worth knowing, and cases no test covers.

