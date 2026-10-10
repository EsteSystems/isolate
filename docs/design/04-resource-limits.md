# 04 — Resource limits

## Purpose

A program cannot use more memory, processes or file descriptors than its capability file allows, so that one instance cannot exhaust the host.

## Scope

- The `memory`, `processes` and `files` keys.
- How each is enforced, and what the program experiences when it reaches a limit.
- The lifetime of the limits.

## Out of scope

- **CPU limits.** The `cpu` key is refused. rctl's `pcpu` limit is too coarse to honour a percentage: tested on FreeBSD 15.1, `pcpu:deny=20` let a busy loop use about 49% of a CPU.
- **Disk space, disk I/O and network bandwidth.**
- **Swap and virtual address space** as separate limits.
- **Per-process limits.** Every limit applies to the jail as a whole: all processes in it, added together.
- **Enforcement without racct.** Limits need a kernel with `kern.racct.enable=1`.

## Mechanism

Limits are `rctl(8)` rules on the jail, added with `rctl_add_rule(2)` after the jail is created and before the program starts.

| Key | Rule | When the limit is reached |
|---|---|---|
| `processes: N` | `jail:<name>:maxproc:deny=N` | `fork` fails with `EAGAIN`. |
| `files: N` | `jail:<name>:openfiles:deny=N` | `open` and similar fail with `EMFILE`. |
| `memory: N` | `jail:<name>:memoryuse:sigkill=N` | The process is killed with `SIGKILL`. |

### Why memory kills instead of refusing

`memoryuse` is resident memory. The `deny` action does not refuse anything for it: the kernel only tries to page the excess out, and the program keeps allocating. Tested on FreeBSD 15.1 with a 64 MB limit:

| Rule | Program growing 8 MB every 250 ms | Program allocating 256 MB at once |
|---|---|---|
| `memoryuse:deny` | Not limited | Not limited |
| `memoryuse:sigkill` | Killed | **Not caught** if it finishes within about a second |
| `vmemoryuse:deny` | `malloc` fails at 32 MB | `malloc` fails at 32 MB |

The kernel samples resident memory about once a second, which is why a short burst escapes `sigkill`. `vmemoryuse:deny` has no such gap, but it limits address space rather than memory in use, so it refuses allocations well below the stated limit and would stop programs that reserve large address ranges. isolate uses `memoryuse:sigkill`.

## Invariants

| ID | Invariant | Status |
|---|---|---|
| LIM-1 | With `processes: N`, the jail never holds more than N processes. | Holds (tested): with N = 8, the eighth process cannot be created. |
| LIM-2 | With `files: N`, the jail never holds more than N open file descriptors. | Holds (tested): with N = 64, the 62nd additional `open` fails. |
| LIM-3 | With `memory: N`, a process whose resident memory stays above N is killed within two seconds. | Holds (tested): exit status 137 under a 64 MB limit; the same program completes under 512 MB. |
| LIM-4 | An instance's limits exist only while its jail exists. No limit from an earlier instance applies to a later one. | Holds (tested): no rules remain after a run; rules are cleared for the jail name before the jail is created. |
| LIM-5 | If the capability file sets a limit and it cannot be applied, the run does not start. | Holds (by inspection): with racct disabled, or when adding a rule fails, setup fails and everything created so far is removed. The scenario for this only runs on a host without racct, so it has not been exercised. |
| LIM-6 | A limit is in force before the program's first instruction runs. | Holds (by inspection): rules are added before the child attaches to the jail. |

## Success criteria

1. `processes: 8`: a program that forks in a loop gets `EAGAIN` on the eighth fork.
2. `files: 64`: a program that opens files in a loop gets `EMFILE` on reaching 64 descriptors.
3. `memory: 64M`: a program that grows steadily is killed; `isolate run` exits 137.
4. The same three programs complete under generous limits.
5. After each run, `rctl` lists no rule for the instance's jail.
6. On a kernel without racct, a capability file with any limit is refused.

Criteria 1–5 pass on FreeBSD 15.1. Criterion 6 has not been run: the test host has racct enabled.

## Failure criteria

- A jail holds more processes or descriptors than its limit.
- A program stays above its memory limit for more than two seconds and keeps running.
- A program runs with no limits although its capability file sets some, and isolate does not refuse.
- A new instance is constrained by a rule left by an old one.

## Known gaps

- **Short memory bursts are not caught.** A program can allocate far beyond its limit if it frees the memory or exits within about a second. Closing this needs a different rule (`vmemoryuse`, or a swap limit) with its own costs; it is undecided.
- The program is killed without warning at the memory limit. There is no soft limit and no signal it could handle.
- Limits count the whole jail, so a memory limit of N with several worker processes is shared between them.
