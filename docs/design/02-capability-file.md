# 02 — Capability file

## Purpose

One text file states everything a program is allowed: who it runs as, what it can see of the filesystem, what network it has, how much of the machine it may use, and its environment. This document is the specification of that file.

## Scope

- The syntax of `.caps` files.
- Every key the parser accepts: meaning and default.
- How command-line options combine with the file.
- What happens when the file is missing or wrong.

## Out of scope

- **Access control inside a mounted directory.** A rule names a directory or a file; a directory is exposed whole.
- **Execute permission.** Rules are read-only or read-write.
- **CPU limits.** See [04-resource-limits.md](04-resource-limits.md).
- **Includes, variables, profiles or inheritance** between capability files.
- **Signing or integrity checking** of capability files. The file is trusted input read as root.
- **Hot reload.** The file is read once, before the jail is created.

## Syntax

```
# comment
key: value            # trailing comment
```

- One `key: value` per line. Leading and trailing whitespace is ignored.
- Lines that are empty or start with `#` are ignored. A `#` inside a value starts a comment, so values cannot contain `#`.
- A line is at most 4096 bytes.
- At most 32 `filesystem:` rules, 32 `env:` entries and 16 `network:` rules.
- A key may be repeated. For single-valued keys the last occurrence wins.

## Keys

| Key | Value | Default |
|---|---|---|
| `user` | `auto`, or the name of an existing user whose uid is not 0 | `auto` |
| `filesystem` (alias `file`) | `<absolute path>[:r]` or `<absolute path>:rw` | none |
| `workspace` | host directory mounted read-write at `/workspace` | none |
| `env` | `NAME=value`; name up to 255 bytes, value up to 1023 | none |
| `env_clear` | `true`, `1`, `yes`, `false`, `0`, `no` | `false` |
| `sysv_ipc` | `true`, `1`, `yes`, `false`, `0`, `no` | `false` |
| `network_mode` | `inherit`, `none`, `vnet`, `vnet:<interface>` | `inherit` |
| `network_ip` | address for the VNET interface, e.g. `10.0.99.2/24` | none |
| `memory` | number with optional `K`, `M`, `G`, `B` suffix (powers of 1024) | unlimited |
| `processes` | integer | unlimited |
| `files` | integer | unlimited |
| `network` | `<proto>[:<address>]:<port>[:<direction>]`, or `unix:<path>`, or `none` | none |

Every key in this table takes effect, with one exception: **`network:` rules are parsed and listed but not enforced.** A run with such rules prints a warning saying so. Enforcement is planned; see [05-network.md](05-network.md), NET-6.

Anything else is an error. In particular these are **refused**, because isolate would have nothing to do with them:

| Refused | Why |
|---|---|
| `cpu:` | CPU limits are out of scope; see [04-resource-limits.md](04-resource-limits.md). |
| `network_default:`, `filesystem_default:` | They never had an effect. Nothing is mounted by default already. |
| `filesystem: <path>:w` | A mount cannot be write-only. |
| `filesystem: <path>:rx`, `:x` | Rules do not control execution. |
| Any key not in the table | Most likely a typo. |

### `user`

- `auto` creates a user named `app-<pid>` for the run and deletes it afterwards.
- Any other value must be an existing user with a non-zero uid. It is never created or deleted. The jail's `/etc/passwd` contains `root` and this user.

### `filesystem`

The host path is mounted with nullfs at the same path inside the jail.

- The path must be absolute, must not be `/`, and must not contain empty, `.` or `..` components.
- The path must exist on the host when the run starts, as a directory or a regular file. A single file is mounted as a single file.
- `:r` or no suffix means read-only. `:rw` means read-write.
- **`/tmp` is special.** A rule for `/tmp` mounts a directory private to the instance, not the host's `/tmp`.

### `sysv_ipc`

With `true`, the jail gets System V shared memory, semaphores and message queues of its own. They are not the host's: nothing created in the jail is visible to another jail, and everything is destroyed when the jail is removed. Without it, the System V calls fail. PostgreSQL needs this; see the [PostgreSQL guide](../postgresql-guide.md).

### `env`

Each entry is set in the program's environment after the built-in variables, so an entry can override `PATH`, `HOME` and the others.

## When the file is missing or wrong

| Situation | Result |
|---|---|
| The file does not exist | A warning, then the run continues with the defaults: `user: auto`, `network_mode: inherit`, no filesystem rules, no limits, inherited environment. Because nothing is mounted, a dynamically linked program cannot start. |
| The file exists but cannot be read, or a line is longer than 4096 bytes | Error. The run does not start. |
| A line has an unknown key, an invalid value, a refused form, or exceeds a rule limit | Each such line is reported as `<file>:<line>: <reason>`. The run does not start. `-v` is not needed to see this. |
| A rule names a path that does not exist, or a limit or network mode cannot be applied | Error at setup. The run does not start and nothing is left behind. See ISO-11, LIM-5, NET-5. |

`isolate run -n` (dry run) applies the same checks to the file and prints the settings a run would use. It does not check that rule paths exist.

## Command-line overrides

| Option | Effect |
|---|---|
| `-c <file>` | Read this file instead of `<binary>.caps`. |
| `-w <dir>` | Replaces any `workspace:` in the file. |
| `--vnet <interface>` | Sets `network_mode` to `vnet` with this interface, replacing the file's mode. |

## Invariants

| ID | Invariant | Status |
|---|---|---|
| CAP-1 | Every key the parser accepts either changes how the program runs, as documented here, or is rejected. There are no silent no-ops. | Holds (tested; unit tests). `network:` rules are the declared exception: accepted, not enforced, and a warning says so on every run. |
| CAP-2 | A line isolate cannot apply is reported on every run, with its file and line number, and the run does not start. | Holds (tested; unit test `loadFromReader reports every line it cannot apply`) |
| CAP-3 | No filesystem rule can mount the host's root, or a path that means something other than it reads. | Holds (tested; unit test `parseFileRule rejects unsafe paths`) |
| CAP-4 | A missing capability file never widens access: the defaults mount nothing. | Holds (tested) |
| CAP-5 | An option given on the command line takes precedence over the same setting in the file. | Holds (by inspection) |
| CAP-6 | Parsing is bounded: line length, rule counts and entry sizes cannot make isolate consume unbounded memory. | Holds (by inspection) |

## Success criteria

1. A file using every key in the table, with valid values, produces a run in which each is observable: the user, the mounts, the environment, the limits, the network mode.
2. A file with a misspelled key, an invalid value, or a refused form is rejected with the file name, line number and reason, without `-v`.
3. `isolate run -n -v` prints exactly the settings the run would use.
4. `isolate detect` followed by `isolate run`, with no edits, starts a program that needs only its libraries.

All four pass.

## Failure criteria

- A capability file is accepted, and the program runs with more access or fewer limits than the file's text states.
- A typo in a key name changes a run without stopping it.
- A rule grants access to a path other than the one written.

## Known gaps

- Values cannot contain `#`. There is no escape.
- A repeated single-valued key is not reported; the last one wins.
- Whether a missing capability file should stop the run instead of falling back to defaults is undecided. It is safe (CAP-4) but rarely what the user wants.
- `network:` rules remain the one accepted key without effect, until NET-6 is built.
