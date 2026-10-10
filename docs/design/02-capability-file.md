# 02 — Capability file

## Purpose

One text file states everything a program is allowed: who it runs as, what it can see of the filesystem, what network it has, how much of the machine it may use, and its environment. This document is the specification of that file.

## Scope

- The syntax of `.caps` files.
- Every key the parser accepts: meaning, default, and whether it is applied.
- How command-line options combine with the file.
- What happens when the file is missing or wrong.

## Out of scope

- **Per-file access control.** A rule names a directory; everything under it is exposed.
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
- A line is at most 4096 bytes. A longer line makes the whole file unreadable.
- At most 32 `filesystem:` rules, 32 `env:` entries and 16 `network:` rules.
- A key may be repeated. For single-valued keys the last occurrence wins.

## Keys

"Applied" means the key changes how the program runs. Keys that are not applied are defects under CAP-1.

| Key | Value | Default | Applied |
|---|---|---|---|
| `user` | `auto`, or the name of an existing user | `auto` | Yes |
| `filesystem` (alias `file`) | `<absolute path>[:<perms>]`, perms from `r`, `w`, `x` | none | Partly; see below |
| `workspace` | host directory mounted read-write at `/workspace` | none | Yes |
| `env` | `NAME=value` | none | Yes |
| `env_clear` | `true` or `1` | false | Yes |
| `network_mode` | `inherit`, `none`, `vnet`, `vnet:<interface>` | `inherit` | Yes |
| `network_ip` | address for the VNET interface, e.g. `10.0.99.2/24` | none | Yes, in VNET mode |
| `memory` | number with optional `K`, `M`, `G`, `B` suffix (powers of 1024) | unlimited | Yes |
| `processes` | integer | unlimited | Yes |
| `files` | integer | unlimited | Yes |
| `network` | `<proto>[:<address>]:<port>[:<direction>]`, or `unix:<path>`, or `none` | none | **No.** Planned; see [05-network.md](05-network.md), NET-6 |
| `cpu` | integer percentage | unlimited | **No** |
| `network_default` | `deny` | allow | **No** |
| `filesystem_default` | `deny` | allow | **No** |

### `user`

- `auto` creates a user named `app-<pid>` for the run and deletes it afterwards.
- Any other value must be an existing user. It is never created or deleted. The jail's `/etc/passwd` contains `root` and this user.

### `filesystem`

The host directory is mounted with nullfs at the same path inside the jail.

- The path must be absolute, must not be `/`, and must not contain empty, `.` or `..` components. Anything else is an invalid rule.
- No `w` means read-only.
- **`/tmp` is special.** A rule for `/tmp` mounts a directory private to the instance, not the host's `/tmp`.
- **Only directories are mounted.** A rule naming a file is skipped. Tested: `filesystem: /etc/hosts:r` leaves `/etc/hosts` absent in the jail.
- **A rule without `r` is skipped.** Tested: `filesystem: /var/log:w` mounts nothing.
- **`x` has no effect.** Whether files can be executed depends on the mount, not on this flag.

The last three are defects under CAP-1.

### `env`

Each entry is set in the program's environment after the built-in variables, so an entry can override `PATH`, `HOME` and the others. A name longer than 255 bytes or a value longer than 1023 bytes is dropped without a message.

## Defaults when there is no file

`isolate run <binary>` reads `<binary>.caps`. If that file does not exist, the run continues with: `user: auto`, `network_mode: inherit`, no filesystem rules, no limits, inherited environment. A warning says so. Because nothing is mounted, a dynamically linked program cannot start.

## Command-line overrides

| Option | Effect |
|---|---|
| `-c <file>` | Read this file instead of `<binary>.caps`. |
| `-w <dir>` | Replaces any `workspace:` in the file. |
| `--vnet <interface>` | Sets `network_mode` to `vnet` with this interface, replacing the file's mode. |

## Invariants

| ID | Invariant | Status |
|---|---|---|
| CAP-1 | Every key the parser accepts either changes how the program runs, as documented here, or is rejected. There are no silent no-ops. | **Violated**: `cpu`, `network_default`, `filesystem_default`, the `x` permission, single-file rules, write-only rules, and over-long `env` entries. `network` rules are not applied either, but the run warns about them. |
| CAP-2 | A line isolate cannot apply (unknown key, invalid value, too many rules) is reported on every run and the run does not start. | **Violated** (tested): such lines are reported only with `-v`, and the run always continues. `memroy: 64M` runs with no memory limit and no message. |
| CAP-3 | No filesystem rule can mount the host's root, or a path that means something other than it reads. | Holds (tested; unit test `parseFileRule rejects unsafe paths`) |
| CAP-4 | A missing capability file never widens access: the defaults mount nothing. | Holds (tested) |
| CAP-5 | An option given on the command line takes precedence over the same setting in the file. | Holds (by inspection) |
| CAP-6 | Parsing is bounded: line length, rule counts and file size cannot make isolate consume unbounded memory. | Holds (by inspection) |

## Success criteria

1. A file using every key in the table, with valid values, produces a run in which each "Applied: Yes" key is observable (the user, the mounts, the environment, the limits, the network mode).
2. A file with a misspelled key, an invalid value, or a rule isolate would skip is refused, with the line number and the reason, without `-v`.
3. `isolate run -n -v` prints exactly the settings the run would use.
4. `isolate detect` followed by `isolate run`, with no edits, starts a program that needs only its libraries.

Criteria 1, 3 and 4 pass today for the keys that are applied. Criterion 2 fails (CAP-2).

## Failure criteria

- A capability file is accepted, and the program runs with more access or fewer limits than the file's text states.
- A typo in a key name changes a run without any message.
- A rule grants access to a path other than the one written.

## Known gaps

- Values cannot contain `#`. There is no escape.
- The `files: 512 (minimum for fork)` advice in the README and in generated files has not been verified.
- Whether a missing capability file should stop the run instead of falling back to defaults is undecided. It is safe (CAP-4) but rarely what the user wants.
