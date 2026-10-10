# 06 — Detection

## Purpose

`isolate detect <binary>` writes a first draft of a capability file so that nobody starts from an empty page. A person reviews and edits it before use.

## Scope

- Static analysis of an ELF binary: the libraries it links, the symbols it imports, strings embedded in it, and its file name.
- Turning those observations into capability-file lines.

## Out of scope

- **Correctness or completeness.** Detection is a set of heuristics. It can grant too much and too little. It is not a security control.
- **Running the program.** No tracing of system calls, no observation of real behaviour.
- **Scripts.** A shell or Python script is not an ELF file; only its file name is considered. Its interpreter is not analysed.
- **Following dependencies.** Libraries are identified by name from the binary's own dynamic section. They are not located on disk or analysed in turn.
- **Non-native ELF files.** Only 64-bit ELF in the host's byte order is read correctly.

## What it does

Four passes, each producing hints. A hint is a description, one or more capability lines, and a confidence from 0 to 100.

| Pass | Reads | Examples of what it concludes |
|---|---|---|
| Libraries | `DT_NEEDED` entries in `.dynamic` | `libc.so` → the four library directories (95). `libssl` → outbound 443 and 80 (80). `libpq` → outbound 5432 (85). `libpthread` → `processes: 10` (60). |
| Symbols | `.dynsym` | `socket` with `bind` or `listen` → `network: tcp:8080:inbound` (85). `socket` alone → outbound 80 (75). `fork`, `execve` → `processes: 10` (80). `open`, `read`, `write`, `fopen` → `filesystem: /tmp:rw` (70). |
| Strings | `.rodata`, `.data`, `.dynstr` | A string starting `/etc/` → that path read-only (60). A string starting `/var/` → that path read-write (65). `http://` or `https://` → outbound 80 and 443 (70). |
| Name | the file name | Contains `nginx` → inbound 80 and 443, `/var/www` read-only, `memory: 128M` (90). Similar entries for `httpd`, `sshd`, `postgres`, `redis`, and generic `server`, `client`, `daemon`. |

The output file starts with fixed defaults (`user: auto`, `memory: 128M`, `processes: 5`, `files: 512`), then the hints in order of confidence. Identical hints are written once. There is no merging of confidences: two different hints that imply the same line both appear.

At most 64 hints are kept. Sections larger than 10 MB are not scanned for strings.

## Invariants

| ID | Invariant | Status |
|---|---|---|
| DET-1 | `detect` never executes the binary it analyses and needs no privileges beyond reading it. | Holds (tested): runs as `nobody`. |
| DET-2 | Every line `detect` writes is one isolate applies. The generated file loads without warnings. | **Violated** (tested). For `nginx` it writes eight `network:` rules, which are not enforced, and rules for single files such as `/var/log/nginx/error.log:rw`, which are skipped. It also repeats keys (`processes: 5` then `processes: 10`), where the last one silently wins. |
| DET-3 | `detect` writes only the output file, and only where asked: `<binary>.caps` or the `-o` path. | Holds (by inspection) |
| DET-4 | A file that is not a readable ELF binary produces a valid capability file with defaults, not an error. | Holds (tested) for a shell script: a warning, then defaults and a `/tmp` rule. |
| DET-5 | Analysis is bounded in memory regardless of the input. | Holds (by inspection) for hint count and string sections. `.dynstr` and the section headers are read at whatever size the file declares. |

## Success criteria

1. For a small dynamically linked C program, the generated file lets the program run with no edits.
2. For a program that listens on a socket, the file includes a line recording that it listens.
3. The generated file passes the capability-file parser with no warnings ([02-capability-file.md](02-capability-file.md), CAP-2).
4. Every generated line is preceded by a comment saying what it was inferred from.

Criteria 1, 2 and 4 pass: the `hello` and `server` examples run from their generated files. Criterion 3 fails for any binary that yields network rules or file paths (DET-2).

## Failure criteria

- `detect` runs, modifies or needs to execute the target.
- A generated file is rejected by `isolate run`, or grants access through a line the user was not shown.
- The documentation or the tool's output presents a generated file as sufficient or safe without review.

## Known gaps

- **The result for a real server is not runnable.** For `nginx`, detection misses `/usr/local/sbin`, `/usr/local/etc/nginx` and `/bin`, and proposes `/var/www`, which may not exist. The file is a starting point for editing, no more.
- Read-write access is proposed for every embedded `/var/…` string, whether or not the program writes there.
- The port in an inbound hint is always 8080 for unrecognised servers; it is not read from the binary.
- Name matching is by substring: a binary called `myserver-client` matches `server`.
- Once CAP-2 is fixed (unknown or unusable lines stop the run), DET-2 must be fixed at the same time, or generated files will stop working.
