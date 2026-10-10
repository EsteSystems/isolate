# 06 — Detection

## Purpose

`isolate detect <binary>` writes a capability file that lets a program start in a jail holding **exactly the shared libraries it is linked against**, and nothing else from the host's library directories. It also notes what else the program might need, for a person to decide.

## Scope

- Finding the shared libraries a dynamically linked ELF program needs, the way the run-time linker would, without running it.
- Writing them as filesystem rules, one per file.
- Recording guesses about other needs (configuration files, data directories, network ports, limits) as comments.

## Out of scope

- **Libraries loaded at run time.** A program can call `dlopen(3)` to load plugins, modules or name-service backends. Nothing in the binary lists them. `detect` says when a program imports `dlopen`, and that is all it can say.
- **Running or tracing the program.** No system-call tracing, no observation of real behaviour.
- **Scripts.** A shell or Python script is not an ELF file. Its interpreter is not analysed; run `detect` on the interpreter.
- **Non-native ELF files.** Only 64-bit ELF in the host's byte order is read correctly.
- **A complete policy.** Data directories, configuration, network access and limits need a person who knows the program.

## Facts and guesses

The generated file contains two kinds of line, and only one kind is live.

| | Source | Written as |
|---|---|---|
| **Facts** | The program's interpreter and the transitive closure of its `DT_NEEDED` libraries, each resolved to a file on this host | Live `filesystem:` rules, read-only |
| **Guesses** | The program's name, the symbols it imports, and strings embedded in it | Comments, for a person to uncomment |

A guess is never live. The strings in a binary name files such as private keys (`ssh` names `/etc/ssh/ssh_host_rsa_key`), and a generated file must not grant access to them unasked.

The limits at the top of the file (`memory`, `processes`, `files`) are defaults. A guess can raise `memory` and `processes` above the defaults; nothing lowers them.

## How libraries are found

1. Read the binary's interpreter from `.interp`, its `DT_NEEDED` names, and its `DT_RUNPATH` (or `DT_RPATH` if there is no run path).
2. Look each name up in the run path (with `$ORIGIN` expanded), then in the directories listed in `/var/run/ld-elf.so.hints`, then in `/lib` and `/usr/lib`. The first directory holding a file of that name wins.
3. Repeat for every library found, until nothing new turns up.

Each library is written as the path the linker will open, which may be a symbolic link. In the jail that path is a mount of the file the link points to.

isolate sets `LD_LIBRARY_PATH` to `/usr/local/lib:/usr/lib:/lib` in every jail. If a library was found in any other directory, the generated file adds an `env: LD_LIBRARY_PATH=` line naming the directories, because the linker's hints file does not exist in the jail.

`--dirs` writes the directories the libraries are in instead of the files. The jail then exposes those directories whole.

## Invariants

"Tested" names a check in `tests/scenarios.sh`, run on FreeBSD 15.1.

| ID | Invariant | Status |
|---|---|---|
| DET-1 | `detect` never executes the binary it analyses and needs no privileges beyond reading it. | Holds (tested): runs as `nobody`. |
| DET-2 | Every live line `detect` writes is one isolate applies as written. The generated file loads without problems. | Holds (tested; unit tests): the files generated for `nginx`, `sshd` and `sh` load cleanly; the ones for `hello` and `ssh` run those programs unedited. |
| DET-3 | `detect` writes only the output file, and only where asked: `<binary>.caps` or the `-o` path. | Holds (by inspection) |
| DET-4 | A file that is not a readable ELF binary produces a valid capability file, not an error. | Holds (by inspection): a warning, then a file with the defaults and no library rules. |
| DET-5 | Analysis is bounded regardless of the input. | Holds (by inspection): at most 512 libraries are followed and 64 guesses kept; string sections over 10 MB are skipped. `.dynstr` and the section headers are read at whatever size the file declares. |
| DET-6 | The libraries listed are exactly the ones the run-time linker loads for the program. | Holds (tested): identical to `ldd` for `ls`, `ssh`, `sshd`, `nginx` and `postgres`. A jail built from the file generated for `find` contains `libc`, `libsys`, the interpreter, the program and the user database, and no other file. |
| DET-7 | Nothing inferred from names, symbols or strings is a live line. | Holds (tested; unit test): the file for `ssh` has no live rule under `/etc`, and has the guesses as comments. |

## Success criteria

1. For a dynamically linked program with no run-time loading, the generated file runs it with no edits.
2. The library rules equal the output of `ldd`.
3. The generated file passes the capability-file parser with no problems.
4. Every guess is a comment, preceded by a line saying what it was inferred from.
5. A program that imports `dlopen` gets a comment saying that its libraries may be incomplete.

All five pass. Measured for `find`: 9 files visible in the jail, against 33,788 with rules for `/lib`, `/usr/lib`, `/usr/local/lib` and `/libexec`.

## Failure criteria

- `detect` runs, modifies or needs to execute the target.
- A generated file is rejected by `isolate run`.
- A generated file grants access to something through a line that was only a guess.
- A library the linker would load is missing from the file, for a program that does not use `dlopen`.

## Known gaps

- **Programs that load libraries at run time need more rules than `detect` can write.** PostgreSQL loads its procedural languages and extensions from `/usr/local/lib/postgresql`; nginx built with dynamic modules loads them from `libexec`. The generated file starts such a program; using a feature that needs a module then fails until its file or directory is added.
- **The file is for the host it was generated on.** Library paths and versions differ between hosts and change with upgrades. After an upgrade that changes a library's file name, the run is refused because a rule names a file that no longer exists; generate the file again.
- A run path inherited from the executable by its libraries (`DT_RPATH` semantics) is not followed; each object's own run path is used. The linker's `LD_LIBRARY_PATH`, `LD_PRELOAD` and `libmap.conf` are ignored.
- The guesses are crude: an inbound port is always 8080 for an unrecognised server, and name matching is by substring.
