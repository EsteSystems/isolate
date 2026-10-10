# isolate

A sandbox launcher for FreeBSD: run a program that is already installed on the host inside a jail that contains only what you list.

```sh
isolate detect /usr/local/bin/myapp      # writes myapp.caps: the exact libraries it links against
doas isolate run /usr/local/bin/myapp    # a jail with those files, a throwaway user, and nothing else
```

The program sees the libraries it is linked against, the directories you name, and no other part of the host. It runs as a user that exists only for that run. When it exits, the jail, its mounts, the user and its limits are gone.

## What it is, and is not

isolate does one job: it confines a program you already have. There is no image to build, no base system to install into a jail, and no daemon. The closest relatives are bubblewrap, firejail and nsjail on Linux.

It is **not a container runner**. It does not package software, move it between machines, or reproduce an environment: the program and its libraries are the host's, and a capability file is written for the host it runs on.

### Compared with other FreeBSD tools

| Tool | What it gives you | How isolate differs |
|---|---|---|
| `jail.conf`, Bastille, iocage, pot, AppJail | Managed jails with a base system of their own: persistent, updatable, many services each | No base system, nothing persists, one program. Much lighter, far less capable. |
| Podman and OCI containers | Images you build, ship and run anywhere | A different job. isolate ships nothing. |
| Service jails (`<name>_svcj` in `rc.conf`, FreeBSD 15) | One line puts an existing service in a jail, with networking and privileges restricted | A service jail shares the host's whole filesystem. isolate's jail holds only what the capability file lists. |
| Capsicum | Sandboxing a program builds into itself | Needs changes to the program. isolate needs none. |

The comparison with service jails is the one that matters, because they are in the base system and take no setup. Checked on FreeBSD 15.1: a program in a default service jail can list `/`, read `/etc/master.passwd` and `/root`, and sees every device node; what it loses is network access and privileges. isolate restricts the other half: `find`, run under isolate from its generated capability file, sees nine files.

Use a service jail when you want a host service to keep working exactly as it does, with less privilege. Use isolate when you want a program to be unable to see the rest of the machine.

## Features

- **A filesystem that holds only what you list**: read-only or read-write rules for directories and single files, mounted into an otherwise empty jail
- **Exact library detection**: `isolate detect` follows a program's shared-library dependencies and lists precisely those files
- **A throwaway user**: created for the run, deleted afterwards, with no other groups
- **Network modes**: the host's network, none, or a VNET stack of its own
- **Network rules**: for a VNET jail, which connections may be made and accepted, enforced with pf
- **Resource limits**: memory, processes and file descriptors, via rctl
- **System V IPC on request**: a private namespace per jail, for programs like PostgreSQL
- **All or nothing**: a capability file is applied in full or the run is refused. Nothing in it is skipped
- **Thorough cleanup**: after a normal exit, a crash, a signal or a reboot
- **Instance management**: list, stop and clean up running instances; an `rc.d` script for services
- **No daemon, no images**: one executable that uses only the FreeBSD base system

The [design documents](docs/design/README.md) state what is guaranteed, what is out of scope, and what is not covered, with the test behind each claim.

## Maturity

isolate is young. It has been developed and tested on one FreeBSD release (15.1), has had no independent security review, and has no port or package. Its behaviour is specified and exercised by about 115 end-to-end checks, but that is not the same as having been attacked. Read the [design documents](docs/design/README.md) before trusting it with hostile code.

## Quick Start

```sh
# Build isolate
zig build

# List the libraries your program links against, as a capability file
./zig-out/bin/isolate detect ./myapp

# Review it; add the directories the program needs for its data
cat ./myapp.caps

# Run in isolation (requires root)
doas ./zig-out/bin/isolate run ./myapp

# List running instances
./zig-out/bin/isolate list

# Stop an instance
doas ./zig-out/bin/isolate stop myapp-abc123

# Clean up orphaned data
doas ./zig-out/bin/isolate clean
```

## Installation

### Requirements

- Zig 0.16.0 (pinned in `build.zig.zon`)
- FreeBSD. Developed and tested on 15.1-RELEASE; earlier releases are untested
- For resource limits: `kern.racct.enable=1`. For VNET: a kernel with `VIMAGE`. `isolate check` reports both
- Root privileges for isolation (detection works without root)

### Building from Source

```sh
# Clone the repository
git clone https://github.com/EsteSystems/isolate.git
cd isolate

# Build (debug)
zig build

# Build (release)
zig build -Doptimize=ReleaseSafe

# Run tests
zig build test

# Install to prefix (default: zig-out)
zig build install
```

### Build Options

| Option | Description | Default |
|--------|-------------|---------|
| `-Doptimize=` | Optimization level (Debug, ReleaseSafe, ReleaseFast, ReleaseSmall) | Debug |
| `-Dtarget=` | Target triple for cross-compilation | native |

## Usage

### Commands

#### `isolate run [options] <binary> [args...]`

Run a binary in isolation.

```sh
# Basic usage
doas isolate run ./myapp

# With workspace directory (mounted as /workspace in jail)
doas isolate run -w /data/tenant1 ./myapp

# With custom capability file
doas isolate run -c custom.caps ./myapp

# With custom instance name
doas isolate run -N myapp-prod ./myapp

# Verbose output
doas isolate run -v ./myapp

# Dry run (no isolation, shows what would happen)
isolate run -n ./myapp
```

Options:
- `-c, --caps <file>`: Capability file (default: `<binary>.caps`)
- `-w, --workspace <dir>`: Workspace directory mounted as `/workspace`
- `-N, --name <name>`: Instance name (default: auto-generated); letters, digits, `.`, `_`, `-`, at most 64 characters
- `--vnet <interface>`: Use VNET isolation with specified interface
- `-v, --verbose`: Verbose output
- `-n, --dry-run`: Show configuration without executing

Options must come before the binary. Everything after it is passed to the binary unchanged, so `isolate run -v ./myapp -v --port 80` gives `-v --port 80` to `myapp`. Use `--` if the binary's own name starts with a dash.

#### `isolate detect [options] <binary> [output.caps]`

Write a capability file listing exactly the shared libraries a program is linked against.

```sh
# Generate <binary>.caps
isolate detect ./myapp

# Specify output file
isolate detect -o custom.caps ./myapp
```

Options:
- `-o, --output <file>`: Output capability file
- `--dirs`: List the directories the libraries are in, instead of the files

`detect` reads the binary; it never runs it. It follows the program's dependencies the way the run-time linker does, and the result matches `ldd`. A generated file looks like this (abridged):

```ini
user: auto
memory: 128M
processes: 5
files: 512

# Shared libraries: exactly the files this program is linked against
filesystem: /libexec/ld-elf.so.1:r
filesystem: /lib/libc.so.7:r
filesystem: /lib/libsys.so.7:r

# Guesses, most confident first. None of these is applied.
# File operations detected
# filesystem: /tmp:rw
```

Two kinds of line, and only one is live. **Facts**, the libraries, are live rules. **Guesses** from the program's name, imported symbols and embedded strings are comments for you to enable. A guess is never applied on its own: the strings in a binary name files such as private keys.

A program that needs only its libraries runs from the generated file as it is. Most real programs also need a rule for their data or configuration, which you add.

What `detect` cannot see: libraries a program loads at run time with `dlopen` (plugins, modules). It says when a program can do that. See [docs/design/06-detection.md](docs/design/06-detection.md).

#### `isolate list`

List all registered instances.

```sh
isolate list
# Output:
# NAME                 PID      JAIL_ID  STATE      BINARY
# -------------------- -------- -------- ---------- ------------------------------
# myapp-abc123         12345    5        running    ./myapp
# server-def456        12346    6        orphaned   ./server
```

#### `isolate stop [options] <name>`

Stop a running instance.

```sh
# Graceful stop (SIGTERM)
doas isolate stop myapp-abc123

# Force: if the process ignores SIGTERM, remove the jail (kills everything in it)
doas isolate stop -f myapp-abc123

# Another signal and a longer wait, e.g. PostgreSQL's fast shutdown
doas isolate stop -s INT -t 30 myapp-abc123
```

Options:
- `-f, --force`: If the process is still running after the wait, remove the jail (which kills everything inside it) and clean up
- `-s, --signal <signal>`: Signal that asks the program to stop: `TERM` (default), `INT`, `QUIT`, `HUP`, `USR1`, `USR2`, `KILL`
- `-t, --timeout <seconds>`: How long to wait for the program to exit (default 5)

#### `isolate clean`

Clean up after instances whose `isolate run` process has died: remove their jails (and anything still running in them), instance directories and ephemeral users, and drop stale registry entries.

```sh
doas isolate clean
```

#### `isolate check`

Check system capabilities for isolation features.

```sh
isolate check
# Output:
# isolate System Check
# ====================
#
# FreeBSD 15.1
#
# Kernel Features:
#   [OK] FreeBSD jails        Supported
#   [OK] racct/rctl           Enabled - resource limits available
#   [OK] VNET/VIMAGE          Available - network isolation supported
#   [OK] nullfs               Supported
#   [OK] devfs                Supported
#
# Privileges:
#   [OK] Running as root      Full isolation available
#
# Network rules (pf):
#   [OK] pf                   Enabled, with isolate's anchor - network rules can be enforced
```

### Capability File Format

Capability files (`.caps`) define the isolation parameters. The full specification is in [docs/design/02-capability-file.md](docs/design/02-capability-file.md).

A file is either applied in full or refused: an unknown key, an invalid value, or a rule for a path that does not exist stops the run with the file name, line and reason.

```ini
# User context
user: auto                    # Create ephemeral user (recommended)
# user: nobody                # Use existing user

# Resource limits
memory: 256M                  # Resident memory limit (K, M, G suffixes); the
                              # process is killed when it exceeds it. Usage is
                              # sampled about once a second.
processes: 10                 # Maximum processes
files: 512                    # File descriptor limit

# Network isolation mode
network_mode: inherit         # Share host network (default)
# network_mode: none          # No network access
# network_mode: vnet:epair0b  # VNET with specified interface
network_ip: 10.0.99.2/24      # IP to configure on VNET interface

# Filesystem access (path:permissions)
filesystem: /lib:r            # Read-only access to /lib
filesystem: /usr/lib:r        # Read-only access to /usr/lib
filesystem: /tmp:rw           # Read-write access to /tmp
filesystem: /data:rw          # Application data directory
filesystem: /etc/resolv.conf:r # A single file
# A rule names a directory or a file that exists on the host. It is
# read-only (:r, the default) or read-write (:rw); nothing else.

# Network rules, for a VNET jail (see "Network Rules" below). With any
# rule present, everything not listed is blocked.
network: tcp:8080:inbound     # Accept connections on TCP port 8080
network: tcp:443:outbound     # Connect to TCP port 443
network: udp:53:outbound      # DNS queries

# System V shared memory, semaphores and message queues, private to the jail
# sysv_ipc: true              # off by default; PostgreSQL needs it

# Environment variables
env: PATH=/usr/bin:/bin
env: HOME=/workspace
env: LANG=C.UTF-8
```

### Workspace Isolation

The workspace feature enables multi-tenancy by mounting a host directory as `/workspace` inside the jail:

```sh
# Create tenant workspaces
mkdir -p /data/tenant1 /data/tenant2

# Run isolated instances with separate data
doas isolate run -w /data/tenant1 -N tenant1-app ./myapp
doas isolate run -w /data/tenant2 -N tenant2-app ./myapp
```

Applications should be configured to use `/workspace` for persistent data.

### VNET Network Isolation

VNET provides complete network stack isolation. Each jail gets its own network stack with separate interfaces, routing tables, and firewall rules.

**Setup:**
```sh
# Create epair interface pair (host side: epair0a, jail side: epair0b)
ifconfig epair create
ifconfig epair0a inet 10.0.99.1/24 up
```

**Capability file (myapp-vnet.caps):**
```ini
user: auto
memory: 128M
processes: 20
files: 1024

network_mode: vnet:epair0b
network_ip: 10.0.99.2/24

filesystem: /lib:r
filesystem: /usr/lib:r
filesystem: /libexec:r
```

isolate configures the address with the host's `ifconfig -j`, so the jail does not need `/sbin` mounted. The loopback interface is brought up automatically.

**Run with VNET:**
```sh
doas isolate run --caps myapp-vnet.caps -w /data/myapp ./myapp

# Access from host
curl http://10.0.99.2:8080/
```

**Multi-tenant with separate networks:**
```sh
# Create separate network for each tenant
ifconfig epair create  # epair0a/epair0b
ifconfig epair create  # epair1a/epair1b
ifconfig epair0a inet 10.0.99.1/24 up
ifconfig epair1a inet 10.0.100.1/24 up

# Run isolated tenants (each with own network)
doas isolate run --caps tenant1.caps -w /data/tenant1 ./myapp  # 10.0.99.2
doas isolate run --caps tenant2.caps -w /data/tenant2 ./myapp  # 10.0.100.2
```

Each jail can reach only the network its own interface is attached to. Tenants on different subnets cannot reach each other unless the host routes between them.

### Network Rules

A VNET jail can reach whatever its interface reaches. Network rules narrow that to the connections you list:

```ini
network_mode: vnet:epair0b
network_ip: 10.0.99.2/24

network: tcp:5432:inbound              # accept connections on 5432
network: tcp:10.0.0.5:443:outbound     # connect to one server
network: udp:53:outbound               # DNS
```

With one or more rules, everything else to and from the jail is dropped. The address in a rule is the other end; host names are not accepted, and rules are IPv4.

Rules are enforced with pf on the host end of the jail's epair, where all of the jail's traffic passes. That takes two things on the host, which isolate does not set up for you:

```sh
# /etc/pf.conf, before any rule that passes traffic
anchor "isolate/*"

sysrc pf_enable=YES
service pf start
```

`isolate check` shows whether pf is ready. A capability file with rules is refused, rather than run unfiltered, when pf is not enabled, when the anchor line is missing, or when the jail is not a VNET jail on an epair. Details are in [docs/design/05-network.md](docs/design/05-network.md).

### Running as a Service

isolate does not supervise programs or start them at boot. [`examples/rc.d/isolate`](examples/rc.d/isolate) is an `rc.d` script that does, by running `isolate run` under `daemon(8)`:

```sh
install -m 555 examples/rc.d/isolate /usr/local/etc/rc.d/isolate
sysrc isolate_enable=YES isolate_instances=myapp \
    isolate_myapp_caps=/usr/local/etc/isolate/myapp.caps \
    isolate_myapp_command="/usr/local/bin/myapp --serve"
service isolate start
```

The instance is started at boot, restarted when it exits, stopped at shutdown, and logged to `/var/log/isolate/myapp.log`. The [PostgreSQL guide](docs/postgresql-guide.md) uses it for a database in a VNET jail, including a reboot test.

## Examples

### Hello World

```sh
# Build the example
cd examples
cc -o hello hello.c

# Detect capabilities
../zig-out/bin/isolate detect ./hello

# Run in isolation
doas ../zig-out/bin/isolate run -v ./hello
```

### TCP Server

```sh
# Build the server example
cd examples
cc -o server server.c

# Detect capabilities (will find network usage)
../zig-out/bin/isolate detect ./server

# Run isolated server
doas ../zig-out/bin/isolate run -v ./server

# Test from another terminal
nc localhost 8080
```

### Multi-tenant Application

```sh
# Create workspace directories
mkdir -p /var/isolate/tenant-{a,b,c}

# Run separate instances
doas isolate run -w /var/isolate/tenant-a -N app-tenant-a ./myapp
doas isolate run -w /var/isolate/tenant-b -N app-tenant-b ./myapp
doas isolate run -w /var/isolate/tenant-c -N app-tenant-c ./myapp

# List all instances
isolate list

# Stop specific tenant
doas isolate stop app-tenant-b
```

## Architecture

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) describes how the code is built.
- [docs/design/](docs/design/README.md) specifies what isolate guarantees: scope, invariants, success and failure criteria, and known gaps.
- [docs/nginx-guide.md](docs/nginx-guide.md) and [docs/postgresql-guide.md](docs/postgresql-guide.md) are worked examples, both run as written on FreeBSD 15.1.

### Module Overview

| Module | Purpose |
|--------|---------|
| `main.zig` | CLI parsing and command dispatch |
| `caps.zig` | Capability file parsing and validation |
| `detect.zig` | ELF reading and capability-file generation |
| `libs.zig` | Shared-library closure of a binary |
| `netrules.zig` | Network rules as pf rules |
| `freebsd.zig` | FreeBSD jail implementation |
| `syscheck.zig` | System capability detection (racct, VNET) |
| `registry.zig` | Instance tracking and persistence |
| `c_api.zig` | C library bindings |

## Testing

```sh
# Run all tests
zig build test

# Run one module's tests (modules without C imports only)
zig test src/caps.zig

# Build and test examples
zig build examples
./zig-out/bin/isolate detect ./zig-out/examples/hello
doas ./zig-out/bin/isolate run ./zig-out/examples/hello
```

The unit tests cover parsing and validation and create no jails. The end-to-end scenarios do, so they need FreeBSD and root:

```sh
zig build && doas sh tests/scenarios.sh
```

They create real jails, users, mounts, limits and a network interface, check about 115 behaviours against the [design documents](docs/design/README.md), and verify at the end that nothing was left behind.

## Troubleshooting

### "Isolation requires root privileges"

Jail creation requires root. Use `doas` or `sudo`:
```sh
doas isolate run ./myapp
```

### "Resource limits requested but racct is not enabled"

A capability file with limits is refused on a kernel without them. Resource limits require `rctl` to be enabled in the kernel:
```sh
# Check if rctl is available
sysctl kern.racct.enable

# Enable in /boot/loader.conf if needed
echo 'kern.racct.enable=1' >> /boot/loader.conf
# Reboot required
```

### "No capability file at ..." / "ELF interpreter /libexec/ld-elf.so.1 not found"

Without a capability file nothing is mounted in the jail, so a dynamically linked program cannot start. Generate a capability file first:
```sh
isolate detect ./myapp
# Then run
doas isolate run ./myapp
```

### Instance shows as "orphaned"

The program is gone but its `isolate run` process did not clean up (it was killed, or the host crashed). Clean up with:
```sh
doas isolate clean
```

### "VNET requested but VIMAGE is not available"

A capability file asking for `network_mode: vnet` is refused on a kernel without it; isolate does not fall back to the host's network. VNET requires VIMAGE support in the kernel:
```sh
# Check if VNET is available
sysctl -n kern.features.vimage

# If not available, rebuild kernel with VIMAGE option
# or use a kernel that includes VIMAGE support
```

### Cannot bind to port 80

Ports below 1024 require root privileges. Either:
- Use a high port (8080, etc.)
- Add `allow.reserved_ports` to jail parameters (requires code modification)

## Platform Support

| Platform | Status |
|----------|--------|
| FreeBSD 15.1 | Tested |
| FreeBSD 13 and 14 | Untested |
| Linux, macOS, Windows | Not supported and not planned. isolate builds on Linux, where `detect` and the unit tests work, but it cannot run anything in isolation there. |

## Contributing

Contributions are welcome! Please read the architecture and design documents before submitting changes. A change that affects an invariant should update the design document that states it.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `zig build test`
5. Submit a pull request

## Security Considerations

- **Review capability files**: `detect` gets the libraries right and guesses at the rest; the guesses are comments until you enable them
- **The default network is the host's**: without `network_mode: none` or `vnet`, the program can connect wherever the host can. Network rules need a VNET jail
- **Check a file before relying on it**: `isolate run -n -v <binary>` prints the settings a run would use
- **Known gaps**: each [design document](docs/design/README.md) ends with what is not covered
- **Ephemeral users**: Use `user: auto` for privilege separation
- **Minimal permissions**: Only grant necessary filesystem and network access
- **Resource limits**: Set appropriate limits to prevent resource exhaustion
- **Workspace isolation**: Use separate workspaces for multi-tenant deployments

## License

BSD 2-Clause License

Copyright (c) 2025-2026, Este Systems

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Acknowledgments

- FreeBSD jail(2) and rctl(8) documentation
- Zig programming language and standard library
