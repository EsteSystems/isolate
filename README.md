# isolate

Infrastructureless container runner using native OS primitives.

isolate provides process isolation without requiring container runtimes, orchestration platforms, or image registries. It uses the operating system's native isolation mechanisms (FreeBSD jails, with Linux namespaces planned) to sandbox applications with minimal overhead.

## Philosophy

**Infrastructure should be invisible.** Applications need isolation, not infrastructure.

Traditional containerization requires learning Docker, Kubernetes, registries, orchestrators, and complex networking. isolate takes a different approach: analyze your binary, generate a capability file, and run it isolated. No images, no daemons, no clusters.

## Features

- **Native OS Isolation**: Uses FreeBSD jails (Linux namespaces planned)
- **VNET Network Isolation**: Isolated network stacks with user-provided interfaces
- **Capability Detection**: Automatically analyzes binaries to determine required permissions
- **Ephemeral Users**: Creates temporary users per instance for privilege separation
- **Resource Limits**: Memory, process, and file descriptor limits via rctl
- **Workspace Mounting**: Mount host directories for persistent application data
- **Instance Management**: Track, list, stop, and clean up running instances
- **System Capability Check**: Verify kernel features before deployment
- **Zero Dependencies**: Single static binary, no runtime dependencies

## Quick Start

```sh
# Build isolate
zig build

# Detect capabilities for your application
./zig-out/bin/isolate detect ./myapp

# Review and edit the generated capability file
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

- Zig 0.13.0 or later
- FreeBSD 13.0 or later (for jail support)
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
- `-N, --name <name>`: Instance name (default: auto-generated)
- `--vnet <interface>`: Use VNET isolation with specified interface
- `-v, --verbose`: Verbose output
- `-n, --dry-run`: Show configuration without executing

#### `isolate detect [options] <binary> [output.caps]`

Analyze a binary and generate a capability file.

```sh
# Generate <binary>.caps
isolate detect ./myapp

# Specify output file
isolate detect -o custom.caps ./myapp
isolate detect ./myapp ./myapp.caps
```

Options:
- `-o, --output <file>`: Output capability file

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

# Force stop (SIGKILL if needed)
doas isolate stop -f myapp-abc123
```

Options:
- `-f, --force`: Send SIGKILL if SIGTERM doesn't work

#### `isolate clean`

Clean up orphaned instances and jail directories.

```sh
doas isolate clean
```

#### `isolate check`

Check system capabilities for isolation features.

```sh
isolate check
# Output:
# System Capabilities Check
# ========================
# racct/rctl (resource limits): available
# VNET/VIMAGE (network isolation): available
# Jails: available
# Running as root: yes
# FreeBSD version: 1500001
```

### Capability File Format

Capability files (`.caps`) define the isolation parameters:

```ini
# User context
user: auto                    # Create ephemeral user (recommended)
# user: nobody                # Use existing user

# Resource limits
memory: 256M                  # Memory limit (K, M, G suffixes)
processes: 10                 # Maximum processes
files: 512                    # File descriptor limit (minimum 512 for fork)

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

# Network access rules (firewall-style, separate from isolation mode)
network: tcp:8080:inbound     # Listen on TCP port 8080
network: tcp:443:outbound     # Connect to TCP port 443
network: udp:53:outbound      # DNS queries

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

Tenants on different subnets cannot communicate with each other.

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

# Edit server.caps to allow inbound connections
echo "network: tcp:8080:inbound" >> ./server.caps

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

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design documentation.

### Module Overview

| Module | Purpose |
|--------|---------|
| `main.zig` | CLI parsing and command dispatch |
| `caps.zig` | Capability file parsing and validation |
| `detect.zig` | ELF binary analysis for capability detection |
| `freebsd.zig` | FreeBSD jail implementation |
| `syscheck.zig` | System capability detection (racct, VNET) |
| `registry.zig` | Instance tracking and persistence |
| `c_api.zig` | C library bindings |

## Testing

```sh
# Run all tests
zig build test

# Run specific test file
zig test src/caps.zig

# Build and test examples
zig build examples
doas ./zig-out/bin/isolate run ./zig-out/examples/hello
```

## Troubleshooting

### "Isolation requires root privileges"

Jail creation requires root. Use `doas` or `sudo`:
```sh
doas isolate run ./myapp
```

### "Failed to set memory limit"

Resource limits require `rctl` to be enabled in the kernel:
```sh
# Check if rctl is available
sysctl kern.racct.enable

# Enable in /boot/loader.conf if needed
echo 'kern.racct.enable=1' >> /boot/loader.conf
# Reboot required
```

### "Could not load capabilities"

Generate a capability file first:
```sh
isolate detect ./myapp
# Then run
doas isolate run ./myapp
```

### Instance shows as "orphaned"

The process exited but cleanup didn't complete. Clean up with:
```sh
doas isolate clean
```

### VNET not available

VNET requires VIMAGE support in the kernel:
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

| Platform | Status | Implementation |
|----------|--------|----------------|
| FreeBSD 13+ | ✅ Supported | Jails, rctl, nullfs |
| FreeBSD 14+ | ✅ Supported | Jails, rctl, nullfs, VNET |
| FreeBSD 15+ | ✅ Tested | Jails, rctl, nullfs, VNET |
| Linux | 🚧 Planned | Namespaces, cgroups, seccomp |
| macOS | ❌ Not planned | No native isolation primitives |
| Windows | ❌ Not planned | No native isolation primitives |

## Contributing

Contributions are welcome! Please read the architecture documentation before submitting changes.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `zig build test`
5. Submit a pull request

## Security Considerations

- **Review capability files**: Auto-detection is heuristic; always review generated `.caps` files
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
