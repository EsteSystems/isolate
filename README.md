# isolate - Infrastructureless Container System

A lightweight, cross-platform alternative to containers using native OS isolation primitives. Currently implemented for FreeBSD jails with planned support for Linux namespaces/cgroups and other platforms. Provides process isolation without requiring container runtimes, orchestration, or registries.

## Features

- **Cross-platform design** - Native OS isolation on each platform
- **Process isolation** via FreeBSD jails (Linux namespaces planned)
- **User isolation** with ephemeral user creation
- **Filesystem isolation** with minimal container-like environments
- **Resource limits** enforced through platform-native mechanisms (rctl, cgroups)
- **Network functionality** preserved within isolation boundaries
- **Zero infrastructure** requirements (no daemons or orchestration)
- **Capability-based configuration** via portable .caps files
- **Automatic capability detection** for existing binaries
- **Automatic cleanup** on process exit

## Quick Start

```sh
# Build the project
make

# Generate capability file for any binary
bin/isolate -d examples/hello

# Run with auto-detected capabilities
doas bin/isolate examples/hello

# Run an isolated TCP server
doas bin/isolate examples/server
```

## Capability Detection

The isolate system can automatically analyze binaries and generate appropriate capability files:

```sh
# Analyze a binary and generate .caps file
bin/isolate -d /path/to/binary

# Generate with custom output file
bin/isolate -d /path/to/binary -o custom.caps

# Review and edit the generated file
cat binary.caps

# Run with detected capabilities
doas bin/isolate /path/to/binary
```

The detection system analyzes:
- Library dependencies for system requirements
- Dynamic symbols for network and file operations
- Embedded strings for configuration paths and URLs
- Application patterns for common service types

## Project Structure

```
isolate/
├── src/           # Source code
├── obj/           # Build artifacts (created during build)
├── bin/           # Compiled binaries (created during build)  
├── examples/      # Example programs and capability files
├── Makefile       # FreeBSD-style build system
└── README.md      # This file
```

## Requirements

### Current Platform (FreeBSD)
- FreeBSD system with jail support
- clang compiler
- Root privileges (for jail creation and user management)
- rctl enabled in kernel (optional, for resource limits)

### Planned Platforms
- **Linux** - namespaces, cgroups, seccomp-bpf
- **Other UNIX systems** - platform-specific isolation primitives

## Build Targets

- `make` or `make all` - Build isolate and examples
- `make clean` - Remove build artifacts
- `make install` - Install to system (default: /usr/local)
- `make test` - Run basic functionality test
- `make test-detect` - Test capability detection
- `make debug` - Build with debug symbols
- `make release` - Build optimized release version
- `make help` - Show all available targets

## Usage

### Detection Mode
```sh
# Analyze a binary
bin/isolate -d myapp

# Run with generated capabilities
doas bin/isolate myapp
```

### Execution Mode
```sh
# Run with specific capability file
doas bin/isolate -c custom.caps myapp

# Verbose output
doas bin/isolate -v myapp

# Dry run (test without execution)
bin/isolate -n myapp
```

## Capability Files

Programs are configured via `.caps` files that specify:

- User context (auto-generated ephemeral users)
- Resource limits (memory, processes, files)
- Network access rules
- Filesystem access permissions
- Environment variables

Example capability file:
```
# User context
user: auto

# Resource limits
memory: 128M
processes: 5
files: 256

# Network access
network: tcp:8080:inbound

# Filesystem access
filesystem: /tmp:rw
filesystem: /etc/resolv.conf:r
```

See `examples/*.caps` for more examples.

## Security

This system provides container-level isolation using native OS primitives:

- Applications run in FreeBSD jails with isolated filesystems
- Ephemeral users prevent privilege escalation
- Resource limits prevent resource exhaustion
- Minimal jail environments reduce attack surface
- No shell or system utilities available within isolation

## Why isolate Instead of Direct Jails or Orchestration?

### Compared to Direct FreeBSD Jails

**Manual jail management is complex and error-prone:**
- Creating jail filesystems requires understanding nullfs, devfs, and mount points
- User management across jail boundaries is manual and fragile
- Resource limits via rctl require understanding complex rule syntax
- No automatic cleanup leads to resource leaks and orphaned jails
- Path resolution between host and jail contexts is confusing
- Security hardening requires deep FreeBSD expertise

**isolate provides a clean abstraction:**
- Automatic jail filesystem creation with minimal required mounts
- Ephemeral user lifecycle tied to application lifetime
- Simple capability-based resource limit specification
- Guaranteed cleanup on process exit or crash
- Path abstraction eliminates host/jail confusion
- Security-by-default configuration

### Compared to Container Orchestration (Docker, Podman, etc.)

**Container platforms add unnecessary complexity:**
- Require daemon processes consuming system resources
- Introduce image registries and complex networking overlays
- Add multiple abstraction layers reducing performance
- Require learning container-specific tooling and concepts
- Create vendor lock-in through platform-specific APIs
- Complicate debugging with additional virtualization layers

**isolate eliminates infrastructure overhead:**
- Zero daemon processes - direct process execution
- No image management or registry dependencies  
- Single binary with no external dependencies
- Native OS performance without virtualization penalty
- Standard POSIX process model for familiar debugging
- Portable capability files work across platforms and environments

### Compared to 3rd Party Jail Orchestrators

**Existing jail orchestrators solve the wrong problems:**
- Focus on multi-host orchestration when single-host isolation suffices
- Require complex configuration management systems
- Introduce additional failure points and operational complexity
- Assume infrastructure teams rather than application developers
- Provide container-like abstractions over native FreeBSD primitives

**isolate focuses on developer productivity:**
- Designed for application developers, not infrastructure teams
- Capability detection eliminates manual configuration
- Single command workflow from analysis to execution
- Gradual adoption path - use on individual applications
- Leverages native OS security primitives without abstraction overhead
- Portable .caps files work across supported platforms

### The Core Philosophy

**Infrastructure should be invisible.** Applications need isolation, not infrastructure. By using native OS primitives directly and providing developer-friendly tooling, isolate delivers container-level security with UNIX-level simplicity.

Most isolation needs don't require the complexity of container orchestration or manual jail management. They need a simple command that says "run this application safely" - which is exactly what isolate provides.

## Workflow

1. **Detect** - Analyze existing binaries for capability requirements
2. **Review** - Edit generated .caps files as needed
3. **Execute** - Run applications with appropriate isolation
4. **Monitor** - Observe resource usage and security boundaries

## License

BSD 3-Clause License

Copyright (c) 2025, daniel@este.systems, Este Systems FZE LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

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

## Author

**daniel@este.systems**  
Este Systems FZE LLC
