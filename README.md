# isolate - Infrastructureless Container System

A lightweight alternative to containers using native FreeBSD jails for process isolation without requiring container runtimes, orchestration, or registries.

## Features

- **Process isolation** via FreeBSD jails
- **User isolation** with ephemeral user creation
- **Filesystem isolation** with minimal jail environments
- **Resource limits** enforced through rctl (memory, processes, files)
- **Network functionality** preserved within isolation
- **Zero infrastructure** requirements (no daemons or orchestration)
- **Capability-based configuration** via .caps files
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

- FreeBSD system with jail support
- clang compiler
- Root privileges (for jail creation and user management)
- rctl enabled in kernel (optional, for resource limits)

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
