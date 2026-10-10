# Architecture

This document describes the architecture of isolate, a process isolation tool using native OS primitives.

## Overview

isolate provides container-like isolation without container infrastructure. Instead of images, layers, and runtimes, it uses the operating system's native isolation mechanisms directly.

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Interface                          │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │   run   │ │ detect  │ │  list   │ │  stop   │ │  clean  │   │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘   │
└───────┼──────────┼──────────┼──────────┼──────────┼─────────────┘
        │          │          │          │          │
┌───────┼──────────┼──────────┼──────────┼──────────┼─────────────┐
│       │          │          └──────────┴──────────┘             │
│       │          │                     │                        │
│  ┌────▼────┐ ┌───▼────┐         ┌─────▼─────┐                  │
│  │  caps   │ │ detect │         │ registry  │                  │
│  │ parser  │ │ (ELF)  │         │ (JSON)    │                  │
│  └────┬────┘ └────────┘         └───────────┘                  │
│       │                                                         │
│  ┌────▼────────────────────────────────────────┐               │
│  │              Platform Abstraction            │               │
│  └────┬────────────────────────────────────────┘               │
│       │                                                         │
│  ┌────▼────────────────────────────────────────┐               │
│  │              FreeBSD / Linux                 │               │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐    │               │
│  │  │  Jails   │ │  Users   │ │  rctl    │    │               │
│  │  └──────────┘ └──────────┘ └──────────┘    │               │
│  └─────────────────────────────────────────────┘               │
│                        Core Modules                             │
└─────────────────────────────────────────────────────────────────┘
```

## Module Structure

### Source Files

```
src/
├── main.zig        Entry point, CLI parsing, command dispatch
├── caps.zig        Capability file parser and data structures
├── detect.zig      ELF binary analysis for capability detection
├── freebsd.zig     FreeBSD jail implementation
├── registry.zig    Instance tracking and persistence
├── syscheck.zig    Kernel feature detection (racct, VNET)
└── c_api.zig       C library bindings for system calls
```

### Module Dependencies

```
main.zig
├── caps.zig
├── detect.zig
├── registry.zig
├── freebsd.zig (conditional: FreeBSD only)
├── syscheck.zig (conditional: FreeBSD only)
└── c_api.zig

freebsd.zig
├── caps.zig
└── syscheck.zig

detect.zig
└── (standalone, uses std only)

registry.zig
└── (standalone, uses std and libjail)

caps.zig
└── (standalone, uses std only)
```

## Data Structures

### Capabilities (`caps.zig`)

The `Capabilities` structure defines the complete isolation specification:

```zig
pub const Capabilities = struct {
    allocator: Allocator,

    // User context
    username: ?[]const u8,        // Specific user or null for auto
    auto_user: bool,              // Create ephemeral user

    // Resource limits
    memory_limit: u64,            // Bytes (0 = unlimited)
    process_limit: u32,           // Max processes
    file_limit: u32,              // Max file descriptors

    // Access rules
    network_rules: ArrayList(NetworkRule),
    file_rules: ArrayList(FileRule),
    env_vars: ArrayList(EnvVar),

    // Workspace
    workspace_path: ?[]const u8,  // Host path for /workspace mount
};

pub const NetworkRule = struct {
    protocol: Protocol,           // tcp, udp, unix
    port: u16,
    direction: Direction,         // inbound, outbound
};

pub const FileRule = struct {
    path: []const u8,
    permissions: Permissions,     // read, write, execute
};
```

### Instance Registry (`registry.zig`)

The registry tracks running instances for management:

```zig
pub const Instance = struct {
    name: []const u8,             // Unique instance identifier
    pid: i32,                     // Process ID
    jail_id: i32,                 // FreeBSD jail ID
    jail_path: []const u8,        // Jail filesystem root
    username: []const u8,         // Ephemeral user (if created)
    binary_path: []const u8,      // Original binary path
    start_time: i64,              // Unix timestamp
    workspace_path: ?[]const u8,  // Mounted workspace (if any)
};

pub const InstanceState = enum {
    running,                      // Process and jail active
    stopped,                      // Clean shutdown
    orphaned,                     // Process gone, cleanup needed
};
```

### Detection Results (`detect.zig`)

Binary analysis produces capability hints:

```zig
pub const CapabilityHint = struct {
    capability_type: CapabilityType,
    value: []const u8,
    confidence: u8,               // 0-100
    source: []const u8,           // What triggered this hint
};

pub const CapabilityType = enum {
    filesystem,
    network,
    memory,
    process,
    environment,
};
```

## Execution Flow

### Run Command

```
1. Parse CLI arguments
2. Load capability file (or use defaults)
3. Validate workspace directory (if specified)
4. Check root privileges
5. Fork process
   │
   ├─ Child Process:
   │   1. Create jail filesystem
   │   2. Create ephemeral user (if auto)
   │   3. Mount required directories (nullfs)
   │   4. Create jail via jail_set()
   │   5. Set resource limits (rctl)
   │   6. Attach to jail
   │   7. Switch to ephemeral user
   │   8. Send jail info to parent (via pipe)
   │   9. execv() target binary
   │
   └─ Parent Process:
       1. Receive jail info from child
       2. Register instance in registry
       3. Wait for child (waitpid)
       4. Cleanup:
          - Remove jail (jail_remove)
          - Unmount filesystems
          - Remove jail directory
          - Delete ephemeral user
       5. Unregister instance
       6. Return exit code
```

### Detect Command

```
1. Parse CLI arguments
2. Open and parse ELF binary
3. Analysis phases:
   │
   ├─ Library Dependencies:
   │   - Parse PT_DYNAMIC segment
   │   - Extract DT_NEEDED entries
   │   - Map libraries to capabilities
   │
   ├─ Symbol Analysis:
   │   - Parse .dynsym section
   │   - Find network/file symbols
   │   - Infer required access
   │
   ├─ String Analysis:
   │   - Scan .rodata section
   │   - Find paths, URLs, ports
   │   - Extract configuration hints
   │
   └─ Pattern Recognition:
       - Match known application signatures
       - Apply application-specific rules

4. Merge hints with confidence scoring
5. Generate capability file
```

## FreeBSD Implementation

### Jail Lifecycle

```
Creation:
┌─────────────────────────────────────────────────────────────┐
│ 1. Generate unique jail name (isolate-<pid>)                │
│ 2. Create jail root: /tmp/isolate-<name>/                   │
│ 3. Create directory structure:                              │
│    /tmp/isolate-<name>/                                     │
│    ├── bin/           (empty or minimal)                    │
│    ├── lib/           (nullfs mount)                        │
│    ├── libexec/       (nullfs mount)                        │
│    ├── usr/lib/       (nullfs mount)                        │
│    ├── dev/           (devfs mount)                         │
│    ├── etc/           (passwd, group files)                 │
│    ├── tmp/           (writable)                            │
│    └── workspace/     (nullfs mount if specified)           │
│ 4. Create passwd/group with ephemeral user                  │
│ 5. Call jail_set() with parameters                          │
│ 6. Apply rctl rules for resource limits                     │
└─────────────────────────────────────────────────────────────┘

Attachment:
┌─────────────────────────────────────────────────────────────┐
│ 1. jail_attach(jid) - Enter jail context                    │
│ 2. setgid(gid) - Set group                                  │
│ 3. setuid(uid) - Drop to ephemeral user                     │
│ 4. chdir("/") - Move to jail root                           │
└─────────────────────────────────────────────────────────────┘

Cleanup:
┌─────────────────────────────────────────────────────────────┐
│ 1. jail_remove(jid) - Terminate jail and all processes      │
│ 2. Unmount all nullfs/devfs mounts                          │
│ 3. rmrf(jail_root) - Remove jail filesystem                 │
│ 4. pw userdel <user> - Remove ephemeral user                │
└─────────────────────────────────────────────────────────────┘
```

### System Calls Used

| Operation | System Call | Purpose |
|-----------|-------------|---------|
| Jail creation | `jail_set()` | Create and configure jail |
| Jail attachment | `jail_attach()` | Enter jail context |
| Jail removal | `jail_remove()` | Destroy jail |
| Filesystem mounting | `nmount()` | Mount nullfs/devfs |
| User creation | `fork()`+`execv("pw")` | Create ephemeral user |
| Resource limits | `fork()`+`execv("rctl")` | Apply rctl rules |
| Process execution | `execv()` | Replace process image |
| Privilege drop | `setuid()`/`setgid()` | Switch to unprivileged user |

### Jail Parameters

```c
// Parameters passed to jail_set()
struct jailparam params[] = {
    { "name",           jail_name },
    { "path",           jail_root },
    { "host.hostname",  jail_name },
    { "persist",        NULL },      // Keep jail after process exits
    { "allow.raw_sockets", NULL },   // If network access needed
    { "ip4.addr",       "inherit" }, // Inherit host networking
};
```

### Resource Limits (rctl)

```sh
# Applied via rctl command
rctl -a jail:<name>:memoryuse:deny=<bytes>
rctl -a jail:<name>:maxproc:deny=<count>
rctl -a jail:<name>:openfiles:deny=<count>
```

## Registry System

### Storage Format

Instance data is stored as JSON files in the registry directory:

```
/var/run/isolate/           (primary, requires root)
/tmp/isolate-registry/      (fallback)
├── myapp-abc123.json
├── server-def456.json
└── ...
```

Each file contains:

```json
{
  "name": "myapp-abc123",
  "pid": 12345,
  "jail_id": 5,
  "jail_path": "/tmp/isolate-isolate-12345",
  "username": "app-12345",
  "binary_path": "/usr/local/bin/myapp",
  "start_time": 1699900000,
  "workspace_path": "/data/tenant1"
}
```

### State Detection

Instance state is determined by checking process and jail existence:

```
┌─────────────────────────────────────────┐
│           Check Instance State          │
└─────────────────┬───────────────────────┘
                  │
                  ▼
        ┌─────────────────┐
        │ kill(pid, 0)    │
        │ Process exists? │
        └────────┬────────┘
                 │
         ┌───────┴───────┐
         │               │
         ▼               ▼
       Yes              No
         │               │
         ▼               ▼
    ┌─────────┐    ┌──────────┐
    │ RUNNING │    │ ORPHANED │
    └─────────┘    └──────────┘
```

## Capability Detection

### ELF Analysis

The detector performs native ELF parsing without external tools:

```
┌─────────────────────────────────────────────────────────────┐
│                    ELF File Structure                        │
├─────────────────────────────────────────────────────────────┤
│  ELF Header                                                  │
│  ├── e_phoff → Program Headers                              │
│  └── e_shoff → Section Headers                              │
│                                                              │
│  Program Headers (for dynamic linking info)                  │
│  └── PT_DYNAMIC → Dynamic segment                           │
│      ├── DT_NEEDED → Required libraries                     │
│      ├── DT_STRTAB → String table                           │
│      └── DT_SYMTAB → Symbol table                           │
│                                                              │
│  Section Headers (for detailed analysis)                     │
│  ├── .dynsym → Dynamic symbols                              │
│  ├── .dynstr → Dynamic string table                         │
│  ├── .rodata → Read-only data (strings)                     │
│  └── .data   → Initialized data                             │
└─────────────────────────────────────────────────────────────┘
```

### Detection Heuristics

| Signal | Interpretation | Confidence |
|--------|----------------|------------|
| Links `libc.so` | Standard C library needed | 95% |
| Links `libssl.so` | TLS/network access | 85% |
| Links `libpq.so` | PostgreSQL access | 90% |
| Symbol `socket` | Network operations | 80% |
| Symbol `open` | File operations | 70% |
| String `/etc/` | Config file access | 60% |
| String `:8080` | Port binding | 75% |
| String `http://` | Outbound HTTP | 70% |

### Confidence Merging

When multiple signals indicate the same capability, confidence is combined:

```
combined = 100 - ((100 - conf1) * (100 - conf2) / 100)

Example:
- Signal A: 70% confidence for network access
- Signal B: 60% confidence for network access
- Combined: 100 - (30 * 40 / 100) = 88% confidence
```

## Security Model

### Threat Model

isolate protects against:

1. **Filesystem escape**: Jail root is isolated, only explicit mounts accessible
2. **Privilege escalation**: Ephemeral unprivileged users, no setuid binaries
3. **Resource exhaustion**: rctl limits on memory, processes, file descriptors
4. **Network abuse**: Explicit network rules required for access
5. **Cross-tenant access**: Separate jails, users, and workspaces per instance

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                     Host System (Trusted)                    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    isolate (root)                    │    │
│  │  - Creates/destroys jails                           │    │
│  │  - Manages ephemeral users                          │    │
│  │  - Sets resource limits                             │    │
│  └─────────────────────────────────────────────────────┘    │
│                           │                                  │
│                    Trust Boundary                            │
│                           │                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                  Jail (Untrusted)                    │    │
│  │  - Limited filesystem view                          │    │
│  │  - Unprivileged user                                │    │
│  │  - Resource-constrained                             │    │
│  │  - No raw network access (unless granted)           │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Capability Principle

Applications run with minimum required privileges:

1. **Explicit grants**: Only capabilities in `.caps` file are available
2. **Default deny**: No network, limited filesystem by default
3. **Ephemeral identity**: New user per instance, deleted on exit
4. **Resource bounds**: Hard limits prevent exhaustion attacks

## Platform Abstraction

### Interface Design

```zig
// Planned: a platform.zig module defining the abstraction
pub const Platform = enum {
    freebsd,
    linux,      // Planned
    unknown,
};

pub fn detect() Platform {
    return switch (builtin.os.tag) {
        .freebsd => .freebsd,
        .linux => .linux,
        else => .unknown,
    };
}

// Each platform implements:
// - createIsolation(caps, binary) - Set up isolation context
// - cleanupIsolation() - Tear down and cleanup
// - Jail/namespace management
// - User management
// - Filesystem isolation
// - Resource limits
```

### Linux Implementation (Planned)

```
FreeBSD              Linux
────────             ─────
jail_set()      →    clone(CLONE_NEW*)
jail_attach()   →    setns()
jail_remove()   →    Process termination
rctl            →    cgroups v2
nullfs          →    bind mounts
                →    seccomp-bpf (syscall filtering)
```

## Error Handling

### Error Categories

```zig
pub const IsolationError = error{
    // Jail operations
    JailCreateFailed,
    JailAttachFailed,
    JailRemoveFailed,

    // Filesystem operations
    MountFailed,
    UnmountFailed,
    DirectoryCreateFailed,

    // User operations
    UserCreateFailed,
    UserDeleteFailed,
    PrivilegeDropFailed,

    // Resource limits
    RctlFailed,

    // General
    OutOfMemory,
    PermissionDenied,
};
```

### Cleanup Guarantees

Cleanup is performed in reverse order of setup, with best-effort continuation:

```zig
pub fn cleanupIsolation() void {
    // Each step continues even if previous fails

    // 1. Remove jail (kills all processes)
    if (jail_state.jail_id > 0) {
        jail_remove(jail_state.jail_id);
    }

    // 2. Unmount filesystems
    unmountAll(jail_state.jail_root_path);

    // 3. Remove jail directory
    rmrf(jail_state.jail_root_path);

    // 4. Delete ephemeral user
    if (jail_state.ephemeral_username[0] != 0) {
        deleteUser(jail_state.ephemeral_username);
    }
}
```

## Performance Considerations

### Startup Overhead

| Operation | Typical Time |
|-----------|--------------|
| Capability parsing | < 1ms |
| User creation | ~50ms |
| Directory setup | ~10ms |
| Mounts (per mount) | ~5ms |
| Jail creation | ~10ms |
| Total overhead | ~100-200ms |

### Memory Overhead

- isolate binary: ~2MB
- Per-instance overhead: ~1MB (jail metadata, registry entry)
- Jail filesystem: Minimal (nullfs mounts share pages with host)

### Comparison with Containers

| Metric | isolate | Docker |
|--------|---------|--------|
| Startup time | ~200ms | ~500ms-2s |
| Memory overhead | ~1MB | ~50-100MB |
| Disk overhead | ~0 (nullfs) | Image layers |
| Dependencies | None | dockerd, containerd |

## Future Directions

### Planned Features

1. **Linux Support**: Namespaces, cgroups v2, seccomp-bpf
2. **Network Policies**: More granular network rules, DNS filtering
3. **Capability Profiles**: Pre-defined profiles for common applications
4. **Remote Management**: API for orchestration integration
5. **Metrics Export**: Prometheus-compatible metrics endpoint

### Extension Points

- Custom mount types (beyond nullfs/devfs)
- Plugin system for capability detection
- Alternative registry backends (etcd, consul)
- Audit logging integration
