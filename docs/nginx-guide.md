# isolate - Process Isolation for FreeBSD

**isolate** is an infrastructureless container runner that provides process isolation using native FreeBSD primitives. This guide demonstrates isolating nginx as a practical use case.

## Table of Contents

- [What is isolate?](#what-is-isolate)
- [Comparison: Traditional Jails vs isolate](#comparison-traditional-jails-vs-isolate)
- [How It Works](#how-it-works)
- [Isolation Layers](#isolation-layers)
- [Nginx Use Case](#nginx-use-case)
- [Step-by-Step Guide](#step-by-step-guide)
- [Deep Dive: How nginx Gets Isolated](#deep-dive-how-nginx-gets-isolated)
- [Instance Management](#instance-management)
- [Comparison: isolate vs Docker](#comparison-isolate-vs-docker)

---

## What is isolate?

Traditional containerization requires learning Docker, Kubernetes, registries, orchestrators, and complex networking. **isolate** takes a different approach:

- **No container images** - Run binaries directly from the host
- **No daemons** - Single binary, no background services
- **No orchestration** - Simple command-line interface
- **Native OS primitives** - Uses FreeBSD jails, not emulation

### Traditional Containers

```
Application → Container Runtime → Image Registry → Orchestrator
                      ↓
          Complex infrastructure required
```

### isolate

```
Application → isolate → FreeBSD Jail
                 ↓
       Zero infrastructure overhead
```

---

## Comparison: Traditional Jails vs isolate

FreeBSD has excellent jail support, and several tools have emerged to manage them. However, these tools were designed for a different use case: running full operating system instances. **isolate** takes a fundamentally different approach optimized for application isolation.

### Traditional Jail Management Tools

#### Manual jail(8) Configuration

The traditional approach requires significant manual setup:

```sh
# 1. Create jail root filesystem (extract base.txz or use bsdinstall)
mkdir -p /jails/nginx
tar -xf /path/to/base.txz -C /jails/nginx

# 2. Configure /etc/jail.conf
cat >> /etc/jail.conf << 'EOF'
nginx {
    host.hostname = "nginx-jail";
    path = "/jails/nginx";
    mount.devfs;
    ip4.addr = 192.168.1.100;
    exec.start = "/bin/sh /etc/rc";
    exec.stop = "/bin/sh /etc/rc.shutdown";
}
EOF

# 3. Start the jail
service jail start nginx

# 4. Enter jail and install software
jexec nginx pkg install nginx

# 5. Configure networking, users, services inside jail...
```

**Problems:**
- Requires full base system extraction (~300MB+ per jail)
- Manual network configuration
- Services managed separately inside each jail
- No automatic cleanup
- Complex lifecycle management

#### ezjail

ezjail simplifies jail creation with basejails and flavours:

```sh
# Initial setup
ezjail-admin install

# Create jail
ezjail-admin create nginx 192.168.1.100

# Start jail
ezjail-admin start nginx

# Install software
ezjail-admin console nginx
pkg install nginx
```

**Improvements over manual:**
- Shared basejail reduces disk usage
- Simpler creation commands
- Flavour system for templating

**Still requires:**
- Base system installation (~150MB shared + per-jail overhead)
- Manual IP address management
- Service configuration inside jail
- Persistent jail infrastructure

#### iocage

iocage uses ZFS for jail management:

```sh
# Fetch release
iocage fetch -r 14.0-RELEASE

# Create jail
iocage create -n nginx -r 14.0-RELEASE ip4_addr="em0|192.168.1.100/24"

# Start jail
iocage start nginx

# Enter and configure
iocage console nginx
pkg install nginx
```

**Features:**
- ZFS snapshots and clones
- Resource limits via RCTL
- Migration support
- Templates

**Overhead:**
- Requires ZFS
- Full FreeBSD release per template (~500MB+)
- Complex property system
- Heavy for single-application isolation

#### BastilleBSD

BastilleBSD provides container-like templates:

```sh
# Bootstrap release
bastille bootstrap 14.0-RELEASE

# Create container
bastille create nginx 14.0-RELEASE 192.168.1.100

# Install packages
bastille pkg nginx install nginx

# Start service
bastille service nginx nginx start
```

**Approach:**
- Template-based deployment
- Thin jails with shared base
- Service management integration

**Requirements:**
- Release bootstrapping
- Template maintenance
- IP address planning

### The isolate Approach

**isolate** was designed for a different problem: *running a single application in isolation without infrastructure overhead*.

```sh
# That's it. One command.
isolate run --caps nginx.caps -w /var/isolate/nginx /var/isolate/nginx/start.sh
```

### Why isolate?

| Aspect | Traditional Tools | isolate |
|--------|------------------|---------|
| **Setup time** | Hours (base install, config, networking) | Minutes (write caps file) |
| **Disk usage** | 150MB-500MB+ per jail | ~0 (uses host binaries) |
| **Base system** | Required (base.txz extraction) | Not needed |
| **IP addresses** | Manual planning required | Optional (inherit or VNET) |
| **User management** | Manual inside jail | Automatic ephemeral users |
| **Cleanup** | Manual jail destruction | Automatic on exit |
| **Resource limits** | Separate RCTL configuration | Declared in caps file |
| **Use case** | Full OS virtualization | Single application isolation |

### Traditional Workflow: Running nginx in a Jail

```sh
# Step 1: Install jail management tool
pkg install ezjail

# Step 2: Initialize basejail (one-time, ~10 minutes)
ezjail-admin install

# Step 3: Plan IP address allocation
# (Check network, avoid conflicts, configure firewall)

# Step 4: Create the jail
ezjail-admin create nginx 'lo1|192.168.100.1'

# Step 5: Start the jail
ezjail-admin start nginx

# Step 6: Enter jail and install nginx
ezjail-admin console nginx
pkg install nginx
# Configure nginx.conf
# Set up rc.conf for nginx
# Create www user
# Set permissions
exit

# Step 7: Manage ongoing
# - Update base system periodically
# - Manage jail startup on boot
# - Handle IP conflicts
# - Clean up old jails manually
```

**Total steps: 7+ | Time: 30+ minutes | Disk: ~200MB**

### isolate Workflow: Running nginx Isolated

```sh
# Step 1: Create workspace and caps file
mkdir -p /var/isolate/nginx
cat > /var/isolate/nginx/nginx.caps << 'EOF'
user: auto
memory: 128M
filesystem: /lib:r
filesystem: /usr/lib:r
filesystem: /usr/local/lib:r
filesystem: /usr/local/sbin:r
filesystem: /tmp:rw
EOF

# Step 2: Run
isolate run --caps /var/isolate/nginx/nginx.caps \
    -w /var/isolate/nginx \
    /usr/local/sbin/nginx -g 'daemon off;'
```

**Total steps: 2 | Time: 2 minutes | Disk: ~0**

### When to Use Each Approach

**Use traditional jail tools (ezjail, iocage, BastilleBSD) when:**

- Running a full operating system environment
- Need persistent jails that survive reboots
- Running multiple services in one jail
- Require jail-specific package installations
- Building development or staging environments
- Need ZFS features (snapshots, replication)

**Use isolate when:**

- Isolating a single application or service
- Need quick, ephemeral isolation
- Want minimal disk and memory overhead
- Running multiple instances of the same application
- Multi-tenant application hosting
- Security sandboxing without infrastructure
- CI/CD pipeline isolation
- Don't want to manage base systems

### The Philosophy

Traditional jail tools ask: *"How do I create a virtual FreeBSD system?"*

**isolate** asks: *"How do I run this one application safely?"*

```
┌─────────────────────────────────────────────────────────────────┐
│              Traditional Jails (ezjail, iocage)                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│   │ Full Base   │  │ Full Base   │  │ Full Base   │            │
│   │ System      │  │ System      │  │ System      │            │
│   │ ─────────── │  │ ─────────── │  │ ─────────── │            │
│   │ pkg, users  │  │ pkg, users  │  │ pkg, users  │            │
│   │ rc scripts  │  │ rc scripts  │  │ rc scripts  │            │
│   │ ─────────── │  │ ─────────── │  │ ─────────── │            │
│   │   nginx     │  │  postgres   │  │    redis    │            │
│   └─────────────┘  └─────────────┘  └─────────────┘            │
│        150MB+          200MB+           150MB+                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                          isolate                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│              Host System (shared libraries)                     │
│   ┌──────────────────────────────────────────────────────────┐  │
│   │  /lib  /usr/lib  /usr/local/lib  (read-only, shared)    │  │
│   └──────────────────────────────────────────────────────────┘  │
│         │                │                  │                   │
│         ▼                ▼                  ▼                   │
│   ┌──────────┐    ┌──────────┐      ┌──────────┐               │
│   │  nginx   │    │ postgres │      │  redis   │               │
│   │  (jail)  │    │  (jail)  │      │  (jail)  │               │
│   └──────────┘    └──────────┘      └──────────┘               │
│       ~0MB           ~0MB              ~0MB                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## How It Works

isolate creates an isolated environment using these FreeBSD features:

| Feature | Purpose | FreeBSD Primitive |
|---------|---------|-------------------|
| **Process Isolation** | Separate process namespace | `jail(2)` |
| **User Isolation** | Ephemeral unprivileged user | `pw(8)` |
| **Filesystem Isolation** | Restricted view of filesystem | `nullfs(5)` |
| **Resource Limits** | Memory, processes, file descriptors | `rctl(8)` |
| **Network Isolation** | Separate network stack (optional) | `VNET/VIMAGE` |

---

## Isolation Layers

When you run a process with isolate, multiple isolation layers are applied:

```
┌──────────────────────────────────────────────────────────────────┐
│                         HOST SYSTEM                              │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                    FreeBSD Jail                            │  │
│  │  ┌──────────────────────────────────────────────────────┐  │  │
│  │  │              Ephemeral User (app-XXXXX)              │  │  │
│  │  │  ┌────────────────────────────────────────────────┐  │  │  │
│  │  │  │            Resource Limits (rctl)             │  │  │  │
│  │  │  │  ┌──────────────────────────────────────────┐  │  │  │  │
│  │  │  │  │         Filesystem (nullfs)             │  │  │  │  │
│  │  │  │  │  ┌────────────────────────────────────┐  │  │  │  │  │
│  │  │  │  │  │      YOUR APPLICATION (nginx)     │  │  │  │  │  │
│  │  │  │  │  └────────────────────────────────────┘  │  │  │  │  │
│  │  │  │  └──────────────────────────────────────────┘  │  │  │  │
│  │  │  └────────────────────────────────────────────────┘  │  │  │
│  │  └──────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### Layer 1: FreeBSD Jail

The jail provides process-level isolation. Processes inside cannot:

- See or signal processes outside the jail
- Access the host's filesystem directly
- Modify system-wide settings
- Access network interfaces (unless explicitly configured)

### Layer 2: Ephemeral User

Each instance runs as a unique, temporary user (e.g., `app-1316`):

- Created on demand with random UID
- Cannot login interactively
- Has no home directory
- Deleted when the instance stops
- Prevents privilege escalation attacks

### Layer 3: Resource Limits

Using FreeBSD's `rctl`, hard limits are enforced:

- **Memory**: Maximum RSS (e.g., 128MB)
- **Processes**: Maximum concurrent processes
- **File descriptors**: Maximum open files

### Layer 4: Filesystem Isolation

The jail has a minimal filesystem constructed from:

- **Read-only mounts**: System libraries (`/lib`, `/usr/lib`)
- **Read-write workspace**: Application data (`/workspace`)
- **Isolated /tmp**: Instance-specific temporary directory
- **No access**: Everything else is invisible

---

## Nginx Use Case

Running nginx in isolate provides:

**Security Benefits:**

- Even if nginx is compromised, attackers can't access the host
- Resource exhaustion attacks are contained
- No root privileges inside the jail
- Minimal attack surface (only required libraries mounted)

---

## Step-by-Step Guide

### 1. Install isolate

```sh
# From package
pkg add isolate-0.2.0.pkg

# Or build from source
git clone https://github.com/EsteSystems/isolate.git
cd isolate && zig build -Doptimize=ReleaseFast
```

### 2. Create the Workspace Directory

```sh
# Create directory structure
mkdir -p /var/isolate/nginx/{html,logs,tmp}
mkdir -p /var/isolate/nginx/tmp/{client_body,proxy,fastcgi,uwsgi,scgi}
chmod -R 777 /var/isolate/nginx
```

Directory structure:

```
/var/isolate/nginx/
├── html/
│   └── index.html      # Web content
├── logs/
│   ├── access.log      # Access logs
│   └── error.log       # Error logs
├── tmp/                # Nginx temp directories
│   ├── client_body/
│   ├── proxy/
│   ├── fastcgi/
│   ├── uwsgi/
│   └── scgi/
├── nginx.conf          # Nginx configuration
├── nginx.caps          # Capability file
└── start.sh            # Startup script
```

### 3. Create the Capability File

The capability file (`nginx.caps`) defines what the isolated process can access:

```ini
# /var/isolate/nginx/nginx.caps
# Nginx isolation capability file

# Create ephemeral user for this instance
user: auto

# Resource limits
memory: 128M
processes: 20
files: 1024

# Shell for startup script
filesystem: /bin:r

# System libraries (read-only)
filesystem: /lib:r
filesystem: /usr/lib:r
filesystem: /libexec:r
filesystem: /usr/local/lib:r

# Nginx binary and configuration
filesystem: /usr/local/sbin:r
filesystem: /usr/local/etc/nginx:r

# Temp directory (isolated per instance)
filesystem: /tmp:rw
```

### 4. Create the Nginx Configuration

Configure nginx to use `/workspace` paths (mapped from the host workspace):

```nginx
# /var/isolate/nginx/nginx.conf
worker_processes 1;
error_log /workspace/logs/error.log;
pid /workspace/nginx.pid;

events {
    worker_connections 64;
}

http {
    include /usr/local/etc/nginx/mime.types;
    default_type application/octet-stream;

    access_log /workspace/logs/access.log;

    # All temp paths inside workspace
    client_body_temp_path /workspace/tmp/client_body;
    proxy_temp_path /workspace/tmp/proxy;
    fastcgi_temp_path /workspace/tmp/fastcgi;
    uwsgi_temp_path /workspace/tmp/uwsgi;
    scgi_temp_path /workspace/tmp/scgi;

    server {
        listen 8080;  # Non-privileged port
        root /workspace/html;

        location / {
            index index.html;
        }
    }
}
```

> **Note:** Port 8080 is used because the ephemeral user cannot bind to privileged ports (<1024). Use a reverse proxy or firewall redirect if you need port 80.

### 5. Create the Startup Script

```sh
#!/bin/sh
# /var/isolate/nginx/start.sh
exec /usr/local/sbin/nginx -g 'daemon off;' -c /workspace/nginx.conf
```

```sh
chmod +x /var/isolate/nginx/start.sh
```

### 6. Run nginx with isolate

```sh
isolate run \
    --caps /var/isolate/nginx/nginx.caps \
    -w /var/isolate/nginx \
    -N nginx \
    /var/isolate/nginx/start.sh
```

| Option | Description |
|--------|-------------|
| `--caps` | Path to capability file |
| `-w` | Workspace directory (mounted as `/workspace`) |
| `-N` | Instance name for management |

### 7. Verify It's Running

```sh
# Check isolate instances
isolate list

# Output:
NAME                 PID      JAIL_ID  STATE      BINARY
-------------------- -------- -------- ---------- -------------------------
nginx-63eca8b9       1316     2        running    /var/isolate/nginx/start.sh

# Test the server
curl http://localhost:8080/
```

---

## Deep Dive: How nginx Gets Isolated

When you run the isolate command, here's exactly what happens:

### Phase 1: User Creation

```sh
# isolate creates an ephemeral user
pw useradd app-1316 -u 1001 -g 1001 -d /nonexistent -s /usr/sbin/nologin
```

This user:

- Has a random UID (1001 in this case)
- Cannot login interactively
- Has no home directory
- Will be deleted when the instance stops

### Phase 2: Jail Filesystem Setup

```
Host Filesystem                              Jail Filesystem
─────────────────                            ─────────────────────────────────
/lib                          ──nullfs──▶    /lib (read-only)
/usr/lib                      ──nullfs──▶    /usr/lib (read-only)
/libexec                      ──nullfs──▶    /libexec (read-only)
/usr/local/lib                ──nullfs──▶    /usr/local/lib (read-only)
/usr/local/sbin               ──nullfs──▶    /usr/local/sbin (read-only)
/usr/local/etc/nginx          ──nullfs──▶    /usr/local/etc/nginx (read-only)
/bin                          ──nullfs──▶    /bin (read-only)
/tmp/isolate-<jail>           ──nullfs──▶    /tmp (read-write, isolated)
/var/isolate/nginx            ──nullfs──▶    /workspace (read-write)

                                             /etc/passwd (generated, minimal)
                                             /etc/group (generated, minimal)
                                             /start.sh (copied binary)
```

> **Security Note:** Each instance gets its own isolated `/tmp` directory (`/tmp/isolate-<jail-name>`), preventing cross-instance information leakage through temporary files.

### Phase 3: Jail Creation

```sh
# Equivalent jail(8) parameters
jail -c \
    name=isolate-1316 \
    path=/tmp/isolate-isolate-1316 \
    persist \
    allow.raw_sockets=false \
    allow.socket_af=true \
    ip4=inherit \
    ip6=inherit
```

### Phase 4: Resource Limits (rctl)

```sh
# Applied via rctl_add_rule()
rctl -a jail:isolate-1316:memoryuse:deny=134217728  # 128MB
rctl -a jail:isolate-1316:maxproc:deny=20           # 20 processes
rctl -a jail:isolate-1316:openfiles:deny=1024       # 1024 file descriptors
```

### Phase 5: Process Execution

```c
// isolate forks and:
1. jail_attach(jid)           // Attach to jail
2. setgid(1001), setuid(1001) // Drop to ephemeral user
3. chdir("/")                 // Change to jail root
4. execv("/start.sh", argv)   // Execute nginx
```

### What nginx Sees Inside the Jail

```sh
# Process list (from inside jail)
$ ps aux
USER    PID %CPU %MEM    VSZ   RSS TT  STAT STARTED    TIME COMMAND
app-1316  1  0.0  0.1  24836 11412  -  IJ   06:56   0:00 nginx: master
app-1316  2  0.0  0.1  24836 11440  -  IJ   06:56   0:00 nginx: worker

# Filesystem view
$ ls /
bin/  etc/  lib/  libexec/  start.sh  tmp/  usr/  workspace/

# Network (inherited from host)
$ netstat -an | grep 8080
tcp4  0  0  *.8080  *.*  LISTEN

# Cannot see host processes
$ ps aux | wc -l
3  # Only nginx master + worker + ps itself
```

---

## Instance Management

### List Running Instances

```sh
isolate list

NAME                 PID      JAIL_ID  STATE      BINARY
-------------------- -------- -------- ---------- -------------------------
nginx-63eca8b9       1316     2        running    /var/isolate/nginx/start.sh
```

### Stop an Instance

```sh
# Graceful stop (SIGTERM)
isolate stop nginx-63eca8b9

# Force stop (SIGKILL)
isolate stop -f nginx-63eca8b9
```

### Clean Up Orphaned Instances

```sh
isolate clean
```

### Check System Capabilities

```sh
isolate check

isolate System Check
====================
FreeBSD 15.0

Kernel Features:
  [OK] FreeBSD jails        Supported
  [OK] racct/rctl           Enabled
  [OK] VNET/VIMAGE          Available
  [OK] nullfs               Supported
  [OK] devfs                Supported

Privileges:
  [OK] Running as root      Full isolation available
```

---

## Comparison: isolate vs Docker

| Aspect | Traditional Docker | isolate |
|--------|-------------------|---------|
| Image required | Yes (pulled from registry) | No (uses host binaries) |
| Daemon required | Yes (dockerd) | No (single binary) |
| Isolation mechanism | Linux namespaces/cgroups | FreeBSD jails/rctl |
| User separation | Configurable | Automatic (ephemeral user) |
| Filesystem | Layered images (overlay) | Selective mounts (nullfs) |
| Overhead | ~50MB+ per container | ~0 (shared libraries) |

---

## Learn More

- [GitHub Repository](https://github.com/EsteSystems/isolate)
- [jail(2) Manual Page](https://man.freebsd.org/cgi/man.cgi?query=jail)
- [rctl(8) Manual Page](https://man.freebsd.org/cgi/man.cgi?query=rctl)

---

*isolate (c) 2025-2026 Este Systems. BSD 2-Clause License.*
