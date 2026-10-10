# Running PostgreSQL with isolate

This guide runs a PostgreSQL server inside an isolate jail: initialized there, reachable from the host, stopped cleanly, and started again with its data intact. It then gives the server a network address of its own and turns it into a service that starts at boot and is restarted if it dies.

Every command below was run as written on FreeBSD 15.1 with the `postgresql19-server` package (19beta4) and isolate 0.3.0. What isolate guarantees is specified in the [design documents](design/README.md).

PostgreSQL is a more demanding guest than a web server, and each of its demands shows up in the capability file:

| PostgreSQL needs | In the capability file |
|---|---|
| The same owner for its data directory on every start | `user: postgres`, not `user: auto` |
| System V shared memory | `sysv_ipc: true` |
| To look its own user up by uid | Nothing: isolate builds a user database in every jail |
| A dozen processes, each with a large descriptor table | `processes` and `files` sized for it |
| ICU, time zone and locale data | Rules for those directories |

## 1. Create the workspace

The workspace holds the database. It is the only part of the host the server can write to.

```sh
mkdir -p /var/db/isolate-pg
chown postgres:postgres /var/db/isolate-pg
chmod 700 /var/db/isolate-pg
```

The `postgres` user is created by the PostgreSQL package. isolate does not create or delete it.

## 2. Write the capability file

Keep the capability file **outside** the workspace. The workspace is mounted read-write in the jail, so a capability file stored there could be rewritten by the program it is meant to confine.

```sh
mkdir -p /usr/local/etc/isolate
cat > /usr/local/etc/isolate/postgres.caps << 'CAPS'
# PostgreSQL in an isolate jail

# A fixed user: it owns the data directory across runs
user: postgres

# PostgreSQL needs System V shared memory
sysv_ipc: true

# Limits apply to the whole jail; see "Sizing the limits"
memory: 2G
processes: 64
files: 32768

# Shell (PostgreSQL runs helper commands through /bin/sh) and libraries
filesystem: /bin:r
filesystem: /lib:r
filesystem: /usr/lib:r
filesystem: /libexec:r
filesystem: /usr/local/lib:r

# PostgreSQL itself, its data files, ICU, time zones and locales
filesystem: /usr/local/bin:r
filesystem: /usr/local/share/postgresql:r
filesystem: /usr/local/share/icu:r
filesystem: /usr/share/zoneinfo:r
filesystem: /usr/share/locale:r

# Private /tmp: lock files and the server's UNIX socket
filesystem: /tmp:rw

env_clear: true
env: LANG=C.UTF-8
CAPS
```

Check it before using it. This prints the settings a run would use, or the line that is wrong:

```sh
isolate run -n -v -c /usr/local/etc/isolate/postgres.caps /usr/local/bin/postgres
```

## 3. Initialize the database

`initdb` runs inside the jail too, as the same user, so the data directory is created with the right owner. The superuser password comes from a file that is deleted afterwards.

```sh
echo 'change-this-password' > /var/db/isolate-pg/pwfile
chown postgres:postgres /var/db/isolate-pg/pwfile
chmod 600 /var/db/isolate-pg/pwfile

isolate run -c /usr/local/etc/isolate/postgres.caps -w /var/db/isolate-pg \
    /usr/local/bin/initdb -D /workspace/data \
    --pwfile=/workspace/pwfile --auth-host=scram-sha-256 --auth-local=reject

rm /var/db/isolate-pg/pwfile
```

The workspace appears in the jail as `/workspace`, so the data directory is `/workspace/data` there and `/var/db/isolate-pg/data` on the host.

## 4. Run the server

```sh
isolate run -c /usr/local/etc/isolate/postgres.caps -w /var/db/isolate-pg -N postgres \
    /usr/local/bin/postgres -D /workspace/data \
    -c listen_addresses=127.0.0.1 -c log_destination=stderr -c max_connections=20
```

The command stays in the foreground for as long as the server runs, and the server's log appears on its output. Two of the options are there because of the jail:

- **`log_destination=stderr`.** The FreeBSD package configures PostgreSQL to log to syslog. There is no syslog socket in the jail, so with that default the log is lost, including the reason for a failed start.
- **`listen_addresses=127.0.0.1`.** The server's UNIX socket is in the jail's private `/tmp`, which the host cannot see. Clients on the host connect over TCP.

You can put all three settings in `/var/db/isolate-pg/data/postgresql.conf` instead.

## 5. Use it

From another terminal:

```sh
isolate list
# NAME                 PID      JAIL_ID  STATE      BINARY
# -------------------- -------- -------- ---------- ------------------------------
# postgres             19327    341      running    /usr/local/bin/postgres

PGPASSWORD=change-this-password psql -h 127.0.0.1 -U postgres
```

## 6. Stop it

```sh
isolate stop postgres
```

This sends `SIGTERM`, which PostgreSQL treats as a smart shutdown: it waits for sessions to end, writes a checkpoint and exits. isolate waits up to five seconds. If sessions are still open after that, `stop` reports that the server is still running and leaves it registered. The shutdown request stays in effect: the server exits by itself once the last session ends. To end it now, use `isolate stop -f postgres`, which removes the jail outright; the server then recovers from its write-ahead log on the next start, as after any crash.

Pressing Ctrl-C in the terminal running the server sends `SIGINT`, PostgreSQL's fast shutdown: sessions are disconnected and the server exits cleanly.

Either way, when `isolate run` returns the jail, its mounts, its limits and its shared memory are gone, and `/var/db/isolate-pg/data` holds the database.

## 7. Start it again

Run the command from step 4 again. The data is where it was left.

## 8. Give it a network of its own

With the host's network, the server can open connections to anything the host can reach, and its port is open on the host's addresses. A VNET jail has its own network stack instead, attached to the host through one interface.

Create an epair, a pair of connected virtual interfaces. The host keeps one end; the jail gets the other. Setting it in `rc.conf` makes it exist at every boot:

```sh
sysrc cloned_interfaces="epair0" ifconfig_epair0a="inet 10.0.99.1/24"
service netif cloneup          # or: ifconfig epair0 create
ifconfig epair0a inet 10.0.99.1/24 up
```

Add the jail's end to the capability file:

```sh
cat >> /usr/local/etc/isolate/postgres.caps << 'CAPS'

# A network stack of its own, on the jail end of an epair
network_mode: vnet:epair0b
network_ip: 10.0.99.2/24
CAPS
```

Tell PostgreSQL to listen on its new address and to accept the host as a client. From the server's side, the host connects from `10.0.99.1`:

```sh
cat >> /var/db/isolate-pg/data/postgresql.conf << 'CONF'
log_destination = 'stderr'
listen_addresses = '*'
max_connections = 20
CONF
echo 'host all all 10.0.99.1/32 scram-sha-256' >> /var/db/isolate-pg/data/pg_hba.conf
```

With the settings in `postgresql.conf`, the command needs no `-c` options any more:

```sh
isolate run -c /usr/local/etc/isolate/postgres.caps -w /var/db/isolate-pg -N postgres \
    /usr/local/bin/postgres -D /workspace/data

PGPASSWORD=change-this-password psql -h 10.0.99.2 -U postgres
```

Now the server answers on `10.0.99.2` only. Port 5432 is closed on `127.0.0.1`, on `10.0.99.1` and on the host's own address, and the jail holds two interfaces: its loopback and `epair0b`. It has no default route, so it can reach the host's end of the epair and nothing beyond it.

When the jail goes away, isolate hands `epair0b` back to the host, so the next start can use it again.

Clients on other machines cannot reach `10.0.99.2` unless the host routes or redirects to it, for example with a pf `rdr` rule. That is host network configuration, outside what isolate does.

### Allow only database connections

A VNET jail can still open connections to anything its interface reaches, and answers on every port something listens on. A network rule narrows that to the one thing a database server is for:

```sh
cat >> /usr/local/etc/isolate/postgres.caps << 'CAPS'

# Accept PostgreSQL connections; nothing else in, nothing out
network: tcp:5432:inbound
CAPS
```

Rules are enforced with pf on the host's end of the epair. The host needs pf enabled, with isolate's anchor in `/etc/pf.conf` before any rule that passes traffic:

```sh
# in /etc/pf.conf
anchor "isolate/*"

sysrc pf_enable=YES
service pf start
isolate check      # the last section reports whether pf is ready
```

With the rule in place the database still answers on 5432, while a ping to `10.0.99.2` and connections to any other port are dropped, and the server cannot open connections of its own. If pf is not enabled or the anchor line is missing, isolate refuses to start the server instead of running it unfiltered.

A server that needs to reach something, such as a replication peer or an authentication service, needs an `outbound` rule for it.

## 9. Run it as a service

isolate does not supervise or start anything at boot; `isolate run` simply stays in the foreground. The repository has an `rc.d` script, [`examples/rc.d/isolate`](../examples/rc.d/isolate), that runs it under `daemon(8)`, which restarts the server if it exits and writes its output to a log file.

Install isolate and the script, then describe the instance in `rc.conf`:

```sh
zig build -Doptimize=ReleaseSafe
install -m 555 zig-out/bin/isolate /usr/local/bin/isolate
install -m 555 examples/rc.d/isolate /usr/local/etc/rc.d/isolate

sysrc isolate_enable=YES isolate_instances=postgres \
    isolate_postgres_caps=/usr/local/etc/isolate/postgres.caps \
    isolate_postgres_workspace=/var/db/isolate-pg \
    isolate_postgres_command="/usr/local/bin/postgres -D /workspace/data" \
    isolate_postgres_stop_signal=INT \
    isolate_postgres_stop_timeout=30
```

`stop_signal=INT` asks PostgreSQL for a fast shutdown: sessions are disconnected and the server exits cleanly. With the default, `TERM`, PostgreSQL waits for every session to end, which can take longer than a shutdown should. If the server is still running after `stop_timeout` seconds, the service removes its jail.

```sh
service isolate start
service isolate status
# isolate: postgres is running (supervisor pid 21830)
service isolate stop
service isolate restart
```

The log is `/var/log/isolate/postgres.log`. To rotate it, tell `newsyslog(8)` to signal the supervisor:

```sh
mkdir -p /usr/local/etc/newsyslog.conf.d
printf '/var/log/isolate/postgres.log\t640\t7\t*\t@T00\tB\t/var/run/isolate-postgres.pid\n' \
    > /usr/local/etc/newsyslog.conf.d/isolate.conf
```

What the service does in each situation, all observed on FreeBSD 15.1:

| Situation | Result |
|---|---|
| The machine boots | The epair is created, the service starts the server in its jail. In a test reboot the database answered 35 seconds after boot. |
| The machine shuts down or reboots | The service stops the server with a fast shutdown. No recovery is needed at the next start. |
| `service isolate stop` with sessions open | Sessions are disconnected; the stop takes about a second. |
| The server crashes or is killed | isolate cleans up the jail and its network rules and exits; the supervisor starts it again after five seconds; PostgreSQL recovers from its write-ahead log. |
| The `isolate run` process is killed | The server keeps running in its jail and keeps answering. Nothing is restarted until the server itself exits, because the supervisor waits for the server's output to close. When it does exit, the supervisor runs `isolate clean` and starts a fresh instance. `service isolate stop` works in this state too. |

The script handles any number of instances; see the comments at its top for the settings.

## What the server can see

```
/                 bin dev etc lib libexec tmp usr var workspace
/dev              fd full null pts random stderr stdin stdout urandom zero
/workspace        the workspace, read-write
/tmp              private to this instance
/etc              a user database holding root and postgres; no password hashes
```

No other part of the host's filesystem exists in the jail.

## Sizing the limits

Limits apply to the jail as a whole, and two of them count differently from what their names suggest.

**`files` counts descriptor-table slots, not open files.** Each PostgreSQL process sizes its descriptor table to about 1,000 entries. A freshly started server has eight processes and already accounts for 8,192. Budget about 1,024 per process: the eight the server always runs, plus one per connection. With `files: 2048` the server starts, fails to fork its helpers with "Resource temporarily unavailable", and shuts down.

**`memory` counts shared memory once per process.** PostgreSQL's shared buffers are mapped by every server process, and each mapping is counted. Measured with 128 MB of shared buffers: 259 MB at idle with eight processes, and 880 MB with 15 connections reading a table, while no single process used more than 37 MB. A process that stays over the limit is killed, which for PostgreSQL means a crash and recovery. Size `memory` for the number of connections you allow, not for the memory the server really occupies, or leave it out.

**`processes`** needs the eight permanent server processes plus one per connection, plus any parallel workers.

## Things to know

- **Supervision is the service's job, not isolate's.** Without step 9, nothing restarts the server or starts it at boot.
- **The data directory is tied to the `postgres` user.** With `user: auto` each run would get a different, temporary user and PostgreSQL would refuse a data directory it does not own.
- **If the `isolate run` process is killed outright**, the server keeps running in its jail. When you run isolate by hand, `isolate clean` removes it and the next start recovers the database. The service does this for you.
- **The command in `rc.conf` is split on spaces.** An argument that contains a space cannot be passed that way; put such settings in `postgresql.conf`.
- **Upgrades and extensions** work as on the host, since the binaries are the host's. An extension that needs files outside the directories above needs a rule for them.
