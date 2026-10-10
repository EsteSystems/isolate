# Running PostgreSQL with isolate

This guide runs a PostgreSQL server inside an isolate jail: initialized there, reachable from the host, stopped cleanly, and started again with its data intact.

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

## What the server can see

```
/                 bin dev etc lib libexec postgres tmp usr var workspace
/dev              fd full null pts random stderr stdin stdout urandom zero
/workspace        the workspace, read-write
/tmp              private to this instance
/etc              a user database holding root and postgres; no password hashes
```

No other part of the host's filesystem exists in the jail. The server has the host's network (`network_mode: inherit`), which is why it can listen on `127.0.0.1`. To give it a network stack of its own instead, see "VNET" in the [README](../README.md).

## Sizing the limits

Limits apply to the jail as a whole, and two of them count differently from what their names suggest.

**`files` counts descriptor-table slots, not open files.** Each PostgreSQL process sizes its descriptor table to about 1,000 entries. A freshly started server has eight processes and already accounts for 8,192. Budget about 1,024 per process: the eight the server always runs, plus one per connection. With `files: 2048` the server starts, fails to fork its helpers with "Resource temporarily unavailable", and shuts down.

**`memory` counts shared memory once per process.** PostgreSQL's shared buffers are mapped by every server process, and each mapping is counted. Measured with 128 MB of shared buffers: 259 MB at idle with eight processes, and 880 MB with 15 connections reading a table, while no single process used more than 37 MB. A process that stays over the limit is killed, which for PostgreSQL means a crash and recovery. Size `memory` for the number of connections you allow, not for the memory the server really occupies, or leave it out.

**`processes`** needs the eight permanent server processes plus one per connection, plus any parallel workers.

## Things to know

- **No supervision.** isolate does not restart the server or start it at boot. For that, run the command from step 4 under a supervisor such as `daemon(8)`.
- **The data directory is tied to the `postgres` user.** With `user: auto` each run would get a different, temporary user and PostgreSQL would refuse a data directory it does not own.
- **Use `isolate clean` after a crash of isolate itself.** If the `isolate run` process is killed outright, the server keeps running in its jail. `isolate clean` removes it; the next start recovers the database.
- **Upgrades and extensions** work as on the host, since the binaries are the host's. An extension that needs files outside the directories above needs a rule for them.
