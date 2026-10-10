#!/bin/sh
#
# End-to-end scenarios for isolate. They create real jails, users, mounts and
# resource limits, so they need FreeBSD and root. Each check is named after
# the invariant it demonstrates; see docs/design/.
#
#   zig build && doas sh tests/scenarios.sh [path/to/isolate]
#
# Exit status is 0 if every check passed. Checks that the host cannot support
# (no racct, no VNET) are reported as SKIP.

I=${1:-./zig-out/bin/isolate}
HERE=$(cd "$(dirname "$0")" && pwd)

[ "$(uname -s)" = FreeBSD ] || { echo "these scenarios need FreeBSD"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "these scenarios need root"; exit 2; }
[ -x "$I" ] || { echo "no isolate executable at $I (run zig build)"; exit 2; }
I=$(realpath "$I")

W=$(mktemp -d /var/tmp/isolate-scenarios.XXXXXX)
chmod 755 "$W"
PASS=0; FAIL=0; SKIP=0

pass() { PASS=$((PASS + 1)); printf 'PASS  %-7s %s\n' "$1" "$2"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL  %-7s %s\n' "$1" "$2"; [ -n "$3" ] && printf '      %s\n' "$3"; }
skip() { SKIP=$((SKIP + 1)); printf 'SKIP  %-7s %s\n' "$1" "$2"; }

# check ID "description" <command...>: passes if the command succeeds
check() { id=$1; desc=$2; shift 2; if "$@" >/dev/null 2>&1; then pass "$id" "$desc"; else fail "$id" "$desc" "$OUT"; fi; }
# Helpers used as the command of a check; they look at $OUT and $RC
has()   { printf '%s\n' "$OUT" | grep -qE -- "$1"; }
lacks() { ! printf '%s\n' "$OUT" | grep -qE -- "$1"; }
rc_is() { [ "$RC" = "$1" ]; }
rc_not0() { [ "$RC" != 0 ]; }

# run <caps file> <args...>: run isolate, capture output and status
run() { caps=$1; shift; OUT=$("$I" run -c "$caps" "$@" 2>&1); RC=$?; }

# Everything isolate creates. Empty when nothing is left behind.
leftovers() {
    ls /var/run/isolate 2>/dev/null | sed 's/^/entry:/'
    jls -h name 2>/dev/null | tail -n +2 | grep '^isolate-' | sed 's/^/jail:/'
    pw usershow -a | cut -d: -f1 | grep -E '^app-[0-9]+$' | sed 's/^/user:/'
    mount | grep ' /var/run/isolate' | awk '{print "mount:" $3}'
    rctl 2>/dev/null | grep '^jail:isolate-' | sed 's/^/limit:/'
}
clean_host() { [ -z "$(leftovers)" ]; }
wait_gone() { n=0; while kill -0 "$1" 2>/dev/null && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done; ! kill -0 "$1" 2>/dev/null; }
instance_name() { "$I" list | awk 'NR>2 {print $1}' | head -1; }

if [ -n "$(leftovers)" ]; then
    echo "The host already has isolate leftovers; run 'isolate clean' first:"; leftovers; exit 2
fi

cc -O0 -o "$W/probe" "$HERE/probe.c" || { echo "could not compile tests/probe.c"; exit 2; }

BASE="user: auto
filesystem: /lib:r
filesystem: /usr/lib:r
filesystem: /libexec:r
filesystem: /bin:r"
mkcaps() { f="$W/$1.caps"; shift; { printf '%s\n' "$BASE"; for l in "$@"; do printf '%s\n' "$l"; done; } > "$f"; printf '%s' "$f"; }
BASECAPS=$(mkcaps base)

echo "== Isolation =="

run "$BASECAPS" /bin/ls /
check ISO-1 "the jail root is not the host's root" lacks '^(boot|home|root|sbin)$'
check ISO-2 "the jail root holds the rule directories" has '^bin$'

run "$BASECAPS" /bin/sh -c 'echo x > /lib/isolate-write-test'
check ISO-3 "a rule without w is read-only" has 'Read-only file system'

run "$(mkcaps id 'filesystem: /usr/bin:r')" /usr/bin/id
check ISO-5 "one uid, one group, not root" has '^uid=[1-9][0-9]*(\([^)]*\))? gid=[1-9][0-9]*(\([^)]*\))? groups=[1-9][0-9]*(\([^)]*\))?$'

run "$BASECAPS" "$W/probe" whoami
check ISO-14 "the program can look its own user up" has '^whoami: uid [0-9]+ is app-[0-9]+$'
run "$(mkcaps nobody 'user: nobody')" "$W/probe" whoami
check ISO-14 "  also when it runs as an existing user" has '^whoami: uid 65534 is nobody$'
run "$BASECAPS" /bin/cat /etc/master.passwd
check ISO-14 "the jail's password file is not readable by the program" has 'Permission denied'

run "$(mkcaps root 'user: root')" /bin/ls /
check ISO-6 "user: root is refused" rc_not0
check ISO-6 "  and says why" has 'Refusing to run as root'

OUT=$(SECRET_FROM_HOST=leak "$I" run -c "$(mkcaps envclear 'env_clear: true' 'env: FOO=bar' 'filesystem: /usr/bin:r')" /usr/bin/env 2>&1); RC=$?
check ISO-7 "env_clear removes inherited variables" lacks 'SECRET_FROM_HOST'
check ISO-7 "  and keeps the file's env entries" has '^FOO=bar$'

MARK="isolate-scenario-$$"
run "$(mkcaps tmp 'filesystem: /tmp:rw')" /bin/sh -c "echo x > /tmp/$MARK && ls /tmp"
check ISO-8 "a /tmp rule is writable in the jail" has "^$MARK\$"
check ISO-8 "  and is not the host's /tmp" test ! -e "/tmp/$MARK"

run "$BASECAPS" /bin/ls /dev
check ISO-9 "/dev has null" has '^null$'
check ISO-9 "/dev hides the host's devices" lacks '^(mem|kmem|io|pci|bpf|geom\.ctl)$'

OUT=$("$I" run -c "$BASECAPS" "$W/probe" fds 2>&1 5</etc/hosts 6</etc/hosts); RC=$?
check ISO-10 "no descriptors beyond stdio are inherited" has '^fds: 0 inherited$'

run "$(mkcaps missing 'filesystem: /nonexistent/isolate-scenario:r')" /bin/ls /
check ISO-11 "a rule that cannot be mounted stops the run" rc_not0
check ISO-11 "  and leaves nothing behind" clean_host

SHM_BEFORE=$(ipcs -m | grep -c '^m')
run "$BASECAPS" "$W/probe" shm
check ISO-12 "System V shared memory is refused by default" has 'shmget failed'
run "$(mkcaps sysv 'sysv_ipc: true')" "$W/probe" shm
check ISO-12 "sysv_ipc: true allows it" has 'segment created and attached'
OUT=$("$I" run -c "$(mkcaps sysvleak 'sysv_ipc: true' 'env: PROBE_SHM_LEAK=1')" "$W/probe" shm 2>&1); RC=$?
check ISO-12 "a segment the program leaves behind goes away with the jail" test "$(ipcs -m | grep -c '^m')" = "$SHM_BEFORE"

run "$BASECAPS" "$W/probe" args $(jot 200)
check ISO-13 "200 arguments arrive" has '^args: 200$'
run "$BASECAPS" "$W/probe" args -v -c x --name y
check ISO-13 "isolate's own option names pass through after the binary" has '^args: 5$'

run "$BASECAPS" "$W/probe" self
check ISO-15 "the program runs from the path it has on the host" has "^self: $W/probe\$"
(cd "$W" && OUT=$("$I" run -c "$BASECAPS" ./probe self 2>&1); printf '%s\n' "$OUT" > "$W/self.out")
OUT=$(cat "$W/self.out")
check ISO-15 "  also when it was named by a relative path" has "^self: $W/probe\$"
printf '#!/bin/sh\necho overwritten > "$0"\n' > "$W/selfwrite.sh"; chmod 777 "$W/selfwrite.sh"
run "$BASECAPS" "$W/selfwrite.sh"
check ISO-15 "  and cannot overwrite itself, even when its file is world-writable" has 'Read-only file system'
check ISO-15 "  (the file on the host is unchanged)" grep -q 'echo overwritten' "$W/selfwrite.sh"

echo "== Capability file =="

run "$(mkcaps typo 'memroy: 64M')" /bin/ls /
check CAP-2 "a misspelled key stops the run, without -v" rc_not0
check CAP-2 "  and names the file and line" has 'typo\.caps:6: Unknown capability: memroy'
for bad in 'cpu: 50' 'network_default: deny' 'filesystem_default: deny' 'filesystem: /var/log:w' 'filesystem: /bin:rx' 'filesystem: /:rw' 'env_clear: maybe' 'memory: lots'; do
    run "$(mkcaps bad "$bad")" /bin/ls /
    check CAP-1 "refused: $bad" rc_not0
done

run "$(mkcaps overlap 'filesystem: /etc/ssh/ssh_config:r' 'filesystem: /etc/ssh:r')" /bin/ls /etc/ssh
check CAP-7 "a rule inside another rule's directory is accepted, in either order" has '^ssh_config$'
run "$(mkcaps conflict 'filesystem: /etc/ssh:r' 'filesystem: /etc/ssh/ssh_config:rw')" /bin/ls /etc/ssh
check CAP-7 "a read-write rule inside a read-only one is refused" rc_not0
check CAP-7 "  with a reason" has 'inside the read-only rule'
mkdir -p "$W/nest"; echo nested > "$W/nest/file"; chmod -R 755 "$W/nest"
run "$(mkcaps tmpnest 'filesystem: /tmp:rw' "filesystem: $W/nest:r")" /bin/cat "$W/nest/file"
check CAP-7 "rules for unrelated paths are both mounted" has '^nested$'

run "$(mkcaps file 'filesystem: /etc/hosts:r')" /bin/cat /etc/hosts
check CAP-1 "a rule for a single file mounts that file" has 'localhost'
check CAP-1 "  and nothing is left mounted afterwards" clean_host

OUT=$("$I" run -c "$W/does-not-exist.caps" /bin/ls / 2>&1); RC=$?
check CAP-4 "a missing file warns and mounts nothing" has 'No capability file'

echo "== Lifecycle =="

run "$BASECAPS" /bin/sh -c 'exit 7'
check LIF-7 "exit status of the program is returned" rc_is 7
run "$BASECAPS" /bin/sh -c 'kill -9 $$'
check LIF-7 "a signal death is 128 + signal" rc_is 137
check LIF-1 "nothing is left after normal and killed runs" clean_host

mkdir -p "$W/ws" "$W/data"; chmod 777 "$W/ws" "$W/data"
echo keep > "$W/ws/file"; echo keep > "$W/data/file"
OUT=$("$I" run -c "$(mkcaps data "filesystem: $W/data:rw")" -w "$W/ws" /bin/sh -c 'echo new > /workspace/made-in-jail' 2>&1); RC=$?
check LIF-3 "workspace files survive cleanup" test "$(cat "$W/ws/file")" = keep
check LIF-3 "read-write rule files survive cleanup" test "$(cat "$W/data/file")" = keep
check LIF-3 "a file written in the jail is on the host" test -f "$W/ws/made-in-jail"
check LIF-1 "nothing is left after a run with mounts" clean_host

"$I" run -c "$BASECAPS" -N scenario-sig "$W/probe" ignore-term >"$W/sig.log" 2>&1 &
M=$!; sleep 2
kill -TERM $M; sleep 1
check LIF-8 "first SIGTERM: isolate stays to clean up" kill -0 $M
kill -TERM $M
check LIF-8 "second SIGTERM: the jail is removed and isolate exits" wait_gone $M
check LIF-1 "nothing is left after two signals" clean_host

"$I" run -c "$BASECAPS" -N scenario-stop "$W/probe" ignore-term >"$W/stop.log" 2>&1 &
M=$!; sleep 2
OUT=$("$I" run -c "$BASECAPS" -N scenario-stop /bin/ls / 2>&1); RC=$?
check LIF-9 "a second instance of the same name is refused" rc_not0
check LIF-9 "  and the first is still registered" test "$(instance_name)" = scenario-stop
OUT=$("$I" stop scenario-stop 2>&1); RC=$?
check LIF-6 "stop refuses while the program ignores SIGTERM" rc_is 1
check LIF-6 "  and the instance stays registered" test "$(instance_name)" = scenario-stop
OUT=$("$I" clean 2>&1); RC=$?
check LIF-2 "clean leaves a managed instance alone" kill -0 $M
OUT=$("$I" stop -f scenario-stop 2>&1); RC=$?
check LIF-6 "stop -f succeeds" rc_is 0
check LIF-6 "  and isolate exits" wait_gone $M
check LIF-1 "nothing is left after stop -f" clean_host

"$I" run -c "$BASECAPS" -N scenario-opts "$W/probe" ignore-term >"$W/opts.log" 2>&1 &
M=$!; sleep 2
T0=$(date +%s); OUT=$("$I" stop -t 1 scenario-opts 2>&1); RC=$?; T1=$(date +%s)
check LIF-6 "stop -t 1 gives up after about a second" test $((T1 - T0)) -le 3
check LIF-6 "  and reports that the program is still running" rc_is 1
OUT=$("$I" stop -s USR1 -t 5 scenario-opts 2>&1); RC=$?
check LIF-6 "stop -s USR1 ends a program that ignores SIGTERM" rc_is 0
check LIF-6 "  and isolate exits" wait_gone $M
check LIF-1 "nothing is left after stop -s" clean_host

"$I" run -c "$BASECAPS" -N scenario-orphan "$W/probe" ignore-term >"$W/orphan.log" 2>&1 &
M=$!; sleep 2
kill -9 $M; sleep 1
check LIF-2 "killing isolate leaves an orphan (precondition)" test -n "$(leftovers)"
OUT=$("$I" clean 2>&1); RC=$?
check LIF-2 "clean removes a registered orphan completely" clean_host

# Leftovers with no registry entry: what a reboot or a lost entry leaves
jail -c name=isolate-999999 path=/ persist >/dev/null
pw useradd -n app-999998 -s /usr/sbin/nologin -d /tmp -c "Isolate ephemeral user"
mkdir -p /var/run/isolate/inst-Zz9Zz9/root; touch -t 202001010000 /var/run/isolate/inst-Zz9Zz9
# Things that only look similar and must not be touched
jail -c name=scenario-not-isolate path=/ persist >/dev/null
pw useradd -n app-999997 -s /usr/sbin/nologin -d /tmp -c "Someone else's user"
OUT=$("$I" clean 2>&1); RC=$?
# (the decoy user matches the name pattern on purpose, so leave it out here)
check LIF-2 "clean removes an unregistered jail, user and directory" test -z "$(leftovers | grep -v '^user:app-999997$')"
check LIF-4 "clean leaves a jail it did not create" jls -j scenario-not-isolate
check LIF-4 "clean leaves a user it did not create" pw usershow -n app-999997
jail -r scenario-not-isolate 2>/dev/null; pw userdel -n app-999997 2>/dev/null

su -m nobody -c "echo '{}' > /var/run/isolate/x.json" 2>/dev/null
check LIF-5 "an unprivileged user cannot write the registry" test ! -e /var/run/isolate/x.json

echo "== Resource limits =="

if [ "$(sysctl -n kern.racct.enable 2>/dev/null)" = 1 ]; then
    run "$(mkcaps procs 'processes: 8')" "$W/probe" procs
    check LIM-1 "processes: 8 stops the eighth process" has 'fork failed after 7 children'
    run "$(mkcaps files 'files: 64')" "$W/probe" files
    check LIM-2 "files: 64 stops at 64 descriptors" has 'open failed after 6[01] extra'
    run "$(mkcaps mem 'memory: 64M')" "$W/probe" mem 250
    check LIM-3 "memory: 64M kills a program that grows past it" rc_is 137
    run "$(mkcaps mem512 'memory: 512M')" "$W/probe" mem 250
    check LIM-3 "the same program finishes under 512M" has 'no limit reached'
    check LIM-4 "no limits remain after the runs" clean_host
else
    skip LIM-1 "racct is not enabled (kern.racct.enable)"
    run "$(mkcaps procs 'processes: 8')" "$W/probe" procs
    check LIM-5 "without racct, a file with limits is refused" rc_not0
fi

echo "== Network =="

LANIP=$(ifconfig "$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')" 2>/dev/null | awk '/inet / {print $2; exit}')
nc -k -l 18999 >/dev/null 2>&1 &
NCPID=$!; sleep 1

run "$(mkcaps none 'network_mode: none')" "$W/probe" conn 127.0.0.1 18999
check NET-1 "network_mode: none cannot create an IPv4 socket" has 'socket failed'

if [ "$(sysctl -n kern.features.vimage 2>/dev/null)" = 1 ] && [ -n "$LANIP" ]; then
    EPA=$(ifconfig epair create); EPB="${EPA%a}b"
    ifconfig "$EPA" inet 10.99.99.1/24 up
    run "$(mkcaps vnet "network_mode: vnet:$EPB" 'network_ip: 10.99.99.2/24')" "$W/probe" conn 10.99.99.1 18999 "$LANIP" 18999
    check NET-2 "vnet: the jail reaches the host on its interface's network" has '10\.99\.99\.1:18999 connected'
    check NET-2 "  and not on the host's other address" has "$LANIP:18999 failed"
    # The kernel hands the interface back as the jail's network stack is torn down
    wait_iface() { n=0; while ! ifconfig "$1" >/dev/null 2>&1 && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done; ifconfig "$1" >/dev/null 2>&1; }
    check NET-4 "the interface is back on the host within five seconds" wait_iface "$EPB"
    check LIF-1 "nothing is left after a VNET run" clean_host

    nc -k -l 18998 >/dev/null 2>&1 &
    NC2=$!
    anchors() { pfctl -a isolate -s Anchors 2>/dev/null | grep -c 'isolate/isolate-'; }
    VN="network_mode: vnet:$EPB"
    IP="network_ip: 10.99.99.2/24"
    if pfctl -s info 2>/dev/null | grep -q 'Status: Enabled' && pfctl -s rules 2>/dev/null | grep -q 'anchor "isolate/\*"'; then
        run "$(mkcaps nr1 "$VN" "$IP" 'network: tcp:18999:outbound')" "$W/probe" conn 10.99.99.1 18999 10.99.99.1 18998
        check NET-6 "outbound: the allowed port connects" has '10\.99\.99\.1:18999 connected'
        check NET-6 "outbound: another port on the same host does not" has '10\.99\.99\.1:18998 failed'
        check NET-6 "no pf anchor is left after the run" test "$(anchors)" = 0

        run "$(mkcaps nr2 "$VN" "$IP" 'network: tcp:10.99.99.1:18998:outbound')" "$W/probe" conn 10.99.99.1 18998 10.99.99.1 18999
        check NET-6 "outbound: a rule with an address allows that address and port" has '10\.99\.99\.1:18998 connected'
        check NET-6 "  and nothing else" has '10\.99\.99\.1:18999 failed'

        run "$(mkcaps nr3 "$VN" "$IP" 'network: none')" "$W/probe" conn 10.99.99.1 18999
        check NET-6 "network: none blocks everything" has '18999 failed'

        "$I" run -c "$(mkcaps nr4 "$VN" "$IP" 'network: tcp:18001:inbound')" -N scenario-net "$W/probe" listen 30 18001 18002 >"$W/net.log" 2>&1 &
        M=$!; sleep 3
        check NET-6 "inbound: the allowed port is reachable from the host" nc -z -w 2 10.99.99.2 18001
        check NET-6 "inbound: another listening port is not" sh -c '! nc -z -w 2 10.99.99.2 18002'
        check NET-6 "the rules are in an anchor named after the jail" test "$(anchors)" = 1
        kill -9 $M; sleep 1
        OUT=$("$I" clean 2>&1); RC=$?
        check NET-6 "clean removes the rules of an orphaned instance" test "$(anchors)" = 0
        wait_iface "$EPB"
    else
        run "$(mkcaps nr1 "$VN" "$IP" 'network: tcp:18999:outbound')" "$W/probe" conn 10.99.99.1 18999
        check NET-6 "without pf and isolate's anchor, a file with network rules is refused" rc_not0
        check NET-6 "  and the program never ran" lacks '^conn:'
        skip NET-6 "pf is not enabled with isolate's anchor; enforcement not exercised"
    fi
    kill $NC2 2>/dev/null

    run "$(mkcaps nrinherit 'network: tcp:443:outbound')" "$W/probe" conn 10.99.99.1 18999
    check NET-6 "network rules without a VNET jail are refused" rc_not0
    check NET-6 "  with a reason" has 'network rules need network_mode: vnet'
    check NET-6 "  and the program never ran" lacks '^conn:'
    run "$(mkcaps nrbad "$VN" 'network: tcp:example.com:443:outbound')" "$W/probe" conn 10.99.99.1 18999
    check NET-6 "a rule with a host name is refused" rc_not0

    run "$(mkcaps vnetbad 'network_mode: vnet:nosuchif9')" "$W/probe" conn 10.99.99.1 18999
    check NET-5 "an interface that does not exist stops the run" rc_not0
    check NET-5 "  and the program never ran" lacks '^conn:'
    check NET-5 "  and nothing is left behind" clean_host
    ifconfig "$EPA" destroy
else
    skip NET-2 "VNET is not available, or no default interface"
fi
kill $NCPID 2>/dev/null

echo "== Detection =="

cc -o "$W/hello" "$HERE/../examples/hello.c" 2>/dev/null
cp "$I" "$W/isolate-copy"   # somewhere an unprivileged user can reach
OUT=$(su -m nobody -c "'$W/isolate-copy' detect -o /dev/null '$W/hello'" 2>&1); RC=$?
check DET-1 "detect runs unprivileged" rc_is 0
"$I" detect "$W/hello" >/dev/null 2>&1
run "$W/hello.caps" "$W/hello"
check DET-2 "a generated file runs the program unedited" has 'Hello from isolated world'
for bin in /bin/ls /usr/bin/ssh /usr/sbin/sshd /usr/local/sbin/nginx /usr/local/bin/postgres; do
    [ -x "$bin" ] || continue
    "$I" detect -o "$W/closure.caps" "$bin" >/dev/null 2>&1
    grep '^filesystem: .*:r$' "$W/closure.caps" | sed 's/^filesystem: //; s/:r$//' | grep -v '/ld-elf' | sort > "$W/closure.ours"
    ldd "$bin" 2>/dev/null | awk '/=>/ {print $3}' | sort > "$W/closure.ldd"
    check DET-6 "the libraries listed for $bin are the ones ldd reports" cmp -s "$W/closure.ours" "$W/closure.ldd"
done
"$I" detect -o "$W/find.caps" /usr/bin/find >/dev/null 2>&1
run "$W/find.caps" /usr/bin/find / -type f
check DET-6 "a jail built from a generated file holds the program's libraries" has '^/lib/libc\.so\.7$'
check DET-6 "  and no other library" lacks '^/lib/libm\.so|^/usr/lib/|^/lib/libz'
"$I" detect -o "$W/ssh.caps" /usr/bin/ssh >/dev/null 2>&1
check DET-7 "nothing guessed from strings is live (no rule under /etc)" sh -c "! grep -q '^filesystem: /etc' '$W/ssh.caps'"
check DET-7 "  but the guesses are there as comments" grep -q '^#.*filesystem: /etc/ssh' "$W/ssh.caps"
run "$W/ssh.caps" /usr/bin/ssh -V
check DET-2 "the file generated for ssh runs it unedited" has 'OpenSSH'

for bin in /usr/local/sbin/nginx /usr/sbin/sshd /bin/sh; do
    [ -x "$bin" ] || continue
    "$I" detect -o "$W/gen.caps" "$bin" >/dev/null 2>&1
    OUT=$("$I" run -n -c "$W/gen.caps" "$bin" 2>&1); RC=$?
    check DET-2 "the file generated for $bin loads without problems" rc_is 0
done

echo
check LIF-1 "the host is clean at the end" clean_host
rm -rf "$W"
echo "passed: $PASS   failed: $FAIL   skipped: $SKIP"
[ "$FAIL" = 0 ]
