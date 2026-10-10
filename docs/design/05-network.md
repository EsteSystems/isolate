# 05 — Network

## Purpose

The capability file decides what network a program has: the host's, none, or a network stack of its own. A further goal, not yet built, is to restrict which connections it may make or accept.

## Scope

- The three network modes and what each guarantees.
- VNET: what isolate does with the interface it is given.
- `network:` rules: the planned enforcement.

## Out of scope

- **Creating network infrastructure.** isolate does not create epair or bridge interfaces, assign addresses on the host side, add routes, or configure NAT. The interface named in the capability file must already exist.
- **Address management.** No DHCP, no allocation of addresses to instances.
- **DNS.** The jail gets no `resolv.conf` unless a rule provides one.
- **IPv6 configuration in VNET jails.** `network_ip` is passed to `ifconfig inet`.
- **Bandwidth limits and traffic accounting.**

## Modes

| `network_mode` | Jail parameters | What the program has |
|---|---|---|
| `inherit` (default) | `ip4=inherit`, `ip6=inherit` | The host's network stack, addresses and routes. It can connect anywhere the host can and listen on any unprivileged port. |
| `none` | `ip4=disable`, `ip6=disable` | No IPv4 or IPv6. Creating such a socket fails. UNIX-domain sockets are not restricted by this mode (not tested). |
| `vnet`, `vnet:<if>` | `vnet=new` | A separate network stack containing a loopback interface and the named interface. |

### VNET

After creating the jail, isolate:

1. Moves the named interface into the jail (`ifconfig <if> vnet <jid>`).
2. If `network_ip` is set, assigns it and brings the interface up (`ifconfig -j <jid> <if> inet <ip> up`).
3. Brings the jail's loopback up with `127.0.0.1/8`.

Both `ifconfig` commands run on the host, so the jail needs no `/sbin`. When the jail is removed, the kernel returns the interface to the host.

The jail gets no default route. It can reach only the networks its interface is directly attached to.

## Invariants

| ID | Invariant | Status |
|---|---|---|
| NET-1 | In `none` mode the program cannot create an IPv4 or IPv6 socket. | Holds (tested) for IPv4: `socket()` fails with `EPROTONOSUPPORT`. IPv6 by inspection. |
| NET-2 | In `vnet` mode the jail's network stack contains only its loopback and the named interface. The host's addresses are not reachable from the jail unless they are on that interface's network. | Holds (tested): the jail reached the host on the epair address and not on the host's LAN address. |
| NET-3 | A service listening in a VNET jail is reachable only at the jail's address, not at the host's addresses. | Holds (tested) |
| NET-4 | The interface given to a VNET jail is back on the host after the run. | Holds (tested) |
| NET-5 | If a capability file asks for `none` or `vnet` and isolate cannot provide it, the run does not start. The program is never given more network than the file states. | **Violated** (by inspection): when the kernel lacks VNET, isolate warns and uses `inherit`, giving the program the host's network. If moving the interface or setting its address fails, isolate warns and continues with a jail that has no working network. |
| NET-6 | When a capability file contains `network:` rules, the program can make and accept only the connections the rules allow. | **Planned.** Rules are parsed and listed; nothing enforces them. A run with rules prints a warning saying so. |

## Planned: enforcing `network:` rules (NET-6)

This is a goal with criteria, not a finished design.

**Rule syntax** (already parsed):

```
network: tcp:8080:inbound        accept TCP connections on port 8080
network: tcp:443:outbound        connect to TCP port 443 anywhere
network: udp:10.0.0.53:53:outbound
network: none                    no connections at all
```

**Intended semantics**

- No `network:` rules: no filtering. Only `network_mode` applies.
- One or more rules: everything not matched by a rule is blocked, in both directions.
- Rules never widen access beyond what the mode already gives.

**Intended mechanism: pf**

Rules for an instance are loaded into a pf anchor of its own when the jail is created and flushed when it is removed.

- In `vnet` mode, the rules filter on the host side of the jail's interface.
- In `inherit` mode the jail shares the host's addresses, so traffic cannot be told apart by address or interface. pf can match TCP and UDP sockets by owning user, and every `user: auto` instance has a user of its own, so rules would be keyed on the ephemeral uid.

**Open questions**

1. pf must be enabled and its main ruleset must reference isolate's anchor. Does isolate require the administrator to set that up, or refuse to run rules without it? Under NET-5 it must refuse.
2. Matching by user covers TCP and UDP only, and only when the user is unique to the instance. Should rules with `user: <existing>` in `inherit` mode be rejected?
3. `unix:<path>` rules cannot be enforced by a packet filter. Drop the form, or enforce it through the filesystem rules?
4. Cleanup: the anchor must be removed on every exit path and by `clean`, like every other per-instance resource ([03-lifecycle.md](03-lifecycle.md), LIF-1 and LIF-2).

## Success criteria

Today:

1. `none`: a program's attempt to open a TCP socket fails.
2. `vnet` with an epair: the program reaches the host's end of the epair, cannot reach the host's other addresses, and a server in the jail answers on the jail's address only.
3. After the run the epair's jail end is listed on the host again.
4. `inherit`: the program reaches whatever the host reaches.

All four pass on FreeBSD 15.1.

For NET-5, once fixed:

5. On a kernel without VNET, a capability file with `network_mode: vnet` is refused.
6. With an interface name that does not exist, the run is refused.

For NET-6, once built:

7. With `network: tcp:443:outbound` as the only rule, the program connects to port 443 and to no other port, and accepts no inbound connection.
8. With `network: tcp:8080:inbound` as the only rule, a server in the jail is reachable on 8080 and the program cannot connect out.
9. After the run, no pf rule or anchor of the instance remains.
10. With pf disabled, a capability file containing rules is refused.

## Failure criteria

- A program in `none` mode communicates over IP.
- A program in `vnet` mode reaches a host address that is not on its interface's network.
- A program asked to run in `none` or `vnet` runs with the host's network.
- Once NET-6 exists: a connection the rules do not allow succeeds.

The third occurs today on a kernel without VNET (NET-5).

## Known gaps

- `allow.socket_af` is set to true in every mode, permitting socket families beyond IPv4, IPv6, UNIX and route. Its effect in `none` mode has not been reviewed.
- IPv6 has not been tested in any mode.
- Several instances cannot share one interface; each VNET instance needs its own.
- In `inherit` mode a program can bind any unprivileged port on any host address, including ones another instance wants.
