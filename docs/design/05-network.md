# 05 — Network

## Purpose

The capability file decides what network a program has: the host's, none, or a network stack of its own. For a program with a stack of its own, it can also say exactly which connections may be made and accepted.

## Scope

- The three network modes and what each guarantees.
- VNET: what isolate does with the interface it is given.
- `network:` rules: what they mean and how they are enforced.

## Out of scope

- **Creating network infrastructure.** isolate does not create epair or bridge interfaces, assign addresses on the host side, add routes, or configure NAT. The interface named in the capability file must already exist.
- **The host's firewall.** isolate loads rules into an anchor of its own. It does not enable pf, write `pf.conf`, or manage any other rule.
- **Network rules without a VNET jail.** With the host's network there is no interface that carries only the program's traffic. A capability file with rules and `network_mode: inherit` is refused.
- **IPv6 in rules, and protocols other than TCP and UDP.** Rules are IPv4. With any rule present, everything they cannot express is blocked.
- **Address management, DNS, bandwidth limits and traffic accounting.**

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

All `ifconfig` commands run on the host, so the jail needs no `/sbin`.

Before removing a VNET jail, isolate moves every interface other than the loopback back to the host (`ifconfig <if> -vnet <jid>`). It does not rely on the kernel returning the interface when the jail goes: a removed jail whose network stack still holds state, such as a TCP connection the program made, stays "dying" for some time, and an interface inside a dying jail cannot be reclaimed.

The jail gets no default route. It can reach only the networks its interface is directly attached to.

## Network rules

```
network: tcp:8080:inbound              accept TCP connections on port 8080
network: tcp:443:outbound              connect to TCP port 443 anywhere
network: udp:10.0.0.53:53:outbound     send DNS queries to one server
network: tcp:10.0.99.1:5432:inbound    accept 5432 from one address
network: udp:514                       both directions
network: none                          no connections at all
```

The form is `<tcp|udp>[:<IPv4 address or network>][:<port>][:<inbound|outbound|both>]`. The address is the *other* end: the destination for `outbound`, the source for `inbound`. Host names are not accepted.

**Meaning**

- No rules: no filtering. The jail can use whatever its interface reaches.
- One or more rules: only what a rule allows is passed. Everything else to or from the jail is dropped, in both directions, including ICMP and IPv6.
- Replies belong to the connection that caused them: an `outbound` rule lets the answers back in.

**Mechanism**

Rules require `network_mode: vnet:<epairNb>`. The jail holds the `b` end of an epair; the `a` end stays on the host, and every packet to or from the jail crosses it. isolate writes pf rules for that interface into an anchor named `isolate/<jail name>`:

```
pass in  quick on epair0a inet proto tcp from any to any port 443 keep state    # outbound from the jail
pass out quick on epair0a inet proto tcp from any to any port 8080 keep state   # inbound to the jail
block drop quick on epair0a all
```

Seen from the host end the directions are mirrored: what the jail sends arrives *in*. Every rule is `quick`, so a match in the anchor decides at once.

The anchor is loaded after the jail is created and before the program starts. pf states on the interface are flushed at the same time, so that connections an earlier user of the interface had open cannot carry over. The anchor is removed when the instance is cleaned up, by `stop` and `clean` for an instance whose isolate process has died, and `clean` removes anchors of jails that no longer exist.

**What the host must provide**

pf enabled, with this line in `pf.conf` before any rule that passes traffic:

```
anchor "isolate/*"
```

`isolate check` reports whether both are in place. If a capability file has rules and they are not, the run is refused.

## Invariants

"Tested" names a check in `tests/scenarios.sh`, run on FreeBSD 15.1.

| ID | Invariant | Status |
|---|---|---|
| NET-1 | In `none` mode the program cannot create an IPv4 or IPv6 socket. | Holds (tested) for IPv4: `socket()` fails with `EPROTONOSUPPORT`. IPv6 by inspection. |
| NET-2 | In `vnet` mode the jail's network stack contains only its loopback and the named interface. The host's addresses are not reachable from the jail unless they are on that interface's network. | Holds (tested) |
| NET-3 | A service listening in a VNET jail is reachable only at the jail's address, not at the host's addresses. | Holds (tested by hand with PostgreSQL; not in the scenarios) |
| NET-4 | The interface given to a VNET jail is back on the host when the run ends, whatever the program did with it. | Holds (tested), including after the program made a TCP connection. |
| NET-5 | If a capability file asks for `none` or `vnet` and isolate cannot provide it, the run does not start. The program is never given more network than the file states. | Holds (tested) for an interface that does not exist. A failed address assignment takes the same path, and a kernel without VNET is refused before the jail is created (both by inspection). |
| NET-6 | When a capability file contains `network:` rules, the program can make and accept only the connections the rules allow. If the rules cannot be enforced, the run does not start. | Holds (tested): an allowed outbound port connects and another port on the same host does not; a rule with an address allows that address and port only; `network: none` blocks everything; an allowed inbound port is reachable from the host and another listening port is not; rules without a VNET jail, or with a host name, are refused. Refusal when pf is not enabled or lacks the anchor: by inspection, since the test host has both. |
| NET-7 | An instance's pf rules exist only while its jail exists. | Holds (tested): no anchor remains after a run, and `clean` removes the anchor of an instance whose isolate process was killed. |

## Success criteria

1. `none`: a program's attempt to open a TCP socket fails.
2. `vnet` with an epair: the program reaches the host's end of the epair and cannot reach the host's other addresses.
3. After the run the epair's jail end is listed on the host again.
4. `inherit`: the program reaches whatever the host reaches.
5. With an interface name that does not exist, the run is refused.
6. With `network: tcp:P:outbound` as the only rule, the program connects to port P and to no other port.
7. With `network: tcp:P:inbound` as the only rule, a server in the jail is reachable on P and on no other port it listens on.
8. After the run, no pf anchor of the instance remains.
9. A capability file with rules and `network_mode: inherit` is refused, with the reason.

All nine pass on FreeBSD 15.1. Not run, because the test host has VNET and pf: refusal on a kernel without VNET, and refusal with pf disabled.

## Failure criteria

- A program in `none` mode communicates over IP.
- A program in `vnet` mode reaches a host address that is not on its interface's network.
- A program asked to run in `none` or `vnet` runs with the host's network.
- A connection the rules do not allow succeeds.
- A program starts although its capability file has rules that were not loaded.
- An instance's rules remain in pf after it is gone.

## Known gaps

- **A rule in the host's `pf.conf` can override the anchor.** A `quick` rule placed before the `anchor` line decides first. The anchor line belongs at the top of the filter rules; isolate checks that it exists, not where it is.
- **With rules, ICMP is blocked**, so `ping` and path-MTU discovery do not work for the jail. No rule form allows it.
- **Rules are IPv4.** IPv6 traffic of a jail with rules is dropped. IPv6 has not been tested in any mode.
- Rules need an epair. A physical or VLAN interface given to a jail has no end on the host to filter on, and a capability file with rules for one is refused.
- Outbound connections beyond the host need the host to forward and usually to translate addresses. That is host configuration; the rules only decide what is allowed to leave the jail.
- `allow.socket_af` is set to true in every mode, permitting socket families beyond IPv4, IPv6, UNIX and route. Its effect in `none` mode has not been reviewed.
- Several instances cannot share one interface; each VNET instance needs its own.
- A jail whose program made network connections can remain listed as dying (`jls -d`) after the run. It holds nothing of isolate's; see [03-lifecycle.md](03-lifecycle.md), "Known gaps".
