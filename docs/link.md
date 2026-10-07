# Link: discovery, transport, supervisor

This file is the latency and reliability contract. If a change makes a file transfer able to delay clipboard, it is a bug even when tests are green.

## Latency budgets

Quiet LAN, p95, measured from the OS event on the sender to apply on the receiver. Not an average. Not a loopback-only number reported as if it were Wi-Fi. M0 measures loopback against a tighter bar so the stack itself is not the problem.

| Traffic | LAN p95 | M0 loopback p95 | Channel |
|---|---|---|---|
| Datagram echo (pointer-sized, 64 bytes) | 15 ms | 2 ms | Realtime, unreliable datagram |
| Clipboard text (under 16 KiB) | 30 ms | 5 ms | Realtime, reliable stream |
| Notification | 100 ms | n/a until M2 | Realtime, reliable |
| Bulk starts moving bytes | 200 ms | n/a until M3 | Bulk connection |
| Dead-path detection, session active | 1 s | tested with a dropped UDP socket | Heartbeat |
| Dead-path detection, idle | 3 s | same | Heartbeat |
| Reconnect after a clean process restart, cached address | under 1 s including handshake | required in M0 | Supervisor |

p95 over at least 1000 samples for the echo and clipboard tests. Print p50, p95, p99. Do not lower these numbers in code comments and call it done.

## Two connections

One Quinn connection shares congestion control between streams and datagrams. A photo send will hitch the pointer. Stream priorities do not fix that. Use two connections.

| Name | Default UDP port | Carries | Buffers | Loss |
|---|---|---|---|---|
| Realtime | 47920 | Hello, control, clipboard, notifications, handoff, input datagrams, presence | Small send/recv windows | Datagrams drop. Control is reliable and small |
| Bulk | 47921 | File bytes only, after a meta handshake on realtime | Large | Reliable, resumable, low priority |

Ports are provisional. They are part of the TXT record, not magic constants scattered through call sites. One `Ports` struct in `link-proto`.

The session is **up** when realtime is established. Bulk is opportunistic. Clipboard must work if bulk never connects.

Both connections pin the same peer identity. Bulk refuses to speak to a fingerprint that realtime has not authenticated in this process lifetime.

### Socket buffers

Set `SO_RCVBUF` and `SO_SNDBUF` explicitly on both endpoints. Quinn documents erratic latency when the OS default UDP buffer is small. Start at 2 MiB on realtime and 4 MiB on bulk, and log the size the kernel actually granted.

Do not block the realtime socket on disk, D-Bus, or JNI. Adapters get a try-send into a ring. If the ring is full, drop oldest for input, coalesce clipboard to the latest generation.

## Dial order

For a known peer, race paths. First handshake that authenticates the pinned fingerprint wins. The losers are closed.

1. Last known socket address, immediately.
2. mDNS result for that fingerprint, if it differs.
3. Stagger the second attempt by 50 ms, not 300 ms. This is Happy Eyeballs with an aggressive LAN timer.

M0 has no mDNS requirement. M0 dials a configured address. The supervisor API must already accept a list of candidate addresses so discovery plugs in without a rewrite.

There is no relay in v1. Do not add a fallback that hides a broken LAN path.

Later, optional, off by default: an iroh endpoint as a third candidate for away-from-home. It must be labeled in the UI as a high-latency path. It must not become the default dial. Do not import iroh until that milestone exists.

## Discovery v1

Used from M1 onward. Specified now so M0 addresses and fingerprints match.

**mDNS service type:** `_link._udp.local.`.

TXT records, all ASCII:

| Key | Value |
|---|---|
| `v` | `1` |
| `fp` | lowercase hex SHA-256 of the 32-byte Ed25519 public key, first 16 bytes (32 hex chars) |
| `rt` | realtime UDP port |
| `bk` | bulk UDP port |
| `name` | display name, max 32 bytes, no newlines |

The full public keys are not in mDNS. They are in the QR and in the pin store. The fingerprint is enough to find a paired device and is enough to avoid talking to the wrong host. Treat the LAN as hostile anyway; mDNS is a hint, not authentication.

**UDP probe**, sent to the realtime port, 24 bytes:

```text
magic: 8 bytes  = 4c 49 4e 4b 44 49 53 31   ("LINKDIS1")
fp:    16 bytes = the same 16-byte fingerprint
```

Reply with the same layout only when the receiver is paired with that fingerprint or is in pairing mode. Otherwise ignore. Do not write an error packet. Do not reflect the probe at an unauthenticated sender beyond this ignore rule.

**Cache:** persist last good socket address per fingerprint. Load it before waiting for mDNS. Invalidate it after three failed dials in a row, then wait for mDNS.

**Not in v1:** BLE advertisements, Wi-Fi Direct, Wi-Fi Aware. Wi-Fi Direct drops the phone's normal association on many devices. BlueZ peripheral mode is too flaky to block the project on. Do not add the crates.

## Supervisor

One state machine per peer. Invalid combinations (for example "established" with no realtime connection) should be unrepresentable. An enum, not booleans.

```text
Idle
  -- unpair / never paired -----------------> Idle
  -- dial requested or cache hit -----------> Dialing
Dialing
  -- realtime authenticated ----------------> Established
  -- dial error or 5 s timeout -------------> Backoff
Established
  -- heartbeat miss (1 s active / 3 s idle) > Degraded
  -- local shutdown or peer close ----------> Dialing   (if still paired)
  -- unpair ---------------------------------> Idle
Degraded
  -- a heartbeat returns -------------------> Established
  -- budget exceeded -----------------------> Dialing
Backoff
  -- timer ---------------------------------> Dialing
```

Backoff delays: 100 ms, 200 ms, 400 ms, 800 ms, then cap at 5 s. Reset the schedule after 10 s spent in `Established`. Add full jitter. Do not tight-loop dial.

Heartbeats are an application control message (`class = presence`), not only QUIC's idle timeout. QUIC's idle timeout is too slow to look "stable" to a person.

- Active (input or clipboard in the last 5 s, or an open bulk transfer): ping every 1 s. Miss budget 1 s.
- Idle: ping every 10 s. Miss budget 3 s.

On a network change (Android `NetworkCallback`, Linux netlink or route socket when that adapter exists): try QUIC connection migration first. If the path is not validated within 500 ms, redial from the cache, then mDNS. M0 simulates this by killing the UDP socket and expecting the supervisor to return to `Established` without a human.

0-RTT: session tickets may be stored per fingerprint. Early data is allowed only for classes marked idempotent in [protocol.md](protocol.md) (presence, clipboard). Never for bulk, unpair, or notification actions. Replay is handled by the per-class sequence counter, which is persisted for clipboard.

## Scheduler

Inside the realtime connection, still keep classes from head-of-line blocking each other more than a single stream would:

- One long-lived unidirectional stream per direction for `control` and `presence` (tiny, always drained first).
- One long-lived stream per direction for `clipboard`, `notify`, and `handoff`.
- Datagrams only for `input`.

Do not open a new stream per clipboard update. Do not put input on a stream.

A dedicated drain task reads realtime and never awaits bulk or the disk.

## What agents get wrong here

- One QUIC connection "because Quinn multiplexes." It multiplexes streams. It does not isolate their congestion from datagrams.
- A 30 s heartbeat because "QUIC has keepalives."
- Queueing every clipboard event. Latest generation wins.
- Treating mDNS as authentication.
- A cloud fallback so the demo works off-LAN. That demo is a different product and will be used to justify keeping the fallback.
