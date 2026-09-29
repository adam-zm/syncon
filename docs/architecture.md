# Architecture

## What Link is

A phone and a Linux desktop stay paired and speak a private protocol on the local network. Copy on one side pastes on the other. A notification can be dismissed from the desktop. A file dropped on one side lands on the other without going through a server. Later, the desktop offers to continue whatever the phone was doing.

That is the iPhone–Mac feeling that is in scope: Continuity, not iCloud.

Two different products get conflated and then both fail:

| Layer | Apple analogue | Link v1 |
|---|---|---|
| Proximity link | Handoff, Universal Clipboard, AirDrop, notification mirror | This project |
| Account sync | iCloud Photos, Notes, messages-when-apart | Out of scope. Do not sneak it into the session |

KDE Connect already does much of the v1 feature list. It is the wrong base. The session is one TCP connection carrying JSON, so a bulk transfer or a stalled write blocks clipboard and input. The protocol logic is duplicated in C++ and Kotlin. Take its feature checklist and its notes on Android OEMs killing background work. Do not take its transport.

## Processes

```text
+-------------------------------+     +----------------------------------+
| Android                       |     | Linux user session               |
|  Compose UI                   |     |  link-gtk  -- D-Bus -->  linkd   |
|  OS adapters (Kotlin)         |     |                     |            |
|  Rust core via UniFFI         |     |                     Rust core    |
+---------------|---------------+     +---------------------|------------+
                |                                           |
                +---- realtime QUIC (UDP) ------------------+
                +---- bulk QUIC (UDP) ----------------------+
```

Rules:

- The GTK process dying must not drop the link. `linkd` owns the sockets.
- The Android UI dying is unavoidable when the OS kills the process. The foreground service and the Rust supervisor are what bring it back. The Compose activity is not the session.
- No second implementation of envelopes, sequencing, or keys in Kotlin or TypeScript.

## Crates

Workspace root: `/workspace/link`.

| Crate | Responsibility | Forbidden |
|---|---|---|
| `link-proto` | Envelope codec, class enums, message bodies, version constant, size limits | Sockets, tokio, files |
| `link-crypto` | Identity bundle, SAS, HKDF, AEAD, cert generation, pin check | Sockets |
| `link-session` | Quinn endpoints, dual connection, scheduler, supervisor state machine, latest-wins apply | mDNS, GTK, JNI |
| `link-discovery` | mDNS, last-address cache, UDP probe, dial racing | Crypto beyond comparing fingerprints |
| `linux/linkd` | Binary: config, key store files, wires discovery to session, stdout metrics in M0 | UI toolkit |
| `linux/link-gtk` | Tray and window. After M0 only | Direct QUIC |
| `android/app` | Compose, permissions, foreground service, listeners | Hand-written protocol |
| `android/core-ffi` | UniFFI surface over the Rust core | A second state machine |

`link-proto`, `link-crypto`, and `link-session` use `#![forbid(unsafe_code)]`.

### Dependency direction

```text
linkd --> link-session --> link-proto
                       --> link-crypto
      --> link-discovery
```

`link-proto` and `link-crypto` do not depend on `link-session`. `link-discovery` does not depend on Quinn. The session tells discovery "I am paired with these fingerprints" and "I am in pairing mode"; discovery does not open QUIC.

Preferred crates when implementation starts (do not substitute a second stack):

| Job | Crate |
|---|---|
| QUIC | `quinn` 0.11.x, rustls |
| Async | `tokio` |
| Codec | `postcard` inside the envelope body. The envelope header itself is hand-packed little-endian so a partial read does not need serde |
| mDNS | `mdns-sd` |
| AEAD / signatures | `ring` or the rustls crypto provider already pulled in. One crypto backend, not both `ring` and `aws-lc` |
| Hash | BLAKE3 for file integrity. SHA-256 for SAS only |
| Linux IPC (post-M0) | `zbus` |

Do not add `iroh` in M0. Do not add `webrtc`. Do not add serde_json on the hot path.

## Resource rules

Memory safety is not a memory bound. These are part of the design, not later polish.

- Every channel in the supervisor is bounded.
- Realtime apply queues are rings. Clipboard and input keep the newest item, not a backlog.
- Bulk has a fixed receive window (start at 4 MiB per peer). Stream to disk once files exist. Do not buffer a file in a `Vec`.
- If the peer is slow: pause bulk, never pause reading the realtime socket.
- Daemon budget once it is a systemd unit: `MemoryMax=256M`, `TasksMax=128`. M0 can run without the unit, but it must not allocate without a cap in the session code.
- Android: the Rust runtime runs on its own threads. JNI callbacks must not block the main looper and must not write the keystore on the packet path.

## What v1 actually ships

Phases are defined in [milestones.md](milestones.md). The feature map, so agents do not invent extras:

| Feature | Phase | Notes |
|---|---|---|
| Pair, reconnect, show path and RTT | M0–M1 | The product is fake until this is boring |
| Clipboard text, then small images | M2 | Sensitive clips never leave the device |
| Notification mirror and actions | M2 | |
| File share, resumable, BLAKE3 | M3 | On the bulk connection |
| Handoff token (app id, title, URL, scroll) | M4 | Small payload, not a process snapshot |
| Trackpad / keyboard | M5 | Datagrams. Separate milestone, do not pull forward |
| Screen mirror | After M5 | Own budget. Lossy video, not a reliable stream |
| SMS | After M5 | Local only |
| Call audio, camera-as-webcam, PAM unlock | Not scheduled | High risk or restricted APIs |

v1 user-facing target is one Android phone and one Linux desktop. Store peers as a map keyed by fingerprint from the first commit so a second peer does not require a protocol break. The M0 binary may still be a single configured peer.

## Workspaces this repo also contains

`/workspace` is a Grok app-builder checkout (Node, TanStack). That web app is not Link. Do not put protocol code in `src/`. Do not start a preview server to demo the link. Agents working only on Link should not edit `src/`, `package.json`, or `/workspace/startup.sh`.
