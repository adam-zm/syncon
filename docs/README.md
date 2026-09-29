# Link specs

Agent reading order. The short lock is [AGENTS.project.md](/workspace/AGENTS.project.md). These files are the detail.

| File | Read it when you are about to |
|---|---|
| [architecture.md](architecture.md) | Add a crate, process, or dependency |
| [link.md](link.md) | Touch sockets, discovery, reconnect, or anything latency-sensitive |
| [protocol.md](protocol.md) | Add a message, change pairing, or change crypto |
| [platforms.md](platforms.md) | Touch Android lifecycle or Linux desktop integration |
| [milestones.md](milestones.md) | Decide what to build next, or claim a slice is done |

Status: specification only. No crate exists yet. Next build is milestone M0 in [milestones.md](milestones.md).

If you need a one-screen picture of the system:

```text
Android UI (Compose)                Linux UI (GTK, later)
        |                                   |
        | Kotlin adapters                   | D-Bus
        v                                   v
 Android foreground service            linkd (user systemd)
        \                                   /
         \------ link-core (Rust) --------/
                     |
            realtime QUIC + bulk QUIC
            mDNS, address cache, UDP probe
```

The core is shared. The shells are not. Clipboard latency is a property of the core and the OS adapters, not of the windows.
