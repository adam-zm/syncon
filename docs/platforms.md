# Platforms

Do not start these shells before their milestone. The rules are here so the session API grows the hooks they need, and so a later agent does not "just use a background thread" on Android.

## Android

The OS, not the protocol, is what will make the link look laggy or dead. Xiaomi, Oppo, and Samsung kill background work that Pixel allows. Test matrix when a device build exists: Pixel (AOSP), Samsung, Xiaomi. One green emulator is not a pass.

### Process model

- UI: one Compose activity for pairing, feature toggles, RTT, and the share target.
- Session: a foreground service of type `connectedDevice`, with the matching `FOREGROUND_SERVICE_CONNECTED_DEVICE` permission. Start it from the visible activity. A persistent notification is required while the link is armed. Do not hide it.
- Rust core: UniFFI, loaded into that service process. One tokio runtime owned by Rust, not by the main looper.
- Clipboard, notifications, and SMS are Kotlin adapters that push events into the core. They do not open sockets.

### Background limits that already burned similar apps

Target current Android (15 / API 35 and 16 / API 36 behavior, not a blog from 2019):

- Starting a foreground service from the background throws `ForegroundServiceStartNotAllowedException` unless an exemption applies.
- `dataSync` foreground services are time-limited. Do not use `dataSync` for the live link.
- WorkManager is for deferred jobs. It is the wrong API for a session that must reconnect in under a second. Do not "fix" reliability by scheduling the session.
- Background network and background BLE scans are restricted. v1 does not need BLE. It does need a network callback.

### Required approach

1. Pair and start the foreground service while the activity is visible.
2. Associate the desktop with Companion Device Manager. Request `REQUEST_COMPANION_START_FOREGROUND_SERVICES_FROM_BACKGROUND` so a later start from the background is legal. Prefer that permission over `REQUEST_COMPANION_RUN_IN_BACKGROUND`.
3. `ConnectivityManager.registerNetworkCallback` (or `registerDefaultNetworkCallback`) calls into the supervisor on the Rust runtime. On available / lost / link-properties changed: migration, then redial. Do not wait for the next heartbeat interval to notice.
4. `START_STICKY`. A watchdog may restart the Rust runtime if a health ping inside the process stalls. Do not hold a wake lock all day. A partial wake lock is allowed only around an in-progress handshake or bulk transfer, and it must be released when the transfer ends or after 2 minutes, whichever comes first.
5. Document, in the pairing screen, the OEM step "disable battery optimization." That is a product requirement, not a support footnote.

### Permissions, feature by feature

Request only the feature the user turned on.

| Feature | Needs | Default |
|---|---|---|
| Link itself | notifications (for the foreground service), nearby wifi devices / local network as required by target SDK | on after pair |
| Clipboard | clipboard listener | on after pair, sensitive clips dropped |
| Notification mirror | notification listener, user must enable in system settings | off until explained |
| File share | share-sheet intent, storage as scoped as the target SDK allows | on |
| Input injection into Android | accessibility service, off until M5, and it will feel worse than a PC-side uinput path | off |
| SMS | SMS role or read/send SMS. Not before its milestone. Local only | off |

No location permission. Discovery is LAN mDNS, not GPS.

### FFI boundary

- UniFFI-generated Kotlin only. No hand-maintained JNI.
- Packet path must not re-enter the main thread.
- Callbacks into Kotlin are `try_send`. If the adapter is overloaded, the core applies the same latest-wins rules it uses everywhere else.
- Keys: Android Keystore for the identity private keys when the shell exists. The Rust core should accept a key-store trait so M0 can use a file and Android can use Keystore without a protocol change.

## Linux

`linkd` runs as the logged-in user. Not root. A system unit that only root can use will not see the user's clipboard or notification bus, and it will expand the blast radius of a protocol bug.

### M0

Binary with a config file:

```text
identity_path
peer_pin_path          # absent during first pair
listen_rt
listen_bk
peer_addr              # optional, skip mDNS
pair_mode              # bool
```

Log to stderr: state transitions, RTT from presence counters, AEAD failures, buffer sizes granted. No clipboard yet required for the echo test. A `--bench-echo` mode that answers presence payloads and records histograms is part of M0, so nobody has to wire GTK to know if the stack is fast.

### Daemon after M0

User systemd unit:

- `Restart=on-failure`
- `MemoryMax=256M`
- `TasksMax=128`
- `NoNewPrivileges=yes`

IPC to the GTK client is D-Bus (`zbus`) on the session bus. Methods are for pairing, feature toggles, and status. The hot path does not go through the UI. The UI subscribes to a status signal.

### Adapters

Hide Wayland vs X11 behind a trait inside `linux/linkd`, not inside `link-session`.

| Need | Wayland | X11 | Notes |
|---|---|---|---|
| Clipboard watch | `wl-clipboard` protocol or `wl-clipboard-rs` | XFixes selection | The Freedesktop clipboard portal does not notify on copy. Do not use it as the watch |
| Clipboard set | same | same | Never write a sensitive clip received from the peer into the OS clipboard |
| Notifications | `org.freedesktop.Notifications` via zbus | same | Actions must round-trip |
| Media keys | MPRIS | MPRIS | Phase 2, not M0 |
| Sleep inhibit | portal Inhibit or logind, only during bulk | same | Release when the transfer ends |
| Phone as keyboard | `uinput` | `uinput` | Off by default. Group `input` is a privilege. Not M0 |

Ship a native deb/rpm or a plain binary first. Flatpak is a later packaging task. It cannot host the clipboard watch or `uinput` without punching holes that remove the sandbox. Do not make Flatpak the primary design.

### Key files

M0 directory, default `$XDG_DATA_HOME/link/` or `./.link-dev` when `--dev` is set (M0 tests use a temp dir):

| File | Mode | Content |
|---|---|---|
| `identity` | 0600 | sign seed, dh seed |
| `peers/<fingerprint>` | 0600 | pinned pubs, last address, last clipboard generation, feature grants |

If the keyring (Secret Service) is easy to add in the GTK milestone, move the seeds there. Do not block M0 on it. Do not commit a dev identity.

## API the session crate should expose

So both shells share a shape. Names can change, the split should not:

```text
trait HostHooks {
    fn on_state(&self, peer: Fingerprint, state: SessionState);
    fn on_rtt(&self, peer: Fingerprint, rtt_ms: u32);
    fn on_clipboard(&self, peer: Fingerprint, generation: u64, text: &str);
    fn send_clipboard(&self, text: &str, sensitive: bool); // sensitive true is a local drop
}

Session::pair_listen(...) -> PairingSession   // yields SAS
Session::dial(peer, candidates)
Session::unpair(peer)
Session::submit_clipboard(...)
Session::poll_events() or callback onto a caller-provided queue
```

The core never calls Wayland, D-Bus, or Android. Tests use an in-memory hook.
