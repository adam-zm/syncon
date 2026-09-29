# Milestones

Do them in order. A later milestone is not a place to hide an M0 failure.

Exit tests are pass/fail. "Works on my machine" without the numbers is not a pass.

## M0 — headless pair

**Goal:** two Linux processes, same Rust session, prove the protocol and the latency budget on loopback.

**Build:** `link-proto`, `link-crypto`, `link-session`, `linux/linkd`. No GTK. No Android. No mDNS required.

**Behavior:**

- `linkd --dev` generates an identity in a temp dir.
- One side `--pair`, the other consumes the pair payload from a file (the `link://pair?...` URL from the protocol doc).
- Both print the same 8-digit SAS. A `--accept-sas` flag is allowed in dev so the test is non-interactive. Production pairing still requires a human; the flag must refuse to run without `--dev`.
- After accept, both sit in `Established`.
- Presence heartbeats keep the peer in `Established`.
- Datagram echo, class `input`, 64-byte body, 1000 messages: p95 under 2 ms on loopback.
- Kill the peer process. The survivor returns to `Dialing`/`Backoff` and reaches `Established` on its own when the peer is restarted, using the cached address, in under 1 s after the peer is listening again.
- A clipboard body with a lower generation does not replace a higher one (unit test plus one integration send).
- AEAD failure closes the connection and does not delete the pin.
- A concurrent bulk-connection transfer of 50 MiB of zeros does not move the datagram-echo p95 above 5 ms on loopback. This is the test that justifies two connections. If someone collapsed them into one connection, this test is what fails.

**Out of M0:** QR rendering, mDNS, D-Bus, systemd unit, real OS clipboard, Android.

## M1 — discovery and a phone skeleton

**Goal:** a phone on the same Wi-Fi pairs by QR and survives its own process death.

**Build:** `link-discovery`, Android service + a minimal Compose pair screen, UniFFI.

**Exit:**

- mDNS find plus UDP probe on a real LAN.
- Cached address dials without waiting for mDNS.
- Wi-Fi toggle: phone returns to `Established` without the user opening the activity, within 3 s of association, on a Pixel. On Samsung and Xiaomi, document the battery-optimization step if it is required, and then meet the same 3 s.
- Wrong SAS pairs nothing.
- RTT visible in the Android UI and in `linkd` logs.

**Out of M1:** clipboard integration with the real OS clipboards. The core clipboard type already exists from M0.

## M2 — daily driver core

**Goal:** the features that make the two devices feel shared.

**Exit:**

- Copy text on Android, paste on Linux, and the reverse. LAN p95 under 30 ms, 100 samples, idle network.
- A clip marked sensitive is not transferred. Test with a synthetic flag even if the OS mark is hard to fake.
- Notification appears on Linux; dismiss or a single action is reflected on the phone.
- Feature toggles default as in [platforms.md](platforms.md).
- The 50 MiB bulk test from M0 still passes while clipboard samples are taken (LAN p95 for clipboard still under 30 ms).

## M3 — files

**Exit:**

- Share sheet on Android and a `linkd` CLI `send` on Linux.
- 1 GiB file, resumable after a killed connection, BLAKE3 matches, resident memory of `linkd` stays under the 256 MiB budget.
- Path traversal in the file name is rejected (`../`, absolute paths, embedded NULs).
- Clipboard p95 during the transfer still under 30 ms.

## M4 — handoff

**Exit:**

- A test peer publishes a handoff token (app id, title, URL). The other side surfaces the latest token for that app id and ignores older generations.
- A tiny browser helper or a CLI is enough. A full browser extension is not required to claim M4 if the token path is real.
- Opening the token fetches nothing from the internet on Link's behalf. The URI is opened by the local OS.

## M5 and after — do not schedule these in the same task as M0–M4

| Slice | Exit bar | Why it is separate |
|---|---|---|
| M5 input | Pointer datagrams, LAN p95 under 15 ms, no effect from a running file transfer | Needs uinput or an Android accessibility service |
| Mirror | Lossy frames, one-frame jitter buffer, not a reliable stream | Video congestion will wreck the realtime connection if it shares it |
| SMS | Threads on the desktop, local only, extra consent | Sensitive data, OEM SMS roles |
| Calls, camera, PAM unlock | Not scheduled | Restricted APIs and easy to make unsafe |

## Suggested task slices inside M0

So two agents do not edit the same files:

1. **Proto + crypto** — crates and the unit tests in the protocol doc. No sockets.
2. **Session + linkd** — Quinn, supervisor, `--bench-echo`, SAS dev flow. Consumes the crates from slice 1. Starts after the envelope API is real, or stubs against the types in [protocol.md](protocol.md) without changing them.
3. **Docs** — only if a test proves the spec wrong. Update the spec in the same change as the fix. Do not silently drift.

Slice 2 depends on slice 1's types. Do not fork the envelope in the session crate "temporarily."

## Definition of not done

- Echo test run once, no histogram.
- Reconnect that needs the user to press a button.
- Bulk and realtime sharing a connection, with a comment that priorities will come later.
- Any network call to a server the user did not run.
- Android work scheduled with WorkManager as the session.
- A web UI in `/workspace/src` standing in for `linkd`.
