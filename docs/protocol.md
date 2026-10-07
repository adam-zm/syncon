# Protocol

Normative draft, version **1**. M0 implements this. Do not invent a parallel debug protocol. Field changes require a version bump and a note in this file. Unknown classes are ignored, not fatal, so a newer peer can talk to an older one.

Byte order is little-endian. Strings are UTF-8 with an explicit length. No JSON. No postcard for the envelope header. Postcard is allowed for bodies inside a class, but M0 bodies below are packed by hand so the codec stays obvious.

## Identity

Each device generates an identity bundle once and stores it in the platform key store (M0: a file mode `0600`).

| Key | Type | Role |
|---|---|---|
| Sign | Ed25519 | Self-signed certificate, pin, SAS |
| DH | X25519 static | Inner AEAD |

Public identity is the 32-byte Ed25519 public key plus the 32-byte X25519 public key.

**Fingerprint** (discovery, UI, filenames): first 16 bytes of `SHA-256(sign_pub)`, lowercase hex.

**Pin:** the Ed25519 public key, not the certificate bytes. The device may regenerate a certificate as long as the key is unchanged. A changed sign key is a different device and must not replace an existing pin silently.

Certificate: self-signed, Ed25519, rustls-compatible, DNS/SAN not used for trust. Verifier accepts the cert only when its subject public key equals the pinned sign key. No WebPKI, no custom CA.

## Pairing

v1 pairing is one desktop and one phone. The desktop displays, the phone scans. M0 may print the payload to stdout and read it from a file instead of drawing a QR. The payload is the same.

QR / file contents, URL:

```text
link://pair?v=1
  &sign=<base32-nopad of 32-byte Ed25519 pub>
  &dh=<base32-nopad of 32-byte X25519 pub>
  &host=<literal IPv4 or IPv6>
  &rt=<udp port>
  &bk=<udp port>
  &name=<percent-encoded display name>
```

Base32 is RFC 4648, no padding, lower case.

Flow:

1. Desktop enters pairing mode for 120 s. It advertises and will accept one unpinned realtime handshake.
2. Phone dials `host:rt` and completes TLS. Desktop presents the key from the QR. Phone presents a freshly generated identity (or its existing one).
3. Both compute the SAS and show it. No clipboard, file, or notification traffic is accepted in this state.
4. A human confirms the SAS matches. Both sides persist the peer pin. Desktop leaves pairing mode.
5. Next connections require the pin. A peer that presents a different sign key is rejected and logged. Do not offer "trust anyway."

**SAS**, 8 decimal digits:

```text
digest = SHA-256(
  "link-sas-v1" ||
  lower_sign_pub || higher_sign_pub ||
  lower_dh_pub   || higher_dh_pub   ||
  tls_exporter("link-sas-v1", 32)
)
number = u32_be(digest[0..4]) mod 100_000_000
display = zero-padded 8 digits, grouped "XXXX XXXX"
```

`lower` / `higher` compare the 32-byte keys as unsigned big-endian so both sides order them the same way. The exporter binds the SAS to this TLS session, so a passive viewer of the QR cannot print a matching code for a different handshake.

Each side sends `pair_confirm` (control class, inner AEAD) when its human accepts the SAS, or `pair_reject` otherwise. A side persists the pin only after it has both confirmed locally and received `pair_confirm`. While pairing, any class other than control, or any control opcode other than `pair_confirm`/`pair_reject`, aborts the pairing.

Cancel, timeout, or a SAS mismatch wipes the provisional peer. No half-paired state on disk.

## Session crypto

TLS 1.3 via Quinn already encrypts the UDP payloads. Link adds an inner AEAD so a TLS-terminating relay, if one is ever introduced, cannot read clipboard or SMS.

After TLS:

1. Each side sends `Hello` in the clear **inside TLS** (not inner-AEAD; the key does not exist yet).
2. Both derive the inner key.
3. Every later envelope body is `ChaCha20-Poly1305`.

### Hello body (plaintext inside TLS)

```text
u8   version            = 1
u8   role               = 0 desktop, 1 phone, 255 unknown
u16  reserved           = 0
[32] eph_x25519_pub
[32] sign_pub           must match the certificate
[32] dh_pub
u32  feature_bits
u16  max_body           proposal, see limits
[16] fingerprint        of sign_pub
```

`feature_bits` for v1:

| Bit | Name |
|---|---|
| 0 | clipboard text |
| 1 | clipboard image (not M0) |
| 2 | notifications (not M0) |
| 3 | blob transfer (not M0) |
| 4 | handoff (not M0) |
| 5 | input datagrams (not M0) |

M0 sets bit 0 only when a clipboard body is part of the test. Bit 5 is set by `linkd --bench-echo`: the latency histogram is class `input` datagrams, 64-byte bodies, not presence. Presence stays the heartbeat. Do not put the histogram on a reliable stream. A pure pairing smoke test may set no feature bits and still must complete Hello and inner AEAD.

### Inner key

```text
static_shared = X25519(local_dh_static, peer_dh_static)
eph_shared    = X25519(local_eph, peer_eph_pub)     // from Hello
exporter      = TLS-Exporter("link-inner-v1", 32)

ikm  = static_shared || eph_shared || exporter
key  = HKDF-SHA256(ikm, salt = "link-aead-v1", info = transcript, len = 32)
```

`transcript` = SHA-256 of (local Hello bytes || peer Hello bytes) with the two Hellos ordered by the same lower/higher sign_pub rule.

Nonce, 12 bytes: `u8 class || u64_le seq || u8 direction || u16 zero`. `direction` is 0 for the lower sign_pub, 1 for the higher, so both sides never reuse a nonce. Sequence numbers start at 1 per class per direction and increment by 1. Reuse is fatal: tear down the connection.

0-RTT early data cannot use this handshake's ephemeral. M0 does not have to implement 0-RTT. When it is added: early-data key is HKDF of `static_shared` and the resumption ticket nonce, only classes `presence` and `clipboard`, and the receiver must reject a `seq` less than or equal to the last persisted seq for that class. Notification actions, unpair, and blob control are never 0-RTT.

## Envelope

On a reliable stream, frames are back-to-back:

```text
u8  version     = 1
u8  class
u16 flags
u64 seq
u32 body_len
u8  body[body_len]
```

Header is 16 bytes. `body_len` counts the ciphertext (or the Hello plaintext). Reject `body_len` above the class limit before allocating.

| Class | Value | Reliable stream | Idempotent / latest-wins | Max body |
|---|---|---|---|---|
| control | 1 | yes | no | 1024 |
| clipboard | 2 | yes | latest generation wins | 16 KiB (larger images go to blob in M3) |
| notify | 3 | yes | no, but coalescable by id | 8 KiB |
| input | 4 | **datagram** | latest seq wins | 256 |
| handoff | 5 | yes | latest per app id | 4 KiB |
| blobmeta | 6 | yes, realtime | no | 1024 |
| presence | 7 | yes | yes | 128 |
| hello | 8 | yes, once | n/a | 256 |

Datagram layout for `input` is the same 16-byte header plus body, with no extra QUIC framing. If the datagram API cannot carry 16 + 256 bytes, lower `max_body` for input; do not fragment in v1.

Flags:

| Bit | Name | Meaning |
|---|---|---|
| 0 | ack_requested | Receiver should send a control ack |
| 1 | is_ack | Body is an ack |
| 2 | zero_rtt | Sent as early data |

Unknown flag bits are ignored. Unknown class: increment a counter, do not disconnect.

### Control messages (postcard or hand-packed; pick hand-packed in M0)

`body` plaintext before AEAD:

```text
u16 opcode
...
```

| Opcode | Name | Payload | Since |
|---|---|---|---|
| 1 | `ping` | `u64` monotonic ms from sender's arbitrary clock | M0 |
| 2 | `pong` | the same `u64` | M0 |
| 3 | `ack` | `u8 class`, `u64 seq` | M0 |
| 4 | `unpair` | empty. Receiver deletes the pin and closes | M1 |
| 5 | `features` | `u32` bits currently granted by the human | M2 |
| 6 | `pair_confirm` | empty. Sent once, only while pairing, after the human confirmed the SAS | M0 |
| 7 | `pair_reject` | empty. Sent once, only while pairing, on cancel or SAS mismatch | M0 |

`ping`/`pong` is allowed as a diagnostic. The latency heartbeat is class `presence`, not a control ping, so a stuck control parser cannot hide a live peer. Presence body:

```text
u64 send_counter
u64 last_rx_counter     # last send_counter observed from the peer
u8  active              # 1 if the sender considers the session active
```

### Clipboard body

```text
u64 generation          # latest wins, persisted across reconnect
u8  kind                # 1 = utf-8 text
u8  sensitive           # if 1, sender should not have sent it; receiver must drop
u16 reserved
u32 text_len
u8  text[text_len]
```

Receiver applies only when `generation` is strictly greater than the last applied generation for that peer. Equal or lower is a replay or a reorder and is ignored, not an error.

The sender must not build this message for clips the OS marked sensitive (`EXTRA_IS_SENSITIVE`, password-manager hints). The flag exists so a bug fails closed on the far side.

### Blob (M3, specified so the realtime connection is not redesigned)

On realtime, class `blobmeta`:

```text
u16 opcode               # 1 offer, 2 accept, 3 reject, 4 complete
u128 id
u64 size
u32 name_len
u8  name[name_len]       # basename only, no slashes, max 255 bytes
[32] blake3
```

Bytes ride on the **bulk** connection as a dedicated bidirectional stream:

```text
u128 id
u64  offset              # resume point
then raw file bytes until size
```

Hash is computed on the receiver over the file as it hits disk. A mismatch deletes the partial file. Window cap is a session concern (4 MiB), not a protocol field, in v1.

### Handoff (M4)

```text
u64 generation
u32 app_id_len
u8  app_id[...]
u32 title_len
u8  title[...]           # max 128 bytes
u32 uri_len
u8  uri[...]             # max 2 KiB
u32 extra_len
u8  extra[...]           # optional scroll/selection blob, opaque, max 1 KiB
```

Latest generation per `app_id` wins.

## Limits agents must enforce before allocate

- Header `body_len` checked against the class max.
- Clipboard text max 16 KiB on this class. Bigger means "use blob", not "raise the cap quietly."
- Display name max 32 bytes.
- One Hello per connection. A second Hello closes the connection.
- `seq == 0` is illegal.
- Nonce reuse or AEAD failure closes the connection and deletes 0-RTT tickets for that peer. It does not delete the long-term pin (that would turn a bit flip into an unpair).

## Compatibility

Version byte `1` only. Any other version: close with a log line, do not try to parse.

M0 must include a unit test that round-trips Hello, presence, and clipboard, and a test that a decremented clipboard generation is ignored. Those tests live in `link-proto` and do not open sockets.
