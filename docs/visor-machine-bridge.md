# Local machine review bridge

`hypermesh-host visor bridge --config /etc/hypermesh/visor-bridge.json` is an
explicit Linux-only root service entry point. Installation does not enable it.
It serves one Unix socket; it never binds TCP. Kernel `SO_PEERCRED` must identify
the configured non-root Visor UID before HTTP processing. Headers, human tokens,
root connections and other local accounts cannot substitute for that UID.
Connections and concurrent reviews are bounded. The socket's existing parent
must be root-owned and not writable by other users. Startup refuses an existing
socket instead of removing another server's endpoint.

Configuration is an owned regular file under trusted directories, with no group
or other write permission. Example shape (replace every deployment identity):

```json
{
  "schema": 1,
  "client_uid": 1001,
  "socket": "/run/hypermesh-visor-bridge/review.sock",
  "conductor": "/usr/lib/hypermesh-visor-headless/conductor",
  "authority_url": "https://authority.example/api/v1/aiuditor/capabilities/review",
  "base": "https://control-plane.example",
  "tenant": "11111111-1111-4111-8111-111111111111",
  "device": "22222222-2222-4222-8222-222222222222",
  "identity": "/var/lib/hypermesh/machine-identity.json",
  "enabled": []
}
```

Nothing is enabled by default. Each enabled binding contains `scope`, `owner`,
`capability_id`, `revision`, `source_sha256` and `graph_sha256`. All fields must
match; no wildcard or learned update is accepted. This local allowlist is
additional to AIuditor's current owner policy, never a substitute. The optional
`wireguard_key` selects an explicit existing key; otherwise the signer uses the
active device record as described in [machine signing](visor-capability-signing.md).

The authorized UID may read `GET /capabilities` for the configured binding list.
`POST /review` accepts one binding plus a fresh UUID `call_id` and
`arguments_json`, a string containing the exact JSON argument bytes. A string
prevents transport reserialization from changing the reviewed tool arguments.
The bridge invokes the existing machine signer, then the configured trusted
Conductor executable with the signed request on stdin. It never returns the
private key or exposes a generic signing operation. Conductor's environment is
fixed and does not inherit provider credentials or injection variables.

An allow response contains `protocol_version: 1`, `call_id`, `call_sha256`
(SHA256 of the exact HTTP request body), `decision: allow` and `expires_at`.
The bridge independently checks Conductor's response against the signed request
and refuses deny, timeouts, mismatched call/digest/expiry and oversized output.
The caller must authenticate the server's kernel UID, correlate the body hash,
and recheck expiry at dispatch. No result is cached or reusable for another call.

This is a review bridge, not a root tool executor. Conductor/Visor dispatch must
still use the immutable capability catalog and a trusted controller that owns
locks, current preconditions, physical limits, cancellation and duplicate-call
prevention. A review cannot relax those controls. No systemd unit, sudo grant,
listener, package update or machine-key change is installed by this code change.
