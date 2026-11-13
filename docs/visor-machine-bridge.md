# Local machine review bridge

`hypermesh-host visor bridge --config /etc/hypermesh/visor-bridge.json` is an
explicit Linux-only root service entry point. Installation does not enable it.
It serves one Unix socket; it never binds TCP. Kernel `SO_PEERCRED` separates the configured non-root Visor UID from root
control clients before HTTP processing. Other UIDs are dropped. Headers and
human tokens cannot substitute for kernel identity. Only root control clients
can obtain machine review; the non-root account can request catalog/dispatch
through fixed Conductor commands.
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
  "dispatch_config": "/etc/hypermesh/capability-dispatch.json",
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

The authorized Visor UID may read `GET /catalog` and call `POST /dispatch`.
Each invokes only the configured root-owned Conductor executable and dispatch
profile. The profile's controller must authenticate root peers and refuse every
non-root connection, so the Visor account cannot bypass machine review by calling
the controller directly. The root Conductor child validates the immutable notes,
reserves controller locks, obtains review, checks limits and deadlines, and
executes through that controller. No caller can select a program or profile.

Root control clients use `GET /capabilities` for the configured binding list and
`POST /review` for a machine review. These routes are unavailable to the non-root
Visor UID. Requests contain one binding plus a fresh UUID `call_id` and
`arguments_json`, a string containing the exact JSON argument bytes. A string
prevents transport reserialization from changing the reviewed tool arguments.
The bridge invokes the existing machine signer, then the configured trusted
Conductor review client with the signed request on stdin. It never returns the
private key or exposes a generic signing operation. Conductor's environment is
fixed and does not inherit provider credentials or injection variables.

An allow response contains `protocol_version: 1`, `call_id`, `call_sha256`
(SHA256 of the exact HTTP request body), `decision: allow` and `expires_at`.
The bridge independently checks Conductor's response against the signed request
and refuses deny, timeouts, mismatched call/digest/expiry and oversized output.
The caller must authenticate the server's kernel UID, correlate the body hash,
and recheck expiry at dispatch. No result is cached or reusable for another call.

The bridge never runs tool programs itself. Its fixed Conductor dispatcher uses the immutable capability catalog and requires a trusted controller that owns
locks, current preconditions, physical limits, cancellation and duplicate-call
prevention. A review cannot relax those controls. No systemd unit, sudo grant,
listener, package update or machine-key change is installed by this code change.
