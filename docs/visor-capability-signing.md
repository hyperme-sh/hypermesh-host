# Host machine signatures for capability review

`hypermesh-host visor sign-call --call CALL.json --base HTTPS_CONTROL_PLANE
--tenant TENANT_UUID --device DEVICE_UUID` signs a bounded call using the existing
machine checkpoint, defaulting to `/var/lib/hypermesh/machine-identity.json`.
The WireGuard key defaults to the active `wg_key_dir` in the checkpoint
directory's private `device.json`, cross-checked against the requested device.
Only legacy state without that field uses `/etc/wireguard/hypermesh.key`. Missing
or mismatched device state refuses the default instead of selecting another
key. Explicit `--identity` and `--wireguard-key` paths support an
operator-selected enrollment. Files must be owned private regular
files beneath trusted directories. The operation never enrolls, renews, rotates,
replaces or weakens a key. It refuses pending rotation and mismatched active
network/tenant/device context.

The call file has `scope`, `owner`, `capability_id`, `revision`, `source_sha256`,
`graph_sha256`, a fresh UUID `call_id`, and an `arguments` JSON object. The signer
hashes the exact argument bytes as parsed, including whitespace inside that
object. It derives the WireGuard public key from the existing private key and
uses the enrolled Ed25519 identity for the distinct capability-review signature
domain. Neither private key appears in the output. The request expires after
20 seconds and includes a fresh random nonce.

Pass stdout directly to `conductor capability-review --endpoint
https://AUTHORITY/api/v1/aiuditor/capabilities/review`. This requires the Conductor
client introduced in PR56 and AIuditor's capability contract introduced in PR89.
The host signer does not call an alternate local allow implementation. No human
JWT or manually issued machine bearer is needed for review. Owner opt-in remains
an independent interactive operation in AIuditor.

This command signs only; it neither executes tools nor starts a listener. The
executor must retain the exact argument bytes and graph, authenticate actual
WireGuard peers, preserve loopback/tunnel-only binding, submit every call through
Conductor, enforce denials and expiry, prevent duplicate execution, and honor
controller limits below Visor. A signed key claim alone is not a tunnel check.
This advances Visor #99 without completing its dispatcher/interface work.

Machine call signatures do not enable package signing or alter the deferred
release-signing work.
