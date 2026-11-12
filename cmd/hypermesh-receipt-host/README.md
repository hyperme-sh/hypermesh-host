# Host usage receipts

Run `go run ./cmd/hypermesh-receipt-host` on the inference host for one active P2 lease. Route Conductor's authenticated tier to the adapter on 127.0.0.1:18081 through your existing trusted transport. Use the same model and recipe digest for this tier and the host runtime.

Set RECEIPT_RUNTIME_ORIGIN to the local HTTP runtime (loopback IP with port), RECEIPT_PLANE_ORIGIN to the HTTPS plane origin, RECEIPT_LEASE and RECEIPT_TENANT to their UUIDs, and RECEIPT_MODEL and RECEIPT_RECIPE_SHA256 to the deployed model and recipe. Set RECEIPT_INGRESS_TOKEN as Conductor's provider key. RECEIPT_DEVICE_TOKEN_FILE points to the bound device's protected runtime credential file.

The adapter forwards authenticated tokenizer requests and non-streaming chat to the local runtime. It submits measured prompt and completion counts under the runtime's completion ID. An incomplete response or unconfirmed receipt returns an error and can leave the attempt outstanding. Retrying inference is a new execution. Optional durable redelivery is described below. Streaming remains unsupported.

For a llama.cpp host, set `RECEIPT_TOKENIZER=llama.cpp`. Plain-text system, user and assistant messages use the serving model's chat template, special-token parser and reported context limit. The tokenizer rejects unsupported message types and template overrides before reservation. Leave the setting empty for runtimes that already implement the Conductor tokenizer response.

Optional extended quantity reporting uses `HYPERMESH_MODEL_REVISION` for the
operator-bound artifact identity and `HYPERMESH_USAGE_DETAILS=true` for reported
cache/reasoning subcounts. Enable these only with a Plane contract that supports
the fields. Defaults retain the legacy five-field report. A configured revision
must match Conductor's reservation. Unknown counts are omitted; invalid subcounts
fail instead of becoming zero or inflating totals.

Set `HYPERMESH_USAGE_OUTBOX` to a private absolute directory dedicated to this
lease and model/recipe scope for durable recovery. The adapter records an
uncertain attempt before inference, then atomically stores only final quantity
metadata before posting it. Startup redelivers pending reports idempotently,
without calling the runtime again. A duplicate attempt is refused; uncertain
attempts stay uncertain. Completed markers prevent duplicate inference until the
lease's outbox is explicitly retired. Prompt/response bodies and credentials are
never persisted. Missing storage or scope mismatch fails closed. This optional
recovery path does not add streaming support or enable monetary settlement.
