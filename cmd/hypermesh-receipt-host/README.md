# Host usage receipts

Run `go run ./cmd/hypermesh-receipt-host` on the inference host for one active P2 lease. Route Conductor's authenticated tier to the adapter on 127.0.0.1:18081 through your existing trusted transport. Use the same model and recipe digest for this tier and the host runtime.

Set RECEIPT_RUNTIME_ORIGIN to the local HTTP runtime (loopback IP with port), RECEIPT_PLANE_ORIGIN to the HTTPS plane origin, RECEIPT_LEASE and RECEIPT_TENANT to their UUIDs, and RECEIPT_MODEL and RECEIPT_RECIPE_SHA256 to the deployed model and recipe. Set RECEIPT_INGRESS_TOKEN as Conductor's provider key. RECEIPT_DEVICE_TOKEN_FILE points to the bound device's protected runtime credential file.

The adapter forwards authenticated tokenizer requests and non-streaming chat to the local runtime. It submits measured prompt and completion counts under the runtime's completion ID. An incomplete response or unconfirmed receipt returns an error and can leave the attempt outstanding. Retrying inference is a new execution. Durable receipt redelivery and streaming remain open.
