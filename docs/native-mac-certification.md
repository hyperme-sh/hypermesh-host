# Evaluate a native Mac certificate

Native collection without enrollment remains available with
`measure-certification`, or `certify-agent` with local measurement flags.
A completed local report is not an issued certificate.

For an enrolled, inactive Apple silicon Mac, the companion Plane evaluator can
freeze an independently reviewed Metal reference and workload. Use the existing
registration plan digest from `registration-status`. Create a root-owned mode
0700 directory for the plan and reports, then run:

```sh
sudo hypermesh-host plan-certification \
  --registration-plan-sha REGISTRATION_SHA \
  --plan /var/root/native-certification/plan.json
```

Review the returned model/runtime/collector pins and the local `plan_sha256`.
The server must have a verified native `metal-llama-bench-depth-v1` class reference,
matching GGUF catalog entry and reviewed runtime/collector pins. CUDA/HTTP
reference speeds are not native Metal references. Missing references do not
prevent independent local measurement collection.

Run the selected local files against that plan:

```sh
sudo hypermesh-host certify-agent \
  --plan /var/root/native-certification/plan.json \
  --approve-plan PLAN_SHA \
  --model-file /absolute/path/model.gguf \
  --runtime-file /absolute/path/llama-bench \
  --artifact-dir /var/root/native-certification/reports --run
```

The CLI checks the saved registration, installed configuration, unloaded host
services and absence of a lease, then runs three independent full-context `MTL0`
loads using the server's pins and context. It checks hardware/inventory drift
before and after measuring. The complete private report remains in the artifact
directory; only bounded measurement proof is uploaded. No service is stopped or
started by these commands. An active service must finish its supported maintenance
flow before inactive certification. The CLI does not interrupt a paid lease.

The plan file retains the request identity before the HTTP request. If planning
fails, retry the same command and file. During execution the approved plan stays
unchanged. `<plan>.evidence.json` retains the exact submission before upload;
retrying the same execution after a network failure reuses it without rerunning
inference. `<plan>.result.json` retains the server's result. Preserve these files
for recovery. An expired plan cannot start fresh measurements. A changed runtime,
reference, inventory or failed run requires a new plan filename and fresh samples.

The result states `passed` or `failed`, with selling still paused and
`physical_acceptance=false`. It does not permit native activation or automatic
renewal. No sustained-performance, tunnel, memory-protection or hardware-attestation
claim follows from this certificate. CLI/agent builds and operator policy must be
qualified and deployed separately; no release or deployment is performed by this
change.
