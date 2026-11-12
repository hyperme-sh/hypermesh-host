# Runtime service channels

Container jobs accept an explicit tag or moving channel in a deployment-approved
repository. Configure `HYPERMESH_RUNTIME_IMAGE_REPOSITORIES` as a JSON list of
exact registry/repository names through host deployment configuration. Empty,
malformed or duplicated policy fails closed. Shared reference vectors cover
repository boundaries, tags, credentials, whitespace and invalid references.

The new `runtime_image` task field normalizes into the existing `image_digest`
field. The older field can also carry an approved channel, preserving its value
through dispatch, runtime arguments and journals. Both fields in one request are
ambiguous and rejected. Existing immutable task references retain their previous
compatibility path; new `runtime_image` values must use the tag-only contract.

NVIDIA and HIP pull a channel before a new container start. A failed channel pull
cannot fall back to an older cached image. Immutable historical references retain
the existing exact-reference cache fallback. A retry retains the task's reference,
model and scope rather than selecting another runtime. Model-file hashes and
host-binary verification remain separate and mandatory in their existing paths.

The `hostchannel` owner case is compiled only with the `nightly` build tag and
registered in Infra's host-supervisor adapter. It uses a loopback plane fixture
and a stubbed Docker runner to check old/new dispatch shapes, scoped credentials
and pull retry. It does not qualify a physical GPU, registry rollout or real peer
installation; combined acceptance remains in Infra #922. Do not run or dispatch
the full nightly suite manually.
