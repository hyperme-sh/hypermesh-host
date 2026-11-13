# Guarded read-only clock controller

`hypermesh-host visor controller --describe` prints the reference driver's exact
condition, immutable limit revision, lock, timeout and freshness requirements.
The limit revision is SHA256 of `hypermesh-clock-controller-v1\nread-only\nno-arguments\n`.
Use those requirements in the owner-managed capability notes. Changing a note or
request cannot change this compiled rule. The only operation reads the clock;
arguments must be an empty object. There is no shell, arbitrary command, file
write, clock adjustment or actuator operation.

`hypermesh-host visor controller --config FILE` explicitly starts its Linux Unix
socket server. Configuration contains `schema: 1`, absolute `socket` and private
`state_dir` paths, and `binding` with the scope, owner, capability ID/revision and
source/graph hashes exported from the validated notes. The file and socket parent
must be root-owned. State is an existing owned mode-0700 directory. Nothing is
installed or started automatically.

The socket is mode0600 and authenticates kernel UID zero before accepting the
controller protocol documented by Conductor. The non-root Visor account cannot
call it directly. The root bridge runs the fixed Conductor dispatcher, which
must obtain AIuditor review before requesting execution. The controller itself
owns an exclusive clock lock, five-second preparation permits, at most one-second
freshness, exact binding/argument checks, and permit consumption. It rechecks
state and deadline immediately before reading. Denial/cancellation releases the
reservation; expiration also releases it after a lost cleanup request.

Before executing, the controller exclusively creates and syncs a record for the
call UUID, including a parent-directory sync. A used ID is refused across restart
or lost replies. It retains up to100,000 records and refuses work at capacity;
there is no remote deletion or reset API. Use a dedicated state directory and one
controller instance. Output contains only the current UTC time and Unix nanoseconds
as strings. This is a real read-only host capability, not a simulated actuator.

Additional hardware controllers must implement their own immutable driver rules,
root-peer authorization, lock/permit semantics, durable duplicate protection and
atomic last-moment e-stop/chassis/geofence/actuator checks. The clock driver does
not claim those physical implementations and refuses every non-clock operation.
Release signing and package versions are unchanged.
