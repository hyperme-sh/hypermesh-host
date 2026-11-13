# On-request headless Visor bundles

`hypermesh-host visor install` installs a separately requested Linux headless
Visor tar bundle into a new private directory. It reuses the host updater's
bounded HTTPS downloads and detached GPG checksum verification. It does not
install packages, start services, change selling posture, configure WireGuard,
or grant any capability. This is the delivery portion of Visor #99.

The operator provides a local JSON descriptor with short-lived HTTPS URLs:

```json
{
  "schema": 1,
  "architecture": "x86_64",
  "bundle": {
    "name": "hypermesh-visor-headless-x86_64.tar.gz",
    "url": "https://artifacts.example/bundle?short-lived-token",
    "size": 123,
    "sha256": "<64 lowercase hex characters>"
  },
  "checksums": {"url": "https://artifacts.example/checksums", "size": 123},
  "signature": {"url": "https://artifacts.example/signature", "size": 123}
}
```

Replace every example size, URL and digest with the exact requested artifact.
Use `aarch64` and its corresponding filename on Linux ARM64. The archive digest
must match both the descriptor and the independently signed `checksums.txt`.
The public key and allowed fingerprints come from independent owner-controlled
configuration, never from the artifact download. No signing identity is created
by this command; unsigned development bundles are refused. Existing signing
and release deferrals remain unchanged.

Create an owner-controlled parent directory with mode 0700, then run:

```sh
hypermesh-host visor install \
  --directory /private/optional-components/visor \
  --manifest /private/request.json \
  --trusted-key /private/visor-release-key.asc \
  --fingerprints TRUSTED_FINGERPRINT
```

The descriptor contains temporary URL credentials; keep it private and discard
it when no longer needed. Download URLs and upstream errors are not printed or
saved. The installation marker contains only schema, architecture and archive
digest. No host device credential is forwarded to artifact storage.

Only the two static Linux binaries and the three packaged documentation/license
files are accepted. Traversal, links, special files, unknown entries, duplicate
files, wrong architectures and incomplete archives are refused. Downloads,
expanded bytes and individual documents have fixed limits. Failed installation
removes its newly created directory; an existing directory is never overwritten.
The command serializes installation/removal with an exclusive sibling lock.
After a crash, inspect the interrupted operation and its files before manually
removing that lock; commands do not guess whether another process is active.

Installation leaves the binaries inactive. Runtime management, owner opt-in
capability publication, machine identity and AIuditor/controller authorization
remain separate Visor #99 work. This command does not establish a moving update
channel or trust a mutable URL as artifact identity.

To remove the downloaded bundle, first stop any process you separately started:

```sh
hypermesh-host visor remove --directory /private/optional-components/visor
```

Removal accepts only its private installation marker, expected files and parent
directories. Unexpected files, links or runtime state cause refusal before any
deletion. Store credentials and runtime state outside this installation tree;
removal never erases the parent directory or sibling host files. To replace a
bundle, remove the inactive old installation and request the new verified one.
