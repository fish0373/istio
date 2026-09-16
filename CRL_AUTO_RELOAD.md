# Istio `caCrl` Auto-Reload — Change Notes

> **Audience**: this document is written to be handed to another AI agent/model (or a human
> reviewer) with no prior context on this change. It explains the problem, the fix, the exact
> files touched, why each change is safe, and what is *not* yet done. Every file path and
> identifier is copy-pasteable and can be grepped directly in this repo.
>
> **Repo**: `istio/istio` (shallow clone of `main`, commit `0cbbd4e` at the time of this work)
> **Branch**: `crl-auto-reload` (based on `main`)
> **Commit**: `735435b` — "Make DestinationRule/Gateway caCrl auto-reload like the root CA trust bundle"
> **Fork**: https://github.com/fish0373/istio/tree/crl-auto-reload
> **Status**: implemented and manually reviewed line-by-line; **not compiled or run** — no Go
> toolchain or running Docker daemon was available in the environment that produced this patch.
> Anyone picking this up should run `go build ./...` and the listed tests before trusting it further.

---

## 1. Problem statement

Istio lets a `DestinationRule` or `Gateway` configure `tls.caCrl`, a path to a Certificate
Revocation List (CRL) file used when validating peer certificates. Unlike the root CA
certificate (`tls.caCertificates`), which Istio already serves through node-agent's SDS
(Secret Discovery Service) and reloads automatically on file change, `caCrl` was embedded
directly into the generated Envoy config as a static `DataSource_Filename`. Envoy does not
watch `DataSource_Filename` paths for changes, and Pilot only regenerates the xDS resource when
the `DestinationRule`/`Gateway` *object itself* changes — not when the file it points to changes
on disk. Result: rotating/updating a CRL file required either touching the config object or
restarting the proxy. This defeats the point of a CRL (frequent revocation updates).

The user's ask: make `caCrl` reload automatically, the same way the trust bundle (root CA) does.

## 2. Root-cause analysis (how root CA auto-reload actually works)

Root CA auto-reload is not one mechanism, it's a pipeline of existing pieces that this change
reuses instead of duplicating:

1. **Resource naming encodes the file path.** `pkg/security/security.go`'s `SdsCertificateConfig`
   type has `GetRootResourceName()`, which turns a CA cert path into an SDS resource name like
   `file-root:/etc/certs/root-cert.pem`. Pilot puts this resource name into the Envoy
   `ValidationContextSdsSecretConfig` instead of embedding the cert bytes/path statically.
2. **node-agent resolves that resource name back to a file path and watches it.**
   `security/pkg/nodeagent/cache/secretcache.go`'s `generateFileSecret()` has a `default:` branch
   that calls `security.SdsCertificateConfigFromResourceName(resourceName)` to decode the path
   back out, reads it via `generateRootCertFromExistingFile()`, and registers an `fsnotify` watch
   on it via `sc.addFileWatcher(cfg.CaCertificatePath, resourceName)`.
3. **File changes flow through a fixed pipeline:** `fsnotify` event → `handleFileWatch()` →
   `sc.OnSecretUpdate(resourceName)` → the registered secret handler
   (`pkg/istio-agent/agent.go`: `RegisterSecretHandler(a.sdsServer.OnSecretUpdate)`) →
   `security/pkg/nodeagent/sds/server.go`'s `Server.OnSecretUpdate` → `sdsservice.go`'s `push()` →
   a new SDS `DiscoveryResponse` is streamed to Envoy for that exact `resourceName`.
4. **The response is built from bytes, not a filename.** `sdsservice.go`'s `toEnvoySecret()`
   puts the freshly-read cert bytes into `CertificateValidationContext.TrustedCa` as
   `DataSource_InlineBytes` — this is what actually gets pushed to Envoy, and Envoy accepts it
   immediately because it's a normal SDS update, not a file it has to re-open itself.

So "auto-reload" for root CA = **(a) put the file path into the SDS resource name, (b) let
node-agent's existing `fsnotify` watcher pick it up, (c) deliver it as inline bytes via SDS
push**. `caCrl` had none of these three things; it was hardcoded as `DataSource_Filename`
straight into the static xDS config, sidestepping the whole SDS/fsnotify system.

## 3. Design of the fix

Rather than inventing a second watch mechanism just for CRLs, this change makes the CRL path
ride along with the *already-watched* CA cert resource:

- The SDS resource name format is extended from `file-root:<caCertPath>` to
  `file-root:<caCertPath>~<crlPath>` when a CRL is configured (`~` is the existing
  `ResourceSeparator` already used by the `file-cert:` format).
- `generateRootCertFromExistingFile()` (root cert generation function) now optionally reads the
  CRL file too and puts its bytes on the same `SecretItem`.
- `secretcache.go` registers a **second** `fsnotify` watch, for the CRL path, under the **same**
  `resourceName` as the CA cert. Since node-agent's watch-to-resource mapping is keyed by
  `(resourceName, filename)` pairs (see `FileCert` struct), watching two different files under one
  `resourceName` is already a supported pattern — no new data structures needed.
- `sdsservice.go`'s `toEnvoySecret()` now sets `CertificateValidationContext.Crl` from
  `SecretItem.CRL` as `DataSource_InlineBytes`, the same way `TrustedCa` is already set from
  `SecretItem.RootCert`.
- On the Pilot side (`authentication.go`, `cluster_tls.go`), the code that used to write
  `defaultValidationContext.Crl = DataSource_Filename(crl)` directly now just adds the CRL path
  into the `SdsCertificateConfig{CRLPath: ...}` struct before calling `GetRootResourceName()` —
  it no longer touches `Crl` at all; the SDS-delivered secret carries it instead.

Envoy semantics note: In `CombinedCertificateValidationContext`, the dynamically-pushed secret
(`ValidationContextSdsSecretConfig`) is merged onto `DefaultValidationContext`. `TrustedCa` has
always been delivered this way; `Crl` can be delivered the same way with no Envoy-side changes.

## 4. Files changed (7 files, +85/-39)

| File | What changed | Why |
|---|---|---|
| [`pkg/security/security.go`](pkg/security/security.go) | Added `SecretItem.CRL []byte`; added `SdsCertificateConfig.CRLPath string`; `GetRootResourceName()` now emits `file-root:<ca>~<crl>` when `CRLPath` is set; `SdsCertificateConfigFromResourceName()` parses both the 1-part (`file-root:<ca>`) and 2-part (`file-root:<ca>~<crl>`) forms | Core data model + resource-name encoding that everything else depends on |
| [`security/pkg/nodeagent/cache/secretcache.go`](security/pkg/nodeagent/cache/secretcache.go) | `generateRootCertFromExistingFile()` gained a `crlPath string` parameter; reads CRL bytes (with the same retry/backoff as the cert read) and puts them on the returned `SecretItem.CRL`. In `generateFileSecret()`'s `default:` branch (the one that parses `file-root:`/`file-cert:` resource names), added `sc.addFileWatcher(cfg.CRLPath, resourceName)` when a CRL is present. All 3 call sites of `generateRootCertFromExistingFile` updated for the new parameter (2 pass `""` since they're unrelated to `caCrl`) | This is where the actual `fsnotify` watch gets registered — the mechanism that makes reload automatic |
| [`security/pkg/nodeagent/sds/sdsservice.go`](security/pkg/nodeagent/sds/sdsservice.go) | `toEnvoySecret()`: the CRL-setting logic is now a `switch`. New first case: if `SecretItem.CRL` is non-empty, use it as `DataSource_InlineBytes`. Existing case (renamed to second case, unchanged behavior): the global plugged-in-CA CRL (`features.EnableCACRL` + `security.CACRLFilePath`) still falls back to `DataSource_Filename` — that's a separate, pre-existing feature (see §6) and was left alone | Delivers the CRL bytes to Envoy over the same SDS push as the cert, instead of a static filename |
| [`pilot/pkg/security/model/authentication.go`](pilot/pkg/security/model/authentication.go) | In `ApplyToCommonTLSContext()` (used for Gateway/sidecar **server-side** mTLS validation, i.e. `ServerTLSSettings.CaCrl`): removed the `if crl != "" { defaultValidationContext.Crl = DataSource_Filename(crl) }` block; added `CRLPath: crl` to the `security.SdsCertificateConfig{CaCertificatePath: caCert}` literal that feeds `GetRootResourceName()` | Routes the server-side `caCrl` through the SDS pipeline instead of a static filename |
| [`pilot/pkg/networking/core/cluster_tls.go`](pilot/pkg/networking/core/cluster_tls.go) | In `constructUpstreamTLS()` (used for DestinationRule **client-side**/outbound mTLS, i.e. `ClientTLSSettings.CaCrl`): same change as above — added `CRLPath: tls.GetCaCrl()` to the `security.SdsCertificateConfig{...}` literal, removed the static `DataSource_Filename` block | Routes the client-side `caCrl` through the SDS pipeline too, so both TLS directions get the fix |
| [`pkg/security/security_test.go`](pkg/security/security_test.go) | Updated `TestSdsCertificateConfigFromResourceName` — converted positional struct literals (e.g. `SdsCertificateConfig{"cert", "key", ""}`) to keyed literals (`SdsCertificateConfig{CertificatePath: "cert", PrivateKeyPath: "key"}`), since `SdsCertificateConfig` now has 4 fields, not 3. Added a new case for `file-root:root~crl`. Changed the "invalid contents" case from `file-root:root~extra` (used to be invalid, is now a *valid* 2-part CRL form) to `file-root:root~crl~extra` (3 parts, still invalid) | Keeps this test compiling and correct after the struct/parsing change; documents the new valid/invalid boundary |
| [`security/pkg/nodeagent/cache/secretcache_test.go`](security/pkg/nodeagent/cache/secretcache_test.go) | Updated the one call to `generateRootCertFromExistingFile(...)` to pass the new 4th argument (`""`) | Keeps this test compiling after the signature change |

## 5. Why this should be safe (things checked by hand)

- **`caCrl` always implies a CA cert path exists.** `pkg/config/validation/validation.go:653-658`
  rejects `caCrl` when combined with `credentialName`, and requires `MUTUAL`/`OPTIONAL_MUTUAL`
  mode (which in turn requires `tls.CaCertificates` to be set, checked a few lines above at
  `validation.go:600-620`). So `GetRootResourceName()` never silently drops a configured CRL for
  lack of a CA cert path — `IsRootCertificate()` (`CaCertificatePath != ""`) is guaranteed true
  whenever `CRLPath != ""` in practice.
- **Positional-literal breakage was fully swept.** Added a 4th field to a struct that had 3;
  grepped the whole repo for `SdsCertificateConfig{` (`grep -rn "SdsCertificateConfig{" --include=*.go`)
  and fixed every non-keyed literal, including two in `security.go` itself
  (`SdsCertificateConfigFromResourceName`'s `file-cert:` branch and
  `SdsCertificateConfigFromResourceNameForOSCACert`) that were **not** in the CRL code path but
  would otherwise fail to compile.
- **Watch registration doesn't need new data structures.** `security/pkg/nodeagent/cache/secretcache.go`'s
  `FileCert{ResourceName, Filename, TargetPath}` key type already supports multiple files per
  `resourceName` (verified by reading `tryAddFileWatcher`/`addSymlinkWatcher`, lines ~354-479);
  adding a second `addFileWatcher` call for the CRL path under the same `resourceName` uses this
  as designed, doesn't collide with anything.
- **The other two CRL code paths are untouched:**
  - `pilot/pkg/xds/sds.go` (Gateway `credentialName` → Kubernetes Secret's `crl`/`ca.crl` key) —
    already auto-reloads via the Kubernetes Secret informer watch, unrelated code path, not
    touched.
  - `security/pkg/nodeagent/sds/sdsservice.go`'s global plugged-in-CA CRL
    (`features.EnableCACRL` + `security.CACRLFilePath`, the well-known
    `/var/run/secrets/istio/crl/ca-crl.pem`) — kept as a fallback `case` in the same `switch`,
    behavior for that feature is unchanged.
- **No Envoy-side change needed.** `CombinedCertificateValidationContext` already merges the
  dynamically-pushed secret onto the static `DefaultValidationContext`; `TrustedCa` already flows
  this way, `Crl` is just another field on the same proto message.

## 6. Three CRL code paths in Istio (context for the reader)

There are three independent ways CRL data reaches Envoy in Istio. Only path (A) was fixed here.

| Path | Config surface | Mechanism | Auto-reload? |
|---|---|---|---|
| **(A)** `DestinationRule`/`Gateway` file-based `caCrl` | `ServerTLSSettings.CaCrl` / `ClientTLSSettings.CaCrl`, paired with `CaCertificates` (a file path mounted into the pod) | **This change**: `file-root:<ca>~<crl>` SDS resource → node-agent fsnotify watch → inline SDS push | ✅ now yes (was no) |
| **(B)** `Gateway` `credentialName` | A Kubernetes `Secret` with a `crl`/`ca.crl` key, referenced by `credentialName` | Pilot's own SDS server (`pilot/pkg/xds/sds.go`) reacts to the Kubernetes Secret informer watch (`pilot/pkg/credentials/kube/secrets.go`) | ✅ already yes, untouched |
| **(C)** Plugged-in CA global CRL | `features.EnableCACRL` + the well-known file `security.CACRLFilePath` (`/var/run/secrets/istio/crl/ca-crl.pem`), mounted via a ConfigMap | istiod watches `/etc/cacerts` via `pilot/pkg/bootstrap/istio_ca.go`'s `fsnotify` watcher and propagates to per-namespace ConfigMaps, **but** node-agent's `sdsservice.go` only checked file *existence* (`isCrlFileProvided()`) and used `DataSource_Filename` — no fsnotify watch registered on the node-agent side | ⚠️ still no — separate, larger gap not addressed by this change (see §7) |

## 7. What is NOT done / follow-ups

1. **Not compiled or tested.** The environment used to write this patch had no Go toolchain and
   no running Docker daemon. Before trusting this patch:
   ```bash
   cd istio && go build ./...
   go test ./pkg/security/... ./security/pkg/nodeagent/... ./pilot/pkg/security/... ./pilot/pkg/networking/core/...
   ```
2. **Path (C) — the global plugged-in-CA CRL — is still not auto-reloading.** This is a distinct,
   larger gap: `security.CACRLFilePath` is never passed into `sc.addFileWatcher(...)` anywhere in
   `secretcache.go`, even though istiod's own copy of the same file (`/etc/cacerts/ca-crl.pem`) is
   correctly `fsnotify`-watched by `pilot/pkg/bootstrap/istio_ca.go`. Fixing this would need
   `secretcache.go`'s `RootCertReqResourceName` branch (the well-known `ROOTCA` SDS resource, not
   the `file-root:` one this change touched) to also read/watch `security.CACRLFilePath` and put
   it on `SecretItem.CRL` — the `toEnvoySecret()` change in this patch (case `len(s.CRL) > 0`)
   already supports this if that data ever gets populated for the `ROOTCA` resource; only the
   node-agent-side watch registration for path (C) remains.
3. **No integration/e2e test added.** `tests/integration/security/...` would be the right place
   for a real end-to-end test that writes a CRL file, mounts it via `caCrl`, updates the file, and
   asserts the proxy picks up the revocation without a restart. The unit-test changes in this
   patch only cover the resource-name encode/decode logic, not the full pipeline.
4. **No release note.** Upstream Istio requires a file under `releasenotes/notes/` for
   user-facing changes; not added since this patch hasn't been validated yet.
5. **Format assumption**: the `~`-separated resource-name encoding assumes neither the CA cert
   path nor the CRL path contains a literal `~` character. This is a pre-existing assumption of
   the `file-cert:`/`file-root:` scheme (already true for the 2-part `file-cert:<cert>~<key>`
   format before this change), not something newly introduced, but worth knowing if a path with
   `~` ever needs to be supported.

## 8. How to verify manually (once a Go toolchain is available)

1. Build a proxy with `caCrl` pointing at a file, e.g. via a `DestinationRule`:
   ```yaml
   trafficPolicy:
     tls:
       mode: MUTUAL
       caCertificates: /etc/certs/root-cert.pem
       caCrl: /etc/certs/ca.crl
       clientCertificate: /etc/certs/cert-chain.pem
       privateKey: /etc/certs/key.pem
   ```
2. Confirm the generated SDS resource name is `file-root:/etc/certs/root-cert.pem~/etc/certs/ca.crl`
   (visible via `istioctl proxy-config secret <pod>` or by inspecting the `ValidationContextSdsSecretConfig.Name`
   in `istioctl proxy-config cluster <pod> -o json`).
3. Update `/etc/certs/ca.crl` in place (e.g. `cp newcrl.pem /etc/certs/ca.crl`) without touching
   the `DestinationRule` object or restarting the pod.
4. Confirm via node-agent logs (`cacheLog` in `secretcache.go`, look for `"adding watcher for file certificate"`
   and later a repeat `"read certificate from file"` log) that the watch fired and the secret was
   regenerated, and that a new SDS push reached Envoy (e.g. via `istioctl proxy-config secret <pod>`
   showing the updated CRL, or Envoy stats for SDS updates).
5. Confirm a certificate that is newly listed in the updated CRL is now rejected without any
   restart.
