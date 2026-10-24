# Evidence Handling

## Staging layout

The configured staging root defaults to `evidence-staging`. Scientific run evidence is grouped by instance and run ID:

```text
evidence-staging/science/<instance-id>/<run-id>/
```

The command-driven workspace and operational scripts create run-scoped
records, captures, and incident evidence. Not every file is produced by every
command or investigation.

Run metadata and additional operational records are stored under `state/`; controller events are appended to `logs/controller.log`. Neither is a substitute for inspecting the evidence directory and command results.

## Review and archive

Review the selected staging directory and recorded artifact hashes before
copying evidence to an approved archive directory under the repository:

```bash
python3 lab/lab.py archive \
  evidence-staging/<run-id> \
  --destination state/archives
```

The controller writes `evidence-manifest.json`, verifies every listed SHA-256
digest in staging and again after copying, and refuses overwrite. It does not
erase staging. Without `--destination`, hashing remains local and durable
transfer is not tested. The controller intentionally rejects destinations
outside the repository; an external transfer is a separate operator-approved
boundary.

## Interpretation

SHA-256 manifests establish correspondence between files at hashing and verification time. They do not establish the truth of observations, completeness of packet capture, absence of omitted evidence, or authenticity of the host. Capture visibility is limited to the selected interface.

See [../lab-set.md](../lab-set.md) for the command sequence and [implementation-status.md](implementation-status.md) for acceptance limits.
