# Investigation Authoring

Author an investigation outside the installed lab resources. The specification
is not a predefined experiment or template; it is supplied by the researcher
for one construction.

Required top-level sections are:

- `schema_version`
- `investigation`
- `apparatus`
- `resources`
- `procedure`
- `observations`
- `evaluation`
- `evidence`
- `safety`
- `resource_budget`

The apparatus currently uses the `docker.compose` backend. Procedure
operations are declarative and bounded: `construct`, `run_service`,
`collect_logs`, `stop`, and `destroy`. Arbitrary host shell execution is not
supported.

Validate and plan before construction:

```bash
python3 lab/lab.py validate-investigation path/to/investigation.yaml
python3 lab/lab.py plan path/to/investigation.yaml \
  --investigation-id local-study-01 \
  --output state/plans/local-study-01.json
```

The generated plan records resource resolution, the specification digest,
ownership, approvals, topology, procedure, and budgets. Review it before
authorizing construction. If the apparatus selects a network profile, the plan
also records the fully resolved policy, provenance hashes, adapters, scopes,
requested capabilities, and verification requirements. `active-profile` is
only the default when no profile is requested; it does not rewrite existing
plans or active experiments.
The plan also includes `network_policy_supported` and any
`network_policy_capability_error`. Do not construct unless the policy is
supported; plan generation itself does not enforce it.

Capabilities and materials are separate catalogs. The `capabilities` command
lists supported lab operations and adapters; the `materials` command lists
explicitly approved artifacts. A
resource is catalog-backed only when its entry names an available
`material_id` of the same kind. The materials catalog may be empty; do not
substitute a capability ID or an image name for a registered material. Compose
images must still be available locally. An unregistered local image may be
used by the existing Compose workflow, but it is not thereby approved as a
material; if its exact image reference is registered, that material must be
available.

Use the network-specific preflight before construction:

```bash
python3 lab/lab.py networks validate-config
sudo -v
python3 lab/lab.py networks preflight
python3 lab/lab.py networks plan --profile isolated \
  --output state/network-plans/isolated.json
```

The current Linux/WSL adapter supports only owned deny-mode IPv4/IPv6 bridge
enforcement. Controlled restricted paths, monitor-mode enforcement, Windows
host controls, and temporary maintenance access must not be requested unless
the corresponding adapter capability has been implemented and verified.
`construct-investigation` creates the project-owned Compose network and applies
and verifies its boundary before starting services. `networks apply` requires
that network to exist; it does not create a network or replace construction.
The supplied profiles currently require unsupported Windows-host, DNS, proxy,
and external runtime-acceptance boundaries, so construction correctly rejects
them while the researcher’s policy still requires those controls. Disabling an
unsupported boundary is an explicit reduction in guarantees, not evidence of
isolation. No Windows Firewall or upstream isolation is implied.
