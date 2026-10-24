# Networks configuration

The active profile is the single line in `active-profile`. The twelve
authoritative, researcher-editable boundary files are under `boundaries/`.
Profiles under `profiles/` select those files and contain only explicit
profile overrides; they are not a second boundary source. Selecting a profile
never requires editing Python or shell source. The profile name does not assert that the current adapter supports every
enabled boundary.

The canonical profile names are exactly:

- `isolated`: deny unnecessary ingress, egress, host, DNS, proxy, and protocol
  paths.
- `observation`: keeps the same deny-by-default traffic controls while
  enabling explicitly scoped packet capture; observation is not isolation
  proof.
- `controlled-access`: requests explicit restricted paths and fails closed in
  the current adapter until those semantics can be verified.
- `maintenance`: keeps the ordinary supported deny policy; temporary
  dependency acquisition is a separate operation and is unavailable until
  verified temporary restoration is implemented.

Every boundary has `enabled`, `mode`, `direction`, `scope`, `rules`,
`exceptions`, `verification`, `description`, and `reason`. Modes are
`allow`, `deny`, `restricted`, and `monitor`. Profile resolution is
deterministic: controller-integrity safeguards are always first, the selected
profile is next, investigation overrides are next, and temporary maintenance
overrides are last and ephemeral.

The first Linux/WSL adapter fully enforces and verifies project-scoped `deny`
rules for IPv4 and IPv6. `restricted`, `allow`, and `monitor` are represented
and validated, but construction fails closed when the adapter cannot verify
their requested semantics. This prevents configuration from being mistaken
for enforcement. Windows, VPN, VMware, and upstream controls remain separate
capabilities.

Review machine-specific values before generating a plan:

```bash
python3 lab/lab.py networks discover
# run `networks configure` only if machine.yaml is missing
# review/edit the existing operator_confirmed values
python3 lab/lab.py networks validate-config
sudo -v
python3 lab/lab.py networks preflight
python3 lab/lab.py networks plan --profile isolated \
  --output state/network-plans/isolated.json
```

`machine.yaml` is host-specific: Docker context, interfaces and network
identities must be confirmed for the current machine. Discovery and validation are read-only.
Preflight verifies the context, default Docker networks, firewall backends,
and privileged read access to firewall rules without changing them. The plan
is read-only and its `supported` field is a policy capability result, not
proof of applied enforcement. The supplied profiles currently require
Windows-host, DNS, and proxy capabilities that are not implemented. The
external-network policy also requires runtime acceptance, which the adapter
does not perform. Therefore the supplied profiles report `supported: false`;
construction fails before creating Compose resources while those requirements
remain enabled.

`networks apply` is project-specific and requires an existing, uniquely
identified Compose network whose ownership labels match the investigation.
It does not belong to machine setup and does not create a network. Construction
creates that network, applies and verifies its boundary, then starts services.

Inspect the effective configuration with:

```bash
python3 lab/lab.py networks profiles
python3 lab/lab.py networks select isolated
python3 lab/lab.py networks boundaries
python3 lab/lab.py networks show
python3 lab/lab.py networks show dns
python3 lab/lab.py networks validate
python3 lab/lab.py networks capabilities
python3 lab/lab.py networks maintenance status
python3 lab/lab.py networks drift sec-lab-i-example
```

The effective policy is resolved when an investigation is planned and pinned
into its runtime policy JSON. Changing `active-profile` affects subsequent
operations, not an already-running investigation. `maintenance enter` and
`maintenance leave` fail closed until a temporary apply/restore adapter exists;
no broad maintenance access is opened implicitly.

The persistent runtime is managed separately from experiments:

```bash
python3 lab/lab.py runtime configure
python3 lab/lab.py runtime start
python3 lab/lab.py runtime verify
python3 lab/lab.py runtime status
python3 lab/lab.py runtime admit-experiment study-a --memory-mib 256
python3 lab/lab.py runtime release-experiment study-a
python3 lab/lab.py runtime stop
```

Runtime admission records ownership, pinned policy, resource reservations, and
conflicts under `state/runtime/runtime.json`. An active experiment prevents
runtime teardown. Maintenance requests are recorded and rejected until the
adapter can provide independently scoped apply, expiry, restoration, and
verification semantics.
