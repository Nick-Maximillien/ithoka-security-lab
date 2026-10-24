# Network Policy

The researcher-editable policy is under `config/networks/`. Select a profile
by changing the single line in `config/networks/active-profile`, or select a
profile and add boundary overrides in an investigation's
`apparatus.network_policy` section. The precedence is controller-integrity
safeguards, selected profile, investigation overrides, then temporary
maintenance overrides. Temporary state is never read as ordinary profile
configuration.

Use `python3 lab/lab.py networks show` to inspect the resolved policy and
`python3 lab/lab.py networks capabilities` to distinguish supported Linux/WSL
adapter controls from unsupported Windows-side controls.

The `isolated` profile requests denial of external, host, DNS, and proxy paths.
The current adapter does not implement distinct Windows-host, DNS, or proxy
enforcement, so it reports the supplied profiles as unsupported rather than
claiming those requested controls are enforced. Compose integrity safeguards
reject published ports and host-access paths. Other profiles can request
different modes, but unsupported requirements fail closed.

The enforcement point is Docker's effective network configuration plus the
policy-driven, project-scoped controller in `scripts/network-boundary.sh`.
Construction
creates the owned network and stopped containers first, then requires the
controller to install and verify IPv4 and IPv6 host/forwarding DROP rules
before any service starts. The controller requires Docker, `sudo`, `iptables`,
and `ip6tables`; missing tools or an unverified bridge fail closed. Rules are
identified by the project name and are removed only after the saved network
identity and ownership labels still match.

This is a Linux/WSL host control, not a Windows or VMware firewall. It does
not prove that Windows-side routes, WSL integration, VPN policy, or upstream
network controls are isolated. Those boundaries require separately authorised
runtime acceptance tests. The supplied external-network policy also requires
runtime acceptance, which the adapter does not implement; runtime support
validation therefore rejects construction before Compose resources are
created. A generated plan is not proof of enforcement.

`networks capabilities` reports Linux bridge-rule implementation separately
from runtime acceptance. `runtime verify` and `runtime doctor` report an
unsupported selected policy explicitly; `runtime start` revalidates the policy
even when the runtime state is already marked running and checks the
read-only machine prerequisites before changing runtime state.

Windows, VMware, VPN, and upstream network controls remain unverified unless
an independent adapter and runtime acceptance test exists. Tests requiring
real external connectivity are not performed by ordinary unit tests.