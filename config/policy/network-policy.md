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

The `isolated` profile is conservative: it denies external, host, DNS, proxy,
and cross-project Docker access, while Compose integrity safeguards continue
to reject published ports and host-access paths. Other profiles can request
different modes, but the adapter reports unsupported modes instead of
silently weakening enforcement.

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
runtime acceptance tests.

Windows, VMware, VPN, and upstream network controls remain unverified unless
an independent adapter and runtime acceptance test exists. Tests requiring
real external connectivity are not performed by ordinary unit tests.