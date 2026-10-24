# Constrained Security Labs Design

# Security Laboratory Design, Boundaries, Constraints & Research Architecture

**Foundational architecture document · Version 2.0 · 17 October 2026**

- **Owner of the foundational document:** Ithoka Microsystems
- **Operational identity of the laboratories:** Unbranded, internally maintained research environments
- **Primary workstation:** HP EliteBook 8470p — Windows 10 Pro, 8 GB RAM
- **Physical client endpoint:** Dell Latitude 3380 — Windows 10 Pro Education, 4 GB RAM
- **Lightweight execution environment:** WSL2 / Ubuntu / Docker
- **Full virtual-machine environment:** VMware Workstation Pro, subject to readiness verification
- **Primary development editor:** Visual Studio Code on the Windows workstation
- **Research scope:** Network security, networking, systems behaviour, software and network-application engineering, blockchain security, blockchain forensics, and evidence-driven investigation
- **Status:** Architecture baseline. The actual controls, isolation boundaries and lifecycle procedures remain unverified until tested.
- **Governing principle:** The laboratory environments are disposable; the research is not. The workstation is where ordinary development and business work continue. Experiments execute inside their assigned environments. Findings are preserved as evidence and knowledge, and useful solutions may emerge from that research.

## 1. Purpose and strategic position

### 1.1 What the laboratories are for

The laboratories are controlled, instrumented environments for investigating how systems communicate, behave, fail, expose information, enforce boundaries and recover. They support both practical security research and the development of useful technical capabilities.

They are not a change in Ithoka Microsystems’ business trajectory. They are experimental assets that extend Ithoka’s existing work in software engineering, business systems, research, automation, integration and operational reliability.

Ithoka’s public positioning starts with understanding real operating conditions, investigating what needs to be understood, and building the system or technical response that the work requires. Its research pages describe research as a way to establish what is actually happening before selecting a system, automation, information model or technology strategy. Its systems pages also connect deployment and operation to new evidence and further improvement. Ithoka Microsystems · Ithoka Research · Ithoka Systems.

Security and networking research fit that approach. Understanding DNS, transport behaviour, routing, endpoint communication, cryptographic protocols, service exposure, distributed systems or blockchain transactions can reveal a real requirement that existing applications do not adequately address.

The laboratories therefore have two inseparable purposes:

1. Investigate: understand a technical or operational reality through controlled experiments and evidence.
2. Develop: where research supports it, design, implement and test a useful tool, network service, protocol integration, defensive capability, application or other technical response.
A finding may remain a research finding. It may inform an existing Ithoka system. It may become a new network-facing capability or software component. It may lead to a client service, a deployment method, an operational control or a new research question.

No particular outcome is mandatory.

### 1.2 The relationship between research and development

The laboratory is not merely a place to practise attacks, and it is not a software product in itself.

Research and development share the same environment because building something often exposes questions that cannot be answered by reading alone. Conversely, research may reveal a problem worth solving with software.

The governing loop is:

Question → model → experiment → evidence → finding → design decision → implementation where justified → validation → operational knowledge → further research.

The development work remains part of this loop. It does not replace research, and research does not have to result in a standalone product.

Examples include:

- A DNS experiment reveals a practical method for distinguishing resolver failures from endpoint failures. The method may become part of a network-assurance utility.
- Packet observations show that a client cannot distinguish a remote service outage from a local routing failure. A diagnostic agent may be designed and tested.
- A controlled tunnel experiment exposes the difficulty of granting a client access to one service without providing access to an entire network. The findings may inform a reusable access-control mechanism.
- Blockchain transaction experiments reveal a gap between an RPC response, a transaction’s inclusion in a block, and its eventual finality. The findings may inform an evidence collection or transaction-monitoring utility.
- Smart-contract testing reveals an invariant violation. The research may produce a test, a remediation, a review method or a reusable defensive library.
These are possible outcomes, not commitments to build all of them.

### 1.3 Research Units and evidence

Ithoka’s Research Unit approach organises investigation around a question about a real system or operating reality. The laboratories follow the same principle.

A laboratory experiment should have a clearly defined question and produce evidence that can be interpreted independently of the runtime in which it was collected.

An experiment may yield:

- A confirmed behaviour or failure condition.
- A falsified hypothesis.
- A reproducible test case.
- A network capture or protocol analysis.
- A configuration or code change.
- A defensive control and its validation results.
- A working utility or application.
- A finding that changes a system design.
- An unresolved question with a documented explanation of what remains unknown.
Evidence is not merely an export of files. It includes the research question, conditions, procedure, observations, analysis, limitations and conclusion.

The lab’s runtime can be deleted after an experiment. Its useful findings must remain available for later research, implementation and review.

### 1.4 Research boundaries

The initial scope includes:

- Networking fundamentals: DNS, TCP, UDP, HTTP(S), addressing, routing, ICMP, IPv4/IPv6, latency, packet loss and connection behaviour.
- Network security: service exposure, access controls, network segmentation, firewalls, cryptographic tunnels, endpoint trust and defensive monitoring.
- Linux, Windows, Docker, WSL and virtual-machine behaviour.
- Packet capture, protocol analysis, logs, route inspection and evidence correlation.
- Secure client/server design and network-facing software.
- Defensive utilities, diagnostics, network agents, protocol adapters and controlled network services.
- Blockchain application security, smart-contract security, Ethereum development workflows, RPC behaviour and transaction analysis.
- Blockchain forensics, including transaction tracing, event/log interpretation, state changes, address relationships and the limitations of available evidence.
- Controlled, authorised use of deliberately vulnerable applications and targets.
- Secure implementation, test design, dependency verification and reproducible development.
- Resource-conscious deployment and reliability under failure.
Higher-risk experiments require a specific scope and isolation review. They must not be treated as automatically authorised simply because they run in a lab.

### 1.5 Out of scope by default

The following are not part of ordinary operation:

- Executing suspicious samples, untrusted binaries or unknown malware on the Windows host.
- Deliberately compromising the daily-use workstation.
- Uncontrolled scanning or exploitation of systems outside the authorised lab.
- Sending exploit traffic to unrelated public systems.
- Publicly exposing vulnerable services as a convenience.
- Broad host networking, unrestricted forwarding or permanent cross-silo connections.
- Running a full Ethereum validator or resource-intensive blockchain node without a separate capacity assessment.
- Treating a public testnet as a private environment where all variables are controllable.
- Treating a container, VM, VPN or packet capture as proof of complete isolation.
- Building elaborate infrastructure before a concrete research requirement justifies it.
The objective is a lean, useful research capability that can grow when the research, hardware and business justify it.

## 2. Foundational architecture decisions

The following decisions govern the laboratories.

1. The Windows host remains the permanent daily-use workstation. It supports ordinary development, VS Code, accounts, Ithoka business operations, trusted source code and research administration.
2. The lab environments are disposable. They are created for a purpose, used for controlled experiments, and removed when no longer needed.
3. The lab is not an Ithoka-branded software product. Its runtime components must not depend on an Ithoka name, company affiliation, logo, branded network, or product identity. The owner is identified in this foundational document only.
4. The architecture is defined by responsibilities and boundaries, not by names. Environments, networks, containers, VMs, scripts and temporary resources should use neutral, technical identifiers.
5. WSL/Docker is the first lightweight execution environment. It is suitable for many Linux userspace, application, service, protocol and container-network experiments.
6. VMware is the full-guest environment. It is used when a separate guest operating system, guest kernel or VM-specific behaviour is required.
7. The Dell is a physical client endpoint, not another lab host by default. Its primary role is to receive selected requests and test real client/server communication under a deliberately narrow access policy.
8. VS Code remains the primary editor on Windows. Lab code can be authored there, but untrusted or experiment code must execute in its assigned lab environment.
9. No lab receives broad access to the Windows host by default. Necessary exceptions must be designed, documented, narrowly scoped and tested.
10. No routine experiment has direct Internet access. Software acquisition and updates happen through a separate maintenance process. Public blockchain testnet experiments require a separately approved, narrowly mediated outbound path, described in Section 9.
11. No routine experiment communicates with another silo. WSL/Docker, VMware and the Dell are not connected merely because connecting them would be convenient.
12. Evidence transfer to the Windows host is manual by default. A future automated path may be considered only after its threat model and controls are documented and validated.
13. Research evidence is durable; experiment runtime is not. Disposable images, containers, VMs and scratch state may be destroyed, but required evidence, analysis and reproducibility records must first be preserved.
14. Every environment has a tested teardown procedure. The ability to start a lab is insufficient; it must also be possible to stop it, revoke its access and verify the expected state afterward.
15. No setting is accepted as proof by itself. An internal network, host-only adapter, firewall rule, tunnel, shutdown command or absence of captured packets must be tested against the relevant threat and expected paths.
Stopping workloads can reduce resource pressure and active network paths. It does not make the hardware physically independent, prove isolation or guarantee that every service has stopped.

## 3. Laboratory environments and their responsibilities

The architecture has three logical execution environments and one separate physical client endpoint.

- Environment A — Windows host: trusted daily workstation, management, source editing, host telemetry and evidence staging.
- Environment B — WSL/Docker: lightweight Linux execution, containerised services and internal container-network experiments.
- Environment C — VMware: full guest OS and kernel experiments on documented virtual networks.
- Physical client endpoint — Dell: a separate device for selected real-client experiments. It is not automatically connected to any lab network.
The environments are logically separated, not physically air-gapped.

```
                  EXTERNAL NETWORKS
           LAN / Wi-Fi / VPN / Internet
                         |
            Ordinary access is not
              experiment authorisation
                         |
+------------------------------------------------------+
| WINDOWS HOST — DAILY WORKSTATION                    |
|                                                      |
| VS Code • Trusted development • Management           |
| Host telemetry • Firewall • Evidence staging         |
|                                                      |
|  +----------------------+  +----------------------+  |
|  | ENVIRONMENT B        |  | ENVIRONMENT C        |  |
|  | WSL / Ubuntu / Docker|  | VMware guest systems |  |
|  | Containers / services|  | Guest OS / VM network|  |
|  +----------------------+  +----------------------+  |
|                                                      |
| Explicitly controlled management and test interfaces |
+------------------------------------------------------+
                         |
             Temporary, narrow tunnel
               only when required
                         |
+------------------------------------------------------+
| DELL — PHYSICAL CLIENT ENDPOINT                     |
|                                                      |
| Client application • Client-side observations         |
| No general access to the host or other lab networks   |
+------------------------------------------------------+

               Manual evidence transfer
                         |
                         v
                WINDOWS EVIDENCE STAGING
                         |
             Review • Hash • Archive • Backup
```

This diagram describes the intended relationship. It does not claim that the current adapter, firewall, tunnel or forwarding configurations already enforce it.

### 3.1 Environment A — Windows host

The Windows host is where the operator manages the research, edits code, reviews evidence and performs normal Ithoka work.

It is not the default place to install or execute:

- Deliberately vulnerable applications.
- Untrusted security tools.
- Suspicious scripts or binaries.
- Exploit practice code that has not been assessed.
- Experimental services that could bind to every host interface.
- Software whose effects on the host are unknown.
Trusted development tools may remain on Windows. A source editor is not itself the same thing as executing the program being edited. However, extensions, agentic coding tools, build scripts, terminals and debugging features can execute code or access credentials. Their permissions and the code they run must be considered separately.

### 3.2 Environment B — WSL/Docker

Use this environment when the research requires Linux userspace, containerised applications, APIs, databases, local services or container networking, but does not require an independent guest kernel for each workload.

It is the preferred initial environment for:

- Local client/server experiments.
- Deliberately vulnerable web applications.
- Small protocol and API services.
- Defensive utilities and network collectors.
- Smart-contract unit tests and local EVM development nodes.
- RPC clients and controlled blockchain tooling.
- Small network-facing prototypes.
- Reproducible software builds that can be executed without exposing the Windows host to untrusted execution.
Docker containers share the Linux host kernel of the Docker environment. They are not independent virtual machines. WSL2 itself is backed by a virtualised Linux environment and integrates with Windows in platform-specific ways. Neither fact eliminates the need to check host access, published ports, mounts, daemon privileges or network routes.

### 3.3 Environment C — VMware

Use VMware when a separate guest operating system or guest kernel is materially necessary.

Examples include:

- Guest OS security configuration and hardening.
- Service and operating-system interaction.
- Guest firewall and route behaviour.
- Client/server communication between different guest OS instances.
- System-level behaviour that cannot be represented adequately by containers.
- Controlled vulnerable-target practice that benefits from a disposable guest.
- Comparative testing across operating systems.
VMware is not the default choice for every experiment. On an 8 GB Windows host with an older CPU and mechanical HDD, a single small guest is a more appropriate initial target than a multi-VM topology.

Host-only and custom isolated networks are preferred for initial experiments. NAT is not an isolation guarantee because it may permit outbound access. Bridged networking is not enabled by default.

### 3.4 Dell — physical client endpoint

The Dell is a separate physical endpoint, introduced only when the research question benefits from a real second machine.

Its intended responsibilities are to:

- Initiate approved client connections.
- Receive explicitly approved test artifacts or commands.
- Run a lightweight client application.
- Produce client-side logs and observations.
- Demonstrate how a real endpoint behaves rather than a localhost process.
- Optionally capture its own communication when that helps answer a question.
It is not a mandatory monitor for the HP. It does not need VMware, Docker or a second copy of the lab infrastructure for its assigned role.

Its limited resources are relevant only to the client workload and any optional local tools. The critically low disk space and memory pressure recorded in the inventory still need basic remediation and remeasurement before routine use, but they do not make the Dell a proposed VM host.

The Dell’s Windows environment is the practice target for authorised experiments. It should be configured to expose only the service and capability that the experiment requires, rather than turned into a generally reachable extension of the lab.

## 4. Hardware baseline and readiness

### 4.1 Primary workstation — HP EliteBook 8470p

Inventory timestamp: 16 October 2026, 3:59:50 PM EAT.
| Property | Recorded observation |
| — | — |
| Model | HP EliteBook 8470p |
| OS | Windows 10 Pro, build 19045, 64-bit |
| CPU | Intel Core i5-3320M, 2.60 GHz |
| CPU topology | 2 physical cores, 4 logical processors |
| RAM | Approximately 8 GiB installed |
| Memory modules | 2 × 4 GiB |
| Storage | Hitachi HTS727550A9E364, approximately 500 GB HDD |
| C: free space | Approximately 52.7 GiB |
| Available memory at inventory | Approximately 3.4 GB |
| Wi-Fi | Intel Centrino Advanced-N 6205; reported link 144 Mbps |
| Ethernet | Adapter present; disconnected |
| Virtualisation-related state | Hyper-V virtual switch present; vmcompute and vmms reported running |
| Existing lightweight environment | WSL Ubuntu 22.04 and Docker, as previously reported |
| VPN | Proton VPN adapter reported up |

**Capacity policy**
The HP can support a constrained initial lab, but its memory, CPU and HDD impose limits.

- Prefer one principal lab workload at a time.
- Run one small VM initially, not a multi-VM estate.
- Stop Docker workloads and shut down WSL before VM experiments unless WSL is explicitly required.
- Power off VMware guests during ordinary Docker-mode experiments.
- Avoid simultaneous heavy builds, packet captures, multiple databases and guest disk activity.
- Measure memory pressure, paging, CPU and disk I/O before, during and after an experiment.
- Preserve adequate free disk space for VM disks, snapshots, captures, build artefacts and evidence.
- Do not run three full Ethereum execution/consensus nodes on this baseline.
- Use local EVM tooling and RPC-based testnet research where appropriate rather than attempting to sync a full public Ethereum node as the starting point.

**Virtualisation discrepancy**
The recorded CPU inventory reported:

- VirtualizationFirmwareEnabled=False
- VMMonitorModeExtensions=False
- SecondLevelAddressTranslationExtensions=False
However, systeminfo indicated that a hypervisor had been detected, and Hyper-V-related components and a default virtual switch were present.

These are not enough to determine whether VMware Workstation Pro will work as required. The discrepancy must be investigated before depending on VMware. A running hypervisor, firmware settings and the availability of CPU virtualisation features are distinct observations.

Required action: inspect the BIOS virtualisation setting and collect a read-only follow-up inventory. Do not assume VMware is ready, and do not change BIOS settings until the existing state is understood.

**Notable listening sockets**
The recorded inventory included listeners such as:

- TCP 5432 — PostgreSQL, reported on wildcard IPv4/IPv6 addresses.
- TCP 80 and 8080 — associated with PID 4 in the snapshot.
- TCP 139 and 445 — SMB-related.
- TCP 135 — RPC-related.
- TCP 2179 — associated with PID 1792.
- TCP 5040 — associated with PID 5108.
- TCP 4000 — loopback-only in the supplied snapshot.
These are investigation items, not automatic findings of vulnerability. Identify the owning process or service, its purpose, whether it is required, its binding address and the effective firewall scope. In particular, determine whether PostgreSQL actually needs to accept connections beyond localhost.

Do not blindly terminate PID 4 or close system services. Establish ownership, dependencies and intended exposure first.

**Network topology clue**
The HP had Wi-Fi address 192.168.137.43 and gateway 192.168.137.1, alongside the Proton VPN adapter and Hyper-V virtual networking.

This address pattern can occur with Windows hotspot or Internet Connection Sharing arrangements, but the inventory alone does not establish the actual topology. Map active adapters, routes, sharing configuration, VPN behaviour and forwarding before changing any of them.

### 4.2 Secondary endpoint — Dell Latitude 3380

Inventory timestamp: 16 October 2026, 3:48:15 PM EAT.
| Property | Recorded observation |
| — | — |
| Model | Dell Latitude 3380 |
| OS | Windows 10 Pro Education, build 19045, 64-bit |
| CPU | Intel Core i3-6006U, 2.00 GHz |
| CPU topology | 2 physical cores, 4 logical processors |
| RAM | Approximately 4 GiB installed |
| Memory module | 1 × 4 GiB |
| Storage | LITEON CV3-CE128-11, 128 GB SSD |
| C: free space | Approximately 99 MiB |
| Available memory at inventory | Approximately 539 MB |
| Wi-Fi | Intel Dual Band Wireless-AC 7265; reported link 780 Mbps |
| Ethernet | Adapter present; disconnected |
| Virtualisation-related state | HypervisorPresent=True; vmcompute stopped |
| VMware services | None listed in supplied snapshot |

**Assigned role and limits**
The Dell is a physical client endpoint. It is not a lab host, packet monitor for the HP, or general-purpose gateway.

The lab may send approved scripts, built artefacts, requests or test payloads to the Dell, and may receive client-side results when the experiment explicitly calls for them. The access path must be narrow, authenticated and temporary.

The Dell’s memory and disk condition still matter for basic Windows stability and the intended client application. They do not justify installing a VM or lab stack there, because that is not its assigned role.

Before routine experiments:

- Safely recover sufficient free disk space.
- Reboot and reassess idle memory pressure.
- Establish update/support status.
- Inventory listeners and network configuration.
- Confirm the tunnel software can run on the intended OS.
- Identify the specific client application and its resource needs.

**Network topology clue**
The Dell had Wi-Fi address 10.2.3.194, gateway 10.2.0.1, and a Wi-Fi Direct adapter at 192.168.137.1.

Together with the HP’s 192.168.137.43 address, this makes a hotspot/ICS relationship worth investigating. It does not establish the active connection path or which device shares connectivity with which.

Map the topology before altering Wi-Fi, VPN, ICS, adapters, firewall rules or tunnel settings.

### 4.3 Windows support and updates

Both machines were recorded as Windows 10 build 19045. Standard Windows 10 support ended on 14 October 2025. The applicable Extended Security Updates status or a migration plan therefore needs to be documented. The installed hotfix list is not proof that a system is fully patched. See Microsoft’s Windows 10 Extended Security Updates guidance.

The host’s role as a trusted daily workstation makes its update state a foundational security issue. The Dell’s role as a deliberately exposed client target also requires an explicit decision about whether the experiment is studying its current supported configuration or a legacy state.

### 4.4 Follow-up measurements

Maintain a record of later measurements without overwriting the original baseline.

**HP follow-up**

- BIOS virtualisation settings and CPU capability.
- WSL version and mode.
- Docker client/server version, context, images, containers and networks.
- Windows update/ESU status.
- Listener owners and intended exposure.
- VPN, hotspot/ICS, routes and forwarding configuration.
- Idle CPU, memory, disk and thermal baseline.
- Resource measurements for one Docker experiment.
- Resource measurements for one small VMware guest.
- Tunnel implementation and endpoint.
- Decision and date.

**Dell follow-up**

- Free disk space after safe cleanup.
- Memory pressure after reboot and at idle.
- Windows update/ESU status.
- Listener owners and intended exposure.
- Actual hotspot/ICS/network topology.
- Tunnel compatibility and endpoint.
- Client application and resource requirements.
- Optional packet-capture capability, if justified.
- Decision and date.

## 5. Operating modes and resource discipline

Operating modes define which workloads and paths may be active at a given time. They are not separate physical security domains.

### 5.1 Mode A — Ordinary Windows workstation

Purpose: ordinary software development, research administration, communication and Ithoka work.

- VMware guests are powered off.
- Lab-specific Docker workloads are stopped.
- WSL is shut down when not needed.
- The temporary Dell tunnel is inactive.
- No experiment-specific forwarding, firewall exception or network path is left enabled.
- VS Code and trusted development tools may be used normally, subject to their own permissions and security.
The host is not considered clean merely because the desktop looks idle. Verify relevant processes and network paths when a preceding experiment used temporary access.

### 5.2 Mode B — WSL/Docker experiment

Purpose: lightweight Linux, application, service and container-network experiments.

1. Close unnecessary Windows applications.
2. Verify VMware guests are powered off.
3. Confirm the Dell tunnel is inactive unless this experiment explicitly requires it.
4. Start WSL/Docker as required.
5. Inventory any pre-existing containers, images and networks before changing them.
6. Create the smallest topology that answers the research question.
7. Prefer a dedicated internal Docker network for experiments that do not require egress.
8. Avoid unnecessary –privileged, host networking, published ports, broad host mounts, host credentials and Docker socket access.
9. Capture at a documented point if observation is needed.
10. If using VS Code’s remote access to the environment, treat that as a specific host-to-lab development path and validate its scope.
11. If the Dell is required, establish the approved tunnel only after its target service and access rules are defined.
12. Export evidence manually, stop workloads and verify the final state.

### 5.3 Mode C — VMware experiment

Purpose: full guest operating-system and kernel experiments.

1. Stop Docker lab workloads.
2. Shut down WSL unless the experiment specifically requires it.
3. Confirm the Dell tunnel is inactive unless explicitly needed.
4. Start only the required guest.
5. Use host-only or a custom isolated virtual network initially.
6. Do not use bridged networking by default.
7. Do not treat NAT as isolation.
8. Disable unnecessary shared folders, clipboard, drag-and-drop and guest integration.
9. Capture from the guest, host or virtual interface only where the research question requires it.
10. If the Dell is needed, design a narrow path to the specific guest service. Do not give the Dell general membership of the VMware network.
11. Shut down the guest, remove temporary access and verify recovery.

### 5.4 Mode D — Temporary physical-client experiment

Purpose: test one approved service from the Dell.

This mode overlays Mode B or Mode C; it does not create a permanent connection.

1. Confirm the research question requires a separate physical client.
2. Identify the target service, protocol and port.
3. Identify the actual service address and where it is listening.
4. Select the tunnel endpoint and determine how the service will be reached from it.
5. Apply a default-deny policy before bringing up the tunnel.
6. Establish the authenticated tunnel.
7. Enable only the required route and access rule.
8. Verify the allowed path.
9. Test representative forbidden paths, including unrelated host services, ports and lab endpoints.
10. Run the experiment and collect evidence at relevant endpoints.
11. Stop client activity.
12. Stop the tunnel and revoke temporary permissions.
13. Confirm the formerly permitted service is no longer reachable through that path.
14. Record results and restore the ordinary operating mode.
The Dell should only have access to what the current experiment explicitly allows. Its ability to receive a payload does not imply permission for the lab to initiate arbitrary connections to the Dell or its other services.

### 5.5 Mode E — Dependency maintenance

Purpose: obtain software, dependencies, vulnerable training applications, test fixtures and updates.

1. Stop ordinary experiments.
2. Identify the exact dependency or image, source and required version.
3. Enable only the documented maintenance path.
4. Fetch the required artifacts.
5. Verify provenance, signatures or digests where available.
6. Close the maintenance path.
7. Verify that the environment no longer has ordinary outbound connectivity.
8. Test the intended isolated network boundary.
9. Start the actual experiment only after the isolation check passes.
This is the normal route for fetching Docker images, updating packages, obtaining VM software and acquiring vulnerable applications for offline practice.

### 5.6 Mode F — Approved blockchain testnet interaction

Purpose: query a public testnet or submit a deliberate test transaction when the research question requires actual public testnet behaviour.

This is not a general-purpose Internet-enabled lab mode. It is a specific exception with a separate access path and explicit limits. Section 9 defines it in detail.

The default execution environments remain without direct Internet access. Where possible, the experiment interacts with a controlled RPC broker rather than being given general network egress. The broker may communicate only with the approved RPC endpoint and permitted methods or request types.

A public testnet is a real external system. Even though testnet assets are not ordinary mainnet assets, the network is not owned by the researcher, and its infrastructure and service policies must be respected.

### 5.7 Resource stop conditions

Measure the idle host before establishing resource thresholds. Use Task Manager, Resource Monitor, Performance Monitor or Get-Counter where useful. Record CPU, available memory, paging, disk I/O and thermal/power symptoms before, during and after a workload.

Stop or contain the experiment if:

- Windows becomes unresponsive or ordinary work is threatened.
- Available memory becomes critically low or sustained paging degrades responsiveness.
- Disk I/O makes the system unusable.
- Unexpected heat, power behaviour or instability appears.
- An experiment exposes an unintended service or reaches an unintended network.
- The tunnel grants more access than approved.
- A workload consumes resources beyond its expected limit.
- Host integrity or security is in doubt.
As an initial guardrail, review whether to stop when available memory falls below roughly 10–15% of installed RAM or sustained paging starts to harm responsiveness. This is a conservative starting threshold, not a universal safety guarantee.

On the HP, prefer one principal workload at a time. On the Dell, the recorded baseline already shows memory pressure; remediate and reassess before routine client experiments.

## 6. Network boundaries and access control

### 6.1 Paths disabled by default

Unless a documented experiment requires otherwise, avoid or disable:

- Container → Windows host services.
- Container → LAN or Internet.
- VMware guest → Windows host services.
- VMware guest → LAN or Internet.
- Unnecessary WSL → Windows service access.
- WSL/Docker ↔︎ VMware communication.
- Dell → unrelated HP services.
- Dell → unrelated container addresses or VM networks.
- Lab → arbitrary Dell services.
- Guest shared folders, clipboard and drag-and-drop.
- Automatic mounting of sensitive Windows directories into containers.
- Access to SSH keys, credentials, browser profiles, source repositories or Docker socket.
- Published Docker ports, Windows port forwarding and bridged adapters unless explicitly approved.
- Persistent tunnel sessions or broad routes between environments.
WSL, Docker and VMware can introduce integration and networking behaviour that is not obvious from a single interface label. Inspect the actual configuration and test it.

Docker documents that an internal network restricts external connectivity, but also notes that host-to-container communication can still be possible through certain paths. An internal network is therefore an important control, not proof that the host cannot reach the container or that no other path exists. See the Docker network creation documentation.

### 6.2 Manual access-change record

No route, tunnel, port, bridge, port forward, shared folder, guest integration or cross-environment connection may be enabled casually.

Before changing one, record:

1. Experiment identifier and purpose.
2. Source and destination.
3. Source and destination interfaces or addresses.
4. Direction, protocol and port.
5. Enforcement point.
6. Expected allowed result.
7. Forbidden paths to test.
8. Capture and telemetry points.
9. Start time and expiry/revocation condition.
10. Rollback procedure.
11. Verification result after closure.
Enable one path at a time. Do not disable the entire firewall to make an experiment work. Do not expose a vulnerable service publicly as a troubleshooting shortcut.

### 6.3 Network profiles

Profile A — Internal isolated experiment

Only the named internal lab communications are intended. No external access is required.

Profile B — Dependency maintenance

A temporary, documented path is enabled to acquire or update specified dependencies. Ordinary experiments are not run during this state. The path is closed and tested before the environment is used for isolated research.

Profile C — Controlled cross-boundary experiment

A named endpoint is permitted to reach a named service on another device or environment. The Dell tunnel and a VS Code-to-lab development channel belong to this profile, with different target and permission requirements.

Profile D — Controlled blockchain RPC experiment

A research process may query or submit permitted testnet requests through a specific external RPC provider. Direct arbitrary Internet access from the experiment environment remains blocked. The RPC path is scoped, monitored and shut down after the experiment.

After a profile change, test both the intended path and representative forbidden paths. Where relevant, include IPv4, IPv6, DNS, proxy settings, routes, forwarding, published ports and alternate interfaces.

If the required restrictions cannot be enforced and tested, do not proceed on the assumption that the lab is isolated.

## 7. VS Code and the development/execution boundary

### 7.1 Governing rule

Code may be authored on Windows; experiment code executes in the environment assigned to the research.

VS Code remains the primary editor. There is no requirement to replace it with a separate editor inside each lab.

The critical distinction is between:

- Authoring: writing, reviewing, editing and organising source code.
- Building: compiling, packaging or resolving dependencies.
- Executing: running the code that performs the experiment.
- Observing: capturing its behaviour and collecting evidence.
These activities may happen in different environments. For example, a Python script can be written in VS Code on Windows, transferred into WSL, and executed there. A C program can be edited on Windows, compiled inside an isolated Linux environment and run against a lab target. A smart contract can be edited in VS Code while tests execute inside a local EVM environment.

The code being displayed in a Windows editor is not inherently dangerous. The danger comes from where code is executed, what privileges it has, what files it can access, what network paths it can use and what other tools are permitted to execute on its behalf.

### 7.2 Two approved development methods

**Method A — Manual transfer and execution**
This is the default method for higher-risk or less-trusted experiments.

1. Write and review source code in VS Code on Windows.
2. Save the source into a designated development workspace.
3. Inspect the files and remove credentials or unrelated content.
4. Transfer only the required source or build input to the lab through a deliberate, documented mechanism.
5. Verify the transferred content, such as by comparing a hash or reviewing the diff.
6. Build and execute it inside the lab.
7. Collect output and evidence there.
8. Manually export only the required evidence or reviewed artifacts to Windows.
9. Preserve the source, relevant build information, results and hashes.
10. Destroy the disposable runtime when it is no longer required.
The transfer mechanism must not quietly introduce a permanent broad shared folder. A manually selected file copy is acceptable only when the source and destination are understood and the transfer path itself is appropriate to the experiment.

**Method B — Controlled VS Code access to the lab**
This is allowed where development speed or repeated testing justifies it and the access path can be sufficiently constrained.

The editor remains on Windows. A VS Code remote-development mechanism may provide a terminal, language server or build workflow inside the lab. This can be convenient, but it is also a deliberate connection from the host into the execution environment.

The remote-development path must therefore be treated like an access channel, not a harmless editor feature.

Required conditions:

- The remote endpoint is the intended lab environment.
- Authentication is explicit.
- Access is limited to the intended workspace and services as far as the selected mechanism allows.
- The remote session is not a tunnel to the entire lab network.
- The lab does not gain general access to Windows source repositories, credentials, home directories or unrelated services.
- The host does not mount broad, sensitive paths into the lab.
- The lab has no direct Internet egress during the experiment unless a separately approved profile is active.
- The remote session is closed when no longer needed.
- The experiment can be stopped and the access path revoked independently of the experiment code.
- The final procedure tests that the development channel is no longer active.
Some remote-development mechanisms require a remote server process or network connection that does not fit a strict no-cross-boundary experiment. If a particular mechanism cannot meet the required boundary, use manual transfer for that experiment.

### 7.3 Development tunnel and Dell tunnel

The VS Code development channel and the Dell client tunnel share the same high-level requirements:

- Authenticated endpoint.
- Cryptographically protected transport where the chosen mechanism uses a network connection.
- Explicit destination and purpose.
- Narrow route and service access.
- No general network membership.
- No unrestricted forwarding.
- Activation only when needed.
- Verifiable closure.
- Evidence of the allowed path and representative forbidden paths.
They are not necessarily the same tunnel or configuration. The Dell tunnel is intended for client-to-service experiments. The development channel is intended for editor-to-lab development. They have different trust relationships and should have separate access policies and lifecycle records.

Do not create one broad tunnel and reuse it for both simply because it is convenient.

### 7.4 Agentic coding and build tools

VS Code agents, extensions, task runners, terminals, debuggers and build systems may execute commands or interact with files and networks. Their actions must follow the same execution boundary.

For higher-risk experiments:

- Do not allow an agent to execute the experiment on Windows merely because it has edited the file there.
- Direct build/test commands to the intended lab environment.
- Do not expose Windows credentials or unrelated source trees to the lab.
- Do not give an agent unrestricted host privileges or a broadly mounted Docker socket as a shortcut.
- Review dependency changes and commands that install software.
- Separate ordinary development credentials from experiment credentials.
- Keep private keys, wallet secrets and provider credentials out of repositories, screenshots and evidence bundles.
- If the agent or editor cannot be constrained to the intended execution environment, use manual transfer.

### 7.5 What development does not permit

The ability to edit code from Windows does not authorise the lab to:

- Execute arbitrary code on the host.
- Read unrelated Windows files.
- Reach every host listener.
- Use the host’s Internet connection without approval.
- Access the Docker daemon as an administrator.
- Share the host’s credentials or browser state.
- Leave a persistent development channel active after the experiment.
The execution boundary applies whether code is typed manually, generated by an AI agent, copied from a public repository or compiled from source.

## 8. Dependency acquisition and vulnerable application practice

### 8.1 Maintenance is separate from execution

The labs need software updates and external artifacts to remain useful. This does not require giving the experiment network unrestricted Internet access.

The preferred workflow is:

Acquire → verify → stage → import or install → close access → test isolation → experiment.

Acquisition and execution are separate operating states.

The same principle applies to:

- Docker images.
- Linux packages.
- VM installation media.
- Vulnerable training applications.
- Exploit-practice source code.
- Compiler and language dependencies.
- Blockchain toolchains.
- Smart-contract libraries.
- Test fixtures and forensic datasets.

### 8.2 WSL/Docker maintenance

The Docker environment will sometimes need network access to fetch current images or software. This should be a deliberate maintenance operation.

Preferred sequence:

1. Stop the active experiment.
2. Identify the required image, package, source repository or dependency.
3. Use a trusted source and specify an exact version or digest where practical.
4. Temporarily enable the approved acquisition path.
5. Fetch the artifacts.
6. Record the source, version, digest and acquisition time.
7. Verify signatures or published checksums where available.
8. Close the acquisition path.
9. Test that the isolated experiment network cannot reach the Internet.
10. Start the experiment only after the test passes.
Use official images and repositories where practical. Pin versions or digests when reproducibility matters; avoid relying on a moving latest tag for a repeatable experiment. Preserve lockfiles, manifests and image digests.

An internal Docker network is appropriate for workloads that do not require egress. Do not use host networking, –privileged, broad port publishing or sensitive host mounts as a shortcut. Do not mount the Docker socket into a vulnerable target or exploit container unless the experiment specifically concerns that interface and has a separate risk assessment.

### 8.3 VMware guest maintenance

A guest may need an update, vulnerable target or training application. The preferred process is:

1. Power off or snapshot the disposable guest as appropriate.
2. Preserve the evidence and configuration required for reproducibility.
3. Acquire required packages or installation media through the documented maintenance process.
4. If guest egress is unavoidable, enable the narrowest practical path for the shortest required period.
5. Install or update the intended components.
6. Close the access path.
7. Restore the isolated network configuration.
8. Boot the guest and test that unintended egress and host/LAN access are unavailable.
9. Record the versions and verification evidence.
NAT may still allow outbound connectivity. Do not treat a NAT adapter as equivalent to an isolated network.

### 8.4 Vulnerable applications and exploit practice

Vulnerable training applications are valid research targets when intentionally selected and used within their intended scope. They should be placed in a disposable environment with no unrelated host credentials or sensitive data.

For each target, record:

- Application and version.
- Official or trusted source.
- Purpose of the target.
- Required dependencies.
- Expected network ports and services.
- Required privilege level.
- Intended attack surface.
- Whether Internet access is needed for acquisition only.
- Whether the application contains known default credentials or destructive functions.
- The teardown and evidence-retention plan.
The lab should not assume that every repository named “vulnerable lab,” every container image or every exploit script is trustworthy. Inspect the source, pin the version, and understand the privileges and network access before running it.

### 8.5 Artifact integrity

A checksum or hash can establish that the acquired artifact matches a recorded digest. It does not independently establish that the artifact is safe or that the source is trustworthy.

Where available, verify:

- Publisher signatures.
- Official checksums.
- Repository provenance.
- Release/version information.
- Container image digests.
- Lockfiles and dependency manifests.
Preserve the verification result. If provenance cannot be established, record that limitation rather than treating the artifact as trusted.

## 9. Blockchain security and forensics research

Blockchain research is part of the same laboratory strategy as traditional networking and security. It does not have to wait for better hardware, and it should not be limited to theory.

The design must, however, distinguish between a local EVM development environment, a real Ethereum node, and a client interacting with a public testnet through an RPC provider. They answer different research questions.

### 9.1 Three different blockchain research environments

Environment 1 — Local EVM and smart-contract laboratory

**Initial priority**
Use Foundry’s forge, cast and anvil, or a comparable lightweight development toolchain, for contract compilation, testing, deployment to a local chain, transaction inspection, reverts, events, state changes, fuzz tests and controlled failure cases.

Anvil is a fast local Ethereum development node. It provides a local EVM and JSON-RPC interface, pre-funded development accounts, configurable mining behaviour, tracing and state controls. It is useful for repeatable contract and application tests. It does not, by itself, create a real multi-peer Ethereum network.

Ethereum Development Framework
+1

Environment 2 — Public testnet through an RPC provider

**Controlled external access**
Use a provider endpoint to read Sepolia chain data, inspect contract state, deploy a test contract, submit transactions and compare local assumptions with public testnet behaviour.

This is the most practical initial way to interact with a real public testnet without maintaining a local Ethereum node. It exposes the experiment to provider behaviour, rate limits, network conditions, public chain state and confirmation/finality timing, but it does not give the lab direct visibility into the entire Ethereum peer-to-peer network.

Environment 3 — Local Ethereum network node research

**Later, capacity-dependent**
Running a genuine Ethereum node involves more than launching a JSON-RPC server. Current post-Merge Ethereum node architecture uses an execution client and a consensus client, which participate in distinct peer-to-peer networks and communicate through the Engine API. A validator is an additional component for block proposal and attestation duties.

ethereum.org
+1

This environment is deferred until hardware, storage, synchronisation time and operational requirements justify it. It is not a prerequisite for beginning smart-contract security or blockchain forensics.

### 9.2 Initial implementation on the HP

The initial blockchain environment should run in WSL/Docker or another suitable disposable environment on the HP, subject to resource measurements.

The first capability set is:

- Foundry toolchain: forge, cast and anvil.
- Solidity contracts and unit tests.
- Local transaction submission and receipt inspection.
- Event/log analysis.
- Contract state queries and state-transition tests.
- Reverts, access-control tests and controlled adversarial test cases.
- Fuzzing and invariant testing where resource limits allow.
- ABI and calldata inspection.
- Python-based analysis using a suitable Ethereum library where useful.
- RPC interaction with a public testnet through a separately controlled path.
- Evidence capture for transactions, receipts, logs, bytecode, source version, block number and RPC observations.
Use one local development node initially. A local Anvil node is sufficient for many smart-contract experiments; the purpose of the experiment determines whether additional nodes are necessary.

The local EVM workload should be bounded by resource measurements. There is no requirement to keep it running continuously. Start it when the experiment needs it, preserve the evidence, and stop it afterward.

### 9.3 What Anvil can and cannot establish

Anvil can support controlled tests of contract execution and local JSON-RPC interactions. It is valuable because it allows repeatable setup, rapid transaction execution, controlled mining behaviour and inspection of execution traces.

Ethereum Development Framework
+1

Anvil alone does not establish:

- Real Ethereum peer discovery.
- Execution-client transaction gossip between independent peers.
- Consensus-client block gossip or fork-choice behaviour.
- Real network propagation delay between independent Ethereum nodes.
- Public-network mempool behaviour.
- Validator or consensus-client security.
- The behaviour of every RPC provider or public node.
- The performance of a real Ethereum node under production workload.
Three Anvil processes connected to one Docker bridge would create three local EVM processes that can be reached over that Docker network if configured accordingly. They do not become a genuine Ethereum P2P network merely because they have different IP addresses. Each would maintain its own local development chain unless additional software or an explicit protocol mechanism connected their behaviour.

Therefore, the initial blueprint does not prescribe three Anvil containers as a substitute for a real Ethereum network.

Use multiple local EVM instances only when the question specifically concerns separate RPC endpoints, isolated chain state, client integration or a deliberately implemented application-level simulation. Do not describe that setup as real Ethereum peer-to-peer research.

### 9.4 Public testnet research

Sepolia is useful when the research question requires real public testnet state or transactions. It should not be treated as a fully controlled experiment, and the researcher should not assume that all public-testnet activity can be reproduced exactly.

Suitable initial questions include:

- How does a locally tested contract behave when deployed to Sepolia?
- How do a submitted transaction, its receipt and its block inclusion differ in observed time?
- What does the RPC provider return before and after a transaction is included?
- How do logs, events and state queries relate to a transaction receipt?
- What happens when a transaction reverts?
- How does the provider respond to an invalid request, a rate limit or an unavailable endpoint?
- How does the lab record evidence when a request times out but the transaction may still have been accepted?
- How can an analyst correlate a transaction hash, block number, receipt and contract event?
- How can a contract’s expected invariants be checked against observed on-chain state?
Use a provider account or public endpoint according to its documented terms and limitations. Provider responses are evidence of what that provider returned; they are not the same as independently verifying every network event from the lab.

The Ethereum documentation describes third-party node providers as an alternative to operating a local node, with corresponding trust and operational considerations. Ethereum: Nodes as a Service. For the initial resource-constrained setup, an RPC provider is a practical interface to the public chain, not a replacement for all possible node-level research.

### 9.5 The external-traffic boundary for blockchain

There is an important distinction in this architecture:

- The default rule is that lab workloads have no direct Internet access.
- Dependency acquisition is a separate maintenance operation.
- Public blockchain testnet interaction is a separate, explicitly authorised research profile.
A real testnet transaction necessarily involves sending a request or transaction to an external service. It would be technically incorrect to claim that a lab can submit a transaction to Sepolia while no information or experiment-related traffic ever leaves the local environment.

To preserve the core isolation model, the lab should not receive general Internet access. Instead, the preferred design is a narrow RPC broker or controlled outbound gateway that performs the explicitly approved external operation on the experiment’s behalf.
Local contract/client experiment
|
| Approved RPC request
v
Controlled RPC broker
- explicit endpoint
- approved methods
- bounded request types
- credential protection
- request/response logging
|
| Only the approved external path
v
Public testnet RPC provider
|
v
Sepolia

This is a mediation boundary, not a magical way to make an external request local. Experiment-related information still reaches the provider. The purpose is to ensure that the lab cannot freely connect to arbitrary Internet destinations, while the external action is narrow, visible and attributable.

The broker itself becomes a trusted component and must be reviewed. It must not become a general proxy, an unrestricted tunnel or a route into other host services.

Where a suitable broker cannot be implemented and verified yet, use a manual, controlled RPC client during a separately approved testnet session, with strict destination and method restrictions as far as the available tools permit. Do not claim that a broad host Internet connection is isolated merely because the application intends to contact one endpoint.

The invariant is: no direct, arbitrary egress from the lab; no communication between silos by default; any public testnet interaction is an explicit, narrowly mediated exception whose outbound traffic is acknowledged, recorded and tested.

### 9.6 Blockchain secrets and key handling

Private keys, seed phrases and provider credentials are sensitive. They must not be stored in public repositories, hardcoded in source, included in screenshots or left in disposable VM/container images.

For local development:

- Use development accounts and test keys only.
- Treat Anvil’s default development accounts and mnemonic as public, disposable test credentials, not as secrets suitable for external networks.
- Do not reuse a local development mnemonic for a public testnet or any real account.
- Keep local-only secrets in the disposable environment or a dedicated secret-injection method, not in committed source.
- Remove test secrets when destroying the environment.
- Do not export private keys with evidence unless the research explicitly requires the key material and a separate handling plan authorises it.
For Sepolia:
- Use a dedicated test account with no mainnet value or authority.
- Keep only the minimum testnet funds required.
- Use a provider credential with limited scope where possible.
- Avoid embedding the provider key in the RPC URL stored in source, shell history, screenshots or logs.
- Redact authentication headers and sensitive URL components from evidence.
- Never send a real mainnet private key or seed phrase to the RPC broker or lab.
The fact that a network is a testnet does not make secret-handling mistakes harmless.

### 9.7 Blockchain security research areas

The initial scope should include the following areas, ordered from accessible local tests to more involved public-network work.
| Area | Example research question | Preferred initial environment |
| — | — | — |
| Contract access control | Can an unauthorised caller change protected state? | Local EVM |
| State invariants | Which sequences of calls violate a defined invariant? | Local EVM and fuzz tests |
| Transaction semantics | How do calldata, execution result, receipt and logs relate? | Local EVM, then testnet |
| Reverts and error handling | Does the client correctly handle reverted or failed transactions? | Local EVM |
| Reentrancy and call interactions | Can a malicious test contract violate an expected invariant? | Isolated local EVM |
| Integer and accounting properties | Do arithmetic and accounting rules preserve intended state? | Local EVM |
| Event and log analysis | What can be inferred from emitted logs, and what cannot? | Local EVM and public RPC |
| Transaction tracing | What execution steps and state effects explain the result? | Local trace tools, then available external evidence |
| RPC behaviour | How does a client behave under timeout, invalid response or rate limit? | Local mock or broker, then controlled provider |
| On-chain forensic analysis | How are transactions, receipts, logs and addresses correlated? | Public testnet data and saved datasets |
| Deployment and verification | Do deployed bytecode and verified source correspond to the expected build? | Local build and testnet |
| Network-layer observations | What traffic is visible between client and RPC provider? | Capture at the documented client/broker boundary |
A testnet RPC provider does not reveal the provider’s internal node topology or all P2P traffic. HTTPS packet capture usually reveals connection metadata and encrypted transport, not the JSON-RPC payload itself. Application-level logging or a controlled local RPC broker is required when the research needs to preserve the request and response content.

### 9.8 Blockchain forensics and evidence

For a blockchain investigation, preserve the evidence needed to reproduce the analysis:

- Chain identifier and network.
- Transaction hash.
- Block number and block hash where applicable.
- Transaction receipt.
- Status and gas-related fields.
- Logs and event topics.
- Contract address.
- ABI and source version used for interpretation.
- RPC endpoint identity, excluding credentials.
- Query method and parameters.
- Query time.
- Raw response where appropriate.
- Tool and library versions.
- Analysis script and its hash.
- Relevant code or contract build information.
- Known limitations of the RPC source.
A decoded event is an interpretation of raw data using an ABI and assumptions about the contract. Preserve enough raw evidence to revisit that interpretation.

A transaction appearing in a block does not automatically establish that the transaction achieved the intended business effect. Review execution status, receipt, logs and state changes. Where confirmation or finality matters, record the chain observation and the point in time at which it was made.

### 9.9 What is deferred

Until resources and research requirements justify the work, defer:

- A fully synced Ethereum execution and consensus client pair.
- Validator operations.
- Multiple real Ethereum P2P nodes.
- Broad public-network propagation measurements.
- High-volume transaction generation.
- Large chain-history or state-data retention.
- Complex indexing infrastructure that duplicates data readily available through an existing provider.
- Automated interaction with public endpoints that cannot be constrained and audited.
These are future expansion options, not prerequisites for meaningful blockchain security and forensic research today.

## 10. Temporary cryptographic tunnel and physical-client access

### 10.1 Purpose

The tunnel supports experiments that need a real client on a separate physical device. The preferred candidate is WireGuard, subject to platform compatibility and a readiness assessment. WireGuard provides authenticated peers and encrypted transport, but does not by itself restrict a peer to a single application. WireGuard documentation.

The intended initial path is:

Dell client → encrypted tunnel → one approved service in the active lab environment.

The lab should not receive unrestricted ability to initiate arbitrary connections to the Dell. A later experiment may need a service hosted on the Dell or reverse-direction communication, but that requires a separate access design and risk review.

### 10.2 Required design decisions

Before configuring the tunnel, establish:

1. Where the tunnel terminates.
2. How the service running in WSL/Docker or VMware is reached from that endpoint.
3. The peer identities and tunnel addresses.
4. The specific target service.
5. The protocol and port.
6. The direction of initiation.
7. The permitted routes.
8. The firewall enforcement points.
9. The activation and expiry condition.
10. The teardown and verification procedure.
A service inside a container or VM is not automatically reachable through a tunnel terminating on Windows. Any forwarding or service exposure between the tunnel endpoint and the target must be explicitly designed.

### 10.3 Least-access policy

The tunnel must not:

- Route the Dell into the whole Docker, WSL or VMware network.
- Provide general access to Windows services.
- Enable LAN access through the tunnel.
- Enable Internet access through the HP.
- Create unrestricted forwarding between tunnel, Wi-Fi, Ethernet or virtual interfaces.
- Remain active after the experiment.
- Be treated as a substitute for service authentication or application security.
Avoid broad AllowedIPs or equivalent route definitions that unintentionally include whole LAN or lab networks. Route configuration and firewall policy must be reviewed together. WireGuard peer authentication establishes which peer is connecting; it does not prove that the peer is uncompromised or that the peer should be permitted to access every reachable service.

### 10.4 Activation and revocation

Activation is an experiment action. Deactivation and access revocation are required teardown actions.

The implementation must provide a clear method to:

- Establish the connection for a named experiment.
- Confirm peer and tunnel state.
- Enable only the associated access permission.
- Stop the connection at the end of the experiment.
- Revoke temporary firewall permissions and routes.
- Verify the tunnel and access path are inactive.
- Confirm that the formerly permitted service is no longer reachable through that path.
The configuration may remain available for future experiments only if it is non-operative by default and does not preserve broad access. The private key must be stored securely and never embedded in evidence or source repositories.

### 10.5 Allowed and forbidden path tests

For an experiment authorising access to one web service, for example, test:

- Allowed: the Dell reaches the specified service and port.
- Forbidden: the Dell cannot reach an unrelated Windows service, a different port, another container, another VM or an unrelated LAN destination through the tunnel.
- Closure: after the tunnel and temporary permissions are revoked, the previously permitted service is no longer reachable through that path.
Do not treat a failed connection as proof that a firewall denied it. A service may be down, a route may be missing or the client may be misconfigured. Use route inspection, listener checks, firewall evidence and packet observations to interpret the result.

A handful of failed connections does not prove every other route is blocked. Record the destinations, ports and address families actually tested.

### 10.6 Tunnel limitations

- Encryption does not make a vulnerable application safe.
- Peer authentication does not prove endpoint integrity.
- A compromised endpoint can use whatever access its policy grants.
- An allowed port may expose more functionality than intended.
- Host forwarding can create paths beyond the apparent tunnel endpoints.
- IPv6, DNS, VPN and virtual-adapter behaviour must be included where applicable.
- A capture on one interface may not reveal the entire route.
The tunnel is an experimental access mechanism, not a permanent remote-access service.

## 11. Wireshark, packet observation and leakage testing

Wireshark is a protocol analyser and evidence tool. It is not a firewall, an endpoint detection system or a mechanism that prevents traffic leakage.

Use it when a defined experiment requires packet-level evidence, when validating a boundary or when investigating suspected unexpected communication. It does not need to run continuously.

### 11.1 Select the capture point according to the question

**Windows Wireshark**

Use Windows Wireshark to observe traffic visible on selected physical, host and virtual interfaces. It does not automatically reveal every packet inside WSL2, every Docker bridge exchange or every VMware virtual-switch path. Validate the selected interface using a known test exchange.

**TShark or tcpdump in WSL**

Use command-line capture when the experiment concerns a WSL-visible interface or needs a repeatable, scriptable capture. A WSL capture does not independently prove what crossed the Windows physical NIC. A container sniffer may require elevated capabilities; do not make privileged packet-capture containers the default.

**Capture inside a VMware guest**

Use this to observe traffic visible to the guest. It is endpoint-side evidence and does not independently prove what crossed the physical host interface.

**Dell-side observation**

Use the Dell to observe its own client-side traffic and connection behaviour. It is useful for validating the client’s view but is not automatically able to see every packet at the HP’s tunnel endpoint or inside a container or guest.

**Blockchain RPC observation**

A capture on a client-to-provider HTTPS connection normally shows transport-level metadata and encrypted application traffic. It should not be described as a decoded JSON-RPC capture. Preserve application-level request/response records at the client or broker when the experiment needs them.

### 11.2 Boundary-validation procedure

1. State the intended boundary and the suspected or permitted path.
2. Identify source and destination endpoints.
3. Select the capture interfaces that can observe the path.
4. Record route tables, listeners and enforcement configuration.
5. Start bounded captures before the test.
6. Generate a known, minimal test exchange.
7. Compare source-side and destination-side observations where feasible.
8. Review firewall logs or counters, connection state and process identity when relevant.
9. Stop the capture and preserve it.
10. Revoke the temporary path and retest.
11. Record what was observed, what was not observed and what the method cannot establish.
A negative capture does not prove that no traffic crossed. The wrong interface, NAT, IPv6, DNS, offload, capture drops, timing or an unobserved path can create a misleading absence of evidence.

### 11.3 Capture hygiene

- Use a bounded duration or ring buffer.
- Record the interface, capture filter, start/stop time and tool version.
- Record packet-drop statistics where available.
- Save raw .pcapng files where supported.
- Treat captures as sensitive; they may contain addresses, internal names, tokens, cookies or application data.
- Review and redact captures before sharing them.
- Use least privilege for capture permissions.
- Store evidence outside disposable runtime storage.
- Hash the final evidence and record the hash.

### 11.4 First capture experiment

Research question: Can the selected capture point observe a known TCP exchange, and what are its blind spots?

1. Build one client and one server on an isolated lab network.
2. Start a capture at the selected point.
3. Initiate one known TCP connection.
4. Identify the expected SYN, SYN-ACK and ACK if the capture point should observe them.
5. Save the capture and record packet counts, timing and any drops.
6. Repeat at another point if testing a boundary.
7. Explain what the capture proves and what it does not prove.
8. Stop the workloads and verify recovery.

## 12. Evidence, findings and durable research records

### 12.1 The governing distinction

The runtime is disposable. Evidence and useful research knowledge are not.

Deleting a lab must not mean losing the question that was investigated, the configuration that produced a result, the code that demonstrated the finding or the evidence needed to review the conclusion.

The lab is not expected to preserve itself as a permanent software installation. The research archive is expected to preserve the material needed to understand and, where practical, reproduce the research.

### 12.2 Evidence categories

An experiment may produce:

- Screenshots and relevant screen recordings.
- Packet captures and protocol summaries.
- Terminal output and logs.
- Listener, route, firewall and network snapshots.
- Source code, scripts, test cases and configuration files.
- Build manifests, dependency lockfiles and container image digests.
- Resource measurements.
- Topology diagrams.
- Before/after state checks and recovery results.
- Tunnel status, route checks and allowed/forbidden path results.
- Smart-contract source, ABI, bytecode and build settings.
- Transaction hashes, receipts, logs, event data and RPC responses.
- Forensic analysis scripts, derived tables and interpretation notes.
- SHA-256 manifests and research conclusions.
- A prototype application or network utility that embodies a finding.
A screenshot is not automatically better evidence than text output. The evidence must answer the research question and preserve enough context to be interpreted correctly.

### 12.3 Evidence zones

Maintain three logical zones on the host side:

1. Evidence staging: files manually received from an experiment, not yet accepted into the authoritative archive.
2. Research archive: reviewed records, source artefacts, raw evidence, analysis and reproducibility material.
3. Disposable runtime storage: container writable layers, temporary files, VM scratch disks, caches and transient build state.
Do not mount the entire Windows filesystem into a lab merely to simplify exports. Do not leave the only copy of important evidence inside a VM snapshot, container or disposable volume.

### 12.4 Manual evidence transfer

Manual transfer is the default until a separate automated method has been designed and validated.

1. Stop or pause the experiment at a known point.
2. Export only the required artifacts to an explicitly selected transfer location.
3. Inspect filenames, file types, sizes and content before opening them on Windows.
4. Hash the final artifacts with SHA-256.
5. Record their source, experiment ID, transfer time and hashes.
6. Copy reviewed evidence into the research archive.
7. Verify that archived files are readable and their hashes match.
8. Back up important evidence.
9. Remove temporary transfer copies only after the archive is verified.
Treat files exported from a potentially compromised guest as untrusted. Do not execute an exported program simply to inspect it.

### 12.5 Research record structure

Each experiment should preserve the following logical information, whether in a document, a structured record or a combination of files:

- Question: what needed to be understood?
- Context: what system, protocol, application or operating condition was investigated?
- Prediction: what behaviour was expected?
- Method: how was the question tested?
- Environment: which lab, version, configuration and network profile were used?
- Observation: what happened?
- Evidence: which files, captures, logs or outputs support the observation?
- Analysis: what does the evidence support, and what alternative explanations remain?
- Finding: what is now better understood?
- Limitations: what was not measured or cannot be concluded?
- Development consequence: is there a useful technical response to build, modify or test?
- Next question: what remains unknown?
A finding may be valuable even if it disproves the original hypothesis or concludes that the evidence is insufficient.

### 12.6 Research Unit relationship

A Research Unit is the durable object of understanding; a lab runtime is a temporary means of investigating it.

The runtime should not become the research identity. A question may be investigated in WSL/Docker today, a VMware guest later and a better-equipped system in the future. The research record should preserve the question, relevant method, evidence, conclusion and known limitations across those changes.

This makes it possible to delete the current containers and VMs without losing the research body they helped produce.

### 12.7 When research produces a network application

A network application is one possible outcome of a finding, not a mandatory category of laboratory component.

Before developing it, record:

- The finding or operational problem it addresses.
- The user, system or network role it serves.
- The capability it needs to provide.
- Its intended operating environment.
- Its trust boundaries and required permissions.
- Its expected behaviour under failure.
- How the capability will be tested.
- Which evidence supports the design.
- What remains unverified.
- Whether the result belongs in an existing Ithoka system, a client engagement, an internal tool or a separately evaluated product idea.
The implementation can then be built and tested in the lab. The resulting source code and build artefacts become durable research outputs after review; the environment in which they were produced can be discarded.

## 13. Host telemetry, containment, teardown and recovery

### 13.1 Host telemetry

Use built-in Windows tools initially:

- Task Manager for CPU, memory and process activity.
- Resource Monitor for memory, disk and network investigation.
- Performance Monitor or Get-Counter for measurements when required.
- Docker statistics for container resource usage.
- VMware’s interface and guest observations for VM state.
- Relevant route, listener and firewall inspection tools.
Take measurements before, during and after experiments.

Do not build a permanent background monitoring agent before its requirements are established. Host metrics are useful for resource and health decisions, but they are not proof of network isolation.

### 13.2 Emergency containment

Containment prioritises stopping activity and preventing further harm while preserving evidence.

1. Stop or power off the relevant VMware guest from the host.
2. Stop the relevant Docker workload.
3. Shut down WSL from Windows if necessary.
4. Stop the Dell tunnel and revoke the temporary access permission if the experiment uses it.
5. Disable the specific temporary network path if required and if its effect is understood.
6. Preserve relevant captures, logs and experiment records.
7. Verify workload, process and tunnel state from outside the workload where possible.
8. Check routes, listeners and connectivity.
9. Record the incident and unexpected state.
A single script cannot be assumed to stop every possible VMware, WSL, Docker and Windows networking state. Establish and test a manual fallback first. Any later automation must be tested in stages.

### 13.3 Teardown policy

The host should eventually have reliable master procedures or commands to remove a disposable lab completely. These should be developed only after the manual lifecycle is understood.

A teardown procedure must distinguish between:

- Runtime resources: disposable containers, VMs, temporary volumes, networks and scratch files.
- Temporary access state: tunnel sessions, experiment-specific permissions, routes, port forwards and other temporary network changes.
- Durable research material: source code retained for reproducibility, raw evidence, analysis, configurations and hashes.
- Trusted host state: ordinary development tools, unrelated applications, accounts and source repositories that must not be deleted.
The teardown mechanism must never equate “remove the lab” with “delete everything associated with research.”

It must not blindly run broad prune, volume deletion or filesystem removal commands. It should identify the resources associated with the target experiment and verify their identity before removal.

### 13.4 Requirements for master teardown commands

Any future host-side master teardown mechanism should:

- Require an explicit target environment or experiment.
- Show or log which resources it intends to stop or remove.
- Preserve the evidence archive and its manifest.
- Stop workloads before deleting resources.
- Revoke temporary access and networking state.
- Check whether the target is actually stopped or removed.
- Detect and report failed steps.
- Avoid removing unrelated Docker resources or user data.
- Record its result.
- Have a manual fallback.
A successful command exit code is not proof that recovery is complete. The post-teardown checks are mandatory.

### 13.5 Recovery verification

After an experiment, record whether:

- No unintended VM or lab container remains running.
- WSL is stopped when required by the selected mode.
- The Dell tunnel is inactive and temporary permissions are revoked.
- Temporary paths, ports, routes and firewall rules are removed.
- Listeners, routes and firewall posture match the expected state.
- The previously allowed service is no longer reachable through the closed path.
- The development channel is closed when it was used.
- Evidence is preserved and associated with the experiment.
- Windows is usable for normal work.
- Any unexpected state has been documented.

## 14. Threat model and limitations

### 14.1 Protected assets

- Windows workstation availability and integrity.
- Ithoka source code, accounts, credentials and business files.
- Personal and business data.
- The home network and other connected devices.
- Research evidence and reproducibility.
- The ability to return to normal development work.
- Blockchain keys, test accounts and provider credentials.
- The integrity of research findings and the ability to distinguish evidence from inference.

### 14.2 Relevant failure scenarios

- A guest or container reaches a host service, LAN or Internet unexpectedly.
- A bridged adapter, published port or port forward is enabled without approval.
- A container receives unnecessary privileges or sensitive host mounts.
- A shared folder, clipboard or remote-development channel exposes a path that was overlooked.
- A capture point misses traffic and creates false confidence.
- IPv6, DNS, a proxy or an unexpected route bypasses an IPv4-only assumption.
- Memory pressure or disk I/O threatens the workstation.
- A stop or teardown command fails.
- Teardown removes evidence or leaves a path active.
- Dependency provenance cannot be established.
- An experiment cannot be reproduced because its configuration was not recorded.
- The Dell tunnel remains active after the experiment.
- The tunnel peer can access more destinations or ports than intended.
- A vulnerable application accidentally listens on an unintended interface.
- An experiment sends a testnet request to an unintended endpoint.
- A provider credential or wallet secret is exposed in source, logs or evidence.
- An RPC response is interpreted as proof of an on-chain state without sufficient supporting evidence.
- An Anvil simulation is incorrectly described as real Ethereum P2P behaviour.
- A public testnet experiment is treated as fully controllable despite external conditions.
- A research artifact is lost when a disposable environment is removed.

### 14.3 Shared-core and non-network leakage

Wireshark observes network traffic visible at its capture point. It does not detect every possible information-transfer channel.

It cannot prove the absence of leakage through:

- Shared folders, clipboard or guest integration not represented as network traffic.
- Process, file or credential access.
- USB or other device passthrough.
- Shared CPU caches, timing behaviour or other microarchitectural side channels.
- An interface or capture point the operator cannot observe.
Docker containers share a Linux host kernel. WSL2 uses a virtualised Linux environment but remains integrated with Windows. VMware guests have separate guest kernels but still share host hardware and may have network or integration paths.

Unknown malware, hostile kernel experiments and deliberate host compromise need a stronger, separately reviewed isolation design.

### 14.4 Evidence limitations

- A matching hash establishes that a file matches the recorded digest, not that the file or original observation is truthful.
- A packet capture proves only what was captured under its conditions and at its observation point.
- A failed connection does not independently prove that a firewall blocked it.
- A service being reachable from one source does not establish reachability from every source.
- A public RPC response records what a provider returned; it does not independently validate the provider’s entire internal process.
- A transaction hash or decoded event does not alone establish the full business meaning of a transaction.
- A local EVM result does not automatically establish behaviour on a public Ethereum network.
- A testnet result may depend on external state, provider behaviour, network conditions and timing.
- A successful teardown command does not prove that every associated resource or route has disappeared.
The research record must distinguish observation, interpretation, inference and unresolved uncertainty.

## 15. Acceptance criteria

The initial build is not accepted merely because Docker, VMware, VS Code remote development, WireGuard or Anvil starts.

Use Pass / Fail / Not tested for each criterion and attach evidence.
| ID | Acceptance criterion |
| — | — |
| AC-1 | Windows remains usable, and lab workloads can be stopped without losing ordinary work. |
| AC-2 | Operating modes have explicit start, stop and verification procedures. |
| AC-3 | WSL/Docker and VMware paths are inventoried; unnecessary integration is disabled by default. |
| AC-4 | A representative network path can be enabled, observed, revoked and tested as unavailable. |
| AC-5 | A minimal Docker client/server experiment is reproducible and produces preserved evidence. |
| AC-6 | A minimal Linux VM can run on a documented virtual network and shut down cleanly, once VMware readiness is confirmed. |
| AC-7 | Capture points and their blind spots are documented. A negative capture is not treated as universal proof. |
| AC-8 | Evidence survives destruction of a disposable runtime and is checked with hashes. |
| AC-9 | Manual containment, teardown and recovery procedures are documented and tested. |
| AC-10 | Resource measurements show that the HP remains usable during the selected workload. |
| AC-11 | Dependencies have recorded sources and versions, with suitable verification evidence. |
| AC-12 | Temporary maintenance egress is closed and tested after acquisition or updates. |
| AC-13 | Windows support/update status and virtualisation discrepancies have documented decisions. |
| AC-14 | Higher-risk experiments receive a separate risk and isolation review. |
| AC-15 | The Dell has adequate free storage and acceptable memory pressure for its intended client workload. |
| AC-16 | The Dell can establish an authenticated, encrypted tunnel to the designated endpoint. |
| AC-17 | The tunnel permits the approved service while representative forbidden paths fail. |
| AC-18 | Tunnel teardown revokes access and the formerly permitted service becomes unreachable through that path. |
| AC-19 | The lab does not require the Dell tunnel for experiments that can be conducted inside an isolated environment. |
| AC-20 | VS Code can be used to author code without automatically executing untrusted experiment code on Windows. |
| AC-21 | Any remote-development channel has a documented scope and a tested closure procedure. |
| AC-22 | A local EVM test can be executed, analysed and preserved without requiring public Internet access. |
| AC-23 | The blockchain research records distinguish local EVM simulation from real public testnet observations. |
| AC-24 | Public testnet access, when required, is explicitly authorised, mediated and closed after the experiment. |
| AC-25 | Provider credentials and test keys are not embedded in source repositories or unredacted evidence. |
| AC-26 | The teardown process can remove disposable runtime resources without deleting the durable research archive. |
| AC-27 | Network applications can be developed and tested as possible research outcomes without making the lab a branded or permanent software product. |
Not tested is not a pass. Record actual conditions and evidence, not just the final status.

## 16. Logical build and implementation sequence

This is the blueprint for building and improving the labs. It describes dependencies, responsibilities and acceptance outcomes rather than prescribing a complete command-by-command installation.

The architecture should remain useful if the current environments are deleted, rebuilt on better hardware or replaced by a more capable dedicated setup.

### 16.1 Module overview

| Module | Purpose | Depends on | Completion outcome |
| --- | --- | --- | --- |
| M0 — Readiness | Establish actual hardware, OS, virtualisation and network state | Existing machines | Known constraints and readiness decisions |
| M1 — Host foundation | Establish host policy, evidence locations and recovery procedures | M0 | Known host state and a defined return to ordinary work |
| M2 — Lightweight environment | Establish WSL/Docker execution and isolated internal networks | M0, M1 | Repeatable local experiment |
| M3 — Observation and evidence | Establish capture, evidence transfer and archive practices | M1, initial M2 experiment | Evidence survives runtime deletion |
| M4 — VM environment | Establish VMware and a minimal isolated guest | M0, M1, M3 | Guest runs and shuts down with verified network boundaries |
| M5 — Physical client | Prepare the Dell for lightweight client experiments | M0, M1 | A usable, understood second endpoint |
| M6 — Controlled access | Establish temporary tunnel or development access when required | M1, M3, M5 or relevant target | One permitted path works; forbidden paths are tested |
| M7 — Lifecycle and teardown | Integrate start, stop, evidence, revocation and recovery | M2, M3, M4, M6 as applicable | Repeatable experiment lifecycle |
| M8 — Blockchain research | Establish local EVM testing and controlled testnet access | M2, M3, M7 | Local tests and public-testnet work are distinguishable and reproducible |
| M9 — Research-driven development | Turn justified findings into useful network or security capabilities | Relevant research and evidence | A testable implementation with a clear origin and validation record |
| M10 — Expansion and review | Add complexity only when justified | Relevant earlier modules | Additional capability with a defined purpose and acceptance tests |

These are logical responsibilities, not a requirement to create ten software packages. A module may be a procedure, configuration, experiment template or small utility. Avoid building a framework where a short, auditable procedure is sufficient.

### 16.2 M0 — Readiness and inventory

Establish facts before changing either machine:

- Resolve the HP and Dell virtualisation discrepancies.
- Record Windows update/support status and the intended OS plan.
- Inspect WSL and Docker versions, contexts, networks and existing workloads.
- Identify owners and intended exposure of notable listeners.
- Map physical, VPN, hotspot/ICS and virtual adapters and routes.
- Record idle CPU, memory and disk behaviour.
- Address the Dell’s low free space and memory pressure.
- Confirm whether VMware is viable on the HP.
- Determine which interfaces and software can support the intended tunnel.
Outcome: a documented baseline and explicit readiness decision for each device.

Do not proceed where an unknown hardware, support or networking condition materially affects the safety of the intended experiment.

### 16.3 M1 — Host foundation

Establish:

- A known ordinary-work baseline.
- A record of firewall profiles and relevant rules.
- Listener and route inventories.
- A way to inspect running lab workloads and resource use.
- Evidence staging and archive locations.
- Manual containment, teardown and recovery procedures.
- A record of intended default-off network paths.
- A process for identifying and revoking temporary access.
This module does not require a permanent monitoring service or a large automation layer. Start with existing Windows tools and documented procedures.

Outcome: the operator can identify what is running, understand relevant network paths, preserve evidence and return to ordinary workstation use.

### 16.4 M2 — Lightweight execution environment

Establish WSL/Ubuntu and Docker as the first disposable environment.

- Confirm the existing WSL installation and mode.
- Confirm the Docker client/server relationship and active context.
- Inventory existing images, containers and networks.
- Create one simple client/server experiment on a dedicated internal Docker network.
- Avoid unnecessary privileges, host mounts, published ports and external connectivity.
- Verify the expected application exchange.
- Stop the workload and verify the resulting state.
Do not assume Docker’s internal network removes every host or platform-integration path.

Outcome: one reproducible lightweight experiment with its configuration and results preserved.

### 16.5 M3 — Observation and evidence

Establish:

- Windows Wireshark and appropriate command-line or endpoint-side capture tools when needed.
- A documented capture-point choice for each experiment.
- A minimal capture test with known traffic.
- Evidence transfer, SHA-256 hashing and archive verification.
- Research records that distinguish observation from interpretation.
- A documented account of capture blind spots.
Start with a small known exchange, not continuous capture of every interface.

Outcome: evidence from the first lightweight experiment can be independently reviewed after its runtime has stopped.

### 16.6 M4 — Full virtual-machine environment

Proceed only after host virtualisation readiness and resource capacity are understood.

Establish:

- A compatible VMware installation.
- A documented virtual-network configuration.
- One small guest on a host-only or custom isolated network.
- Unnecessary shared-folder, clipboard and drag-and-drop integration disabled.
- A known guest-network test.
- Clean guest shutdown and recovery checks.
The first guest should be small enough that Windows remains usable.

Outcome: a repeatable, observable and disposable VM experiment.

### 16.7 M5 — Physical client endpoint

Prepare the Dell for real-client testing:

- Recover adequate free disk space safely.
- Reassess memory pressure after reboot.
- Document its security-update or migration plan.
- Inventory listeners, routes and network interfaces.
- Map the actual hotspot/ICS topology.
- Confirm tunnel compatibility.
- Identify the intended lightweight client application.
- Establish a method for observing the Dell’s own connection behaviour.
Do not install a VM or lab stack on the Dell merely because it is available.

Outcome: a healthy and understood physical client that adds value when a separate endpoint is needed.

### 16.8 M6 — Controlled access

Build temporary cross-boundary access only when the experiment requires it.

For the Dell tunnel:

1. Select the tunnel endpoint.
2. Establish authenticated peer identities.
3. Choose a non-conflicting tunnel address plan.
4. Define the narrow route.
5. Ensure the service is exposed only where required.
6. Apply firewall enforcement.
7. Define activation and revocation.
8. Verify the approved path.
9. Test forbidden paths.
10. Stop the tunnel and revoke permissions.
11. Verify that access is no longer available.
12. Preserve the test evidence without exporting private keys.
For VS Code remote development, apply the same high-level requirements to the editor-to-lab channel, but use a separate scope and lifecycle.

Outcome: the intended development or client path works, and its access can be revoked and verified.

### 16.9 M7 — Lifecycle and teardown

Establish a common manual experiment lifecycle:

1. Review the research question and select the operating mode.
2. Check the baseline and stop unrelated workloads.
3. Start only the required environment.
4. Enable any required temporary access.
5. Run the experiment and collect bounded evidence.
6. Stop the client and workloads.
7. Revoke the temporary network path.
8. Export, inspect and hash evidence.
9. Verify that no unintended process, route, listener or tunnel remains.
10. Confirm the host has returned to its expected state.
11. Record the result and any deviation.
Begin manually. Automate a step only after its inputs, outputs, failure modes and recovery behaviour are understood.

Outcome: a repeatable lifecycle that does not rely on remembering undocumented changes.

### 16.10 M8 — Blockchain research capability

Start with local EVM research; introduce public testnet interaction only when the research question requires it.

Initial local capability:

- Install or acquire a trusted, versioned Foundry toolchain through the maintenance process.
- Execute forge tests and local anvil experiments.
- Use cast or a suitable library for controlled JSON-RPC requests.
- Test contract behaviour, invariants, events and transaction results.
- Preserve source, build information, traces and test results.
- Measure resource use and shut down the environment after the experiment.
Controlled public-testnet capability:
- Select the RPC provider and network.
- Define the permitted requests and destinations.
- Protect test credentials and wallet keys.
- Enable the approved broker or controlled access path.
- Record requests, responses, transaction hashes and relevant block data.
- Close access and verify the return to the normal isolated state.
Do not begin by building a full Ethereum node, validator or multi-node P2P network. Those capabilities may be added later when a question cannot be answered by local EVM testing and RPC-based public-chain research.

Outcome: blockchain security and forensics can begin on the existing hardware without pretending that local simulations and public-network observations are equivalent.

### 16.11 M9 — Research-driven development

When a finding justifies a useful capability, create a separate development record linked to the research evidence.

The process is:

1. Identify the finding or operational problem.
2. Establish the requirement for the proposed capability.
3. Define its operating environment and trust boundaries.
4. Decide whether it belongs in an existing Ithoka system, a client solution, an internal utility or a separately evaluated product.
5. Author code in VS Code.
6. Execute builds and experiments inside the appropriate lab.
7. Test normal behaviour, failures and security boundaries.
8. Preserve code, configurations, test results and limitations.
9. Revisit the original research question and determine whether the implementation supports or changes the finding.
10. Preserve the resulting technical knowledge.
This module is not a requirement to create a product for every experiment. Its purpose is to ensure the architecture can accommodate development when the evidence warrants it.

### 16.12 M10 — Expansion and review

Potential future additions include:

- More complex Docker or VM topologies.
- Comparative routing and firewall experiments.
- Additional physical client platforms.
- More formal evidence collection.
- Additional contract analysis and blockchain datasets.
- Controlled RPC request recording.
- Defensive network monitoring utilities.
- Protocol gateways and local edge services.
- Automated teardown and environment recreation.
- Dedicated lab hardware or stronger isolation where a research question justifies it.
Each addition must identify the question it enables, new privileges or paths it introduces, its resource cost and its acceptance tests.

## 17. Experiment record template

Experiment ID/title:
Date/time and operator:
Research question:
Hypothesis/prediction:
Scope and authorisation:
Risk assessment:
Research domain: Networking / Security / Network application / Blockchain / Forensics / Other
Operating environment: Windows / WSL-Docker / VMware / Dell endpoint
Network profile: A isolated / B maintenance / C cross-boundary / D blockchain RPC
External access required: Yes / No
Dell required: Yes / No
VS Code remote channel active: Yes / No / Not applicable
Tunnel active: Yes / No
Topology and versions:
Source and destination:
Path being tested — direction, protocol and port:
Enforcement point:
Capture/telemetry points:
Procedure and commands:
Expected result:
Observed result:
Forbidden paths tested:
External requests and destinations, if applicable:
Blockchain network, chain ID, transaction or contract identifiers, if applicable:
Evidence references:
SHA-256 hashes:
Analysis and alternative explanations:
Limitations and blind spots:
Development implication, if any:
Containment, teardown and recovery checks:
Acceptance status: Pass / Fail / Not tested
Conclusion:
Next research question:

## 18. Governing principles

1. The labs serve research and engineering. They are not an end in themselves and do not change Ithoka’s business trajectory.
2. The runtime is disposable; the research is durable. Evidence and useful knowledge must survive deletion of the environment.
3. The lab is unbranded. Its operational identity does not depend on Ithoka names, logos or affiliation. The owner is named in this foundational document.
4. Code execution stays in the assigned environment. VS Code remains the primary editor, but editing on Windows does not authorise execution of untrusted experiment code on Windows.
5. Networking is controlled, not assumed. Every cross-boundary path has a purpose, scope, enforcement point, verification method and revocation procedure.
6. External access is a deliberate exception. Dependency maintenance is separated from experiments. Public blockchain research uses a narrowly controlled path, not unrestricted lab Internet access.
7. Blockchain simulation and public-network behaviour are distinct. Anvil supports local EVM testing; it is not a substitute for a real Ethereum P2P network.
8. Network applications are possible research outcomes. They are developed when findings justify them, not added as a standalone laboratory component.
9. Evidence must outlive the runtime. Teardown removes disposable environments without destroying the research archive.
10. Complexity follows evidence. Add a tool, path, privilege, service or environment only when a concrete research question justifies it.
11. Acceptance requires verification. A configuration setting or successful startup is not proof that a security boundary works.
12. The architecture survives hardware changes. New machines may improve capacity or isolation, but the research lifecycle, evidence discipline and boundary principles remain applicable.
The enduring architecture is not a particular installation of Docker, VMware, WireGuard or Anvil. It is the method by which Ithoka investigates technical realities, tests claims, preserves evidence and develops useful responses without needlessly endangering the trusted workstation.

## Appendix A — Read-only follow-up inventory

These commands inspect current state. They are not installation or configuration instructions. Review and redact sensitive output before sharing it.

### A1. HP — WSL and Docker

Run in PowerShell on the HP:
“===== WSL STATUS =====”
wsl –status
wsl –version
wsl –list –verbose
wsl –list –running

“===== WSL CONFIG =====”
if (Test-Path “$env:USERPROFILE\.wslconfig") {
    Get-Content "$env:USERPROFILE.wslconfig”
} else {
“No user .wslconfig file found.”
}

“===== DOCKER =====”
docker version
docker info
docker context ls
docker context show
docker ps -a –no-trunc
docker network ls
docker system df

“===== NETWORKING / SHARING =====”
Get-NetAdapter -IncludeHidden
Get-NetConnectionProfile
Get-NetNat -ErrorAction SilentlyContinue
Get-Service SharedAccess, hns, vmcompute, vmms -ErrorAction SilentlyContinue
netsh interface portproxy show all

Do not run docker system prune, wsl –unregister or deletion commands as part of inventory.

### A2. Identify listener owners

Use the PID from the latest socket inventory. PIDs can change after reboot, so do not rely on an old PID alone.
Get-Process -Id 5492 -ErrorAction SilentlyContinue |
Select-Object Id, ProcessName, Path

Get-CimInstance Win32_Service |
Where-Object ProcessId -eq 5492 |
Select-Object Name, DisplayName, State, StartMode, ProcessId

Replace 5492 with the current PID being investigated. Review firewall rules and intended exposure before concluding that a wildcard listener is reachable from another device. Do not disable the firewall to simplify the investigation.

### A3. Inside the existing Ubuntu WSL distribution

date -Is
uname -a
cat /etc/os-release

printf ‘===== CPU / MEMORY =====’
lscpu
free -h
grep -E ‘MemTotal|MemAvailable|SwapTotal|SwapFree’ /proc/meminfo

printf ‘===== STORAGE =====’
df -hT
lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,ROTA,MODEL

printf ‘===== NETWORK =====’
ip -brief address
ip route show table all
ip -6 route show table all
cat /etc/resolv.conf
ss -lntup

printf ‘===== DOCKER =====’
docker version
docker context ls
docker info
docker ps -a –no-trunc
docker network ls
docker system df

### A4. VMware readiness

Do not install VMware as part of inventory. Resolve the virtualisation discrepancy and review support and storage constraints first.

If VMware is already installed, inspect its version and virtual-network configuration. In VMware Workstation Pro → Edit → Virtual Network Editor, record without changing anything:

- Which networks are Host-only, NAT and Bridged.
- Subnet and DHCP state for each network.
- Any custom virtual networks.
- Shared-folder, clipboard, drag-and-drop and USB auto-connect settings.

### A5. Dell readiness

After a safe storage review and cleanup plan, repeat disk-space and memory measurements. Do not remove unknown files or run broad cleanup commands merely to free space.

Confirm:

- Adequate free disk space for the intended client workload.
- Acceptable memory pressure after reboot and at idle.
- Applicable security updates or migration plan.
- Actual network/hotspot topology.
- Tunnel software compatibility.
- The reason the device improves the experiment.

## Appendix B — Evidence integrity

### B1. Windows SHA-256

Get-FileHash “C:_FILE” -Algorithm SHA256

Get-Item “C:_FILE” |
Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc

### B2. Linux SHA-256

sha256sum /path/to/evidence-file
stat /path/to/evidence-file

A matching hash establishes that a file matches the recorded hash. It does not establish that the original evidence was truthful, complete or captured correctly.

## Appendix C — Reference material

These references inform product behaviour and research methodology. They do not certify the current configuration of either machine or validate the security of the laboratory.
Ithoka research and systems approach

1. Ithoka Microsystems — Home
2. Ithoka — Research
3. Ithoka — Systems
4. Ithoka — About
Networking, isolation and evidence
5. Wireshark User’s Guide — Live Capture
6. Wireshark User’s Guide — Capture Options
7. TShark documentation
8. Microsoft — WSL networking
9. Docker — Network creation and internal networks
10. WireGuard
11. Broadcom — VMware Virtual Network Editor
12. Microsoft — Windows 10 Extended Security Updates
Ethereum and smart-contract research
13. Ethereum — Nodes and clients
14. Ethereum — Node architecture
15. Ethereum — Run a node
16. Ethereum — Nodes as a Service
17. Foundry — Anvil
18. Foundry — Fork testing
19. Ethereum — Hello World smart-contract tutorial
These sources support the distinctions between local EVM testing, Ethereum execution/consensus clients and third-party RPC access. The exact software versions, public-testnet conditions, provider capabilities and local machine readiness must still be checked when implementing a specific experiment.