# Docker Lab --- Low-Level Design & Implementation Specification

**Document type:** Implementation specification\
**Version:** 0.1 --- initial engineering baseline\
**Status:** Draft for implementation and controlled validation\
**Parent document:** *Constrained Security Labs Design --- Security
Laboratory Design, Boundaries, Constraints & Research Architecture*,
Version 2.0, 17 October 2026\
**Execution environment:** Existing Ubuntu distribution under WSL2 with
Docker, subject to read-only readiness checks\
**Primary host:** HP EliteBook 8470p --- Windows 10 Pro, approximately 8
GB RAM, Intel Core i5-3320M, HDD\
**Operator / implementation engineer:** Owner of the lab\
**Scope of this document:** Environment B --- WSL / Ubuntu / Docker only

> Historical baseline: this document contains the original experiment-oriented
> design and is retained for traceability. The current implementation is
> experiment-independent; use [lab-set.md](lab-set.md) and
> [docs/architecture.md](docs/architecture.md) for the authoritative
> construction workflow.

------------------------------------------------------------------------

## 1. Purpose

This document translates the foundational lab design into an
implementable Docker-lab architecture. It defines the components,
repository layout, configuration boundaries, lifecycle, reset behaviour,
containment strategy, monitoring, evidence handling, tests and
implementation sequence.

It is not an instruction to install everything immediately. The first
implementation step is inventory and readiness verification. Existing
WSL distributions, Docker contexts, containers, networks, images,
mounts, listeners and host networking must be inspected before anything
is changed.

The initial objective is deliberately small:

> Build one repeatable client/server experiment on a dedicated internal
> Docker network, collect evidence, reset the experiment to a known
> baseline, stop the lab without rebuilding it, and verify that the host
> has returned to its expected state.

The first version must not attempt to provide a universal malware
sandbox or claim perfect isolation from Windows. Docker containers share
the Linux kernel of the Docker environment; WSL2 integrates with
Windows. The architecture is intended for controlled networking,
application, protocol, defensive-tooling and similar experiments whose
risk is appropriate for this environment. Unknown malware, hostile
kernel experiments and deliberate host-compromise research require a
separate isolation review and may require stronger, dedicated hardware.

## 2. What "the lab" consists of

The lab is not just a folder, a Docker Compose file or a collection of
running containers. It is the combination of:

1.  **Definitions** --- version-controlled Compose files, network
    definitions, image versions, configuration, policy and experiment
    descriptions.
2.  **Runtime** --- the containers, Docker networks, volumes and
    processes created from those definitions.
3.  **Control plane** --- scripts and operator procedures that validate,
    start, stop, reset and remove lab resources.
4.  **Containment plane** --- restrictions on network paths, host
    access, privileges, mounts, published ports and temporary
    exceptions.
5.  **Observation plane** --- packet captures and relevant endpoint,
    Docker, WSL and host telemetry.
6.  **Evidence plane** --- experiment records, outputs, capture files,
    hashes, configuration snapshots and conclusions stored outside
    disposable runtime state.
7.  **Recovery plane** --- a known baseline, reset procedure,
    emergency-stop procedure and complete-removal procedure.
8.  **Verification** --- tests that show expected communication works,
    forbidden communication fails, reset works, stop works, and evidence
    survives runtime deletion.

The design files are the lab's equivalent of application source code.
The running containers are a deployment. A reset is a rollback to the
experiment baseline. A full wipe is infrastructure removal. Evidence is
durable research output and must not live only inside a container or
disposable volume.

## 3. Requirements and invariants

### 3.1 Required behaviour

-   The operator can start a defined experiment from a known
    configuration.
-   Stopping a session does not require reinstalling Docker or
    rebuilding every image.
-   Resetting an experiment removes its mutable runtime state and
    recreates it from a documented baseline.
-   A full teardown can remove the lab's containers, networks and
    lab-owned volumes without deleting the evidence archive.
-   A host-side emergency action can terminate the Docker lab and, if
    necessary, shut down the WSL distribution or WSL VM.
-   Routine experiments have no direct Internet egress.
-   Containers do not receive broad access to Windows files, host
    credentials, the Docker socket or unrelated services by default.
-   No container port is published to Windows or the LAN by default.
-   A temporary exception must identify its purpose, scope, enforcement
    point, verification method, expiry and rollback.
-   Network observation is used to investigate and validate behaviour,
    not treated as proof of complete isolation.
-   The operator preserves evidence before destructive reset or wipe,
    unless immediate containment requires stopping first.
-   Every acceptance result is recorded as **Pass**, **Fail** or **Not
    tested**. Not tested is not a pass.

### 3.2 Non-negotiable network invariant

**The containment boundary must prevent unauthorised egress; the
emergency-stop mechanism is a secondary response.**

A packet observed leaving an allowed boundary has already escaped. A
monitor that notices it and then kills containers cannot undo that
transmission. Therefore, prevention must be implemented at the narrowest
enforceable network boundary available and verified with tests.
Monitoring and the killswitch add detection and containment; they do not
replace egress controls.

### 3.3 No claim of absolute isolation

The initial lab is logically separated, not physically air-gapped. A
Docker internal network restricts external connectivity for containers
attached to it, but does not by itself prove that Windows cannot reach a
container, that no other interface exists, or that WSL integration
provides no other path. Wireshark sees only traffic visible at its
selected capture point. The design must document what each test and
sensor can and cannot establish.

## 4. Architecture overview

``` text
WINDOWS HOST — TRUSTED DAILY WORKSTATION
|
|-- VS Code / ordinary development
|-- Host telemetry and operator controls
|-- Evidence staging and durable archive
|-- Host-side emergency-stop procedure
|
`-- WSL2 Ubuntu — Docker environment
    |
    |-- Lab control scripts (operator-controlled)
    |-- Docker Compose project (lab-owned resources only)
    |-- Dedicated internal experiment network
    |     |-- client container
    |     `-- server/target container
    |
    |-- Optional observer container or capture at a documented interface
    |-- Lab-owned volumes only where explicitly required
    `-- Disposable experiment state

Manual evidence export:
WSL/container output --> review/staging --> SHA-256 --> durable Windows archive

No default route from experiment containers to the LAN or Internet.
No default published ports.
No default Windows-directory mounts.
No Docker socket mounted into experiment containers.
```

This is a logical architecture, not proof of the current machine's
topology. Existing adapters, WSL configuration, Docker context,
firewall, VPN, hotspot/ICS, port forwarding and listeners must be
inventoried before implementation.

## 5. Component design

### 5.1 Operator interface

The operator interface is a small set of explicit commands or scripts.
It must not silently change the whole machine's networking or delete
resources it does not own.

Required operations:

-   `preflight` --- inspect readiness and fail if assumptions are not
    met.
-   `validate` --- validate configuration and list the planned lab
    resources.
-   `start` --- create/start only the selected lab profile.
-   `status` --- show project containers, networks, mounts/ports where
    inspectable, and current session state.
-   `test-boundary` --- run the documented allowed-path and
    forbidden-path checks.
-   `capture-start` / `capture-stop` --- optional, explicit capture
    actions tied to an experiment.
-   `stop` --- stop workloads and remove temporary access; preserve
    images and reusable baseline artefacts.
-   `reset` --- stop and recreate the mutable experiment state from the
    baseline.
-   `emergency-stop` --- best-effort host-side containment; must not
    depend solely on a process inside the lab.
-   `destroy` --- remove lab-owned containers, networks and disposable
    volumes after evidence handling.
-   `archive` --- stage evidence, create hashes and verify the archive.

Start with auditable PowerShell and Bash scripts. Do not build a large
orchestration framework before the manual lifecycle and its failure
modes are understood.

### 5.2 Compose project

Use one named Compose project for lab-owned resources. The project name
must be stable and neutral, such as `sec-lab-docker`. All lab
containers, networks and volumes must be identifiable through the
project name and explicit labels.

The first Compose topology should contain only:

-   one client workload;
-   one server or target workload;
-   one dedicated internal network;
-   optional evidence output through a narrowly scoped, explicit path;
-   no published ports;
-   no privileged containers;
-   no host network mode;
-   no broad Windows bind mounts;
-   no Docker socket mount;
-   no external network attachment.

Do not attach existing personal development containers to the lab
network. Do not use a broad `docker compose down --volumes` command
against a project that has not been verified as lab-owned.

### 5.3 Container roles

**Client:** Generates the test traffic needed by the experiment. It
should have only the tools required by the research question.

**Server/target:** Provides one named service on the internal network.
It must listen only where required and must not publish its port to the
host.

**Observer:** Prefer capture from a documented host/WSL interface or a
dedicated observer when the experiment needs it. A container observer
may require additional capabilities or access to an interface; do not
grant those capabilities automatically. Add them only after defining
what is captured and reviewing the added privilege.

The first test does not need an observer container if a simple
request/response and endpoint logs answer the question. Add packet
capture in the next stage and document its vantage point.

### 5.4 Images and dependencies

-   Use trusted sources and explicit versions; pin digests where
    practical.
-   Record image name, tag, digest, source, acquisition date and
    verification result.
-   Acquire images and packages during a separate maintenance operation.
-   Do not give an ordinary experiment unrestricted Internet access to
    make dependency downloads convenient.
-   Close the maintenance path and test egress before running an
    isolated experiment.
-   A hash proves correspondence with a recorded digest, not that the
    software is safe.
-   Avoid a moving `latest` tag for reproducible experiments.
-   Do not install large packages into a running target if they can be
    staged in advance.

## 6. Proposed repository and filesystem layout

Use a dedicated directory inside the Ubuntu filesystem, not a
Windows-mounted path, for runtime scripts and lab execution. Evidence
can be exported manually to a dedicated Windows staging directory after
review. This reduces accidental coupling between experiment runtime and
the Windows workspace.

``` text
~/security-lab/
├── README.md
├── VERSION
├── .gitignore
├── config/
│   ├── lab.env.example
│   ├── resource-limits.env.example
│   ├── networks/
│   │   ├── active-profile
│   │   ├── machine.yaml.example
│   │   ├── boundaries/
│   │   └── profiles/
│   └── policy/
│       └── network-policy.md
├── experiments/
│   └── EXP-0001-client-server/
│       ├── experiment.yaml
│       ├── README.md
│       ├── client/
│       ├── server/
│       └── tests/
├── scripts/
│   ├── preflight.sh
│   ├── validate.sh
│   ├── start.sh
│   ├── status.sh
│   ├── test-boundary.sh
│   ├── stop.sh
│   ├── reset.sh
│   ├── destroy.sh
│   └── archive.sh
├── baseline/
│   ├── baseline-manifest.yaml
│   └── README.md
├── state/
│   └── .gitkeep
├── work/
│   └── .gitkeep
├── evidence-staging/
│   └── .gitkeep
└── logs/
    └── .gitkeep
```

### Directory rules

-   `config/`, `compose/`, `experiments/` and `scripts/` are
    version-controlled.
-   `config/lab.env.example` contains placeholders only. Do not commit
    credentials.
-   Local `lab.env`, private keys, tokens, wallet files, captures and
    sensitive outputs must be ignored by Git.
-   `baseline/` describes the expected clean state and pinned artifacts;
    it is not a location for secrets.
-   `state/` is mutable experiment state and can be cleared during
    reset.
-   `work/` is scratch output and can be cleared during reset.
-   `evidence-staging/` is temporary export staging, not the sole
    archive.
-   `logs/` is runtime/operator logging and must be reviewed for secrets
    before export.
-   The durable archive must be outside the disposable Compose project
    and must never be a Compose-managed disposable volume.
-   Do not place all evidence inside a container filesystem; container
    deletion would destroy it.
-   Do not mount the entire home directory or Windows user profile into
    a container.

The layout is a starting point. Do not create empty abstractions for
modules that the first experiment does not need.

## 7. Configuration and ownership model

Every resource must have an owner and lifecycle.

  -------------------------------------------------------------------------------------
  Resource          Owner           Survives `stop`    Survives `reset`      Removed by
                                                                              `destroy`
  ----------------- --------------- --------------- ------------------- ---------------
  Compose           Lab repository              Yes                 Yes              No
  definitions                                                           

  Pinned images     Docker image                Yes                 Yes       Optional,
                    store                                                      explicit

  Lab containers    Compose project      No running           Recreated             Yes
                                           workload                     

  Internal lab      Compose project  May be removed           Recreated             Yes
  network                                                               

  Mutable           Experiment              Usually   Cleared/recreated             Yes
  experiment volume                                                     

  Baseline          Lab repository              Yes                 Yes              No
  manifest/config                                                       

  Evidence staging  Operator                    Yes                 Yes      No, unless
                                                                             separately
                                                                               reviewed

  Durable archive   Operator/host               Yes                 Yes    Never by lab
  on Windows                                                                  `destroy`

  Temporary         Host/operator   Must be revoked     Must be revoked Must be revoked
  route/firewall                                                        
  exception                                                             

  WSL distribution  Host/platform               Yes                 Yes         Only by
                                                                          separate host
                                                                                 action
  -------------------------------------------------------------------------------------

`stop`, `reset`, `destroy` and host-level emergency termination are
different operations. Their names and scripts must not be
interchangeable.

## 8. Network design

### 8.1 Default profile: internal isolated experiment

The default experiment network is a dedicated Docker network declared as
internal. Only containers explicitly attached to it can participate in
that experiment topology. Do not attach it to a pre-existing network.

Illustrative Compose fragment for review---not yet approved as the final
implementation:

``` yaml
name: sec-lab-docker

services:
  client:
    build:
      context: ../experiments/EXP-0001-client-server/client
    networks:
      - experiment_net
    restart: "no"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    # Add only the minimum tmpfs or writable path the client needs.
    # No ports, privileged mode, host network, host mounts or Docker socket.

  server:
    build:
      context: ../experiments/EXP-0001-client-server/server
    networks:
      - experiment_net
    restart: "no"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    # Expose the service to peers on the Docker network only.
    # Do not publish it to the host.

networks:
  experiment_net:
    name: sec-lab-exp-0001
    driver: bridge
    internal: true
```

This is a design sketch. It must be validated against the installed
Docker Compose version and the needs of the selected images before use.
Some applications need writable temporary directories or a non-root
user; configure those narrowly rather than removing all hardening
because a container fails to start.

### 8.2 Network policy table

  -----------------------------------------------------------------------
  Path                    Default policy          How it is verified
  ----------------------- ----------------------- -----------------------
  Client → named server   Allow only if required  Successful expected
  service                 by the experiment       request and server-side
                                                  log

  Client → unrelated lab  Deny / no route unless  Attempt a controlled
  service                 explicitly declared     connection and record
                                                  result

  Container → public      Deny                    Controlled egress
  Internet                                        tests, route/config
                                                  inspection and
                                                  observation at relevant
                                                  host interfaces

  Container → LAN peer    Deny                    Test a known,
                                                  authorised test address
                                                  and inspect
                                                  host/network policy

  Container → Windows     Deny unless a specific  Test only against a
  host listener           experiment requires it  deliberately selected
                                                  safe test service;
                                                  inspect bindings and
                                                  routes

  Windows host →          No published port by    Inspect Docker/WSL
  container               default; do not assume  integration and test
                          total inaccessibility   from the host

  Container → other       Deny by default         Inspect network
  Docker networks                                 attachments and test
                                                  representative
                                                  forbidden paths

  Container → Docker      Deny                    Inspect mounts and
  daemon socket                                   Compose definitions

  Container → Windows     Deny by default         Inspect bind mounts and
  filesystem                                      WSL integration
                                                  assumptions

  Container → DNS         Deny for fully isolated Inspect resolver
  resolver                experiments unless      configuration and test
                          explicitly needed       DNS separately

  IPv6 egress             Must be understood, not Inspect IPv6
                          assumed disabled        addresses/routes and
                                                  test the intended
                                                  policy

  Maintenance download    Off during experiment   Record activation,
  path                                            acquisition, closure
                                                  and post-closure test
  -----------------------------------------------------------------------

An unsuccessful connection alone does not prove which control blocked
it. Pair connection tests with configuration inspection and telemetry.
Test IPv4 and IPv6 where enabled. DNS failure is not the same thing as
egress prevention: an application may use an IP address directly.

### 8.3 Host ports and bindings

-   No `ports:` mappings in the default Compose file.
-   Do not use `network_mode: host`.
-   Do not enable broad Windows port forwarding as a troubleshooting
    shortcut.
-   If a later experiment needs host-to-container access, define the
    exact service, port, source, direction, enforcement point, duration
    and rollback first.
-   Bind any necessary host-published service to loopback where the
    platform and use case support it, but do not treat loopback binding
    alone as a complete isolation guarantee.
-   Never expose a vulnerable target to the LAN or public Internet for
    convenience.

### 8.4 DNS, VPN and routing

The host has previously been observed with a Proton VPN adapter and
virtual networking. The topology must be re-inventoried before the lab's
egress tests are considered meaningful. VPN presence does not itself
mean traffic is contained; it can also change routes and the interface
where packets appear.

Do not assume that Docker's internal network alone governs every
WSL-to-Windows, Windows-to-WSL, VPN, IPv6, DNS, proxy or forwarding
path. Record the actual paths and test the ones relevant to the
experiment.

## 9. Killswitch and containment design

### 9.1 Meaning of "killswitch"

The killswitch is a set of independent containment actions, not a single
magical Docker setting. It has three layers:

1.  **Preventive boundary:** default-deny network policy and a minimal
    container configuration.
2.  **Detection and response:** observation and tests identify
    unexpected paths or behaviour; the operator or controller stops the
    experiment.
3.  **Host-controlled termination:** a control outside the experiment
    containers can stop the lab workloads and, at a higher severity,
    terminate the WSL runtime.

The host is more authoritative than the containers for emergency
termination. A process inside a compromised or hung container cannot be
the only component responsible for stopping itself.

### 9.2 Important limitation: packet-triggered shutdown

A rule such as "if any packet tries to leave, immediately kill the lab"
is a desired response, but it is not safe to implement as a claim based
solely on Wireshark detection. By the time a capture tool observes a
packet, that packet may already have passed the relevant enforcement
point. Captures can also miss packets because of interface choice,
offload behaviour, timing, privileges or resource limits.

Therefore:

-   **Block egress at the enforcement point first.**
-   Use capture/monitoring to detect and investigate attempted or
    unexpected traffic where visible.
-   Treat an unexpected egress observation as a stop condition.
-   If attempted-egress detection is required, choose and validate an
    enforcement/telemetry point capable of observing that attempt before
    or at the boundary; document exactly what it can see.
-   Do not claim "any packet escape is detected" until the
    implementation has been tested against a defined set of paths and
    failure modes.
-   A test that sees no packet is not proof that no packet escaped
    through an unobserved interface.

### 9.3 Trigger conditions

The emergency response should be invoked when any of these occurs:

-   unexpected external egress is confirmed or strongly indicated;
-   an experiment reaches a host, LAN or unrelated lab service that
    should be forbidden;
-   an unapproved published port, route, bridge, port forward or tunnel
    appears;
-   a container is found with unexpected privileges, host mounts,
    credentials or Docker socket access;
-   the allowed/forbidden path test fails;
-   the containment or observation tool stops working during an
    experiment that depends on it;
-   the lab controller loses state or cannot confirm which profile is
    active;
-   Windows becomes unresponsive or resource pressure threatens ordinary
    work;
-   teardown fails or a temporary path cannot be revoked;
-   host integrity is in doubt.

### 9.4 Response levels

**Level 1 --- Stop the experiment**

1.  Stop client activity.
2.  Stop the Compose project.
3.  Disable any experiment-specific access path.
4.  Preserve the relevant logs/capture if doing so does not prolong the
    risk.
5.  Verify containers are stopped and no published port or temporary
    route remains.
6.  Record the event and do not restart until the cause is understood.

**Level 2 --- Terminate the Docker lab runtime**

1.  Use the host-side emergency-stop procedure, not a command that must
    execute inside a lab container.
2.  Stop lab containers/project.
3.  Verify Docker lab containers are not running.
4.  If the Docker/WSL runtime remains suspect or unresponsive, shut down
    the relevant WSL distribution or WSL runtime from Windows.
5.  Verify the host has returned to its expected state.
6.  Preserve evidence after containment, if safe.

**Level 3 --- Host recovery**

1.  Stop using the lab.
2.  Disconnect the machine from networks only if needed to contain an
    ongoing incident and consistent with the operator's recovery plan.
3.  Inspect processes, routes, listeners, firewall rules, WSL state and
    Docker resources from Windows.
4.  Do not blindly kill system processes or disable the host firewall.
5.  Restore known host configuration and reboot if required.
6.  Do not resume experiments until the event has been assessed and the
    relevant controls re-tested.

### 9.5 Host-side emergency stop

Implement the Windows-side emergency stop as a small, manually invoked
PowerShell script after the actual WSL distribution name and Docker
context have been confirmed. The first version should be conservative
and should target only the known lab project.

Required behaviour:

-   log the timestamp and action;
-   attempt to stop the named lab Compose project;
-   verify lab containers are no longer running;
-   report failure explicitly rather than silently continuing;
-   provide a separate, clearly named higher-severity action to
    terminate WSL;
-   never run `wsl --unregister`;
-   never run broad Docker prune commands;
-   never delete the evidence archive;
-   never kill unrelated Docker containers or alter all Windows firewall
    rules by default.

The WSL shutdown command is broad: it can stop unrelated workloads in
WSL. Use it only after confirming the impact and accepting that it
terminates the WSL runtime, not just this project. The host emergency
procedure must remain usable even if a container or the in-WSL
controller is hung.

### 9.6 What this killswitch does not guarantee

It cannot guarantee protection against every kernel exploit, Docker/WSL
platform flaw, host compromise, shared-kernel weakness, hardware side
channel, unobserved path or malicious action by an administrator. The
lab is not appropriate for every class of hostile sample. A stronger
threat model may require a dedicated machine or a physically separate
network.

## 10. Lifecycle state machine

The lab lifecycle should be explicit:

``` text
OFF
 |
 v
PREFLIGHT --> FAIL CLOSED if requirements are not met
 |
 v
READY
 |
 v
STARTING --> validate config, confirm expected resources, create network/workloads
 |
 v
RUNNING --> capture / execute experiment / record observations
 |  \
 |   \ unexpected path, resource danger or failed control
 |    v
 |  CONTAINING --> stop workloads, revoke access, verify
 |
 v
STOPPING --> stop client and server, stop capture, revoke exceptions
 |
 v
VERIFYING --> inspect containers, ports, networks, routes and host state
 |
 +---- clean ------> STOPPED
 |
 +---- uncertain --> INCIDENT / HOST RECOVERY
 |
 v
RESETTING --> preserve needed evidence, remove mutable runtime state, recreate baseline
 |
 v
BASELINE READY

DESTROY is a separate operator-approved operation:
preserve evidence -> stop -> verify ownership -> remove lab-owned resources -> verify absence.
```

### Lifecycle definitions

-   **Stop:** Ends active workloads. Keeps reusable images, source
    definitions and baseline configuration.
-   **Reset:** Returns mutable experiment state to the declared
    baseline. Recreates containers/networks/ephemeral state from pinned
    definitions. Does not erase evidence.
-   **Destroy:** Removes lab-owned runtime resources and disposable
    volumes. Does not uninstall Docker/WSL and does not delete durable
    evidence.
-   **Emergency stop:** Prioritises containment over graceful
    completion; evidence may be incomplete.
-   **WSL termination:** Host-level action that terminates the WSL
    runtime/distribution and can affect unrelated WSL processes.
-   **Rebuild:** Recreates runtime resources from definitions and pinned
    dependencies. It should not mean reinstalling the entire lab stack.

## 11. Baseline and reset semantics

### 11.1 Define what "baseline" means

The baseline is not "whatever happens to be running now." It is a
recorded, reproducible state comprising:

-   versioned Compose and experiment configuration;
-   pinned image tags/digests or build inputs;
-   declared networks;
-   declared writable paths and volumes;
-   expected container identities and startup state;
-   expected network policy;
-   a list of expected ports (empty by default);
-   expected resource limits where supported and appropriate;
-   a baseline manifest with software versions and creation date;
-   tests that prove the baseline behaves as expected.

### 11.2 Mutable versus durable state

**Mutable state to reset:** containers, scratch files, temporary
databases, experiment-specific volumes, temporary networks and transient
processes.

**Durable state to preserve:** source/configuration, baseline manifest,
research records, approved evidence, archive hashes and reviewed
outputs.

If a research question requires persistence (for example, studying
database recovery), declare that state explicitly as part of the
experiment and decide whether reset should restore a clean snapshot,
reinitialise data, or preserve a designated dataset. Do not let
persistence happen accidentally.

### 11.3 Reset procedure

1.  Confirm the experiment ID and the lab project name.
2.  Stop new client activity.
3.  Stop capture cleanly if possible.
4.  Export evidence and logs needed for analysis.
5.  Hash staged evidence.
6.  Verify that the target Compose project and volumes are lab-owned.
7.  Stop/remove only the experiment's containers and networks.
8.  Remove or reinitialise only the experiment's declared mutable
    volumes.
9.  Recreate the project from the pinned configuration.
10. Run preflight and boundary tests.
11. Confirm the baseline manifest matches the intended versions and
    resources.
12. Record reset outcome and any deviation.

Do not use global `docker system prune`, `docker volume prune`, WSL
unregister or broad deletion commands as a reset strategy.

### 11.4 Complete wipe

A complete wipe is not the normal stop/reset path. It is a deliberate
operation after evidence has been archived.

The wipe script must: - show the exact lab-owned resources it intends to
remove; - require an explicit confirmation token or typed project
name; - stop the lab project; - remove only verified lab-owned
containers, networks and volumes; - leave source/configuration and
evidence alone unless a separate operator action requests their
deletion; - verify that the resources are absent afterward.

Removing the Docker images is optional because images are reusable
cached artefacts, not active sessions. Make cache removal a separate
explicit action. Never make WSL distribution deletion part of the normal
`destroy` operation.

## 12. Evidence architecture

Evidence must survive container, network and WSL-runtime deletion.

### 12.1 Experiment directory

Each experiment gets a unique ID, for example `EXP-0001-client-server`.
The record must include:

-   research question and hypothesis;
-   scope and authorisation;
-   date/time and operator;
-   host, WSL, Docker, Compose and image versions;
-   topology and network profile;
-   source/destination, protocol and port;
-   enforcement point;
-   expected allowed behaviour;
-   forbidden paths tested;
-   procedure and commands;
-   observations and results;
-   capture points and blind spots;
-   limitations and alternative explanations;
-   containment, teardown and recovery checks;
-   conclusion and next question.

### 12.2 Evidence folder

Example:

``` text
evidence/
└── EXP-0001-client-server/
    ├── experiment-record.md
    ├── environment-inventory.txt
    ├── compose-rendered.yaml
    ├── docker-inspect/
    ├── container-logs/
    ├── packet-captures/
    ├── test-results/
    ├── resource-measurements/
    ├── hashes.sha256
    └── archive-manifest.md
```

Review outputs before export. Redact credentials, private keys, provider
tokens, personal data and unrelated host details. Do not place secrets
into captures, logs or screenshots intentionally.

### 12.3 Transfer

1.  Stop or contain the experiment.
2.  Copy only selected evidence to the staging directory.
3.  Review for secrets and unrelated data.
4.  Generate SHA-256 hashes.
5.  Copy the reviewed bundle into the durable Windows archive.
6.  Verify hashes after transfer.
7.  Record the archive location and verification result.
8.  Only then reset or destroy disposable runtime state.

A hash records integrity relative to the recorded digest; it does not
prove that an observation was complete or truthful.

## 13. Observation and leakage inventory

Wireshark is an observation tool, not the lab's firewall and not a
universal leak detector. It should be started for an experiment when a
defined question requires packet-level evidence, and stopped when that
capture is no longer needed. Avoid continuous capture of every interface
on this resource-constrained host.

For each experiment, maintain a leakage inventory:

  -------------------------------------------------------------------------------
  ID                Potential path           Default treatment Evidence /
                                                               verification
  ----------------- ------------------------ ----------------- ------------------
  L-01              Container → Internet via Deny for default  Egress test,
                    Docker bridge            profile           route/config
                                                               inspection,
                                                               host-side capture
                                                               where visible

  L-02              Container → LAN          Deny              Controlled
                                                               forbidden-path
                                                               test

  L-03              Container → Windows host Deny unless       Inspect
                    service                  approved          bindings/routes;
                                                               test a selected
                                                               safe listener

  L-04              Published container port None by default   Rendered Compose
                                                               config and Docker
                                                               port inspection

  L-05              Host network mode        Prohibited by     Compose review
                                             default           

  L-06              Privileged container /   Prohibited by     Compose and
                    extra capabilities       default           container
                                                               inspection

  L-07              Docker socket mount      Prohibited        Mount inspection

  L-08              Windows/home-directory   Prohibited by     Compose and mount
                    bind mount               default           inspection

  L-09              WSL-to-Windows           Inventory and     WSL configuration
                    integration              narrow where      review and
                                             practical         targeted tests

  L-10              DNS/proxy path           No assumption;    Resolver/proxy
                                             test explicitly   inspection and
                                                               controlled query
                                                               tests

  L-11              IPv6 alternate path      Inventory and     Address/route
                                             test if enabled   inspection and
                                                               IPv6 test

  L-12              VPN/host route change    Inventory before  Route/interface
                                             each relevant     snapshot before
                                             experiment        and after

  L-13              Remote development       Off unless        Session status and
                    channel                  required          closure test

  L-14              Temporary host           Off by default    Snapshot
                    firewall/port-forward                      before/after;
                    rule                                       verify revocation

  L-15              Shared files/credentials No broad mounts;  Mount inspection
                                             no credentials    and repository
                                                               review

  L-16              Evidence lost during     Prevent with      Hash-verified
                    reset                    external archive  archive before
                                                               destructive action

  L-17              Capture blind spot       Document capture  Known test traffic
                                             point             and explicit
                                                               limitations

  L-18              Resource exhaustion      Bound workloads   CPU, memory,
                                             and monitor host  paging, disk and
                                                               responsiveness
                                                               record
  -------------------------------------------------------------------------------

Expand this inventory only when a new experiment adds a new path or
capability. Record owner, threat, control, test, evidence, result and
residual uncertainty for each relevant path.

## 14. Resource policy for the HP

The HP's approximate 8 GB RAM, two physical CPU cores and mechanical HDD
mean that the initial lab must stay small.

-   Run one principal workload at a time.
-   Begin with one client and one small server.
-   Do not run a heavy packet capture, multiple databases and large
    builds simultaneously.
-   Measure idle host CPU, available memory, paging and disk I/O before
    the experiment.
-   Record the same measures during and after the experiment.
-   Stop if Windows becomes unresponsive, paging materially harms
    usability, disk I/O makes ordinary work unusable, heat/power
    behaviour is abnormal, or resource use exceeds the planned limit.
-   Use an initial review threshold around 10--15% available RAM as a
    conservative guardrail, not a guarantee.
-   Do not assume a container memory limit alone protects the Windows
    host from every WSL/Docker resource issue.
-   Ensure enough disk space for image layers, builds, captures,
    archives and later VM use.

The host's current Docker/WSL configuration and resource state must be
inventoried before selecting numeric limits. Do not invent capacity
settings before observing the actual baseline.

## 15. Implementation sequence

Implement in dependency order. Each stage has a deliverable and an exit
test. Do not move to a later stage merely because software starts.

### Stage 0 --- Readiness inventory

**Actions** - Record `wsl --status`, WSL version and distribution
list. - Record Docker client/server version, context, info, containers,
networks and disk use. - Inspect existing Docker resources before
changing them. - Inspect WSL network mode/configuration, Windows
adapters/routes, VPN state, port proxies and relevant firewall
profiles/rules. - Record Windows listener owners and intended
exposure. - Measure idle CPU, available memory, paging and disk. -
Confirm whether Docker is using the expected WSL distribution/context.

**Exit criteria** - Existing resources are understood and no unrelated
container/network will be accidentally modified. - A baseline snapshot
exists. - Unknown conditions that materially affect the planned
experiment are documented and resolved or explicitly block the build.

### Stage 1 --- Repository and ownership

**Actions** - Create the directory layout. - Add README, `.gitignore`,
baseline manifest and experiment template. - Define the stable Compose
project name and lab resource labels. - Separate durable evidence from
mutable runtime state. - Add no destructive scripts yet.

**Exit criteria** - The repository can be reviewed without starting
containers. - No secrets are present. - Ownership rules for resources
and directories are documented.

### Stage 2 --- Minimal client/server topology

**Actions** - Create the first experiment with one client and one
server. - Use one dedicated internal Docker network. - Do not publish
ports. - Do not mount Windows directories, credentials or the Docker
socket. - Do not use privileged mode or host networking. - Pin image
versions or record exact build inputs. - Run a known request from client
to server.

**Exit criteria** - The expected request succeeds. - The server records
the expected request. - The containers have only the intended network
attachment. - There are no unexpected published ports or mounts. -
Evidence is recorded.

### Stage 3 --- Boundary verification

**Actions** - Verify the client can reach the intended service. - Test
representative forbidden destinations using safe, controlled targets. -
Inspect container routes, network attachments, ports, capabilities and
mounts. - Test relevant IPv4/IPv6, DNS and host-access assumptions. -
Observe traffic from a documented capture point if required. - Record
what each negative test does and does not prove.

**Exit criteria** - Allowed path passes. - Forbidden-path tests produce
the expected result. - Configuration inspection supports the result. -
No unexplained network path remains within the declared scope. - If a
boundary cannot be verified, the profile is not approved for experiments
that depend on it.

### Stage 4 --- Lifecycle and reset

**Actions** - Implement `start`, `status`, `stop`, `reset` and
`destroy`. - Keep reset separate from destroy. - Add ownership checks
before destructive actions. - Preserve evidence outside the Compose
project. - Run the experiment, stop it, reset it and run it again.

**Exit criteria** - A session can stop without reinstalling the lab. -
Reset recreates the declared baseline. - Evidence survives reset. -
Destroy removes only lab-owned disposable resources. - A second run is
reproducible.

### Stage 5 --- Host-side emergency stop

**Actions** - Implement a Windows-side PowerShell emergency-stop script
for the confirmed project. - Log the action and result. - Verify the
project is stopped. - Add a separate higher-severity WSL shutdown path
with clear warning. - Test it first with harmless workloads. - Document
what is affected if WSL shutdown terminates unrelated processes.

**Exit criteria** - The emergency stop does not depend on a lab
container. - It targets only known lab resources at its normal
severity. - It reports failure clearly. - The higher-severity action is
deliberate and separately invoked. - The operator can verify the
resulting host state.

### Stage 6 --- Capture and evidence archive

**Actions** - Add the chosen capture method for a known test exchange. -
Record capture interface and limitations. - Create the evidence bundle
and SHA-256 manifest. - Transfer the bundle to the Windows archive and
verify hashes. - Delete/recreate the runtime and confirm the evidence
remains readable.

**Exit criteria** - Evidence can be reviewed after runtime deletion. -
Hash verification succeeds after transfer. - Secrets and unrelated host
data are not exported. - The capture's visibility limits are documented.

### Stage 7 --- Failure injection and acceptance

**Actions** - Test a deliberately stopped container. - Test a failed
start due to invalid configuration. - Test a boundary test failure. -
Test a stop/teardown failure scenario that can be reproduced safely. -
Test resource-pressure stop behaviour using a controlled, low-risk
workload. - Test emergency stop and recovery. - Record the exact
observed results.

**Exit criteria** - Failure paths are visible and do not silently report
success. - The operator knows which state the lab is in. - Temporary
paths are revoked or the run is marked failed. - Host recovery is
documented and tested. - Acceptance criteria are completed with
evidence.

## 16. Command and script contracts

The implementation engineer should make each script predictable and
conservative.

### `preflight.sh`

Must check, without making changes: - Docker daemon is reachable through
the intended context; - expected project/configuration exists; - the
selected experiment ID is valid; - required images/build inputs are
available; - no conflicting lab run is active; - the expected network
profile is selected; - required host-side conditions have been
confirmed; - sufficient resource/disk headroom remains for the
experiment.

If a required check fails, exit non-zero and explain why. Do not "fix"
unknown host networking automatically.

### `validate.sh`

Must: - validate Compose syntax using the installed Compose
implementation; - render the configuration for review; - identify
services, networks, ports, volumes, privileged flags, capabilities and
host mounts; - fail or require explicit review if prohibited settings
appear; - avoid starting the experiment as a side effect.

### `start.sh`

Must: - run preflight and validation first; - verify that the selected
profile is the default isolated profile or an explicitly approved
profile; - start only the named project; - report the actual resources
started; - fail closed if required boundary checks do not pass; - not
silently enable Internet access, published ports, tunnels or host
firewall exceptions.

### `stop.sh`

Must: - stop the selected lab project; - revoke any experiment-specific
exception created by the lab procedure; - verify the containers are
stopped; - report any resource or access path it could not verify; -
preserve images and durable evidence.

### `reset.sh`

Must: - require a valid experiment/project identifier; - preserve/stage
evidence first, except during urgent containment; - remove only declared
mutable experiment state; - recreate from pinned definitions; - re-run
preflight and boundary checks; - fail if the recreated baseline differs
from the manifest.

### `destroy.sh`

Must: - display the resources it will remove; - verify each resource is
lab-owned; - require deliberate confirmation; - remove lab-owned
containers, networks and disposable volumes only; - leave the
repository, baseline definitions and durable evidence intact; - verify
removal and report residual resources.

### Host `EmergencyStop.ps1`

Must: - work independently of the lab container runtime; - attempt the
named Compose project stop; - verify the project state; - optionally
offer a separate WSL shutdown action; - log timestamp, command outcomes
and unresolved state; - never unregister a distribution, globally prune
Docker resources or delete evidence.

The exact command implementation should follow the installed
Docker/Compose and WSL versions recorded during Stage 0. Do not paste a
script into production use until its target distribution, Docker
context, project name and failure behaviour have been reviewed.

## 17. Acceptance test matrix

Record **Pass / Fail / Not tested**, timestamp, test conditions,
evidence reference and operator notes.

  -----------------------------------------------------------------------
  ID                      Test                    Expected result
  ----------------------- ----------------------- -----------------------
  DL-01                   Preflight against the   Correct context and
                          intended Docker context daemon are identified;
                                                  unknown context blocks
                                                  start

  DL-02                   Validate Compose        Valid configuration;
                          configuration           prohibited settings are
                                                  identified

  DL-03                   Start minimal           Only expected project
                          client/server           resources start
                          experiment              

  DL-04                   Client reaches intended Request succeeds and
                          server                  server-side evidence
                                                  exists

  DL-05                   Container port          No unintended host/LAN
                          inspection              published port

  DL-06                   Mount/capability        No broad host mounts,
                          inspection              Docker socket or
                                                  unnecessary privileges

  DL-07                   Internal network        Only intended
                          inspection              containers attach to
                                                  the experiment network

  DL-08                   Internet egress test    Unapproved egress is
                                                  blocked under the
                                                  declared test
                                                  conditions

  DL-09                   LAN/host forbidden-path Representative
                          test                    forbidden paths fail;
                                                  result is corroborated
                                                  with config/telemetry

  DL-10                   IPv6/DNS review         Applicable paths are
                                                  tested or explicitly
                                                  marked unresolved

  DL-11                   Capture known traffic   Capture point sees
                                                  expected traffic; blind
                                                  spots are documented

  DL-12                   Stop                    Workloads stop;
                                                  reusable
                                                  definitions/images
                                                  remain

  DL-13                   Reset                   Mutable state is reset
                                                  and the baseline can
                                                  run again

  DL-14                   Evidence persistence    Evidence remains
                                                  available after runtime
                                                  deletion

  DL-15                   Hash verification       SHA-256 verification
                                                  succeeds after transfer

  DL-16                   Destroy                 Only lab-owned
                                                  disposable resources
                                                  are removed

  DL-17                   Host emergency stop     Lab stops without
                                                  relying on a
                                                  container-side
                                                  controller

  DL-18                   WSL termination         Operator can
                          recovery                deliberately terminate
                                                  WSL and verify the
                                                  resulting host state

  DL-19                   Failure injection       Failure is reported; no
                                                  false success status

  DL-20                   Resource guardrail      Operator can detect and
                                                  stop an experiment that
                                                  threatens Windows
                                                  usability

  DL-21                   Maintenance closure     After acquisition, the
                                                  experiment profile
                                                  returns to isolated
                                                  mode and egress is
                                                  re-tested

  DL-22                   Repeatability           Same pinned
                                                  configuration produces
                                                  the expected topology
                                                  and behaviour again
  -----------------------------------------------------------------------

A passing result applies only to the tested configuration and paths. A
change to WSL, Docker, Compose, host firewall, VPN, routes, image
version or network profile may invalidate relevant tests.

## 18. Operational checklists

### Before every experiment

-   [ ] Research question and experiment ID are recorded.
-   [ ] Scope and authorisation are clear.
-   [ ] Selected profile and expected paths are defined.
-   [ ] Host/Docker/WSL state is known enough for this experiment.
-   [ ] Unrelated workloads are stopped.
-   [ ] Resource headroom is acceptable.
-   [ ] Compose configuration passes validation.
-   [ ] Required images and dependencies are present and versioned.
-   [ ] No unnecessary port, mount, privilege or socket access is
    present.
-   [ ] Evidence destination and capture point are defined.
-   [ ] Emergency-stop method is available.

### After every experiment

-   [ ] Stop client activity and lab workloads.
-   [ ] Stop captures cleanly where possible.
-   [ ] Revoke temporary routes, tunnels, ports and firewall exceptions.
-   [ ] Export and review evidence.
-   [ ] Hash and verify the evidence archive.
-   [ ] Inspect containers, networks, ports, mounts and routes.
-   [ ] Confirm the host returned to its expected state.
-   [ ] Record failures, uncertainty and limitations.
-   [ ] Reset or destroy only after evidence handling.
-   [ ] Mark all acceptance tests Pass, Fail or Not tested.

### During an incident

-   [ ] Prioritise containment over experiment completion.
-   [ ] Invoke host-side emergency stop if needed.
-   [ ] Do not rely on the suspect container to terminate itself.
-   [ ] Do not disable the whole host firewall as a troubleshooting
    step.
-   [ ] Preserve evidence only when doing so does not prolong exposure.
-   [ ] Verify revocation and host state.
-   [ ] Record the event and do not restart until reviewed.

## 19. Decisions deliberately deferred

The following are not yet fixed because they depend on the actual
installed environment or a defined experiment:

-   exact Docker/Compose versions and current daemon context;
-   whether Docker Desktop or Docker Engine inside WSL is in use;
-   exact WSL network mode and host integration behaviour;
-   final numeric resource limits;
-   specific packet-capture vantage point and privileges;
-   whether a host-level firewall rule is needed beyond Docker/WSL
    network controls;
-   exact PowerShell emergency-stop implementation;
-   whether any experiment needs persistent volumes;
-   whether the first experiment requires DNS, IPv6, or host
    communication;
-   whether a later experiment justifies an observer container or
    additional capabilities.

These are explicit implementation questions, not gaps to fill with
assumptions. Resolve them through Stage 0 inventory and the needs of the
first experiment.

## 20. Foundational alignment

This implementation specification carries forward the parent design's
principles:

-   The runtime is disposable; research evidence is durable.
-   Code executes in the assigned environment.
-   Routine experiments do not have direct Internet access.
-   Dependency acquisition is a separate maintenance operation.
-   No cross-silo communication is enabled merely for convenience.
-   Temporary paths have a purpose, scope, enforcement point,
    verification and revocation procedure.
-   A packet capture is evidence from one vantage point, not proof of
    universal isolation.
-   A successful stop command does not prove every route or resource is
    gone.
-   Start, stop, reset, destroy and host-level termination are separate
    operations.
-   Complexity is added only when a concrete research question justifies
    it.
-   Acceptance requires tested evidence, not merely successful startup.

**Initial implementation target:** Stage 0 through Stage 4. Do not begin
with the full killswitch automation. First establish a known host
baseline, a minimal internal client/server experiment, verified network
behaviour, durable evidence and a repeatable reset. Then implement and
test the host-side emergency stop against that known baseline.
