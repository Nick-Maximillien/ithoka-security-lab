import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from lab.networks import policy_json, resolve_network_policy


ROOT = Path(__file__).resolve().parents[1]
PROJECT = "sec-lab-i-network-test"
NETWORK_ID = "a" * 64


class NetworkBoundaryScriptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo"
        self.bin = Path(self.temporary.name) / "bin"
        self.bin.mkdir()
        (self.root / "scripts").mkdir(parents=True)
        shutil.copytree(ROOT / "lab", self.root / "lab")
        source = (ROOT / "scripts" / "network-boundary.sh").read_text(
            encoding="utf-8"
        )
        source = source.replace(
            '"/sys/class/net/$BRIDGE/bridge"',
            '"$TEST_SYS_CLASS_NET/$BRIDGE/bridge"',
        )
        (self.root / "scripts" / "network-boundary.sh").write_text(
            source, encoding="utf-8"
        )
        self.sys_class_net = Path(self.temporary.name) / "sys-class-net"
        (self.sys_class_net / "br-owned" / "bridge").mkdir(parents=True)
        self.policy_file = Path(self.temporary.name) / "policy.json"
        policy = resolve_network_policy(ROOT, "isolated", {
            "windows_host": {"enabled": False},
            "dns": {"enabled": False},
            "proxies": {"enabled": False},
        })
        self.policy_file.write_text(policy_json(policy), encoding="utf-8")
        self.firewall_state = Path(self.temporary.name) / "firewall.json"
        self.firewall_state.write_text(json.dumps({
            "chains": [],
            "rules": [{
            "tool": "iptables",
            "chain": "INPUT",
            "args": [
                "-i", "unrelated0", "-m", "comment", "--comment",
                "unrelated-rule", "-j", "DROP",
            ],
            }],
        }), encoding="utf-8")
        self._write_command("sudo", "#!/bin/sh\n[ \"$1\" = \"-n\" ] && shift\nexec \"$@\"\n")
        self._write_command("docker", self._docker_mock())
        self._write_command("ip", self._ip_mock())
        firewall_mock = self._firewall_mock()
        self._write_command("iptables", firewall_mock)
        self._write_command("ip6tables", firewall_mock)
        self.environment = {
            **os.environ,
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "FAKE_FIREWALL_STATE": str(self.firewall_state),
            "TEST_SYS_CLASS_NET": str(self.sys_class_net),
        }

    def tearDown(self):
        self.temporary.cleanup()

    def _write_command(self, name, contents):
        command = self.bin / name
        command.write_text(contents, encoding="utf-8")
        command.chmod(0o755)

    @staticmethod
    def _docker_mock():
        return f"""#!/usr/bin/env python3
import json
import sys

args = sys.argv[1:]
if args[:3] == ["network", "ls", "-q"]:
    print("{NETWORK_ID}")
    raise SystemExit(0)
if args[:2] != ["network", "inspect"]:
    raise SystemExit("unexpected docker command: " + repr(args))
template = args[args.index("--format") + 1]
if template.startswith("{{{{.Internal}}}}|"):
    print("true|bridge|{PROJECT}|security-lab|network-test")
elif template == "{{{{.Name}}}}":
    print("{PROJECT}_investigation")
elif "com.docker.network.bridge.name" in template:
    print("")
elif template == "{{{{json .IPAM.Config}}}}":
    print(json.dumps([{{"Subnet": "172.30.0.0/16", "Gateway": "172.30.0.1"}}]))
elif ".Subnet" in template:
    print("172.30.0.0/16")
else:
    raise SystemExit("unexpected docker format: " + template)
"""

    @staticmethod
    def _ip_mock():
        return """#!/usr/bin/env python3
import json
print(json.dumps([{
    "ifname": "br-owned",
    "addr_info": [{"family": "inet", "local": "172.30.0.1"}],
}]))
"""

    @staticmethod
    def _firewall_mock():
        return """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
path = Path(os.environ["FAKE_FIREWALL_STATE"])
state = json.loads(path.read_text(encoding="utf-8"))
if args == ["--version"]:
    print(tool + " v1.8.9 (legacy)")
    raise SystemExit(0)
if args[:1] == ["-S"]:
    if len(args) == 1:
        for chain in ("INPUT", "OUTPUT", "FORWARD"):
            for rule in state["rules"]:
                if rule["tool"] == tool and rule["chain"] == chain:
                    print("-A " + chain + " " + " ".join(rule["args"]))
        for item in state["chains"]:
            if item["tool"] == tool:
                print("-N " + item["chain"])
                for rule in item["rules"]:
                    print("-A " + item["chain"] + " " + " ".join(rule))
        raise SystemExit(0)
    chain = args[1]
    item = next((item for item in state["chains"]
                 if item["tool"] == tool and item["chain"] == chain), None)
    if item is not None:
        print("-N " + chain)
        for rule in item["rules"]:
            print("-A " + chain + " " + " ".join(rule))
        raise SystemExit(0)
    if chain in {"INPUT", "OUTPUT", "FORWARD"}:
        for rule in state["rules"]:
            if rule["tool"] == tool and rule["chain"] == chain:
                print("-A " + chain + " " + " ".join(rule["args"]))
        raise SystemExit(0)
    raise SystemExit(1)
if not args or args[0] not in {"-C", "-I", "-D", "-N", "-A", "-X"}:
    raise SystemExit("unexpected firewall command: " + repr(args))
action = args[0]
if action == "-N":
    if any(item["tool"] == tool and item["chain"] == args[1] for item in state["chains"]):
        raise SystemExit(1)
    state["chains"].append({"tool": tool, "chain": args[1], "rules": []})
    path.write_text(json.dumps(state), encoding="utf-8")
    raise SystemExit(0)
if action == "-X":
    item = next((item for item in state["chains"]
                 if item["tool"] == tool and item["chain"] == args[1]), None)
    if item is None or item["rules"]:
        raise SystemExit(1)
    if any(rule["tool"] == tool and args[1] in rule["args"]
           for rule in state["rules"]):
        raise SystemExit(1)
    state["chains"].remove(item)
    path.write_text(json.dumps(state), encoding="utf-8")
    raise SystemExit(0)
chain = args[1]
item = next((item for item in state["chains"]
             if item["tool"] == tool and item["chain"] == chain), None)
if item is None and chain not in {"INPUT", "OUTPUT", "FORWARD"}:
    raise SystemExit(1)
if action == "-I":
    rule_args = args[3:]
elif action in {"-C", "-D", "-A"}:
    rule_args = args[2:]
else:
    raise SystemExit("unexpected firewall command: " + repr(args))
rules = item["rules"] if item is not None else None
if rules is None:
    rules = [rule["args"] for rule in state["rules"]
             if rule["tool"] == tool and rule["chain"] == chain]
matches = [index for index, rule in enumerate(rules) if rule == rule_args]
if action == "-C":
    raise SystemExit(0 if matches else 1)
if action == "-I":
    rules.insert(max(0, int(args[2]) - 1), rule_args)
elif action == "-A":
    rules.append(rule_args)
elif action == "-D":
    if not matches:
        raise SystemExit(1)
    rules.pop(matches[0])
if item is not None:
    item["rules"] = rules
else:
    state["rules"] = [
        rule for rule in state["rules"]
        if not (rule["tool"] == tool and rule["chain"] == chain)
    ]
    state["rules"].extend(
        {"tool": tool, "chain": chain, "args": rule}
        for rule in rules
    )
path.write_text(json.dumps(state), encoding="utf-8")
"""

    def _run(self, action, policy_file=None):
        policy = policy_file or self.policy_file
        return subprocess.run(
            [
                "bash",
                str(self.root / "scripts" / "network-boundary.sh"),
                action,
                PROJECT,
                str(policy),
            ],
            cwd=self.root,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_adapter_applies_owned_chains_idempotently_and_preserves_unrelated_rules(self):
        first = self._run("apply")
        self.assertEqual(first.returncode, 0, first.stderr)
        applied = self.firewall_state.read_text(encoding="utf-8")
        second = self._run("apply")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.firewall_state.read_text(encoding="utf-8"), applied)
        verified = self._run("verify")
        self.assertEqual(verified.returncode, 0, verified.stderr)
        state = json.loads(applied)
        self.assertEqual(len(state["chains"]), 4)
        self.assertTrue(any(
            rule["chain"] == "INPUT"
            and rule["args"] == [
                "-i", "unrelated0", "-m", "comment", "--comment",
                "unrelated-rule", "-j", "DROP",
            ]
            for rule in state["rules"]
        ))

    def test_adapter_cleanup_removes_only_project_owned_chains_and_jumps(self):
        applied = self._run("apply")
        self.assertEqual(applied.returncode, 0, applied.stderr)
        removed = self._run("remove")
        self.assertEqual(removed.returncode, 0, removed.stderr)
        state = json.loads(self.firewall_state.read_text(encoding="utf-8"))
        self.assertEqual(state["chains"], [])
        self.assertEqual(state["rules"], [{
            "tool": "iptables",
            "chain": "INPUT",
            "args": [
                "-i", "unrelated0", "-m", "comment", "--comment",
                "unrelated-rule", "-j", "DROP",
            ],
        }])

    def test_adapter_rejects_unsupported_runtime_acceptance_without_mutation(self):
        policy = resolve_network_policy(ROOT, "isolated", {
            "windows_host": {"enabled": False},
            "dns": {"enabled": False},
            "proxies": {"enabled": False},
            "external_networks": {"verification": ["forwarding_rules"]},
        })
        unsupported = Path(self.temporary.name) / "unsupported.json"
        unsupported.write_text(policy_json(policy), encoding="utf-8")
        before = self.firewall_state.read_text(encoding="utf-8")
        result = self._run("apply", unsupported)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported verification requirements", result.stderr)
        self.assertEqual(self.firewall_state.read_text(encoding="utf-8"), before)


if __name__ == "__main__":
    unittest.main()
