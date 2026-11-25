#!/usr/bin/env python3
"""Unit tests for rustdesk-ctl with fake docker, systemctl and ss commands."""

import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
OLD = "rustdesk/rustdesk-server@sha256:" + "a" * 64
NEW_DIGEST = "sha256:" + "b" * 64
NEW = "rustdesk/rustdesk-server@" + NEW_DIGEST

# One fake for docker, systemctl and ss; the shared state lives in state.json.
FAKE = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
tool = Path(sys.argv[0]).name
args = sys.argv[1:]
lab = Path(os.environ["LAB"])
state_file = lab / "state.json"
state = json.loads(state_file.read_text())
mode = state.get("mode", "")
rustdesk = Path(os.environ["RUSTDESK"])
with (lab / "calls").open("a") as stream:
    stream.write(tool + " " + " ".join(args) + "\n")

def save():
    state_file.write_text(json.dumps(state))

def image():
    env = rustdesk / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith("RUSTDESK_IMAGE="):
                return line.split("=", 1)[1]
    return state["default_image"]

def start(services=("hbbr", "hbbs")):
    new = image().endswith("b" * 64)
    for service in services:
        state["containers"][service] = {"status": "running", "restarts": 0}
        if mode == "crash-new" and new and service == "hbbr":
            state["containers"][service]["restarts"] = 2
        if mode == "crash-always" and service == "hbbr":
            state["containers"][service]["restarts"] = 2
    save()

def stop():
    state["containers"] = {}
    save()

if tool == "ss":
    up = all(state["containers"].get(s, {}).get("status") == "running" for s in ("hbbs", "hbbr"))
    if up and mode != "ports-down":
        print("LISTEN 0 128 *:port *:*")
    sys.exit(0)

if tool == "systemctl":
    if args[:1] == ["show"]:
        prop, unit = args[1 if args[0] != "-p" else 2], args[-1]
        prop = args[args.index("-p") + 1]
        if prop == "ActiveState":
            print("active" if state["active"].get(unit) else "inactive")
        elif prop == "NextElapseUSecRealtime":
            print("Sun 2026-11-29 04:30:00 UTC")
        elif prop == "Result":
            print("success")
        else:
            print("")
        sys.exit(0)
    quiet = [a for a in args if not a.startswith("--")]
    verb, units = quiet[0], quiet[1:]
    now = "--now" in args
    if verb == "is-enabled":
        sys.exit(0 if all(u in state["enabled"] for u in units) else 1)
    if verb == "enable":
        for unit in units:
            state["enabled"][unit] = True
            if now:
                state["active"][unit] = True
    elif verb == "disable":
        for unit in units:
            state["enabled"].pop(unit, None)
            if now:
                state["active"].pop(unit, None)
                if unit == "rustdesk-compose.service":
                    stop()
    elif verb in ("start", "restart"):
        for unit in units:
            state["active"][unit] = True
            if unit == "rustdesk-compose.service":
                if mode == "restart-fails":
                    save()
                    sys.exit(1)
                start()
    elif verb == "stop":
        for unit in units:
            state["active"].pop(unit, None)
            if unit == "rustdesk-compose.service":
                stop()
    save()
    sys.exit(0)

# docker
if args[:2] in (["compose", "version"], ["buildx", "version"]) or args[:1] == ["info"]:
    sys.exit(0)
if args[:2] == ["compose", "config"]:
    if "--images" in args:
        print(image())
        print(image())
    sys.exit(0)
if args[:2] == ["compose", "pull"]:
    if mode == "pull-fails" and image().endswith("b" * 64):
        sys.exit(1)
    sys.exit(0)
if args[:2] == ["compose", "up"]:
    if "--no-deps" in args:
        if mode == "keygen-fails":
            sys.exit(1)
        data = rustdesk / "data"
        if not (data / "id_ed25519").exists():
            state["generated"] = state.get("generated", 0) + 1
            (data / "id_ed25519").write_text("SK-%d" % state["generated"])
            (data / "id_ed25519").chmod(0o644)
            (data / "id_ed25519.pub").write_text("PK-%d" % state["generated"])
        start(("hbbs",))
    else:
        start()
    sys.exit(0)
if args[:2] == ["compose", "down"]:
    stop()
    sys.exit(0)
if args[:2] == ["compose", "logs"]:
    if "--no-log-prefix" in args and args[-1] in ("hbbs", "hbbr") and "--since" not in args:
        key = (rustdesk / "data/id_ed25519.pub").read_text()
        if mode == "hbbr-old-key" and args[-1] == "hbbr":
            key = "PK-OLD"
        print("Key: " + key)
        if mode == "long-logs":
            for i in range(60000):
                sys.stdout.write("INFO relay connection from 192.0.2.1:%d\n" % i)
    elif "--tail" in args:
        print("line \x1b]0;pwned\x07 error")
    elif mode == "log-errors":
        print("ERROR something \x1b[2J broke")
    sys.exit(0)
if args[:2] == ["compose", "exec"]:
    print(args[-2] + " 1.1.16")
    sys.exit(0)
if args[:3] == ["buildx", "imagetools", "inspect"]:
    print('"' + state.get("latest", NEW_DIGEST) + '"')
    sys.exit(0)
if args[:1] == ["inspect"]:
    fmt = args[args.index("-f") + 1]
    names = args[args.index("-f") + 2:]
    for name in names:
        container = state["containers"].get(name)
        if mode == "transient" and name == "hbbr" and fmt == "{{.State.Status}}":
            state["inspected"] = state.get("inspected", 0) + 1
            save()
            if state["inspected"] == 1:
                print("exited")
                continue
        if container is None:
            sys.exit(1)
        if fmt == "{{.State.Status}}":
            print(container["status"])
        elif fmt == "{{.RestartCount}}":
            print(container["restarts"])
        else:
            print("%s %s 2026-11-25T00:00:00Z" % (container["status"], container["restarts"]))
    sys.exit(0)
if args[:1] == ["ps"]:
    flt = args[args.index("--filter") + 1]
    for name in state["containers"]:
        if flt.startswith("label=") or flt == "name=^%s$" % name:
            print("id-" + name)
    sys.exit(0)
if args[:1] == ["rm"]:
    for cid in args[2:]:
        state["containers"].pop(cid[3:], None)
    save()
    sys.exit(0)
if args[:2] == ["image", "ls"]:
    for image_id in state.get("images", []):
        print(image_id)
    sys.exit(0)
if args[:2] == ["image", "rm"]:
    if "-f" in args:
        state["images"] = [i for i in state.get("images", []) if i not in args]
        save()
    sys.exit(0)
print("unexpected docker call: " + " ".join(args), file=sys.stderr)
sys.exit(3)
'''.replace("NEW_DIGEST", repr(NEW_DIGEST))


class RustdeskCtl(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rustdesk-ctl-")
        self.addCleanup(temporary.cleanup)
        self.lab = Path(temporary.name)
        self.rustdesk = self.lab / "opt/rustdesk"
        self.units = self.lab / "units"
        self.sbin = self.lab / "sbin"
        self.docker_config = self.lab / "etc-docker"
        self.checkout = self.lab / "checkout"
        for directory in (self.units, self.sbin, self.lab / "bin", self.checkout / "files"):
            directory.mkdir(parents=True)
        fake = self.lab / "bin/fake"
        fake.write_text(FAKE)
        fake.chmod(0o755)
        for tool in ("docker", "systemctl", "ss"):
            (self.lab / "bin" / tool).symlink_to(fake)

        script = (ROOT / "rustdesk-ctl").read_text()
        for old, new in (
            ('readonly RUSTDESK_DIR="/opt/rustdesk"', f'readonly RUSTDESK_DIR="{self.rustdesk}"'),
            ('readonly CTL_PATH="/usr/local/sbin/rustdesk-ctl"', f'readonly CTL_PATH="{self.sbin}/rustdesk-ctl"'),
            ('readonly UNIT_DIR="/etc/systemd/system"', f'readonly UNIT_DIR="{self.units}"'),
            ('readonly DOCKER_CONFIG_DIR="/etc/docker"', f'readonly DOCKER_CONFIG_DIR="{self.docker_config}"'),
            ('readonly LEGACY_UPDATER="/usr/local/sbin/rustdesk-safe-update.sh"',
             f'readonly LEGACY_UPDATER="{self.sbin}/rustdesk-safe-update.sh"'),
            ('readonly LEGACY_LOCK="/run/lock/rustdesk-update.lock"',
             f'readonly LEGACY_LOCK="{self.lab}/run-lock-rustdesk-update.lock"'),
            ('readonly TIMER_STAMP_DIR="/var/lib/systemd/timers"', f'readonly TIMER_STAMP_DIR="{self.lab}/timers"'),
            ("readonly WAIT_SECONDS=30", "readonly WAIT_SECONDS=1"),
            ("readonly SETTLE_SECONDS=15", "readonly SETTLE_SECONDS=0"),
            ("readonly WATCHDOG_RECHECK_SECONDS=20", "readonly WATCHDOG_RECHECK_SECONDS=0"),
            ('require_root() { [ "$(id -u)" -eq 0 ] || die "run as root"; }', "require_root() { :; }"),
            ("[ -d /run/systemd/system ] || die", "true || die"),
            (" -o root -g root", ""),
            ('main "$@"\n', 'if [ "${1:-}" = __call ]; then shift; "$@"; else main "$@"; fi\n'),
        ):
            self.assertIn(old, script)
            script = script.replace(old, new)
        self.ctl = self.checkout / "rustdesk-ctl"
        self.ctl.write_text(script)
        self.ctl.chmod(0o755)
        for item in (ROOT / "files").iterdir():
            (self.checkout / "files" / item.name).write_text(item.read_text())
        self.write_state()

    def write_state(self, **changes):
        state = {"mode": "", "containers": {}, "active": {}, "enabled": {},
                 "default_image": OLD, "latest": NEW_DIGEST}
        state.update(changes)
        (self.lab / "state.json").write_text(json.dumps(state))

    def state(self):
        return json.loads((self.lab / "state.json").read_text())

    def calls(self):
        path = self.lab / "calls"
        return path.read_text().splitlines() if path.exists() else []

    def run_ctl(self, *args, script=None):
        environment = dict(os.environ, LAB=str(self.lab), RUSTDESK=str(self.rustdesk),
                           PATH=str(self.lab / "bin") + os.pathsep + os.environ["PATH"])
        return subprocess.run(["bash", str(script or self.ctl), *args], env=environment, text=True,
                              capture_output=True, timeout=60, stdin=subprocess.DEVNULL)

    def installed(self, key=True, env=None, mode=""):
        """Simulate a running installation."""
        (self.rustdesk / "data").mkdir(parents=True, exist_ok=True)
        (self.rustdesk / "docker-compose.yml").write_text((ROOT / "files/docker-compose.yml").read_text())
        if key:
            (self.rustdesk / "data/id_ed25519").write_text("SK-OLD")
            (self.rustdesk / "data/id_ed25519.pub").write_text("PK-OLD")
        if env:
            (self.rustdesk / ".env").write_text(env)
        running = {"status": "running", "restarts": 0}
        self.write_state(mode=mode, containers={"hbbs": dict(running), "hbbr": dict(running)},
                         active={"rustdesk-compose.service": True},
                         enabled={"rustdesk-compose.service": True})

    # ------------------------------------------------------------ install

    def test_fresh_install_generates_key_with_hbbs_first_and_enables_everything(self):
        legacy = self.sbin / "rustdesk-safe-update.sh"
        legacy.write_text("old")
        result = self.run_ctl("install")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PK-1", result.stdout)
        data = self.rustdesk / "data"
        self.assertEqual(data.stat().st_mode & 0o777, 0o700)
        self.assertEqual((data / "id_ed25519").stat().st_mode & 0o777, 0o600)
        self.assertTrue((self.rustdesk / "docker-compose.yml").exists())
        for unit in ("rustdesk-compose.service", "rustdesk-update.service", "rustdesk-update.timer",
                     "rustdesk-watchdog.service", "rustdesk-watchdog.timer"):
            self.assertTrue((self.units / unit).exists(), unit)
        self.assertTrue(os.access(self.sbin / "rustdesk-ctl", os.X_OK))
        self.assertFalse(legacy.exists())
        calls = self.calls()
        self.assertLess(calls.index("docker compose up -d --wait --no-deps hbbs"),
                        calls.index("systemctl start rustdesk-compose.service"))
        enabled = self.state()["enabled"]
        for unit in ("rustdesk-compose.service", "rustdesk-update.timer", "rustdesk-watchdog.timer"):
            self.assertIn(unit, enabled)

    def test_reinstall_keeps_key_and_image_and_does_not_restart(self):
        self.installed(env="RUSTDESK_IMAGE=" + NEW + "\n")
        result = self.run_ctl("install")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.rustdesk / "data/id_ed25519.pub").read_text(), "PK-OLD")
        self.assertEqual((self.rustdesk / ".env").read_text(), "RUSTDESK_IMAGE=" + NEW + "\n")
        calls = self.calls()
        self.assertNotIn("docker compose up -d --wait --no-deps hbbs", calls)
        self.assertNotIn("systemctl start rustdesk-compose.service", calls)
        self.assertIn("docker compose up -d --wait --remove-orphans", calls)

    def test_install_can_skip_timers(self):
        result = self.run_ctl("install", "--no-auto-update", "--no-watchdog")
        self.assertEqual(result.returncode, 0, result.stderr)
        enabled = self.state()["enabled"]
        self.assertNotIn("rustdesk-update.timer", enabled)
        self.assertNotIn("rustdesk-watchdog.timer", enabled)
        self.assertIn("systemctl disable --now rustdesk-watchdog.timer", self.calls())

    def test_install_fails_when_services_are_unhealthy(self):
        self.write_state(mode="ports-down")
        result = self.run_ctl("install")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not listening", result.stderr)
        self.assertNotIn("rustdesk-update.timer", self.state()["enabled"])

    def test_install_needs_the_checkout_and_valid_flags(self):
        self.assertEqual(self.run_ctl("install", "--bogus").returncode, 2)
        copy = self.lab / "elsewhere/rustdesk-ctl"
        copy.parent.mkdir()
        copy.write_text(self.ctl.read_text())
        result = self.run_ctl("install", script=copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checkout of the repository", result.stderr)

    # ------------------------------------------------------------- update

    def test_update_deploys_latest_and_removes_old_image(self):
        self.installed(env="RUSTDESK_IMAGE=" + OLD + "\nOTHER=1\n")
        result = self.run_ctl("update")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.rustdesk / ".env").read_text(), "OTHER=1\nRUSTDESK_IMAGE=" + NEW + "\n")
        self.assertIn("docker image rm " + OLD, self.calls())
        self.assertFalse(list(self.rustdesk.glob(".env.*")))

    def test_update_is_a_no_op_when_latest(self):
        self.installed(env="RUSTDESK_IMAGE=" + NEW + "\n")
        result = self.run_ctl("update")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already uses the latest", result.stdout)
        self.assertFalse(any(c.startswith("docker compose pull") for c in self.calls()))

    def test_failed_update_restores_previous_image(self):
        for mode in ("pull-fails", "crash-new"):
            with self.subTest(mode=mode):
                self.installed(env="RUSTDESK_IMAGE=" + OLD + "\n", mode=mode)
                result = self.run_ctl("update")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("restoring the previous image", result.stderr)
                self.assertEqual((self.rustdesk / ".env").read_text(), "RUSTDESK_IMAGE=" + OLD + "\n")
                self.assertFalse(list(self.rustdesk.glob(".env.*")))
                self.assertNotIn("docker image rm " + OLD, self.calls())

    def test_failed_rollback_keeps_backup(self):
        self.installed(env="RUSTDESK_IMAGE=" + OLD + "\n", mode="crash-always")
        result = self.run_ctl("update")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rollback failed", result.stderr)
        backups = list(self.rustdesk.glob(".env.backup.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), "RUSTDESK_IMAGE=" + OLD + "\n")

    def test_update_waits_for_the_lock(self):
        self.installed()
        with open(self.rustdesk / ".update.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = self.run_ctl("update")
        self.assertEqual(result.returncode, 75)

    # ----------------------------------------------------------- watchdog

    def test_watchdog_leaves_a_healthy_server_alone(self):
        self.installed()
        result = self.run_ctl("watchdog")
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))
        self.assertNotIn("systemctl restart rustdesk-compose.service", self.calls())

    def test_watchdog_ignores_a_transient_failure(self):
        self.installed(mode="transient")
        result = self.run_ctl("watchdog")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("systemctl restart rustdesk-compose.service", self.calls())

    def test_watchdog_restarts_a_down_server_and_records_it(self):
        self.installed()
        state = self.state()
        state["containers"]["hbbr"]["status"] = "exited"
        (self.lab / "state.json").write_text(json.dumps(state))
        result = self.run_ctl("watchdog")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("hbbr: exited", result.stderr)
        self.assertIn("recovered", result.stderr)
        self.assertIn("systemctl restart rustdesk-compose.service", self.calls())
        self.assertEqual(len((self.rustdesk / ".watchdog-restarts").read_text().split()), 1)

    def test_watchdog_stops_after_three_restarts_an_hour(self):
        self.installed()
        state = self.state()
        state["containers"] = {}
        (self.lab / "state.json").write_text(json.dumps(state))
        now = int(time.time())
        (self.rustdesk / ".watchdog-restarts").write_text(
            "%d\n%d\n%d\n%d\n" % (now - 7200, now - 1000, now - 500, now - 10))
        result = self.run_ctl("watchdog")
        self.assertEqual(result.returncode, 1)
        self.assertIn("3 restarts in the last hour", result.stderr)
        self.assertNotIn("systemctl restart rustdesk-compose.service", self.calls())

    def test_watchdog_respects_a_stopped_service_and_a_running_update(self):
        self.installed()
        state = self.state()
        state["containers"] = {}
        state["active"] = {}
        (self.lab / "state.json").write_text(json.dumps(state))
        result = self.run_ctl("watchdog")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("systemctl restart rustdesk-compose.service", self.calls())

        self.installed()
        state = self.state()
        state["containers"] = {}
        (self.lab / "state.json").write_text(json.dumps(state))
        with open(self.rustdesk / ".update.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = self.run_ctl("watchdog")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("skipping", result.stdout)
        self.assertNotIn("systemctl restart rustdesk-compose.service", self.calls())

    def test_watchdog_reports_a_failed_recovery(self):
        self.installed(mode="restart-fails")
        state = self.state()
        state["containers"] = {}
        (self.lab / "state.json").write_text(json.dumps(state))
        result = self.run_ctl("watchdog")
        self.assertNotEqual(result.returncode, 0)

    # ---------------------------------------------------------------- key

    def test_key_rotation_backs_up_the_old_pair(self):
        self.installed()
        result = self.run_ctl("key", "rotate", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PK-1", result.stdout)
        data = self.rustdesk / "data"
        self.assertEqual((data / "id_ed25519.pub").read_text(), "PK-1")
        self.assertEqual((data / "id_ed25519").stat().st_mode & 0o777, 0o600)
        backups = list((self.rustdesk / "key-backups").iterdir())
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / "id_ed25519").read_text(), "SK-OLD")
        order = [c for c in self.calls() if c.startswith(("docker compose down", "docker compose up"))]
        self.assertEqual(order, ["docker compose down", "docker compose up -d --wait --no-deps hbbs",
                                 "docker compose up -d --wait"])

    def test_failed_key_rotation_restores_the_old_pair(self):
        for mode in ("keygen-fails", "hbbr-old-key"):
            with self.subTest(mode=mode):
                self.installed(mode=mode)
                result = self.run_ctl("key", "rotate", "--yes")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("restoring the previous key", result.stderr)
                self.assertEqual((self.rustdesk / "data/id_ed25519").read_text(), "SK-OLD")
                self.assertEqual((self.rustdesk / "data/id_ed25519.pub").read_text(), "PK-OLD")
                self.assertEqual(list((self.rustdesk / "key-backups").iterdir()), [])

    def test_key_rotation_needs_confirmation_and_key_show_prints_the_key(self):
        self.installed()
        result = self.run_ctl("key", "rotate")
        self.assertEqual(result.returncode, 1)
        self.assertIn("use --yes", result.stderr)
        self.assertNotIn("docker compose down", self.calls())
        result = self.run_ctl("key", "show")
        self.assertEqual((result.returncode, result.stdout), (0, "PK-OLD\n"))

    # ---------------------------------------------------------- uninstall

    def plant_leftovers(self):
        for unit in ("rustdesk-compose.service", "rustdesk-update.service", "rustdesk-update.timer",
                     "rustdesk-watchdog.service", "rustdesk-watchdog.timer"):
            (self.units / unit).write_text("[Unit]\n")
        (self.units / "rustdesk-compose.service.d").mkdir()
        (self.units / "rustdesk-compose.service.d/override.conf").write_text("[Service]\n")
        (self.units / "multi-user.target.wants").mkdir()
        (self.units / "multi-user.target.wants/rustdesk-compose.service").symlink_to(
            self.units / "rustdesk-compose.service")
        (self.units / "multi-user.target.wants/other.service").symlink_to("/dev/null")
        (self.units / "timers.target.wants").mkdir()
        (self.units / "timers.target.wants/rustdesk-old.timer").symlink_to("/nonexistent")
        (self.lab / "timers").mkdir()
        (self.lab / "timers/stamp-rustdesk-update.timer").write_text("")
        (self.lab / "timers/stamp-other.timer").write_text("")
        (self.lab / "run-lock-rustdesk-update.lock").write_text("")
        (self.sbin / "rustdesk-safe-update.sh").write_text("old")
        (self.sbin / "rustdesk-ctl").write_text("ctl")
        state = self.state()
        state["images"] = ["img-current", "img-older-digest"]
        (self.lab / "state.json").write_text(json.dumps(state))

    def assert_nothing_left(self):
        self.assertEqual(sorted(p.name for p in self.units.rglob("*")),
                         ["multi-user.target.wants", "other.service", "timers.target.wants"])
        self.assertEqual([p.name for p in (self.lab / "timers").iterdir()], ["stamp-other.timer"])
        self.assertFalse((self.lab / "run-lock-rustdesk-update.lock").exists())
        self.assertEqual(list(self.sbin.iterdir()), [])
        state = self.state()
        self.assertEqual((state["containers"], state["images"]), ({}, []))

    def test_uninstall_removes_everything_but_the_key_pair(self):
        self.installed(env="RUSTDESK_IMAGE=" + NEW + "\n")
        (self.rustdesk / "key-backups").mkdir()
        (self.rustdesk / "docker-compose.override.yml").write_text("services: {}\n")
        self.plant_leftovers()
        result = self.run_ctl("uninstall")
        self.assertEqual(result.returncode, 1)
        self.assertIn("use --yes", result.stderr)
        self.assertTrue((self.units / "rustdesk-compose.service").exists())

        result = self.run_ctl("uninstall", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(p.name for p in self.rustdesk.iterdir()), ["data", "key-backups"])
        self.assertEqual((self.rustdesk / "data/id_ed25519.pub").read_text(), "PK-OLD")
        self.assert_nothing_left()

    def test_purge_removes_everything(self):
        self.installed(env="RUSTDESK_IMAGE=" + NEW + "\n")
        self.plant_leftovers()
        result = self.run_ctl("uninstall", "--purge", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.rustdesk.exists())
        self.assert_nothing_left()
        # Running it again on a clean system is harmless.
        result = self.run_ctl("uninstall", "--purge", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)

    # ------------------------------------------------- status, logs, misc

    def test_status_reports_failures_and_sanitizes_log_lines(self):
        self.installed(mode="log-errors")
        result = self.run_ctl("status")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("hbbs uses this key", result.stdout)
        self.assertNotIn("\x1b", result.stdout)
        state = self.state()
        state["containers"]["hbbr"]["status"] = "exited"
        (self.lab / "state.json").write_text(json.dumps(state))
        result = self.run_ctl("status")
        self.assertEqual(result.returncode, 1)
        self.assertIn("[FAIL] hbbr: exited", result.stdout)

    def test_status_finds_the_key_at_the_top_of_a_long_log(self):
        # grep -q would stop at the first line; with pipefail the writer's
        # SIGPIPE made the check fail on long-running servers.
        self.installed(mode="long-logs")
        result = self.run_ctl("status")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("hbbr uses this key", result.stdout)

    def test_logs_version_and_argument_errors(self):
        self.installed()
        result = self.run_ctl("logs", "5")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("\x1b", result.stdout)
        self.assertIn("docker compose logs --tail 5", self.calls())
        result = self.run_ctl("version")
        self.assertIn("hbbs:          hbbs 1.1.16", result.stdout)
        self.assertIn("Update:        available", result.stdout)
        for args in (("logs", "x"), ("logs", "1", "2"), ("key",), ("key", "rotate", "--force"),
                     ("key", "show", "x"), ("status", "x"), ("restart",), ()):
            with self.subTest(args=args):
                self.assertEqual(self.run_ctl(*args).returncode, 2)

    # ------------------------------------------------------- daemon.json

    def test_docker_firewall_config_is_created_or_merged(self):
        self.write_state()
        result = self.run_ctl("__call", "disable_docker_firewall")
        self.assertEqual(result.returncode, 0, result.stderr)
        config = self.docker_config / "daemon.json"
        self.assertEqual(json.loads(config.read_text()),
                         {"iptables": False, "ip6tables": False, "userland-proxy": False})
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)

        config.write_text('{"log-driver": "journald", "iptables": true}\n')
        result = self.run_ctl("__call", "disable_docker_firewall")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(config.read_text()),
                         {"log-driver": "journald", "iptables": False, "ip6tables": False,
                          "userland-proxy": False})
        backups = list(self.docker_config.glob("daemon.json.backup.*"))
        self.assertEqual(len(backups), 1)
        self.assertIn("journald", backups[0].read_text())
        self.assertIn("systemctl restart docker.service", self.calls())

    def test_docker_firewall_config_keeps_invalid_json_and_restores_on_failed_restart(self):
        config = self.docker_config / "daemon.json"
        self.docker_config.mkdir()
        config.write_text("{broken")
        result = self.run_ctl("__call", "disable_docker_firewall")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config.read_text(), "{broken")
        self.assertFalse(list(self.docker_config.glob("daemon.json.new.*")))

        config.write_text('{"debug": true}\n')
        failing = self.lab / "bin/systemctl"
        failing.unlink()
        failing.write_text('#!/bin/sh\n[ "$1" = restart ] && exit 1\nexit 0\n')
        failing.chmod(0o755)
        result = self.run_ctl("__call", "disable_docker_firewall")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("previous configuration was restored", result.stderr)
        self.assertEqual(config.read_text(), '{"debug": true}\n')


if __name__ == "__main__":
    unittest.main()
