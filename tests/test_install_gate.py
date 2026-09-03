import json
import os
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest

import install_gate as G
from samples import PIPE_SH, PIPE_SH_SUDO, PIPE_SH_PROCSUB, PIPE_SH_SHORT

HERE = Path(__file__).resolve().parent


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    monkeypatch.setenv("KIBISIS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("KIBISIS_INSTALL_GATE", "gate")
    G.settings.mode = "gate"
    G.settings.state_dir = tmp_path / "state"
    G.settings.lock = tmp_path / "state" / "install-lock.json"
    G.settings.registry_timeout = 1.0
    G.settings.retries = 0
    yield


# ── a registry that never touches the network ───────────────────────────────

NPM_DOC = {
    "dist-tags": {"latest": "5.1.0"},
    "maintainers": [{"name": "fontsource-bot"}],
    "versions": {
        "5.0.0": {"dist": {"integrity": "sha512-OLD"}, "_npmUser": {"name": "fontsource-bot"}},
        "5.1.0": {"dist": {"integrity": "sha512-NEW"}, "_npmUser": {"name": "fontsource-bot"}},
    },
}
PYPI_DOC = {"info": {"name": "requests", "version": "2.32.3", "author": "Kenneth Reitz"},
            "urls": [{"digests": {"sha256": "a" * 64}}, {"digests": {"sha256": "b" * 64}}]}
CRATE_DOC = {"crate": {"max_stable_version": "1.0.230"}}
CRATE_VER = {"version": {"checksum": "c" * 64, "published_by": {"login": "dtolnay"}}}


def fake_fetch(url, headers, timeout):
    if "registry.npmjs.org/@fontsource%2Fcinzel" in url or "registry.npmjs.org/left-pad" in url:
        return json.dumps(NPM_DOC).encode()
    if "registry.npmjs.org/" in url:
        raise urllib.error.HTTPError(url, 404, "nf", {}, None)
    if "pypi.org/pypi/requests/" in url:
        return json.dumps(PYPI_DOC).encode()
    if "pypi.org/pypi/" in url:
        raise urllib.error.HTTPError(url, 404, "nf", {}, None)
    if url.endswith("/crates/serde"):
        return json.dumps(CRATE_DOC).encode()
    if "/crates/serde/" in url:
        return json.dumps(CRATE_VER).encode()
    raise TimeoutError("registry down")


# ── argv classification ──────────────────────────────────────────────────────

@pytest.mark.parametrize("tool,argv", [
    ("npm", ["test"]), ("npm", ["run", "build"]), ("npm", ["ci"]), ("npm", ["ls"]),
    ("pip", ["list"]), ("pip", ["show", "requests"]), ("pip", ["install", "-e", "."]), ("pip", ["install", "."]),
    ("uv", ["run", "python", "x.py"]), ("uv", ["sync"]), ("uv", ["venv"]),
    ("cargo", ["build"]), ("cargo", ["install", "--list"]), ("cargo", ["install", "--path", "."]),
    ("npx", ["--no-install", "tsc"]), ("yarn", ["build"]), ("pnpm", ["run", "dev"]),
])
def test_non_install_shapes_pass_through(tool, argv, tmp_path):
    r = G.parse_argv(tool, argv, tmp_path)
    assert r is None or r.lockfile_governed


def test_npx_local_bin_passes_and_unknown_is_a_fetch(tmp_path):
    (tmp_path / "node_modules" / ".bin").mkdir(parents=True)
    (tmp_path / "node_modules" / ".bin" / "tsc").write_text("#!/bin/sh\n")
    sub = tmp_path / "src" / "deep"
    sub.mkdir(parents=True)
    assert G.parse_argv("npx", ["tsc", "--noEmit"], sub) is None
    r = G.parse_argv("npx", ["-y", "some-unclaimed-name@latest"], sub)
    assert r is not None and r.eco == "npm" and r.specs == ["some-unclaimed-name@latest"]
    r = G.parse_argv("npx", ["-p", "typescript", "tsc"], sub)
    assert r.specs == ["typescript"]


@pytest.mark.parametrize("tool,argv,eco,specs", [
    ("npm", ["install", "@fontsource/cinzel"], "npm", ["@fontsource/cinzel"]),
    ("npm", ["i", "-g", "left-pad@1.3.0"], "npm", ["left-pad@1.3.0"]),
    ("pnpm", ["add", "left-pad"], "npm", ["left-pad"]),
    ("yarn", ["add", "left-pad"], "npm", ["left-pad"]),
    ("pip", ["install", "requests==2.32.3"], "pypi", ["requests==2.32.3"]),
    ("pip3", ["install", "--upgrade", "requests[socks]"], "pypi", ["requests[socks]"]),
    ("uv", ["pip", "install", "requests"], "pypi", ["requests"]),
    ("uv", ["add", "requests"], "pypi", ["requests"]),
    ("pipx", ["install", "requests"], "pypi", ["requests"]),
    ("cargo", ["install", "serde"], "crates", ["serde"]),
    ("cargo", ["add", "serde", "--features", "derive"], "crates", ["serde"]),
    ("cargo", ["install", "--version", "1.0.230", "serde"], "crates", ["serde@1.0.230"]),
])
def test_install_shapes_are_recognised(tool, argv, eco, specs, tmp_path):
    r = G.parse_argv(tool, argv, tmp_path)
    assert r is not None and r.eco == eco and r.specs == specs


def test_url_and_git_specs_are_url_installs(tmp_path):
    assert G.parse_argv("npm", ["install", "github:foo/bar"], tmp_path).eco == "url"
    assert G.parse_argv("pip", ["install", "git+https://x.test/r.git"], tmp_path).eco == "url"
    assert G.parse_argv("cargo", ["install", "--git", "https://x.test/r", "tool"], tmp_path).eco == "url"


def test_bare_npm_install_gates_only_what_the_lockfile_does_not_pin(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "^1.0.0", "newdep": "^2"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/left-pad": {"version": "1.3.0"}}}))
    r = G.parse_argv("npm", ["install"], tmp_path)
    assert r.specs == ["newdep@^2"]


def test_requirements_file_is_read_unless_hash_pinned(tmp_path):
    (tmp_path / "req.txt").write_text("requests==2.32.3  # http\n-e .\n")
    assert G.parse_argv("pip", ["install", "-r", "req.txt"], tmp_path).specs == ["requests==2.32.3"]
    (tmp_path / "locked.txt").write_text("requests==2.32.3 --hash=sha256:abc\n")
    assert G.parse_argv("pip", ["install", "-r", "locked.txt"], tmp_path).lockfile_governed


# ── command-string classification (L1) ──────────────────────────────────────

@pytest.mark.parametrize("cmd", [
    "ls -la", "git status", "npm test", "cargo build --release",
    "pip list", "curl -s https://x.test/api | jq .", "python3 build.py", "echo pip install is fun",
])
def test_routine_commands_never_trip(cmd, tmp_path):
    assert G.classify_command(cmd, tmp_path) == []


@pytest.mark.parametrize("cmd,tool", [
    (PIPE_SH, "curl|sh"),
    (PIPE_SH_SUDO, "curl|sh"),
    (PIPE_SH_PROCSUB, "curl|sh"),
    ("python3 -m pip install requests", "python -m pip"),
    ("/usr/bin/npm install left-pad", "npm"),
    ("env -i PATH=/usr/bin npm install left-pad", "env"),
    ("PATH=/usr/bin:/bin npm install left-pad", "env"),
])
def test_bypass_shapes_are_caught(cmd, tool, tmp_path):
    tools = [r.tool for r in G.classify_command(cmd, tmp_path)]
    assert tool in tools


@pytest.mark.parametrize("cmd", [
    "export PATH=$PATH:/home/u/go/bin && xurl whoami",
    "PATH=/home/u/.bun/bin:$PATH gbrain sync",
    "which uv python3.12; ls /home/u/.local/bin/uv",
    'f="/tmp/x_$(date +%s)"; echo hi > "$f"',
])
def test_path_prepends_and_path_listings_are_not_bypasses(cmd, tmp_path):
    assert G.classify_command(cmd, tmp_path) == []


def test_approved_ticket_blesses_the_lock(tmp_path):
    t = G.Tuple5("npm", "left-pad", "5.1.0", "x", "sha512-NEW")
    tid = G.write_ticket([t])
    G.post_approval_response(description=f"m ticket={tid}", choice="once", pattern_key="plugin_rule:kibisis:install:left-pad")
    assert G.Lock().status(t) == "ok" and G.take_ticket([t]) is None


def test_resolution_respects_its_time_budget(tmp_path):
    def slow(url, headers, timeout):
        import time as _t
        _t.sleep(0.2)
        return json.dumps(NPM_DOC).encode()
    req = G.Request(eco="npm", tool="npm", specs=["left-pad"] * 30)
    v = G.check(req, fetch=slow, budget=0.5)
    assert not v.allow and any("time budget" in p for p in v.problems) and len(v.tuples) < 30


def test_touching_gate_files_is_caught(tmp_path):
    reqs = G.classify_command(f"echo '[]' > {G.settings.lock}", tmp_path)
    assert any(r.tool == "gate files" for r in reqs)


def test_hook_follows_cd_for_npx_local_bins(tmp_path):
    proj = tmp_path / "frontend"
    (proj / "node_modules" / ".bin").mkdir(parents=True)
    (proj / "node_modules" / ".bin" / "tsc").write_text("#!/bin/sh\n")
    assert G.classify_command(f"cd {proj} && npx tsc --noEmit 2>&1 | head -20", tmp_path) == []
    assert G.classify_command("npx tsc --noEmit", tmp_path)[0].specs == ["tsc"]


def test_pipeline_and_wrappers(tmp_path):
    reqs = G.classify_command("cd proj && sudo -E npm install left-pad 2>&1 | tail -3", tmp_path)
    assert [r.specs for r in reqs] == [["left-pad"]]


# ── resolution and the lock ──────────────────────────────────────────────────

def test_resolve_each_ecosystem():
    t = G.resolve("npm", "@fontsource/cinzel", fake_fetch)
    assert (t.version, t.publisher, t.hash) == ("5.1.0", "fontsource-bot", "sha512-NEW")
    assert G.resolve("npm", "@fontsource/cinzel@5.0.0", fake_fetch).hash == "sha512-OLD"
    t = G.resolve("pypi", "requests==2.32.3", fake_fetch)
    assert t.name == "requests" and t.hash.startswith("sha256-")
    t = G.resolve("crates", "serde", fake_fetch)
    assert (t.version, t.publisher) == ("1.0.230", "dtolnay")


def test_unknown_name_and_dead_registry_are_unresolved():
    with pytest.raises(G.Unresolved):
        G.resolve("npm", "definitely-not-a-package-zz", fake_fetch)
    with pytest.raises(G.Unresolved):
        G.resolve("npm", "left-pad", lambda *a: (_ for _ in ()).throw(TimeoutError("down")))


def test_check_misses_then_bless_then_ok(tmp_path):
    req = G.parse_argv("npm", ["install", "@fontsource/cinzel"], tmp_path)
    v = G.check(req, fetch=fake_fetch)
    assert not v.allow and "missing" in v.problems[0]
    G.Lock().bless(v.tuples)
    v2 = G.check(req, fetch=fake_fetch)
    assert v2.allow and v2.pinned_specs == ["@fontsource/cinzel@5.1.0"]


def test_hash_or_publisher_change_is_a_miss(tmp_path):
    t = G.Tuple5("npm", "left-pad", "5.1.0", "fontsource-bot", "sha512-NEW")
    lock = G.Lock()
    lock.bless([t])
    assert lock.status(G.Tuple5("npm", "left-pad", "5.1.0", "fontsource-bot", "sha512-EVIL")) == "hash changed"
    assert lock.status(G.Tuple5("npm", "left-pad", "5.1.0", "someone-else", "sha512-NEW")) == "publisher changed"


def test_registry_down_parks_it_does_not_proceed(tmp_path):
    req = G.parse_argv("npm", ["install", "left-pad"], tmp_path)
    v = G.check(req, fetch=lambda *a: (_ for _ in ()).throw(TimeoutError("down")))
    assert not v.allow and "unreachable" in v.problems[0]


# ── tickets, parks, and the human path ───────────────────────────────────────

def test_ticket_is_single_use_and_expires(tmp_path, monkeypatch):
    t = G.Tuple5("npm", "left-pad", "5.1.0", "x", "sha512-NEW")
    tid = G.write_ticket([t], "npm install left-pad")
    assert G.take_ticket([t]) == tid
    assert G.take_ticket([t]) is None
    tid2 = G.write_ticket([t])
    monkeypatch.setattr(G.time, "time", lambda: 10 ** 10)
    assert G.take_ticket([t]) is None


def test_denied_approval_voids_the_ticket(tmp_path):
    t = G.Tuple5("npm", "left-pad", "5.1.0", "x", "sha512-NEW")
    tid = G.write_ticket([t])
    G.post_approval_response(description=f"blah ticket={tid}", choice="deny", pattern_key="plugin_rule:kibisis:install:left-pad")
    assert G.take_ticket([t]) is None


def test_park_bless_round_trip(tmp_path):
    req = G.parse_argv("npm", ["install", "@fontsource/cinzel"], tmp_path)
    v = G.check(req, fetch=fake_fetch)
    pid = G.park(req, v.tuples, v.problems, tmp_path)
    assert pid in G.human_command("parked")
    out = G.human_command(f"bless {pid}", fetch=fake_fetch)
    assert "blessed 1" in out
    assert G.check(req, fetch=fake_fetch).allow
    assert G.human_command("parked") == "kibisis: nothing parked."


def test_park_footer_rides_on_terminal_results():
    import kibisis as K
    K._settings.enabled = True
    body = json.dumps({"output": "[kibisis:parked id=20260902-120000-abcdef] npm install of x is parked" + " " * 40, "returncode": 75})
    out = K.transform("terminal", {"command": "npm install x"}, body)
    assert out is not None and "bless 20260902-120000-abcdef" in out


def test_seed_reads_lockfiles(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {
        "": {"name": "app"}, "node_modules/left-pad": {"version": "1.3.0", "integrity": "sha512-LP"}}}))
    (tmp_path / "Cargo.lock").write_text('[[package]]\nname = "serde"\nversion = "1.0.230"\nchecksum = "cc"\n')
    found = G.seed(tmp_path)
    keys = {(t.eco, t.name, t.version) for t in found}
    assert ("npm", "left-pad", "1.3.0") in keys and ("crates", "serde", "1.0.230") in keys


UV_LOCK = '''version = 1
requires-python = ">=3.10"

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "certifi" },
]
sdist = { url = "https://files.pythonhosted.org/r.tar.gz", hash = "sha256:aaaa", size = 1 }
wheels = [
    { url = "https://files.pythonhosted.org/r.whl", hash = "sha256:bbbb", size = 2 },
]

[[package]]
name = "certifi"
version = "2024.8.30"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://x/c.tar.gz", hash = "sha256:cccc", size = 3 }

[[package.wheels]]
url = "https://x/c.whl"
hash = "sha256:dddd"

[package.metadata]
requires-dist = []
'''


def test_lock_parser_fallback_matches_tomllib(tmp_path, monkeypatch):
    with_tomllib = G._lock_packages(UV_LOCK)
    # force the 3.10 path
    import builtins
    real_import = builtins.__import__

    def no_tomllib(name, *a, **k):
        if name == "tomllib":
            raise ImportError
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", no_tomllib)
    fallback = G._lock_packages(UV_LOCK)
    names = [(p["name"], p["version"]) for p in fallback]
    assert names == [("requests", "2.32.3"), ("certifi", "2024.8.30")]
    assert fallback[1]["sdist"]["hash"] == "sha256:cccc" and fallback[1]["wheels"][0]["hash"] == "sha256:dddd"
    (tmp_path / "uv.lock").write_text(UV_LOCK)
    (tmp_path / "Cargo.lock").write_text('[[package]]\nname = "serde"\nversion = "1.0.230"\nchecksum = "cc"\n')
    seeded = {(t.eco, t.name, t.version) for t in G.seed(tmp_path)}
    assert ("pypi", "certifi", "2024.8.30") in seeded and ("crates", "serde", "1.0.230") in seeded
    if with_tomllib and "sdist" in with_tomllib[0]:
        assert {(p["name"], p["version"]) for p in with_tomllib} == set(names)


# ── the hook (L1) ────────────────────────────────────────────────────────────

def test_hook_off_is_silent(tmp_path, monkeypatch):
    G.settings.mode = "off"
    assert G.pre_tool_call("terminal", {"command": PIPE_SH_SHORT}) is None


def test_hook_returns_approve_with_ticket_on_miss(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "_http_fetch", fake_fetch)
    d = G.pre_tool_call("terminal", {"command": "npm install @fontsource/cinzel"})
    assert d["action"] == "approve" and d["rule_key"] == "kibisis:install:@fontsource/cinzel"
    assert "ticket=" in d["message"] and "missing" in d["message"]
    assert G.pre_tool_call("terminal", {"command": "npm test"}) is None


def test_hook_lets_blessed_installs_through(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "_http_fetch", fake_fetch)
    G.Lock().bless([G.Tuple5("npm", "@fontsource/cinzel", "5.1.0", "fontsource-bot", "sha512-NEW")])
    assert G.pre_tool_call("terminal", {"command": "npm install @fontsource/cinzel"}) is None


def test_hook_escalates_edits_to_its_own_files():
    d = G.pre_tool_call("write_file", {"path": str(G.settings.lock), "content": "[]"})
    assert d and d["action"] == "approve"


# ── the shim (L2), end to end in a subprocess ────────────────────────────────

def _run_shim(tool, argv, tmp_path, extra_env=None):
    G.install_shims()
    shim = G.shims_dir() / tool
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    real = fake_bin / tool
    real.write_text("#!/bin/sh\necho REAL-$0 \"$@\"\n")
    real.chmod(0o755)
    env = dict(os.environ, PATH=f"{shim.parent}{os.pathsep}{fake_bin}{os.pathsep}/usr/bin:/bin",
               KIBISIS_STATE_DIR=str(tmp_path / "state"), **(extra_env or {}))
    return subprocess.run([sys.executable, str(shim)] + argv, capture_output=True, text=True, env=env, cwd=tmp_path, timeout=60)


def test_shim_passes_non_installs_to_the_real_binary(tmp_path):
    p = _run_shim("npm", ["test"], tmp_path, {"KIBISIS_INSTALL_GATE": "gate"})
    assert p.returncode == 0 and "REAL-" in p.stdout and "test" in p.stdout


def test_shim_is_transparent_when_gate_is_off(tmp_path):
    p = _run_shim("npm", ["install", "anything"], tmp_path, {"KIBISIS_INSTALL_GATE": "off"})
    assert p.returncode == 0 and "REAL-" in p.stdout


def test_shim_parks_an_unblessed_install_without_running_it(tmp_path):
    # registry is unreachable in the test sandbox either way: that is a park too
    p = _run_shim("npm", ["install", "left-pad"], tmp_path, {"KIBISIS_INSTALL_GATE": "gate"})
    assert p.returncode == 75, p.stderr
    assert "REAL-" not in p.stdout
    assert "[kibisis:parked id=" in p.stderr
    assert (tmp_path / "state" / "parked").exists() and list((tmp_path / "state" / "parked").glob("*.json"))


def test_shim_reads_mode_from_gate_json_when_env_is_absent(tmp_path):
    (tmp_path / "state").mkdir(exist_ok=True)
    (tmp_path / "state" / "gate.json").write_text(json.dumps({"mode": "off"}))
    p = _run_shim("pip", ["install", "requests"], tmp_path, {"KIBISIS_INSTALL_GATE": ""})
    assert p.returncode == 0 and "REAL-" in p.stdout
