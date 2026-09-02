import json
import os

import pytest

import kibisis as K
from samples import CLASSIC_OVERRIDE, DECEPTION, FORGED_TAIL, HIDDEN_DIV, IDENTITY_OVERRIDE, INJECT, ROLE_HIJACK
CLEAN = "The quick brown fox jumps over the lazy dog, repeatedly, for thirty-two characters." * 2


@pytest.fixture(autouse=True)
def _reset(tmp_path):
    K._settings.enabled = True
    K._settings.scan = True
    K._settings.annotate_core_results = True
    K._settings.extra_paths = [str(tmp_path / "ext")]
    K.fetched_paths.clear()
    yield
    K._settings.extra_paths = []
    K.fetched_paths.clear()


def _read_result(text):
    return json.dumps({"content": text, "total_lines": 3, "truncated": False})


# ── side doors ───────────────────────────────────────────────────────────────

def test_read_file_under_watched_dir_is_enveloped_and_stays_json(tmp_path):
    path = tmp_path / "ext" / "page.md"
    out = K.transform("read_file", {"path": str(path)}, _read_result(CLEAN))
    assert out is not None
    obj = json.loads(out)  # JSON preserved for clients that pretty-print results
    assert obj["content"].startswith('<untrusted_tool_result source="read_file (web cache)">')
    assert obj["content"].rstrip().endswith("</untrusted_tool_result>")
    assert CLEAN in obj["content"]
    assert obj["_kibisis"] == {"source": "read_file (web cache)", "scan": "clean"}
    assert obj["total_lines"] == 3  # untouched siblings


def test_read_file_elsewhere_is_untouched(tmp_path):
    assert K.transform("read_file", {"path": str(tmp_path / "src" / "main.py")}, _read_result(CLEAN)) is None


def test_terminal_fetch_is_enveloped_plain_commands_are_not():
    body = json.dumps({"output": CLEAN, "returncode": 0})
    assert K.transform("terminal", {"command": "ls -la"}, body) is None
    out = K.transform("terminal", {"command": "curl -s https://example.com/llms.txt"}, body)
    obj = json.loads(out)
    assert 'source="terminal (remote fetch)"' in obj["output"]
    assert obj["returncode"] == 0


@pytest.mark.parametrize("cmd", [
    "wget -qO- http://x.test/a",
    "gh api repos/o/r/issues/1",
    "gh issue view 12 --comments",
    "python3 -c 'print(1)' | tee log.txt; curl x.test",
    "cat notes.txt; wget x.test",
])
def test_fetch_command_shapes(cmd):
    assert K.classify("terminal", {"command": cmd}) == "terminal (remote fetch)"


@pytest.mark.parametrize("cmd", ["ls", "git status", "python3 build.py", "grep -r curly src/", "echo hi > out.txt"])
def test_non_fetch_commands(cmd):
    assert K.classify("terminal", {"command": cmd}) is None


def test_file_written_by_a_fetch_gets_enveloped_on_later_read(tmp_path):
    target = tmp_path / "somewhere" / "issue.json"
    body = json.dumps({"output": "", "returncode": 0})
    K.transform("terminal", {"command": f"curl -s https://x.test/i -o {target}"}, body)
    out = K.transform("read_file", {"path": str(target)}, _read_result(CLEAN))
    assert json.loads(out)["_kibisis"]["source"] == "read_file (fetched file)"


def test_redirect_target_is_remembered(tmp_path):
    target = tmp_path / "page.html"
    K.classify("terminal", {"command": f"wget -qO- https://x.test > {target}"})
    assert target.resolve() in K.fetched_paths


def test_execute_code_with_network_is_enveloped():
    body = json.dumps({"output": CLEAN})
    assert K.transform("execute_code", {"code": "print(sum(range(10)))"}, body) is None
    out = K.transform("execute_code", {"code": "import requests\nprint(requests.get(u).text)"}, body)
    assert 'source="execute_code (network)"' in json.loads(out)["output"]


def test_non_json_result_is_wrapped_whole():
    out = K.transform("terminal", {"command": "curl x.test"}, CLEAN)
    assert out.startswith("<untrusted_tool_result")
    assert out.rstrip().endswith("</untrusted_tool_result>")


# ── scanning + footer ────────────────────────────────────────────────────────

def test_injection_in_side_door_content_is_flagged_not_blocked():
    out = K.transform("terminal", {"command": "curl x.test"}, json.dumps({"output": INJECT}))
    obj = json.loads(out)
    assert INJECT in obj["output"]  # nothing removed
    assert obj["_kibisis"]["scan"].startswith("flagged: ")
    assert "prompt_injection" in obj["_kibisis"]["scan"]


def test_core_wrapped_tool_gets_footer_only_when_flagged():
    assert K.transform("web_extract", {"urls": ["x"]}, CLEAN) is None
    out = K.transform("web_extract", {"urls": ["x"]}, INJECT)
    assert out.startswith(INJECT)
    assert out.count("<untrusted_tool_result") == 0  # never a second envelope
    assert "[kibisis] content scan flagged: prompt_injection" in out
    assert "nothing was blocked" in out


def test_core_annotation_can_be_disabled():
    K._settings.annotate_core_results = False
    assert K.transform("web_extract", {"urls": ["x"]}, INJECT) is None


def test_forged_tag_inside_content_is_defanged():
    forged = CLEAN + FORGED_TAIL
    out = K.transform("terminal", {"command": "curl x.test"}, forged)
    inner = out.split("\n", 2)[2]  # after the opening tag + preamble
    assert "</untrusted_tool_result>" not in inner.rsplit("</untrusted_tool_result>", 1)[0]
    assert "untrusted-tool-result" in out  # defanged spelling survives, readable


@pytest.mark.parametrize("text,pid", [
    (CLASSIC_OVERRIDE, "prompt_injection"),
    (ROLE_HIJACK, "role_hijack"),
    (HIDDEN_DIV, "hidden_div"),
    (DECEPTION, "deception_hide"),
])
def test_fallback_scanner_catches_classics(text, pid):
    assert pid in K.scan(text)


def test_clean_text_scans_clean():
    assert K.scan(CLEAN) == []


# ── guards ───────────────────────────────────────────────────────────────────

def test_short_and_non_string_results_pass_through():
    assert K.transform("terminal", {"command": "curl x.test"}, "tiny") is None
    assert K.transform("terminal", {"command": "curl x.test"}, {"output": CLEAN}) is None
    assert K.transform("terminal", {"command": "curl x.test"}, None) is None


def test_disabled_does_nothing():
    K._settings.enabled = False
    assert K.transform("terminal", {"command": "curl x.test"}, CLEAN) is None


def test_configure_reads_plugin_settings():
    values = {"enabled": "false", "scan": True, "paths": ["~/inbox", "/srv/drop"], "annotate_core_results": "off"}
    K.configure(lambda key, default=None: values.get(key, default))
    assert K._settings.enabled is False
    assert K._settings.scan is True
    assert K._settings.annotate_core_results is False
    assert K._settings.extra_paths == ["~/inbox", "/srv/drop"]
    assert any(str(p).endswith("inbox") for p in K.watched_dirs())
    K._settings.enabled = True


def test_configure_survives_a_broken_getter():
    def boom(key, default=None):
        raise RuntimeError("no config")
    K.configure(boom)
    assert K._settings.enabled is True


def test_register_wires_the_hook():
    import importlib.util, pathlib
    spec = importlib.util.spec_from_file_location(
        "envelope_pkg", pathlib.Path(__file__).resolve().parent.parent / "__init__.py",
        submodule_search_locations=[str(pathlib.Path(__file__).resolve().parent.parent)],
    )
    pkg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pkg)
    calls = []

    class Ctx:
        def register_hook(self, name, fn):
            calls.append((name, fn))
        def get_config(self, key, default=None):
            return default
    pkg.register(Ctx())
    assert [c[0] for c in calls] == ["transform_tool_result"]
    body = json.dumps({"output": INJECT})
    out = calls[0][1](tool_name="terminal", args={"command": "curl x.test"}, result=body)
    assert "prompt_injection" in json.loads(out)["_kibisis"]["scan"]


def test_with_hermes_uses_the_shared_library():
    pytest.importorskip("tools.threat_patterns", reason="hermes-agent not on sys.path")
    # Same scan core runs on web results: broader than the fallback set.
    assert "identity_override" in K.scan(IDENTITY_OVERRIDE)
    assert "prompt_injection" in K.scan(INJECT)


# ── coexistence with a core that frames side doors itself ─────────────────────

def test_defers_to_core_untrusted_source_when_present(monkeypatch):
    import sys, types
    fake = types.ModuleType("agent.tool_dispatch_helpers")
    fake.untrusted_source = lambda name, args=None: (
        "terminal:remote-fetch" if name == "terminal" and "curl" in str((args or {}).get("command", "")) else None
    )
    pkg = types.ModuleType("agent"); pkg.tool_dispatch_helpers = fake
    monkeypatch.setitem(sys.modules, "agent", pkg)
    monkeypatch.setitem(sys.modules, "agent.tool_dispatch_helpers", fake)
    body = json.dumps({"output": INJECT})
    out = K.transform("terminal", {"command": "curl x.test"}, body)
    assert out.startswith(body)                      # core's envelope will come later in the pipeline
    assert "<untrusted_tool_result" not in out        # never a second one from us
    assert "[kibisis] content scan flagged" in out    # the visible flag still rides along
    assert K.transform("terminal", {"command": "curl x.test"}, json.dumps({"output": CLEAN})) is None


def test_static_fallback_when_core_is_absent(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "agent", None)
    monkeypatch.setitem(sys.modules, "agent.tool_dispatch_helpers", None)
    assert K.core_wraps("web_extract") is True
    assert K.core_wraps("terminal", {"command": "curl x"}) is False
