"""kibisis install gate — a lock of (ecosystem, name, version, publisher, hash)
tuples under the package installers the agent can reach.

Two layers share this module and one lock file:

* **L2, the floor** — ``shims/`` puts a thin wrapper in front of ``npm``, ``npx``,
  ``pip``, ``uv``, ``pipx``, ``cargo``, ``pnpm`` and ``yarn``.  A wrapper that is not
  handling an install ``exec``s the real binary at once.  An install whose every
  tuple is in the lock runs with the resolution pinned.  Anything else is written
  to ``parked/`` and the wrapper exits 75 (``EX_TEMPFAIL``) without installing.
  The wrapper never reads model output, so nothing the model is told can move it.
* **L1, the tripwire** — a ``pre_tool_call`` hook does the same check on the
  command string before it runs and returns ``approve`` on a miss, so the human
  gate Hermes already has fires while someone is present.  Approval writes a
  short-lived ticket the shim honours once.  L1 also escalates the shapes the shim
  cannot see (absolute-path installers, ``python -m pip``, ``curl | sh``, and any
  tool call that touches the gate's own files).

Fail-open here means: the *check* dying never blocks the agent's shell.  The
agent keeps reading and working.  It does not get the package.

Stdlib only.  Network access goes through one injectable ``fetch`` so tests never
touch a registry.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("hermes.plugins.kibisis.install_gate")

EX_TEMPFAIL = 75
PARK_MARK = "[kibisis:parked"
TICKET_TTL = 300  # seconds a human approval stays honoured by the shim
USER_AGENT = "hermes-kibisis-install-gate (+https://github.com/CocaKova/hermes-kibisis)"

SHIMMED = ("npm", "npx", "pnpm", "yarn", "pip", "pip3", "uv", "pipx", "cargo")


# ── settings ─────────────────────────────────────────────────────────────────

class Settings:
    mode: str = "off"                      # off | tripwire | gate
    lock: Path = Path.home() / ".hermes" / "kibisis" / "install-lock.json"
    state_dir: Path = Path.home() / ".hermes" / "kibisis"
    registry_timeout: float = 5.0
    retries: int = 1


settings = Settings()


def configure(get: Optional[Callable[[str, Any], Any]] = None) -> None:
    """Read ``plugins.entries.kibisis.settings.install_*`` via the plugin ctx."""
    env_mode = os.environ.get("KIBISIS_INSTALL_GATE")
    if env_mode in ("off", "tripwire", "gate"):
        settings.mode = env_mode
    if os.environ.get("KIBISIS_STATE_DIR"):
        settings.state_dir = Path(os.environ["KIBISIS_STATE_DIR"])
        settings.lock = settings.state_dir / "install-lock.json"
    if get is None:
        _read_sync_file()
        return
    try:
        mode = get("install_gate", None)
        if isinstance(mode, bool):
            mode = "gate" if mode else "off"
        if isinstance(mode, str) and mode.lower() in ("off", "tripwire", "gate"):
            settings.mode = mode.lower()
        lock = get("install_lock", None)
        if isinstance(lock, str) and lock.strip():
            settings.lock = Path(lock).expanduser()
            settings.state_dir = settings.lock.parent
        t = get("install_registry_timeout", None)
        if isinstance(t, (int, float)) and t > 0:
            settings.registry_timeout = float(t)
    except Exception:  # noqa: BLE001
        logger.debug("install_gate: configure failed; keeping defaults", exc_info=True)
    _write_sync_file()


def _sync_path() -> Path:
    return settings.state_dir / "gate.json"


def _write_sync_file() -> None:
    """The shims run outside the plugin process; they learn the mode from here."""
    try:
        settings.state_dir.mkdir(parents=True, exist_ok=True)
        _sync_path().write_text(json.dumps({"mode": settings.mode, "lock": str(settings.lock),
                                            "registry_timeout": settings.registry_timeout}), encoding="utf-8")
    except Exception:  # noqa: BLE001
        logger.debug("install_gate: could not write gate.json", exc_info=True)


def _read_sync_file() -> None:
    if os.environ.get("KIBISIS_INSTALL_GATE"):
        return  # explicit env wins (tests, one-off runs)
    try:
        doc = json.loads(_sync_path().read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return
    if doc.get("mode") in ("off", "tripwire", "gate"):
        settings.mode = doc["mode"]
    if isinstance(doc.get("lock"), str):
        settings.lock = Path(doc["lock"])
    if isinstance(doc.get("registry_timeout"), (int, float)):
        settings.registry_timeout = float(doc["registry_timeout"])


def _dir(name: str) -> Path:
    d = settings.state_dir / name
    d.mkdir(parents=True, exist_ok=True)
    return d


# ── data ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Tuple5:
    eco: str
    name: str
    version: str
    publisher: str
    hash: str

    def key(self) -> str:
        return f"{self.eco}:{self.name}:{self.version}:{self.hash}"

    def short(self) -> str:
        h = self.hash.split("-", 1)[-1]
        return f"{self.eco}:{self.name}@{self.version} by {self.publisher} {self.hash[:7]}…{h[-6:]}"


@dataclass
class Request:
    """One install-shaped invocation, as the shim or the hook sees it."""
    eco: str                        # npm | pypi | crates | url | bypass
    tool: str                       # npm, pip, cargo, curl|sh, …
    specs: List[str] = field(default_factory=list)   # what was asked for
    argv: List[str] = field(default_factory=list)
    reason: str = ""                # for bypass / url shapes
    lockfile_governed: bool = False  # `npm ci`, `pip -r hashed.txt`: already pinned


# ── spec parsing ─────────────────────────────────────────────────────────────

_NPM_INSTALL = {"install", "i", "add", "isntall", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal"}
_PNPM_INSTALL = {"add", "install", "i"}
_YARN_INSTALL = {"add", "install"}
_PIP_INSTALL = {"install"}
_URL_SPEC = re.compile(r"^(?:git\+|https?://|git://|ssh://|github:|gitlab:|bitbucket:|file:)", re.I)
_PY_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")
_PY_EXACT = re.compile(r"^==\s*([A-Za-z0-9.+!_-]+)$")


def _positional(argv: Iterable[str], takes_value: Iterable[str] = ()) -> List[str]:
    out: List[str] = []
    skip = False
    tv = set(takes_value)
    for a in argv:
        if skip:
            skip = False
            continue
        if a == "--":
            continue
        if a.startswith("-"):
            if a in tv:
                skip = True
            continue
        out.append(a)
    return out


def _split_npm_spec(spec: str) -> Tuple[str, str]:
    """``@scope/name@^1.2`` → (``@scope/name``, ``^1.2``); bare → (name, "")."""
    if spec.startswith("@"):
        rest = spec[1:]
        if "@" in rest:
            n, v = rest.split("@", 1)
            return "@" + n, v
        return spec, ""
    if "@" in spec:
        n, v = spec.split("@", 1)
        return n, v
    return spec, ""


def _find_up(start: Path, rel: str) -> Optional[Path]:
    cur = start.resolve()
    for _ in range(12):
        cand = cur / rel
        if cand.exists():
            return cand
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def _npm_unlocked_deps(cwd: Path) -> List[str]:
    """Names in package.json that package-lock.json does not already pin."""
    pj = cwd / "package.json"
    if not pj.exists():
        return []
    try:
        data = json.loads(pj.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return []
    wanted: Dict[str, str] = {}
    for sect in ("dependencies", "devDependencies", "optionalDependencies"):
        d = data.get(sect)
        if isinstance(d, dict):
            wanted.update({k: str(v) for k, v in d.items()})
    locked: set = set()
    pl = cwd / "package-lock.json"
    if pl.exists():
        try:
            lock = json.loads(pl.read_text(encoding="utf-8"))
            for k in (lock.get("packages") or {}):
                if k.startswith("node_modules/"):
                    locked.add(k.rsplit("node_modules/", 1)[-1])
            for k in (lock.get("dependencies") or {}):
                locked.add(k)
        except Exception:  # noqa: BLE001
            pass
    return [f"{n}@{v}" if v and not v.startswith(("file:", "link:")) else n
            for n, v in wanted.items() if n not in locked and not str(v).startswith(("file:", "link:"))]


def _local_bin_exists(cmd: str, cwd: Path) -> bool:
    if "/" in cmd:
        return True
    nm = _find_up(cwd, f"node_modules/.bin/{cmd}")
    return nm is not None


def parse_argv(tool: str, argv: List[str], cwd: Optional[Path] = None) -> Optional[Request]:
    """Classify a shimmed tool's argv. ``None`` means "not an install: pass through"."""
    cwd = cwd or Path.cwd()
    argv = list(argv)
    if tool in ("npm", "pnpm", "yarn"):
        pos = _positional(argv, takes_value=("--prefix", "-C", "--registry", "--workspace", "-w"))
        if not pos:
            return None
        sub, rest = pos[0], pos[1:]
        table = {"npm": _NPM_INSTALL, "pnpm": _PNPM_INSTALL, "yarn": _YARN_INSTALL}[tool]
        if sub == "ci" or (tool == "npm" and sub == "clean-install"):
            return Request(eco="npm", tool=tool, argv=argv, lockfile_governed=True)
        if sub not in table:
            return None
        if tool == "yarn" and sub == "install":
            rest = []
        specs = rest if rest else _npm_unlocked_deps(cwd)
        if not specs:
            return Request(eco="npm", tool=tool, argv=argv, lockfile_governed=True)
        if any(_URL_SPEC.match(s) or s.startswith((".", "/", "~")) for s in specs):
            urls = [s for s in specs if _URL_SPEC.match(s)]
            if urls:
                return Request(eco="url", tool=tool, specs=urls, argv=argv, reason="git/URL package spec")
            specs = [s for s in specs if not s.startswith((".", "/", "~"))]
            if not specs:
                return None
        return Request(eco="npm", tool=tool, specs=specs, argv=argv)

    if tool == "npx":
        pkgs: List[str] = []
        i = 0
        cmd: Optional[str] = None
        while i < len(argv):
            a = argv[i]
            if a in ("-p", "--package"):
                if i + 1 < len(argv):
                    pkgs.append(argv[i + 1])
                i += 2
                continue
            if a.startswith("--package="):
                pkgs.append(a.split("=", 1)[1])
            elif a in ("--no-install", "--no", "--offline", "--prefer-offline"):
                return None
            elif a in ("-c", "--call") and i + 1 < len(argv):
                cmd = argv[i + 1].split(" ", 1)[0]
                i += 2
                continue
            elif not a.startswith("-") and cmd is None:
                cmd = a
                break
            i += 1
        if pkgs:
            return Request(eco="npm", tool=tool, specs=pkgs, argv=argv)
        if cmd is None:
            return None
        if _local_bin_exists(cmd, cwd):
            return None
        if _URL_SPEC.match(cmd):
            return Request(eco="url", tool=tool, specs=[cmd], argv=argv, reason="git/URL package spec")
        return Request(eco="npm", tool=tool, specs=[cmd], argv=argv)

    if tool in ("pip", "pip3", "pipx", "uv"):
        a = argv
        if tool == "uv":
            if not a:
                return None
            if a[0] == "pip" and len(a) > 1 and a[1] == "install":
                a = a[2:]
            elif a[0] == "add":
                a = a[1:]
            elif a[0] == "tool" and len(a) > 1 and a[1] == "install":
                a = a[2:]
            elif a[0] in ("sync", "lock"):
                return Request(eco="pypi", tool=tool, argv=argv, lockfile_governed=True)
            else:
                return None
        else:
            if not a or a[0] not in _PIP_INSTALL:
                return None
            a = a[1:]
        specs: List[str] = []
        req_files: List[str] = []
        i = 0
        while i < len(a):
            x = a[i]
            if x in ("-r", "--requirement", "-c", "--constraint"):
                if i + 1 < len(a):
                    req_files.append(a[i + 1])
                i += 2
                continue
            if x.startswith(("-r=", "--requirement=")):
                req_files.append(x.split("=", 1)[1])
            elif x in ("-e", "--editable"):
                i += 2
                continue
            elif x in ("-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--python", "-p", "--target", "-t"):
                i += 2
                continue
            elif x.startswith("-"):
                pass
            elif x.startswith((".", "/", "~")) or x.endswith((".whl", ".tar.gz", ".zip")):
                pass  # local path: nothing is fetched from a registry
            else:
                specs.append(x)
            i += 1
        for rf in req_files:
            p = (cwd / rf) if not os.path.isabs(rf) else Path(rf)
            try:
                text = p.read_text(encoding="utf-8")
            except Exception:  # noqa: BLE001
                continue
            if "--hash=" in text:
                continue  # hash-pinned requirements are their own lock
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                specs.append(line)
        if any(_URL_SPEC.match(s) or "@" in s and "://" in s for s in specs):
            urls = [s for s in specs if _URL_SPEC.match(s) or "://" in s]
            return Request(eco="url", tool=tool, specs=urls, argv=argv, reason="git/URL package spec")
        if not specs:
            return None if not req_files else Request(eco="pypi", tool=tool, argv=argv, lockfile_governed=True)
        return Request(eco="pypi", tool=tool, specs=specs, argv=argv)

    if tool == "cargo":
        pos = _positional(argv, takes_value=("--manifest-path", "--target-dir", "--root", "--registry", "--index", "--features", "-F", "--version", "--vers", "--git", "--branch", "--tag", "--rev", "--path"))
        if not pos or pos[0] not in ("install", "add"):
            return None
        if "--list" in argv or "--path" in argv:
            return None
        if "--git" in argv:
            i = argv.index("--git")
            return Request(eco="url", tool=tool, specs=[argv[i + 1] if i + 1 < len(argv) else "--git"], argv=argv, reason="git package spec")
        specs = pos[1:]
        ver = None
        for flag in ("--version", "--vers"):
            if flag in argv:
                i = argv.index(flag)
                ver = argv[i + 1] if i + 1 < len(argv) else None
        if ver and specs:
            specs = [f"{s}@{ver}" if "@" not in s else s for s in specs]
        if not specs:
            return None
        return Request(eco="crates", tool=tool, specs=specs, argv=argv)
    return None


# ── command-string classification (L1) ───────────────────────────────────────

_PIPE_SH_RE = re.compile(r"(?:curl|wget|fetch)\b[^|\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k|fi)?sh\b", re.I)
_PROC_SUBST_SH_RE = re.compile(r"\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b", re.I)
_PY_M_PIP_RE = re.compile(r"\bpython[0-9.]*\s+-m\s+(?:pip|pipx|uv)\b")
_ENV_I_RE = re.compile(r"\benv\s+-i\b")
# a PATH assignment that drops $PATH entirely replaces the shims; prepends/appends keep them
_PATH_REPLACE_RE = re.compile(r"(?:^|[\s;&|(])(?:export\s+)?PATH=(?P<v>\"[^\"]*\"|'[^']*'|\S*)")
_SEG_SPLIT_RE = re.compile(r"\s*(?:\|\||&&|[|;\n])\s*")
_WRAPPER_PREFIX = ("sudo", "env", "nice", "nohup", "time", "command", "exec", "xargs", "timeout", "doas")


_REDIRECT_TOKEN = re.compile(r"^(?:\d*[<>]{1,2}&?\d*|&>{1,2})(?P<rest>.*)$")


def _strip_redirects(argv: List[str]) -> List[str]:
    out: List[str] = []
    skip = False
    for a in argv:
        if skip:
            skip = False
            continue
        m = _REDIRECT_TOKEN.match(a)
        if m:
            if not m.group("rest"):
                skip = True  # `> file`: the file is the next token
            continue
        out.append(a)
    return out


def _gate_paths() -> List[str]:
    return [str(settings.lock), str(settings.state_dir / "tickets"), str(settings.state_dir / "parked"),
            str(settings.state_dir / "shims")]


def classify_command(command: str, cwd: Optional[Path] = None) -> List[Request]:
    """Every install-shaped or gate-bypassing thing a shell command string does."""
    out: List[Request] = []
    if _PIPE_SH_RE.search(command) or _PROC_SUBST_SH_RE.search(command):
        out.append(Request(eco="url", tool="curl|sh", specs=re.findall(r"https?://\S+", command)[:3], reason="remote script piped into a shell"))
    if _PY_M_PIP_RE.search(command):
        out.append(Request(eco="bypass", tool="python -m pip", reason="installer invoked through the interpreter; the shim cannot see it"))
    if _ENV_I_RE.search(command):
        out.append(Request(eco="bypass", tool="env", reason="environment reset (env -i); the shim cannot see what runs inside"))
    else:
        for m in _PATH_REPLACE_RE.finditer(command):
            if "$PATH" not in m.group("v") and "${PATH" not in m.group("v"):
                out.append(Request(eco="bypass", tool="env", reason="PATH replaced outright; the shims are no longer in front"))
                break
    for gp in _gate_paths():
        if gp and gp in command:
            out.append(Request(eco="bypass", tool="gate files", reason=f"touches the install gate's own files ({gp})"))
            break
    here = Path(cwd) if cwd else Path.cwd()
    for seg in _SEG_SPLIT_RE.split(command):
        seg = seg.strip()
        if not seg:
            continue
        try:
            argv = shlex.split(seg, posix=True)
        except ValueError:
            argv = seg.split()
        argv = _strip_redirects(argv)
        # follow `cd dir &&` so npx / package.json lookups see the right directory
        if argv and argv[0] == "cd":
            target = argv[1] if len(argv) > 1 else "~"
            try:
                here = (Path(target).expanduser() if target.startswith(("/", "~")) else here / target).resolve()
            except Exception:  # noqa: BLE001
                pass
            continue
        # strip leading assignments and wrappers: `FOO=1 sudo -E npm i x`
        while argv and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0]) or argv[0] in _WRAPPER_PREFIX):
            if argv[0] in ("sudo", "doas", "env", "nice", "nohup", "timeout", "xargs"):
                argv = argv[1:]
                while argv and argv[0].startswith("-"):
                    argv = argv[1:]
                continue
            argv = argv[1:]
        if not argv:
            continue
        tool = os.path.basename(argv[0])
        if tool in SHIMMED:
            req = parse_argv(tool, argv[1:], here)
            if req is not None and not req.lockfile_governed:
                if "/" in argv[0]:
                    req.reason = (req.reason + "; " if req.reason else "") + "installer invoked by path, the shim cannot see it"
                out.append(req)
    return out


# ── registry resolution ──────────────────────────────────────────────────────

class Unresolved(Exception):
    pass


FetchFn = Callable[[str, Dict[str, str], float], bytes]


def _http_fetch(url: str, headers: Dict[str, str], timeout: float) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — registry URLs only
        return resp.read()


def _get_json(url: str, fetch: FetchFn, headers: Optional[Dict[str, str]] = None) -> Any:
    last: Optional[Exception] = None
    for attempt in range(settings.retries + 1):
        try:
            return json.loads(fetch(url, headers or {}, settings.registry_timeout))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise Unresolved(f"not found at registry ({url})") from exc
            last = exc
        except Exception as exc:  # noqa: BLE001
            last = exc
        if attempt < settings.retries:
            time.sleep(0.3)
    raise Unresolved(f"registry unreachable ({type(last).__name__}: {last})")


def _resolve_npm(spec: str, fetch: FetchFn) -> Tuple5:
    name, rng = _split_npm_spec(spec)
    url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")
    doc = _get_json(url, fetch)
    versions = doc.get("versions") or {}
    tags = doc.get("dist-tags") or {}
    if rng in versions:
        v = rng
    elif rng in tags:
        v = tags[rng]
    elif rng and re.fullmatch(r"[=v]?\d+\.\d+\.\d+(?:[-+][\w.]+)?", rng):
        v = rng.lstrip("=v")
        if v not in versions:
            raise Unresolved(f"{name}@{v} is not a published version")
    else:
        v = tags.get("latest")
        if not v or v not in versions:
            raise Unresolved(f"{name}: no latest version")
    vdoc = versions[v]
    dist = vdoc.get("dist") or {}
    integrity = dist.get("integrity") or (("sha1-" + dist["shasum"]) if dist.get("shasum") else "")
    if not integrity:
        raise Unresolved(f"{name}@{v}: registry gave no integrity hash")
    pub = (vdoc.get("_npmUser") or {}).get("name") or ((doc.get("maintainers") or [{}])[0] or {}).get("name") or "unknown"
    return Tuple5("npm", name, v, str(pub), str(integrity))


def _resolve_pypi(spec: str, fetch: FetchFn) -> Tuple5:
    m = _PY_NAME.match(spec.strip())
    if not m:
        raise Unresolved(f"cannot parse {spec!r}")
    name, _extras, rest = m.group(1), m.group(2), m.group(3).strip()
    ex = _PY_EXACT.match(rest)
    if ex:
        doc = _get_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{ex.group(1)}/json", fetch)
    else:
        doc = _get_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json", fetch)
    info = doc.get("info") or {}
    v = str(info.get("version") or "")
    files = doc.get("urls") or []
    if not v or not files:
        raise Unresolved(f"{name}: no release files")
    digests = sorted(str((f.get("digests") or {}).get("sha256") or "") for f in files)
    digests = [d for d in digests if d]
    if not digests:
        raise Unresolved(f"{name}=={v}: no sha256 digests")
    # One hash for the tuple: sha256 over the sorted set of file digests, so
    # any added/replaced file in the release changes it.
    combined = hashlib.sha256("\n".join(digests).encode()).hexdigest()
    pub = str(info.get("author") or info.get("maintainer") or info.get("author_email") or "unknown").strip() or "unknown"
    return Tuple5("pypi", info.get("name") or name, v, pub, "sha256-" + combined)


def _resolve_crates(spec: str, fetch: FetchFn) -> Tuple5:
    name, _, ver = spec.partition("@")
    hdr = {"User-Agent": USER_AGENT}
    if not ver:
        doc = _get_json(f"https://crates.io/api/v1/crates/{urllib.parse.quote(name)}", fetch, hdr)
        ver = str((doc.get("crate") or {}).get("max_stable_version") or (doc.get("crate") or {}).get("max_version") or "")
        if not ver:
            raise Unresolved(f"{name}: no version")
    doc = _get_json(f"https://crates.io/api/v1/crates/{urllib.parse.quote(name)}/{urllib.parse.quote(ver)}", fetch, hdr)
    vd = doc.get("version") or {}
    checksum = str(vd.get("checksum") or "")
    if not checksum:
        raise Unresolved(f"{name}@{ver}: no checksum")
    pub = str((vd.get("published_by") or {}).get("login") or "unknown")
    return Tuple5("crates", name, ver, pub, "sha256-" + checksum)


def resolve(eco: str, spec: str, fetch: Optional[FetchFn] = None) -> Tuple5:
    fetch = fetch or _http_fetch
    if eco == "npm":
        return _resolve_npm(spec, fetch)
    if eco == "pypi":
        return _resolve_pypi(spec, fetch)
    if eco == "crates":
        return _resolve_crates(spec, fetch)
    raise Unresolved(f"no registry for {eco}")


# ── lock file ────────────────────────────────────────────────────────────────

class Lock:
    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path or settings.lock)
        self.entries: List[Dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data = data.get("entries") or []
            self.entries = [e for e in data if isinstance(e, dict)]
        except FileNotFoundError:
            self.entries = []
        except Exception:  # noqa: BLE001
            logger.warning("install_gate: lock file unreadable, treating as empty: %s", self.path)
            self.entries = []

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"version": 1, "entries": self.entries}, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)

    def find(self, t: Tuple5) -> Optional[Dict[str, Any]]:
        for e in self.entries:
            if e.get("eco") == t.eco and e.get("name") == t.name and e.get("version") == t.version:
                return e
        return None

    def status(self, t: Tuple5) -> str:
        """``ok`` | ``missing`` | ``hash changed`` | ``publisher changed``."""
        e = self.find(t)
        if e is None:
            return "missing"
        if e.get("hash") != t.hash:
            return "hash changed"
        if e.get("publisher") and t.publisher and e["publisher"] != t.publisher:
            return "publisher changed"
        return "ok"

    def bless(self, tuples: Iterable[Tuple5], by: str = "human") -> int:
        n = 0
        for t in tuples:
            if self.status(t) == "ok":
                continue
            self.entries = [e for e in self.entries if not (e.get("eco") == t.eco and e.get("name") == t.name and e.get("version") == t.version)]
            self.entries.append({**asdict(t), "blessed": time.strftime("%Y-%m-%d"), "by": by})
            n += 1
        if n:
            self.save()
        return n

    def bless_url(self, url: str, body_sha256: str, by: str = "human") -> None:
        self.entries = [e for e in self.entries if not (e.get("eco") == "url" and e.get("name") == url)]
        self.entries.append({"eco": "url", "name": url, "version": "", "publisher": "", "hash": "sha256-" + body_sha256,
                             "blessed": time.strftime("%Y-%m-%d"), "by": by})
        self.save()


# ── tickets and parks ────────────────────────────────────────────────────────

def _new_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + "-" + hashlib.sha1(os.urandom(8)).hexdigest()[:6]


def write_ticket(tuples: Iterable[Tuple5], command: str = "") -> str:
    tid = _new_id()
    p = _dir("tickets") / f"{tid}.json"
    p.write_text(json.dumps({"id": tid, "created": time.time(), "tuples": [asdict(t) for t in tuples],
                             "command_sha256": hashlib.sha256(command.encode()).hexdigest()}), encoding="utf-8")
    return tid


def void_ticket(tid: str) -> bool:
    p = settings.state_dir / "tickets" / f"{tid}.json"
    try:
        p.unlink()
        return True
    except FileNotFoundError:
        return False


def take_ticket(tuples: Iterable[Tuple5]) -> Optional[str]:
    """Consume one unexpired ticket covering every tuple. Single use."""
    need = {t.key() for t in tuples}
    d = settings.state_dir / "tickets"
    if not d.exists():
        return None
    now = time.time()
    for p in sorted(d.glob("*.json")):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if now - float(doc.get("created", 0)) > TICKET_TTL:
            p.unlink(missing_ok=True)
            continue
        have = {Tuple5(**t).key() for t in doc.get("tuples", []) if isinstance(t, dict)}
        if need and need <= have:
            p.unlink(missing_ok=True)
            return str(doc.get("id"))
    return None


def park(req: Request, resolved: List[Tuple5], problems: List[str], cwd: Optional[Path] = None) -> str:
    pid = _new_id()
    p = _dir("parked") / f"{pid}.json"
    p.write_text(json.dumps({
        "id": pid, "created": time.time(), "tool": req.tool, "eco": req.eco, "argv": req.argv,
        "specs": req.specs, "cwd": str(cwd or Path.cwd()), "reason": req.reason,
        "tuples": [asdict(t) for t in resolved], "problems": problems,
    }, indent=1), encoding="utf-8")
    return pid


def list_parked() -> List[Dict[str, Any]]:
    d = settings.state_dir / "parked"
    out: List[Dict[str, Any]] = []
    if not d.exists():
        return out
    for p in sorted(d.glob("*.json")):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:  # noqa: BLE001
            continue
    return out


def bless_parked(pid: str, fetch: Optional[FetchFn] = None, by: str = "human") -> Tuple[int, List[str]]:
    """Move a park's tuples into the lock. Unresolved specs are resolved now."""
    p = settings.state_dir / "parked" / f"{pid}.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    lock = Lock()
    tuples = [Tuple5(**t) for t in doc.get("tuples", [])]
    notes: List[str] = []
    if doc.get("eco") in ("npm", "pypi", "crates"):
        have = {t.name for t in tuples}
        for spec in doc.get("specs", []):
            nm = _spec_name(doc["eco"], spec)
            if nm in have:
                continue
            try:
                tuples.append(resolve(doc["eco"], spec, fetch))
            except Unresolved as exc:
                notes.append(f"{spec}: {exc}")
    elif doc.get("eco") == "url":
        for u in doc.get("specs", []):
            if not u.startswith(("http://", "https://")):
                notes.append(f"{u}: only http(s) URLs can be blessed by body hash")
                continue
            try:
                body = (fetch or _http_fetch)(u, {}, settings.registry_timeout)
            except Exception as exc:  # noqa: BLE001
                notes.append(f"{u}: could not fetch to hash it ({exc})")
                continue
            lock.bless_url(u, hashlib.sha256(body).hexdigest(), by=by)
    n = lock.bless(tuples, by=by)
    p.unlink(missing_ok=True)
    return n, notes


def drop_parked(pid: str) -> bool:
    p = settings.state_dir / "parked" / f"{pid}.json"
    try:
        p.unlink()
        return True
    except FileNotFoundError:
        return False


def _spec_name(eco: str, spec: str) -> str:
    if eco == "npm":
        return _split_npm_spec(spec)[0]
    if eco == "pypi":
        m = _PY_NAME.match(spec)
        return (m.group(1) if m else spec).lower()
    return spec.partition("@")[0]


# ── the decision ─────────────────────────────────────────────────────────────

@dataclass
class Verdict:
    allow: bool
    tuples: List[Tuple5]
    problems: List[str]           # human-readable, one per spec that is not ok
    pinned_specs: List[str]       # specs rewritten to the exact resolved version

    def summary(self) -> str:
        parts = [f"  ok      {t.short()}" for t in self.tuples if t.short() not in " ".join(self.problems)]
        parts += [f"  {p}" for p in self.problems]
        return "\n".join(parts)


HOOK_BUDGET = 12.0   # seconds L1 may spend resolving; core's pre_tool_call timeout is 30 s and fail-closed
SHIM_BUDGET = 90.0   # seconds L2 may spend before parking the rest unresolved


def check(req: Request, lock: Optional[Lock] = None, fetch: Optional[FetchFn] = None,
          budget: float = SHIM_BUDGET) -> Verdict:
    """Resolve every spec and compare with the lock. Never raises, never overruns ``budget``."""
    lock = lock or Lock()
    tuples: List[Tuple5] = []
    problems: List[str] = []
    pinned: List[str] = []
    if req.eco == "url":
        for u in req.specs or ["(url)"]:
            problems.append(f"park              {u}: {req.reason or 'URL install'}; no registry tuple exists")
        return Verdict(False, [], problems, [])
    if req.eco == "bypass":
        return Verdict(False, [], [f"park              {req.tool}: {req.reason}"], [])
    deadline = time.monotonic() + budget
    for i, spec in enumerate(req.specs):
        if time.monotonic() > deadline:
            rest = len(req.specs) - i
            problems.append(f"park              {rest} more spec(s) not resolved: time budget of {budget:.0f}s spent; "
                            "bless from the park record, which resolves them then")
            break
        try:
            t = resolve(req.eco, spec, fetch)
        except Unresolved as exc:
            problems.append(f"park              {spec}: {exc}")
            continue
        tuples.append(t)
        st = lock.status(t)
        if st != "ok":
            problems.append(f"{st:<17} {t.short()}")
        pinned.append(_pin(req.eco, spec, t))
    return Verdict(not problems and bool(tuples), tuples, problems, pinned)


def _pin(eco: str, spec: str, t: Tuple5) -> str:
    if eco == "npm":
        return f"{t.name}@{t.version}"
    if eco == "pypi":
        m = _PY_NAME.match(spec)
        extras = m.group(2) or "" if m else ""
        return f"{t.name}{extras}=={t.version}"
    if eco == "crates":
        return f"{t.name}@{t.version}"
    return spec


# ── seeding from lockfiles ───────────────────────────────────────────────────

def seed(project: Path) -> List[Tuple5]:
    """Tuples from lockfiles that already exist in a project tree (depth ≤ 3)."""
    found: List[Tuple5] = []
    project = Path(project).expanduser().resolve()
    for p in project.rglob("*"):
        if len(p.relative_to(project).parts) > 4 or "node_modules" in p.parts or ".venv" in p.parts:
            continue
        if p.name == "package-lock.json":
            try:
                lock = json.loads(p.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                continue
            for k, v in (lock.get("packages") or {}).items():
                if not k.startswith("node_modules/") or not isinstance(v, dict):
                    continue
                name = k.rsplit("node_modules/", 1)[-1]
                if v.get("version") and v.get("integrity"):
                    found.append(Tuple5("npm", name, str(v["version"]), "", str(v["integrity"])))
        elif p.name == "uv.lock":
            found.extend(_seed_uv_lock(p))
        elif p.name == "Cargo.lock":
            found.extend(_seed_cargo_lock(p))
    return found


def _seed_uv_lock(p: Path) -> List[Tuple5]:
    out: List[Tuple5] = []
    try:
        import tomllib  # py3.11+
        doc = tomllib.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return out
    for pkg in doc.get("package") or []:
        name, ver = pkg.get("name"), pkg.get("version")
        digests = []
        for f in [pkg.get("sdist")] + list(pkg.get("wheels") or []):
            if isinstance(f, dict) and f.get("hash", "").startswith("sha256:"):
                digests.append(f["hash"].split(":", 1)[1])
        if name and ver and digests:
            # Same combination rule as _resolve_pypi, but a uv.lock rarely lists
            # every file PyPI does, so the seed records the file hashes it has.
            out.append(Tuple5("pypi", name, str(ver), "", "sha256-" + hashlib.sha256("\n".join(sorted(digests)).encode()).hexdigest()))
    return out


def _seed_cargo_lock(p: Path) -> List[Tuple5]:
    out: List[Tuple5] = []
    try:
        import tomllib
        doc = tomllib.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return out
    for pkg in doc.get("package") or []:
        if pkg.get("name") and pkg.get("version") and pkg.get("checksum"):
            out.append(Tuple5("crates", pkg["name"], str(pkg["version"]), "", "sha256-" + str(pkg["checksum"])))
    return out


# ── the shim (L2) ────────────────────────────────────────────────────────────

def real_binary(tool: str) -> Optional[str]:
    """The next ``tool`` on PATH after our own shims directory."""
    shim_dir = shims_dir().resolve()
    parts = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p and Path(p).resolve() != shim_dir]
    return shutil.which(tool, path=os.pathsep.join(parts))


def _rewrite_pinned(tool: str, argv: List[str], req: Request, verdict: Verdict) -> List[str]:
    """Replace loose specs with the exact resolution that was checked."""
    if not verdict.pinned_specs or len(verdict.pinned_specs) != len(req.specs):
        return argv
    mapping = dict(zip(req.specs, verdict.pinned_specs))
    return [mapping.get(a, a) for a in argv]


def shim_main(tool: str, argv: Optional[List[str]] = None) -> int:
    """Entry point for every file in ``shims/``. Returns the exit code."""
    configure()
    argv = list(sys.argv[1:] if argv is None else argv)
    real = real_binary(tool)
    if real is None:
        sys.stderr.write(f"kibisis: {tool} not found on PATH beyond the shim\n")
        return 127
    if settings.mode != "gate":
        os.execv(real, [real] + argv)
    try:
        req = parse_argv(tool, argv, Path.cwd())
    except Exception:  # noqa: BLE001 — a parser bug must not wedge the tool
        logger.debug("install_gate: parse failed; passing through", exc_info=True)
        req = None
    if req is None or req.lockfile_governed:
        os.execv(real, [real] + argv)
    verdict = check(req)
    if verdict.allow:
        os.execv(real, [real] + _rewrite_pinned(tool, argv, req, verdict))
    if verdict.tuples and not [p for p in verdict.problems if p.startswith("park")]:
        tid = take_ticket(verdict.tuples)
        if tid:
            Lock().bless(verdict.tuples, by=f"approval {tid}")
            os.execv(real, [real] + _rewrite_pinned(tool, argv, req, verdict))
    pid = park(req, verdict.tuples, verdict.problems, Path.cwd())
    sys.stderr.write(park_line(pid, req, verdict) + "\n")
    return EX_TEMPFAIL


def park_line(pid: str, req: Request, verdict: Verdict) -> str:
    what = ", ".join(req.specs) if req.specs else req.tool
    return (f"{PARK_MARK} id={pid}] {req.tool} install of {what} is parked, nothing was installed. "
            f"Not in the install lock:\n{verdict.summary()}\n"
            f"A human blesses it with: hermes kibisis bless {pid}   (or /kibisis bless {pid} in chat). "
            "Report this to the user and continue with other work; do not retry or work around it.")


# ── the hook (L1) ────────────────────────────────────────────────────────────

def pre_tool_call(tool_name: str, args: Any) -> Optional[Dict[str, Any]]:
    """The ``pre_tool_call`` body. ``None`` = proceed; else an ``approve`` directive."""
    if settings.mode == "off":
        return None
    if not isinstance(args, dict):
        return None
    if tool_name == "terminal":
        command = str(args.get("command") or "")
    elif tool_name == "execute_code":
        command = str(args.get("code") or "")
    elif tool_name in ("write_file", "patch", "apply_patch", "edit_file", "delete_file", "move_file"):
        text = " ".join(str(v) for v in args.values() if isinstance(v, str))
        if any(gp in text for gp in _gate_paths()):
            return _approve([Request(eco="bypass", tool=tool_name, reason="edits the install gate's own files")], Verdict(False, [], ["park    edits the install gate's own files"], []))
        return None
    else:
        return None
    if not command:
        return None
    reqs = classify_command(command)
    if not reqs:
        return None
    lock = Lock()
    tuples: List[Tuple5] = []
    problems: List[str] = []
    started = time.monotonic()
    for req in reqs:
        left = max(0.5, HOOK_BUDGET - (time.monotonic() - started))
        v = check(req, lock, budget=left)
        tuples.extend(v.tuples)
        problems.extend(v.problems)
    if not problems:
        return None
    tid = write_ticket([t for t in tuples if lock.status(t) != "ok"], command) if tuples else ""
    return _approve(reqs, Verdict(False, tuples, problems, []), tid)


def _approve(reqs: List[Request], verdict: Verdict, tid: str = "") -> Dict[str, Any]:
    names = sorted({_spec_name(r.eco, s) for r in reqs for s in (r.specs or [r.tool])})
    rule_key = "kibisis:install:" + ",".join(names)[:120]
    msg = ("kibisis install gate: not in the install lock\n" + verdict.summary() +
           ("\nApproving once writes these tuples to the lock." if tid else "\nApproving runs it; nothing is recorded (no registry tuple).") +
           (f" ticket={tid}" if tid else ""))
    return {"action": "approve", "message": msg, "rule_key": rule_key}


_TICKET_IN_MSG = re.compile(r"ticket=(\d{8}-\d{6}-[0-9a-f]{6})")


_DENIALS = {"deny", "denied", "d", "smart_deny", "no", "reject", "timeout", "cancel", "cancelled"}
_APPROVALS = {"once", "session", "always", "o", "s", "a", "approve", "approved", "smart_approve", "yes"}


def post_approval_response(description: str = "", choice: str = "", pattern_key: str = "", **_: Any) -> None:
    """Observer on the human's decision: approval blesses the ticket's tuples into the
    lock (so the shim, or an install the shim cannot see, goes through); denial voids it."""
    if not str(pattern_key).startswith("plugin_rule:kibisis:install:"):
        return
    m = _TICKET_IN_MSG.search(str(description))
    if not m:
        return
    tid = m.group(1)
    c = str(choice).lower()
    if c in _DENIALS:
        void_ticket(tid)
    elif c in _APPROVALS:
        p = settings.state_dir / "tickets" / f"{tid}.json"
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return
        Lock().bless([Tuple5(**t) for t in doc.get("tuples", []) if isinstance(t, dict)], by=f"approval {c}")
        void_ticket(tid)


# ── park footer for transform_tool_result ────────────────────────────────────

def park_footer(result: str) -> Optional[str]:
    """When a tool result carries a park line, add the one line the human needs."""
    if PARK_MARK not in result:
        return None
    m = re.search(re.escape(PARK_MARK) + r" id=([0-9-]+-[0-9a-f]{6})\]", result)
    if not m:
        return None
    return (f"\n[kibisis] install parked (id {m.group(1)}). Nothing was installed. "
            f"Bless it with `hermes kibisis bless {m.group(1)}` or `/kibisis bless {m.group(1)}`; "
            f"drop it with `/kibisis drop {m.group(1)}`.")


# ── human commands (CLI + slash) ─────────────────────────────────────────────

def human_command(raw: str, fetch: Optional[FetchFn] = None) -> str:
    """``parked`` | ``bless <id>`` | ``drop <id>`` | ``seed <dir>`` | ``status`` | ``install-shims``."""
    configure()
    parts = raw.strip().split()
    verb = parts[0] if parts else "status"
    if verb == "status":
        n = len(Lock().entries)
        return (f"kibisis install gate: mode={settings.mode}, lock={settings.lock} ({n} tuples), "
                f"parked={len(list_parked())}, shims={'on PATH' if shims_on_path() else 'NOT on PATH'}")
    if verb == "parked":
        items = list_parked()
        if not items:
            return "kibisis: nothing parked."
        lines = []
        for d in items:
            age = int((time.time() - float(d.get("created", 0))) / 60)
            lines.append(f"{d['id']}  {age}m ago  {d.get('tool')} {' '.join(d.get('specs') or [])}  ({d.get('cwd')})")
            for p in d.get("problems") or []:
                lines.append("    " + p)
        return "\n".join(lines)
    if verb == "bless" and len(parts) > 1:
        try:
            n, notes = bless_parked(parts[1], fetch)
        except FileNotFoundError:
            return f"kibisis: no park with id {parts[1]}"
        return f"kibisis: blessed {n} tuple(s) into {settings.lock}." + ("".join("\n  " + x for x in notes)) + \
            "\nRe-run the install; the shim lets it through now."
    if verb == "drop" and len(parts) > 1:
        return "kibisis: dropped." if drop_parked(parts[1]) else f"kibisis: no park with id {parts[1]}"
    if verb == "seed" and len(parts) > 1:
        tuples = seed(Path(parts[1]))
        n = Lock().bless(tuples, by="seed")
        return f"kibisis: found {len(tuples)} tuples in lockfiles under {parts[1]}, {n} new in the lock."
    if verb == "install-shims":
        return install_shims()
    return "usage: kibisis status | parked | bless <id> | drop <id> | seed <project-dir> | install-shims"


def shims_dir() -> Path:
    return settings.state_dir / "shims"


def shims_on_path() -> bool:
    return str(shims_dir()) in os.environ.get("PATH", "").split(os.pathsep)


_SHIM_BODY = '''"""Shared body of every kibisis shim. Generated by `hermes kibisis install-shims`."""
import os
import sys

sys.path.insert(0, {plugin_dir!r})
import install_gate  # noqa: E402


def run(tool: str) -> None:
    try:
        code = install_gate.shim_main(tool)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — never wedge the tool on a shim bug
        sys.stderr.write(f"kibisis shim error ({{exc}}); running {{tool}} unchecked\\n")
        real = install_gate.real_binary(tool)
        if real:
            os.execv(real, [real] + sys.argv[1:])
        code = 127
    sys.exit(code)
'''

_SHIM_LAUNCHER = '''#!/usr/bin/env python3
# kibisis install-gate shim for {tool}. Generated; regenerate with `hermes kibisis install-shims`.
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _shim import run
run({tool!r})
'''


def install_shims() -> str:
    """Write the launchers into the state dir (never into the plugin tree: the plugin
    scanner rightly dislikes extensionless executables) and print the config to add."""
    d = shims_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "_shim.py").write_text(_SHIM_BODY.format(plugin_dir=str(Path(__file__).resolve().parent)), encoding="utf-8")
    for name in SHIMMED:
        p = d / name
        p.write_text(_SHIM_LAUNCHER.format(tool=name), encoding="utf-8")
        p.chmod(0o755)
    env = d / "env.sh"
    env.write_text(f'# kibisis install gate: shims first on PATH\ncase ":$PATH:" in *":{d}:"*) ;; *) export PATH="{d}:$PATH";; esac\n', encoding="utf-8")
    return (f"shims ready in {d}\n"
            "Add to ~/.hermes/config.yaml (an explicit list replaces the automatic ~/.bashrc sourcing, so keep your rc files in it):\n"
            "  terminal:\n    shell_init_files:\n      - ~/.profile\n      - ~/.bashrc\n"
            f"      - {env}\n"
            "  plugins:\n    entries:\n      kibisis:\n        settings:\n          install_gate: gate\n"
            "Then restart the gateway. The shims only enforce when install_gate is 'gate'; otherwise they exec the real tool untouched.")
