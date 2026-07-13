"""Deterministic tool functions ("skills") exposed to the BugFund agents.

These are plain, typed, async callables with rich docstrings. They are the
*only* way agents touch the filesystem, the SAST/DAST engines, or the Docker
sandbox. ``TOOL_REGISTRY`` + ``tool_schemas()`` advertise JSON-Schema
descriptions so the tools can be bound to an LLM tool-calling layer later.

Design notes:
- ``execute_sandbox_script`` delegates to an injectable :class:`SandboxClient`
  (the execution_engine wires a concrete one) so the skill is unit-testable
  with a fake client today.
- ``find_function_references`` uses Python's ``ast`` for precise, cheap
  call-site retrieval — so the Threat Modeler never needs the whole repo in
  context.
- ``apply_source_patch`` materializes a patched *copy* of the target tree so
  the Patcher can re-run the exact PoV against patched code without touching
  the original.
"""
from __future__ import annotations

import ast
import asyncio
import enum
import json
import re
import shutil
from pathlib import Path
from typing import Any, Iterator, Optional, Protocol, TypedDict, runtime_checkable

__all__ = [
    "ReadDepth",
    "CodebaseView",
    "SastReport",
    "SandboxResult",
    "ReferenceReport",
    "FunctionReference",
    "NucleiReport",
    "NucleiFinding",
    "PatchedTree",
    "ToolError",
    "SandboxClient",
    "set_sandbox_client",
    "get_sandbox_client",
    "read_codebase",
    "run_sast_scanner",
    "run_nuclei",
    "find_function_references",
    "apply_source_patch",
    "execute_sandbox_script",
    "TOOL_REGISTRY",
    "tool_schemas",
]


class ToolError(RuntimeError):
    """A skill failed in an expected, recoverable way (missing dep, bad path, ...)."""


# --------------------------------------------------------------------------- #
# Return shapes (JSON-serializable so they can live inside LangGraph state)
# --------------------------------------------------------------------------- #
class CodebaseView(TypedDict):
    root: str
    depth: str
    truncated: bool
    file_count: int
    languages: dict[str, int]
    files: list[dict[str, Any]]
    tree: str


class SastReport(TypedDict):
    scanner: str
    rule_set: str
    returncode: int
    findings: list[dict[str, Any]]
    raw: dict[str, Any]


class SandboxResult(TypedDict):
    stdout: str
    stderr: str
    exit_code: Optional[int]
    duration_ms: int
    container_id: Optional[str]
    timed_out: bool


class FunctionReference(TypedDict):
    path: str
    line: int
    column: int
    enclosing: str
    snippet: str


class ReferenceReport(TypedDict):
    function: str
    language: str
    search_root: str
    total: int
    truncated: bool
    references: list[FunctionReference]


class NucleiFinding(TypedDict):
    template_id: str
    name: str
    severity: str
    type: str
    matched: str
    cvss: Optional[str]
    description: str
    reference: list[str]


class NucleiReport(TypedDict):
    scanner: str
    target: str
    returncode: int
    findings: list[NucleiFinding]
    raw_lines: list[str]


class PatchedTree(TypedDict):
    original_root: str
    patched_root: str
    patched_files: list[str]
    skipped: list[str]


class ReadDepth(str, enum.Enum):
    TREE = "tree"            # directory listing only
    SIGNATURES = "signatures"  # + def/class signatures (no bodies)
    FULL = "full"            # + full file contents (bounded per file)


# Rule presets understood by run_sast_scanner (Semgrep --config values).
_SEMGREP_RULESETS = {
    "auto": "auto",
    "security": "p/security-audit",
    "owasp": "p/owasp-top-ten",
    "cwe-top25": "p/cwe-top-25",
    "python": "p/python",
    "javascript": "p/javascript",
    "default": "p/default",
}

_IGNORED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "target",
    "*.patched",
}
_LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".jsx": "javascript", ".go": "go", ".rs": "rust",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".java": "java", ".rb": "ruby", ".php": "php", ".cs": "csharp",
}
_SIG_RE = {
    "python": re.compile(r"^\s*(async\s+def\s+\w+|def\s+\w+|class\s+\w+|@[\w.]+)", re.M),
}

_MAX_BYTES_PER_FILE = 20_000


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #
def _ignored(rel_parts: tuple[str, ...]) -> bool:
    for pat in _IGNORED_DIRS:
        if any(p == pat for p in rel_parts):
            return True
        if "*" in pat and any(re.fullmatch(pat.replace("*", ".*"), p) for p in rel_parts):
            return True
    return False


def _iter_source_files(root: Path, suffix: str) -> Iterator[Path]:
    for p in sorted(root.rglob(f"*{suffix}")):
        if not p.is_file():
            continue
        if _ignored(p.relative_to(root).parts):
            continue
        yield p


def _read_bounded(p: Path) -> str:
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            return fh.read(_MAX_BYTES_PER_FILE)
    except OSError:
        return ""


def _render_tree(files: list[dict[str, Any]]) -> str:
    return "\n".join(sorted(f["path"] for f in files[:400]))


def _parse_semgrep_result(r: dict[str, Any]) -> dict[str, Any]:
    extra = r.get("extra") or {}
    metadata = extra.get("metadata") or {}
    return {
        "rule_id": r.get("check_id") or r.get("rule_id"),
        "message": extra.get("message"),
        "severity": extra.get("severity"),
        "path": r.get("path"),
        "start_line": (r.get("start") or {}).get("line"),
        "end_line": (r.get("end") or {}).get("line"),
        "cwe": metadata.get("cwe"),
    }


def _parse_nuclei(obj: dict[str, Any]) -> NucleiFinding:
    info = obj.get("info") or {}
    classification = info.get("classification") or {}
    return NucleiFinding(
        template_id=obj.get("template-id") or obj.get("templateID") or obj.get("id", ""),
        name=info.get("name", ""),
        severity=info.get("severity", "info"),
        type=obj.get("type", ""),
        matched=obj.get("matched") or obj.get("host") or obj.get("matched-at") or "",
        cvss=classification.get("cvss-metrics"),
        description=info.get("description", ""),
        reference=list(info.get("reference") or []),
    )


def _call_name(func: ast.AST) -> Optional[str]:
    """Recover the called name from a Call.func node (foo / obj.foo / a.b.foo)."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _call_name(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return None


# --------------------------------------------------------------------------- #
# Tool 1 — read_codebase
# --------------------------------------------------------------------------- #
async def read_codebase(
    path: str,
    depth: ReadDepth = ReadDepth.SIGNATURES,
    *,
    max_files: int = 500,
) -> CodebaseView:
    """Read a codebase on disk into a structured, size-bounded view.

    Args:
        path: Root directory of the target source tree.
        depth: ``TREE`` = listing only; ``SIGNATURES`` = listing + def/class
            signatures (no bodies); ``FULL`` = listing + full file contents
            (truncated per file to ``_MAX_BYTES_PER_FILE``).
        max_files: Hard cap on the number of files returned.

    Returns:
        A :class:`CodebaseView` with the file list, per-language counts, and a
        tree string. Contents/signatures are omitted for binary/unknown types.

    Raises:
        ToolError: if ``path`` does not exist or is not a directory.
    """
    root = Path(path).resolve()
    if not root.is_dir():
        raise ToolError(f"read_codebase: not a directory: {root}")

    files: list[dict[str, Any]] = []
    languages: dict[str, int] = {}
    truncated = False

    for p in _iter_source_files(root, ""):
        if not p.is_file():
            continue
        if len(files) >= max_files:
            truncated = True
            break

        ext = p.suffix.lower()
        lang = _LANG_BY_EXT.get(ext, "")
        if lang:
            languages[lang] = languages.get(lang, 0) + 1

        entry: dict[str, Any] = {
            "path": str(p.relative_to(root)).replace("\\", "/"),
            "language": lang,
            "size": p.stat().st_size,
        }

        if depth == ReadDepth.FULL and lang:
            entry["content"] = _read_bounded(p)
        elif depth == ReadDepth.SIGNATURES and lang in _SIG_RE:
            entry["signatures"] = _SIG_RE[lang].findall(_read_bounded(p))

        files.append(entry)

    return CodebaseView(
        root=str(root),
        depth=depth.value,
        truncated=truncated,
        file_count=len(files),
        languages=languages,
        files=files,
        tree=_render_tree(files),
    )


# --------------------------------------------------------------------------- #
# Tool 2 — run_sast_scanner (Semgrep)
# --------------------------------------------------------------------------- #
async def run_sast_scanner(
    target_dir: str,
    rule_type: str = "auto",
    *,
    extra_args: Optional[list[str]] = None,
    timeout_s: int = 300,
) -> SastReport:
    """Run a SAST engine (Semgrep) over ``target_dir`` and return parsed findings.

    Args:
        target_dir: Directory to scan.
        rule_type: Rule preset — ``auto | security | owasp | cwe-top25 | python |
            javascript | default``. Unknown values are passed to ``semgrep
            --config`` verbatim (so a registry URL or local path works too).
        extra_args: Extra CLI args forwarded to the scanner.
        timeout_s: Hard timeout for the scan.

    Returns:
        A :class:`SastReport` with normalized findings
        (rule_id, severity, path, start/end line, cwe) and the raw Semgrep JSON.

    Raises:
        ToolError: if the scanner binary is missing, the target is invalid,
            or the scan times out.
    """
    root = Path(target_dir)
    if not root.is_dir():
        raise ToolError(f"run_sast_scanner: not a directory: {root}")

    config = _SEMGREP_RULESETS.get(rule_type, rule_type)
    cmd = ["semgrep", "--json", "--quiet", "--config", config, str(root), *(extra_args or [])]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise ToolError("run_sast_scanner: 'semgrep' not found on PATH") from exc

    try:
        stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise ToolError(f"run_sast_scanner: timed out after {timeout_s}s")

    raw: dict[str, Any] = {}
    try:
        raw = json.loads(stdout_b.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        pass

    findings = [_parse_semgrep_result(r) for r in raw.get("results", [])]
    return SastReport(
        scanner="semgrep",
        rule_set=rule_type,
        returncode=proc.returncode if proc.returncode is not None else -1,
        findings=findings,
        raw=raw,
    )


# --------------------------------------------------------------------------- #
# Tool 3 — run_nuclei (deterministic DAST for the Supervisor)
# --------------------------------------------------------------------------- #
async def run_nuclei(
    target: str,
    *,
    templates: Optional[str] = None,
    severity: Optional[str] = None,
    extra_args: Optional[list[str]] = None,
    timeout_s: int = 300,
) -> NucleiReport:
    """Run Nuclei against a live ``target`` (URL or host:port) and parse findings.

    Nuclei finds the cheap, deterministic stuff AI is bad at (exposed configs,
    known CVEs, default headers, simple XSS/templates). The Supervisor then
    triages which findings are worth promoting to hypotheses for the Actor.

    Args:
        target: Scheme URL or ``host:port`` of the running service to scan.
        templates: Optional ``-t`` template path/URL (else Nuclei defaults).
        severity: Optional severity filter (e.g. ``"high,critical"``).
        extra_args: Extra CLI args forwarded to ``nuclei``.
        timeout_s: Hard timeout for the scan.

    Returns:
        A :class:`NucleiReport` with normalized findings (template_id, severity,
        matched, cvss, description, references) plus the raw JSONL lines.

    Raises:
        ToolError: if ``nuclei`` is missing or the scan times out.
    """
    if not target:
        raise ToolError("run_nuclei: target is required (URL or host:port)")

    cmd = ["nuclei", "-jsonl", "-silent", "-target", target]
    if templates:
        cmd += ["-t", templates]
    if severity:
        cmd += ["-severity", severity]
    cmd += list(extra_args or [])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise ToolError("run_nuclei: 'nuclei' not found on PATH") from exc

    try:
        stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise ToolError(f"run_nuclei: timed out after {timeout_s}s")

    raw_lines = stdout_b.decode("utf-8", "replace").splitlines()
    findings: list[NucleiFinding] = []
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(_parse_nuclei(json.loads(line)))
        except json.JSONDecodeError:
            continue

    return NucleiReport(
        scanner="nuclei",
        target=target,
        returncode=proc.returncode if proc.returncode is not None else -1,
        findings=findings,
        raw_lines=raw_lines,
    )


# --------------------------------------------------------------------------- #
# Tool 4 — find_function_references (AST call-site search for the Threat Modeler)
# --------------------------------------------------------------------------- #
async def find_function_references(
    func_name: str,
    *,
    search_root: Optional[str] = None,
    language: str = "python",
    max_results: int = 50,
    snippet_lines: int = 4,
) -> ReferenceReport:
    """Find every call site of ``func_name`` and return only those snippets.

    Lets the Threat Modeler pull *just* the relevant data/control-flow context
    instead of feeding the whole repo into the LLM. A match is any call whose
    terminal name equals ``func_name`` (so ``obj.foo`` matches a search for
    ``foo``); imported aliases are not resolved (a documented limitation).

    Args:
        func_name: Function/method name to search for (terminal identifier).
        search_root: Directory to search. Defaults to the registered target root.
        language: Only ``"python"`` is supported today (via the ``ast`` module).
        max_results: Cap on the number of references returned.
        snippet_lines: Lines of context included after each call line.

    Returns:
        A :class:`ReferenceReport` of call sites with file, line, enclosing
        scope, and a short source snippet.

    Raises:
        ToolError: if ``search_root`` is missing/invalid or the language is
            unsupported.
    """
    if language != "python":
        raise ToolError(
            f"find_function_references: language={language!r} unsupported (use 'python')."
        )
    if not search_root:
        raise ToolError("find_function_references: search_root is required")
    root = Path(search_root).resolve()
    if not root.is_dir():
        raise ToolError(f"find_function_references: not a directory: {root}")

    references: list[FunctionReference] = []
    truncated = False

    for p in _iter_source_files(root, ".py"):
        src = _read_bounded(p)
        try:
            tree = ast.parse(src, filename=str(p))
        except SyntaxError:
            continue  # skip un-parseable files; one bad file must not break the scan
        src_lines = src.splitlines()
        rel = str(p.relative_to(root)).replace("\\", "/")

        for line, col, enclosing in _collect_calls(tree, func_name):
            if len(references) >= max_results:
                truncated = True
                break
            start = max(0, line - 1)
            snippet = "\n".join(src_lines[start : start + snippet_lines])
            references.append(
                FunctionReference(
                    path=rel, line=line, column=col, enclosing=enclosing, snippet=snippet
                )
            )
        if truncated:
            break

    return ReferenceReport(
        function=func_name,
        language=language,
        search_root=str(root),
        total=len(references),
        truncated=truncated,
        references=references,
    )


def _collect_calls(tree: ast.AST, func_name: str) -> list[tuple[int, int, str]]:
    """Yield (lineno, col, enclosing_scope) for each matching call in ``tree``."""
    out: list[tuple[int, int, str]] = []

    def visit(node: ast.AST, scope: str) -> None:
        cur_scope = scope
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            cur_scope = f"{scope}.{node.name}" if scope else node.name
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name and (name == func_name or name.split(".")[-1] == func_name):
                out.append((node.lineno, node.col_offset, cur_scope))
        for child in ast.iter_child_nodes(node):
            visit(child, cur_scope)

    visit(tree, "")
    return out


# --------------------------------------------------------------------------- #
# Tool 5 — apply_source_patch (materialize a patched copy for the Patcher)
# --------------------------------------------------------------------------- #
async def apply_source_patch(
    target_path: str,
    patches: list[dict[str, str]],
    *,
    dest: Optional[str] = None,
    overwrite: bool = False,
) -> PatchedTree:
    """Copy the target tree and apply ``patches`` to the copy (original untouched).

    Used by the Patcher for differential verification: the same PoV is re-run
    against the patched copy; if it no longer triggers, the patch is proven.

    Args:
        target_path: Original target source root.
        patches: List of ``{"path": rel_path, "new_content": str}`` overwrites.
        dest: Destination directory (defaults to ``<target_path>.patched``).
        overwrite: If True, replace an existing staging dir.

    Returns:
        A :class:`PatchedTree` with the patched root and the per-file results.

    Raises:
        ToolError: if the target is invalid or the staging dir already exists
            without ``overwrite``.
    """
    src = Path(target_path).resolve()
    if not src.is_dir():
        raise ToolError(f"apply_source_patch: not a directory: {src}")

    dst = Path(dest).resolve() if dest else src.parent / f"{src.name}.patched"
    if dst.exists():
        if not overwrite:
            raise ToolError(f"apply_source_patch: staging dir exists: {dst}")
        shutil.rmtree(dst)
    shutil.copytree(src, dst)

    patched: list[str] = []
    skipped: list[str] = []
    for patch in patches:
        rel = patch.get("path", "")
        content = patch.get("new_content", "")
        target_file = dst / rel
        try:
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_text(content, encoding="utf-8")
            patched.append(rel)
        except OSError:
            skipped.append(rel)

    return PatchedTree(
        original_root=str(src),
        patched_root=str(dst),
        patched_files=patched,
        skipped=skipped,
    )


# --------------------------------------------------------------------------- #
# Tool 6 — execute_sandbox_script
# --------------------------------------------------------------------------- #
@runtime_checkable
class SandboxClient(Protocol):
    """Contract the execution_engine implements to run untrusted scripts."""

    async def run_script(
        self,
        *,
        script_code: str,
        env_vars: dict[str, str],
        timeout_s: int,
        network: bool,
    ) -> SandboxResult:
        ...


_sandbox_client: Optional[SandboxClient] = None


def set_sandbox_client(client: SandboxClient) -> None:
    """Inject the concrete sandbox client (called by the execution_engine at startup)."""
    global _sandbox_client
    _sandbox_client = client


def get_sandbox_client() -> SandboxClient:
    if _sandbox_client is None:
        raise ToolError(
            "execute_sandbox_script: no SandboxClient configured. "
            "Call agent_swarm.skills.set_sandbox_client(...) "
            "(wired by the execution_engine)."
        )
    return _sandbox_client


async def execute_sandbox_script(
    script_code: str,
    env_vars: Optional[dict[str, str]] = None,
    *,
    timeout_s: int = 60,
    network: bool = False,
) -> SandboxResult:
    """Execute a Python PoV script inside an isolated Docker sandbox.

    The script runs ephemerally in the execution engine; stdout / stderr / exit
    code are captured and returned for the Critic. Network is disabled by default.

    Args:
        script_code: Full Python source of the PoV.
        env_vars: Environment variables injected into the container. ``POV_TARGET``
            is the convention for the path the PoV should operate on (so the same
            script can be re-run against a patched copy).
        timeout_s: Per-run timeout (seconds).
        network: If True, allow outbound network (default off — prefer off).

    Returns:
        A :class:`SandboxResult` with keys ``stdout``, ``stderr``, ``exit_code``,
        ``duration_ms``, ``container_id``, ``timed_out``.

    Raises:
        ToolError: if no :class:`SandboxClient` has been wired up.
    """
    client = get_sandbox_client()
    return await client.run_script(
        script_code=script_code,
        env_vars=dict(env_vars or {}),
        timeout_s=timeout_s,
        network=network,
    )


# --------------------------------------------------------------------------- #
# Registry / schema advertisement (for future LLM tool-binding)
# --------------------------------------------------------------------------- #
TOOL_REGISTRY = {
    "read_codebase": read_codebase,
    "run_sast_scanner": run_sast_scanner,
    "run_nuclei": run_nuclei,
    "find_function_references": find_function_references,
    "apply_source_patch": apply_source_patch,
    "execute_sandbox_script": execute_sandbox_script,
}


def tool_schemas() -> dict[str, dict[str, Any]]:
    """Minimal JSON-Schema description of each tool (for LLM tool-binding)."""
    return {
        "read_codebase": {
            "description": read_codebase.__doc__.splitlines()[0].strip(),
            "parameters": {"path": "string", "depth": "tree|signatures|full"},
        },
        "run_sast_scanner": {
            "description": run_sast_scanner.__doc__.splitlines()[0].strip(),
            "parameters": {"target_dir": "string", "rule_type": "string"},
        },
        "run_nuclei": {
            "description": run_nuclei.__doc__.splitlines()[0].strip(),
            "parameters": {"target": "string", "severity": "string?"},
        },
        "find_function_references": {
            "description": find_function_references.__doc__.splitlines()[0].strip(),
            "parameters": {"func_name": "string", "search_root": "string"},
        },
        "apply_source_patch": {
            "description": apply_source_patch.__doc__.splitlines()[0].strip(),
            "parameters": {"target_path": "string", "patches": "array"},
        },
        "execute_sandbox_script": {
            "description": execute_sandbox_script.__doc__.splitlines()[0].strip(),
            "parameters": {"script_code": "string", "env_vars": "object"},
        },
    }
