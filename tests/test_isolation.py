"""Proof that the read-only side cannot import or reach the mutating side."""
import ast
import pathlib
import subprocess
import sys
import textwrap

import phishguard
from phishguard.mutating.policy import ActionType
from phishguard.readonly import READ_ONLY_TOOL_NAMES, ReadOnlyToolbox

ROOT = pathlib.Path(phishguard.__file__).parent
FORBIDDEN = ("phishguard.mutating", "phishguard.api")


def _imports(path: pathlib.Path):
    tree = ast.parse(path.read_text())
    pkg = ".".join(path.relative_to(ROOT.parent).with_suffix("").parts[:-1])
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                yield a.name
        elif isinstance(n, ast.ImportFrom):
            base = n.module or ""
            if n.level:
                parts = pkg.split(".")[: len(pkg.split(".")) - (n.level - 1)]
                base = ".".join(parts + ([base] if base else []))
            yield base
            for a in n.names:
                yield f"{base}.{a.name}"


def _scan(dirpath_or_files):
    bad = []
    for f in dirpath_or_files:
        for name in _imports(f):
            if name.startswith(FORBIDDEN) or ".mutating" in name:
                bad.append((str(f), name))
    return bad


def test_readonly_source_never_mentions_mutating():
    files = list((ROOT / "readonly").rglob("*.py"))
    assert files
    assert _scan(files) == []


def test_agent_and_llm_source_never_import_mutating():
    files = list((ROOT / "llm").rglob("*.py")) + [ROOT / "agent.py", ROOT / "models.py", ROOT / "config.py"]
    assert _scan(files) == []


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code)], capture_output=True, text=True,
                          cwd=ROOT.parent)


def test_runtime_import_closure_excludes_mutating():
    r = _run("""
        import sys, phishguard.readonly, phishguard.agent, phishguard.llm
        bad = [m for m in sys.modules if m.startswith('phishguard.mutating') or m == 'phishguard.api']
        print(bad); sys.exit(1 if bad else 0)
    """)
    assert r.returncode == 0, r.stdout + r.stderr


def test_readonly_works_even_if_mutating_import_is_blocked():
    r = _run("""
        import sys, importlib.abc
        class Block(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path, target=None):
                if name.startswith('phishguard.mutating'):
                    raise ImportError('blocked: ' + name)
        sys.meta_path.insert(0, Block())
        from datetime import datetime, timezone
        from phishguard.agent import PhishingAgent
        from phishguard.config import Settings
        from phishguard.llm import MockLLM
        from phishguard.models import EmailMessage
        e = EmailMessage(id='x', timestamp=datetime(2026,3,3,10,tzinfo=timezone.utc), sender_email='a@b.com', body='hi')
        print(PhishingAgent(MockLLM(), Settings()).analyze(e).risk_percent)
    """)
    assert r.returncode == 0, r.stdout + r.stderr


def test_toolbox_has_no_mutating_tools(benign):
    names = {t["name"] for t in ReadOnlyToolbox(benign).schemas()}
    assert names == set(READ_ONLY_TOOL_NAMES)
    assert not names & {a.value for a in ActionType}


def test_toolbox_rejects_mutating_tool_calls(benign):
    tb = ReadOnlyToolbox(benign)
    for name in ("transfer_funds", "pay_invoice", "change_bank_details", "quarantine_email"):
        assert "error" in tb.call(name, {"amount": 1})
