"""improve.py never edits code, refuses patches to protected paths, and respects the LLM budget."""

import hashlib
import pathlib
import subprocess

import pytest

from redteam import improve
from redteam.improve import BudgetExceeded, BudgetGuard, ProtectedPathError, check_patch, write_patch

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _diff(path_a: str, path_b: str | None = None) -> str:
    path_b = path_b or path_a
    return f"--- a/{path_a}\n+++ b/{path_b}\n@@ -1 +1 @@\n-x\n+y\n"


@pytest.mark.parametrize(
    "patch",
    [
        _diff("phishguard/mutating/gateway.py"),
        _diff("phishguard/mutating/totp.py"),
        _diff("phishguard/readonly/../mutating/policy.py"),  # traversal back into a protected dir
        _diff("PhishGuard/Mutating/Gateway.py"),  # case-insensitive file systems
        _diff("phishguard/api.py"),
        _diff("phishguard/config.py"),
        _diff("phishguard/security.py"),
        _diff("redteam/improve.py"),
        _diff("tests/test_mfa_gateway.py"),
        _diff("phishguard/readonly/features.py", "phishguard/mutating/new.py"),  # benign source, protected target
        "--- /dev/null\n+++ b/phishguard/mutating/backdoor.py\n@@ -0,0 +1 @@\n+x\n",  # new file
        "diff --git a/phishguard/readonly/x.py b/phishguard/mutating/x.py\nrename from phishguard/readonly/x.py\nrename to phishguard/mutating/x.py\n",
        "diff --git a/a.bin b/phishguard/mutating/a.bin\nBinary files a/a.bin and b/phishguard/mutating/a.bin differ\n",
        _diff("/etc/passwd"),
        _diff("../outside.py"),
        _diff("C:/repo/phishguard/readonly/features.py"),
        "just some text, no diff headers\n",
    ],
)
def test_protected_or_unsafe_patches_are_refused(patch, tmp_path):
    with pytest.raises(ProtectedPathError):
        check_patch(patch)
    out = tmp_path / "p.patch"
    with pytest.raises(ProtectedPathError):
        write_patch(patch, out)
    assert not out.exists()  # refused before anything reached disk


def test_readonly_patch_is_allowed():
    assert check_patch(_diff("phishguard/readonly/features.py")) == {"phishguard/readonly/features.py"}


def test_mutating_package_is_on_the_protected_list():
    assert "phishguard/mutating/" in improve.PROTECTED
    for f in (ROOT / "phishguard" / "mutating").glob("*.py"):
        with pytest.raises(ProtectedPathError):
            check_patch(_diff(str(f.relative_to(ROOT))))


def _tree_hash() -> str:
    h = hashlib.sha256()
    for d in ("phishguard", "tests", "redteam", "scripts"):
        for f in sorted((ROOT / d).rglob("*.py")):
            h.update(str(f).encode() + f.read_bytes())
    return h.hexdigest()


@pytest.fixture(scope="module")
def proposal(tmp_path_factory):
    out = tmp_path_factory.mktemp("proposals")
    before = _tree_hash()
    r = improve.run_improve(out, date="20260101")
    return r, out, before


def test_run_writes_only_proposals_and_changes_no_code(proposal):
    r, out, before = proposal
    assert _tree_hash() == before
    assert sorted(p.name for p in out.iterdir()) == ["20260101.md", "20260101.patch", "20260101_regression_draft.py"]
    md = (out / "20260101.md").read_text()
    assert "Nothing here has been applied" in md and "phishguard/mutating/" in md
    assert r["misses"] >= 4 and r["simulation"]["rescued"] >= 1


def test_generated_patch_is_checked_and_applies_cleanly(proposal):
    _, out, _ = proposal
    patch = (out / "20260101.patch").read_text()
    assert check_patch(patch) == {"phishguard/readonly/features.py"}
    r = subprocess.run(
        ["git", "apply", "--check", str(out / "20260101.patch")], cwd=ROOT, capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr  # --check only: nothing is modified


def test_regression_draft_is_valid_python_and_not_collected(proposal):
    _, out, _ = proposal
    compile((out / "20260101_regression_draft.py").read_text(), "draft", "exec")
    assert "tests" not in out.parts[-1]


def test_patch_into_protected_path_is_refused_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setattr(improve, "build_patch", lambda *a, **k: _diff("phishguard/mutating/gateway.py"))
    r = improve.run_improve(tmp_path, date="20260102")
    assert r["patch"].startswith("REFUSED") and not (tmp_path / "20260102.patch").exists()
    assert "REFUSED" in (tmp_path / "20260102.md").read_text()


@pytest.mark.parametrize("bad", ["phishguard", "phishguard/readonly", "tests", "redteam"])
def test_refuses_to_write_inside_code_dirs(bad):
    with pytest.raises(ProtectedPathError):
        improve.run_improve(ROOT / bad / "proposals")


def test_budget_cap_is_hard_and_clamped():
    g = BudgetGuard(price_in=1.0, price_out=5.0, cap_usd=50.0)
    assert g.cap_usd == 2.0  # --budget can only lower the ceiling
    g.reserve(1000, 1000)
    g.charge(390_000, 300_000)  # $0.39 + $1.50
    with pytest.raises(BudgetExceeded):
        g.reserve(200_000, 1000)  # worst case would pass $2


class GreedyLLM:
    def __init__(self):
        self.calls = 0

    def complete(self, *, system, messages, tools, max_tokens):
        from phishguard.llm.base import LLMResponse

        self.calls += 1
        n = len(messages[0]["content"].encode())  # realistic: never more tokens than bytes
        return LLMResponse(text="variant", input_tokens=n, output_tokens=max_tokens)


def test_llm_loop_stops_at_budget(tmp_path):
    llm = GreedyLLM()
    r = improve.run_improve(tmp_path, date="20260103", use_llm=True, price_in=300.0, price_out=1500.0, llm=llm)
    assert 0 < r["spent_usd"] <= 2.0 and llm.calls < 21
    assert "Stopped" in (tmp_path / "20260103.md").read_text()


def test_llm_needs_prices(tmp_path):
    r = improve.run_improve(tmp_path, date="20260104", use_llm=True, llm=GreedyLLM())
    assert r["spent_usd"] == 0.0 and "required to enforce the budget" in (tmp_path / "20260104.md").read_text()


class LyingLLM(GreedyLLM):
    def complete(self, **kw):
        r = super().complete(**kw)
        r.input_tokens = 10_000_000  # bills far more than the upper bound
        return r


def test_overbilling_stops_immediately(tmp_path):
    llm = LyingLLM()
    improve.run_improve(tmp_path, date="20260105", use_llm=True, price_in=0.01, price_out=0.01, llm=llm)
    assert llm.calls == 1 and "Stopped" in (tmp_path / "20260105.md").read_text()
