"""Offline tests for the evaluation sets: customization tiers, Phishing Pot sampling/loading, per-source breakdown."""

import email
import email.policy
import json
import mailbox
import pathlib
import sys

import pytest

from phishguard.dataset.external import ExternalDataMissing, load_external
from phishguard.dataset.metrics import wilson
from phishguard.dataset.pot import load_pot
from phishguard.dataset.tiers import BRANDS, TIERS, generate_tiers, write_tiers
from phishguard.readonly import parse_eml

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT / "scripts"))
import download_datasets as dl  # noqa: E402
import eval_breakdown  # noqa: E402

GOOD = (FIX / "phish_bec_auth_fail.eml").read_bytes()


# ---------------------------------------------------------------------------- metrics
def test_wilson_interval_known_values():
    lo, hi = wilson(0, 10)
    assert lo == 0.0 and abs(hi - 0.2775) < 1e-3
    lo, hi = wilson(10, 10)
    assert hi == 1.0 and abs(lo - 0.7225) < 1e-3
    lo, hi = wilson(222, 481)
    assert lo < 222 / 481 < hi and abs(lo - 0.4175) < 1e-3
    assert wilson(0, 0) == (0.0, 1.0)


# ---------------------------------------------------------------------------- tiers
@pytest.fixture(scope="module")
def tiers():
    return generate_tiers(100, 2026)  # the documented set; red-flag averages are compared on all of it


def test_tiers_are_deterministic_and_balanced(tiers):
    again = generate_tiers(100, 2026)
    assert [t.raw for t in tiers] == [t.raw for t in again]
    assert generate_tiers(5, 7)[0].raw != tiers[0].raw
    for t in TIERS:
        assert sum(1 for i in tiers if i.tier == t and i.label == 1) == 100
        assert sum(1 for i in tiers if i.tier == t and i.label == 0) == 100


def test_every_tier_message_goes_through_the_real_parser(tiers):
    for it in tiers:
        parsed = parse_eml(it.raw)
        assert parsed.subject and parsed.sender_email
        assert parsed.spf in ("pass", "fail", "softfail", "none") or parsed.spf


def test_red_flags_fall_as_customization_rises(tiers):
    flags = {t: [len(i.cues) for i in tiers if i.tier == t and i.label] for t in TIERS}
    avg = {t: sum(v) / len(v) for t, v in flags.items()}
    assert avg["T1"] > avg["T2"] > avg["T3"] > avg["T4"]
    assert max(flags["T4"]) <= 1  # tailored mail carries at most one red flag by design
    assert all(not i.cues for i in tiers if not i.label)  # controls have no planted red flags


def test_tier_infrastructure_never_labels_a_real_brand_domain_malicious(tiers):
    brand_domains = {d for _, d, _ in BRANDS.values()}
    for it in tiers:
        m = email.message_from_bytes(it.raw, policy=email.policy.default)
        dom = str(m["From"]).rsplit("@", 1)[-1].rstrip(">").lower()
        if it.tier == "T2" and it.label:
            assert not any(dom == b or dom.endswith("." + b) for b in brand_domains)
        if it.tier == "T2" and not it.label:
            assert any(dom == b or dom.endswith("." + b) for b in brand_domains)


def test_write_tiers_writes_files_and_manifest(tmp_path):
    n = write_tiers(tmp_path, 3, 2026)
    rows = [json.loads(x) for x in (tmp_path / "manifest.jsonl").read_text().splitlines()]
    assert n == len(rows) == 24
    assert all((tmp_path / r["file"]).is_file() for r in rows)
    assert {r["tier"] for r in rows} == set(TIERS)


# ---------------------------------------------------------------------------- external loader keeps the source
def test_external_loader_records_source_file(tmp_path):
    root = tmp_path / "ext"
    (root / "ham" / "20030228_easy_ham").mkdir(parents=True)
    (root / "ham" / "20030228_easy_ham" / "0001.x").write_bytes((FIX / "benign_internal_plain.eml").read_bytes())
    (root / "phish").mkdir()
    mb = mailbox.mbox(str(root / "phish" / "phishing-2025.mbox"))
    mb.add(GOOD)
    mb.flush()
    mb.close()
    items = load_external(root).items
    assert {(i.category, i.source) for i in items} == {
        ("easy_ham", "20030228_easy_ham"),
        ("nazario_phish", "phishing-2025"),
    }


# ---------------------------------------------------------------------------- phishing pot
def _blob(path: str, data: bytes) -> dict:
    return {"path": path, "type": "blob", "sha": dl.git_blob_sha(data), "size": len(data)}


def test_git_blob_sha_matches_git():
    assert dl.git_blob_sha(b"hello phishing\n") == "62abd1c0cd0e5c488269bc2a74254786af2a9f8a"


def test_pot_sample_is_seeded_and_bounded():
    files = [{"path": f"email/sample-{i}.eml", "sha": "x", "size": 1} for i in range(50)]
    a, b = dl.pot_sample(files, 10, 1), dl.pot_sample(list(reversed(files)), 10, 1)
    assert a == b and len(a) == 10
    assert dl.pot_sample(files, 500, 1) == sorted(files, key=lambda f: f["path"])


def test_fetch_pot_verifies_hashes_and_skips_oversized(tmp_path, monkeypatch):
    big = b"X" * (dl.POT_MAX_BYTES + 1)
    tree = {
        "truncated": False,
        "tree": [
            _blob("email/sample-1.eml", GOOD),
            _blob("email/sample-2.eml", GOOD + b"\n"),  # served tampered below
            {**_blob("email/sample-3.eml", b""), "size": len(big)},
            _blob("README.md", b"not mail"),
        ],
    }
    fetched = []

    def fake_get(url, limit=0):
        if url == dl.POT_TREE:
            return json.dumps(tree).encode()
        fetched.append(url.rsplit("/", 1)[-1])
        return GOOD  # sample-2's listed hash is for different bytes -> mismatch

    monkeypatch.setattr(dl, "_get", fake_get)
    r = dl.fetch_pot(tmp_path, n=10)
    assert r["sampled"] == 3 and r["too_large"] == 1 and r["failures"] == 1 and r["fetched"] == 1
    assert "sample-3.eml" not in fetched  # never downloaded: the parser would reject it anyway
    assert (tmp_path / "pot" / "sample-1.eml").is_file() and not (tmp_path / "pot" / "sample-2.eml").exists()
    manifest = json.loads((tmp_path / "pot" / "manifest.json").read_text())
    assert manifest["commit"] == dl.POT_COMMIT and "CC BY-NC" in manifest["license"]

    ext, _ = load_pot(tmp_path)
    assert len(ext.items) == 1 and ext.items[0].source == "phishing_pot"
    assert ext.skipped == {"EmlTooLarge": 1, "not_downloaded": 1}

    assert dl.clean_pot(tmp_path) == 1
    assert (tmp_path / "pot" / "manifest.json").is_file()
    with pytest.raises(ExternalDataMissing, match="cleaned"):
        load_pot(tmp_path)


def test_load_pot_without_manifest_is_explicit(tmp_path):
    with pytest.raises(ExternalDataMissing, match="--only pot"):
        load_pot(tmp_path)


# ---------------------------------------------------------------------------- report script
def test_eval_breakdown_tiers_report(tmp_path):
    out = tmp_path / "report.md"
    assert (
        eval_breakdown.main(
            ["--parts", "tiers", "--tiers-n", "4", "--out", str(out), "--json", str(tmp_path / "r.json")]
        )
        == 0
    )
    text = out.read_text()
    assert "Customization tiers" in text and "| **T4**" in text and "without config" in text
    data = json.loads((tmp_path / "r.json").read_text())
    assert set(data["tiers"]["tiers"]) == set(TIERS)


def test_eval_breakdown_reports_missing_data_instead_of_failing(tmp_path, monkeypatch):
    monkeypatch.setattr(eval_breakdown, "load_pot", lambda: (_ for _ in ()).throw(ExternalDataMissing("no pot")))
    out = tmp_path / "report.md"
    assert eval_breakdown.main(["--parts", "pot", "--out", str(out)]) == 0
    assert "Not run: no pot" in out.read_text()
