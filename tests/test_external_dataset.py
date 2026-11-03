"""Offline tests for the public-corpus pipeline: download script (network mocked), loader, evaluation."""

import io
import mailbox
import pathlib
import sys
import tarfile

import pytest

from phishguard.dataset.evaluate import evaluate, main
from phishguard.dataset.external import ExternalDataMissing, load_external
from redteam.builders import deep_mime

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT / "scripts"))
import download_datasets as dl  # noqa: E402


def _tar(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:bz2") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _mbox(path: pathlib.Path, raws: list[bytes]) -> None:
    mb = mailbox.mbox(str(path))
    for r in raws:
        mb.add(r)
    mb.flush()
    mb.close()


@pytest.fixture
def corpus(tmp_path):
    root = tmp_path / "external"
    ham = [p for p in sorted(FIX.glob("benign_*.eml"))]
    phish = [p.read_bytes() for p in sorted(FIX.glob("phish_*.eml"))]
    for i, p in enumerate(ham):
        sub = "easy_ham" if i < 2 else "hard_ham"
        (root / "ham" / sub).mkdir(parents=True, exist_ok=True)
        (root / "ham" / sub / f"{i:04d}.{p.stem}").write_bytes(p.read_bytes())
    (root / "ham" / "easy_ham" / "cmds").write_text("not a mail")
    (root / "phish").mkdir(parents=True)
    _mbox(root / "phish" / "phishing0.mbox", phish + [deep_mime(50).encode()])
    return root


def test_loader_labels_and_skips(corpus):
    s = load_external(corpus)
    assert sorted(s.categories) == ["easy_ham", "hard_ham", "nazario_phish"]
    assert sum(i.label for i in s.items) == 7 and sum(1 - i.label for i in s.items) == 3
    assert s.skipped == {"EmlTooComplex": 1}  # counted, not dropped silently
    assert len(load_external(corpus, limit_per_class=2).items) == 4


def test_missing_data_is_explicit(tmp_path):
    with pytest.raises(ExternalDataMissing, match="download_datasets"):
        load_external(tmp_path)
    with pytest.raises(SystemExit) as e:
        main(["--dataset", "external", "--data-dir", str(tmp_path)])
    assert e.value.code == 2


def test_evaluate_external_and_compare(corpus, capsys):
    m = evaluate(dataset="external", data_dir=str(corpus))
    assert m["total"] == 10 and m["dataset"] == "external"
    assert set(m["confusion"]) == {"tp", "fp", "tn", "fn"} and m["f1"] is not None
    main(["--dataset", "both", "--data-dir", str(corpus), "--n", "5"])
    out = capsys.readouterr().out
    assert (
        "| synthetic | rules |" in out
        and "| external | rules |" in out
        and "| external | rules | nazario_phish |" in out
    )


def test_download_pipeline_offline(tmp_path, monkeypatch):
    ham_tar = _tar({"easy_ham/0001.x": (FIX / "benign_internal_plain.eml").read_bytes()})
    mbox_path = tmp_path / "src.mbox"
    _mbox(mbox_path, [(FIX / "phish_bec_auth_fail.eml").read_bytes()])

    def fake_fetch(url, out):
        out.write_bytes(mbox_path.read_bytes() if url.endswith(".mbox") else ham_tar)

    monkeypatch.setattr(dl, "_fetch", fake_fetch)
    monkeypatch.setattr(dl, "nazario_files", lambda: ["phishing0.mbox"])
    dest = tmp_path / "ext"
    assert dl.main(["--dest", str(dest)]) == 0
    assert (dest / "ham" / "20030228_easy_ham" / "easy_ham" / "0001.x").exists()
    assert (dest / "phish" / "phishing0.mbox").exists() and (dest / "checksums.json").exists()
    assert len(load_external(dest).items) == 4  # 3 ham archives (same fake content) + 1 phish
    # trust-on-first-use: a changed file is refused on the next run
    (dest / "downloads" / "phishing0.mbox").write_bytes(b"From x\ntampered\n")
    assert dl.main(["--dest", str(dest), "--only", "phish"]) == 1


def test_pinned_checksum_mismatch(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    with pytest.raises(dl.ChecksumMismatch):
        dl._verify(f, {}, {"a.bin": "0" * 64})


@pytest.mark.parametrize("bad", ["../evil", "/abs/evil", "a/../../evil", "C:/win/evil", "..\\evil"])
def test_safe_extract_refuses_traversal(tmp_path, bad):
    arc = tmp_path / "x.tar.bz2"
    arc.write_bytes(_tar({"ok": b"1", bad: b"2"}))
    with pytest.raises(dl.UnsafeArchive):
        dl.safe_extract(arc, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_raw_mail_never_committed():
    assert "data/external/" in (ROOT / ".gitignore").read_text()
