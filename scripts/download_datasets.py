"""Download public mail corpora into data/external/ (git-ignored; raw mail is never committed).

    python scripts/download_datasets.py                 # all sources
    python scripts/download_datasets.py --only ham      # SpamAssassin easy_ham + hard_ham
    python scripts/download_datasets.py --only phish    # Nazario phishing corpus

Sources
- Ham:   Apache SpamAssassin public corpus, https://spamassassin.apache.org/old/publiccorpus/
         (20030228_easy_ham, 20030228_easy_ham_2, 20030228_hard_ham; .tar.bz2)
- Phish: Jose Nazario's phishing corpus, https://monkey.org/~jose/phishing/
         (mbox files; the list is read from the index page so new years are picked up)

Integrity
- Neither project publishes checksums we can pin from here, so verification is trust-on-first-use:
  the SHA-256 of every downloaded file is written to data/external/checksums.json, and later runs
  refuse a file whose hash changed. Pass --expect-sha256 NAME=HEX to pin a hash you obtained
  out of band.
- Archives are extracted with safe_extract(): no absolute paths, no "..", no links or devices,
  bounded member count and total size. Mbox files must parse with the stdlib mailbox module.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mailbox
import pathlib
import re
import shutil
import sys
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEST = ROOT / "data" / "external"
SA_BASE = "https://spamassassin.apache.org/old/publiccorpus/"
SA_FILES = ["20030228_easy_ham.tar.bz2", "20030228_easy_ham_2.tar.bz2", "20030228_hard_ham.tar.bz2"]
NAZARIO_INDEX = "https://monkey.org/~jose/phishing/"
NAZARIO_FALLBACK = ["phishing0.mbox", "phishing1.mbox", "phishing2.mbox", "phishing3.mbox"]
MAX_MEMBERS = 50_000
MAX_TOTAL_BYTES = 2_000_000_000
MAX_DOWNLOAD = 500_000_000
UA = "phishguard-dataset-fetcher/1.0"


class UnsafeArchive(RuntimeError):
    pass


class ChecksumMismatch(RuntimeError):
    pass


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_extract(archive: pathlib.Path, dest: pathlib.Path) -> int:
    """Extract a tar archive, refusing anything that could write outside `dest`."""
    dest = dest.resolve()
    with tarfile.open(archive) as tf:
        members = tf.getmembers()
        if len(members) > MAX_MEMBERS:
            raise UnsafeArchive(f"{len(members)} members")
        total = 0
        for m in members:
            name = m.name.replace("\\", "/")
            target = (dest / name).resolve()
            if name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts or re.match(r"^[a-zA-Z]:", name):
                raise UnsafeArchive(f"unsafe path {m.name!r}")
            if dest != target and dest not in target.parents:
                raise UnsafeArchive(f"escapes destination: {m.name!r}")
            if not (m.isfile() or m.isdir()):
                raise UnsafeArchive(f"links/devices not allowed: {m.name!r}")
            total += m.size
            if total > MAX_TOTAL_BYTES:
                raise UnsafeArchive("archive expands beyond size limit")
        dest.mkdir(parents=True, exist_ok=True)
        for m in members:
            if m.isdir():
                (dest / m.name).mkdir(parents=True, exist_ok=True)
                continue
            out = dest / m.name
            out.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with src, open(out, "wb") as f:
                shutil.copyfileobj(src, f)
    return len(members)


def check_mbox(path: pathlib.Path) -> int:
    n = sum(1 for _ in mailbox.mbox(str(path)))
    if n == 0:
        raise ValueError(f"{path.name}: no messages parsed")
    return n


def _fetch(url: str, out: pathlib.Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r, open(out, "wb") as f:
        size = 0
        while chunk := r.read(1 << 20):
            size += len(chunk)
            if size > MAX_DOWNLOAD:
                raise RuntimeError(f"{url} larger than {MAX_DOWNLOAD} bytes")
            f.write(chunk)


def _verify(path: pathlib.Path, lock: dict[str, str], pinned: dict[str, str]) -> str:
    digest = sha256(path)
    want = pinned.get(path.name) or lock.get(path.name)
    if want and want != digest:
        raise ChecksumMismatch(f"{path.name}: sha256 {digest} != expected {want}")
    lock[path.name] = digest
    return digest


def nazario_files() -> list[str]:
    try:
        req = urllib.request.Request(NAZARIO_INDEX, headers={"User-Agent": UA})
        html = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")
        names = sorted(set(re.findall(r'href="((?:private-)?phishing[\w.-]*)"', html)))
        return [n for n in names if not n.endswith((".html", "/"))] or NAZARIO_FALLBACK
    except OSError:
        return NAZARIO_FALLBACK


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=["ham", "phish"])
    ap.add_argument("--dest", default=str(DEST))
    ap.add_argument("--expect-sha256", action="append", default=[], metavar="NAME=HEX")
    a = ap.parse_args(argv)
    dest = pathlib.Path(a.dest)
    (dest / "downloads").mkdir(parents=True, exist_ok=True)
    lock_path = dest / "checksums.json"
    lock = json.loads(lock_path.read_text()) if lock_path.exists() else {}
    pinned = dict(x.split("=", 1) for x in a.expect_sha256)
    failures = 0

    jobs: list[tuple[str, str, str]] = []
    if a.only in (None, "ham"):
        jobs += [("ham", SA_BASE + f, f) for f in SA_FILES]
    if a.only in (None, "phish"):
        jobs += [("phish", NAZARIO_INDEX + f, f) for f in nazario_files()]

    for kind, url, name in jobs:
        out = dest / "downloads" / name
        try:
            if not out.exists():
                print(f"fetch {url}")
                _fetch(url, out)
            digest = _verify(out, lock, pinned)
            if kind == "ham":
                n = safe_extract(out, dest / "ham" / name.split(".")[0])
            else:
                (dest / "phish").mkdir(exist_ok=True)
                target = dest / "phish" / (name if name.endswith(".mbox") else name + ".mbox")
                shutil.copyfile(out, target)
                n = check_mbox(target)
            print(f"ok   {name}: {n} items, sha256 {digest[:16]}...")
        except (OSError, UnsafeArchive, ChecksumMismatch, ValueError, tarfile.TarError) as e:
            failures += 1
            print(f"FAIL {name}: {type(e).__name__}: {e}", file=sys.stderr)
    lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True))
    print(f"done: {len(jobs) - failures}/{len(jobs)} sources ready in {dest}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
