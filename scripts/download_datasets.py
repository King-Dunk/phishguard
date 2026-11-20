"""Download public mail corpora into data/external/ (git-ignored; raw mail is never committed).

    python scripts/download_datasets.py                 # all sources
    python scripts/download_datasets.py --only ham      # SpamAssassin easy_ham + hard_ham
    python scripts/download_datasets.py --only phish    # Nazario phishing corpus
    python scripts/download_datasets.py --only pot      # phishing_pot sample (opt-in, see below)
    python scripts/download_datasets.py --pot-clean     # delete the phishing_pot .eml files, keep the manifest

Sources
- Ham:   Apache SpamAssassin public corpus, https://spamassassin.apache.org/old/publiccorpus/
         (20030228_easy_ham, 20030228_easy_ham_2, 20030228_hard_ham; .tar.bz2)
- Phish: Jose Nazario's phishing corpus, https://monkey.org/~jose/phishing/
         (mbox files; the list is read from the index page so new years are picked up). CC BY 4.0.
- Phish: rf-peixoto's Phishing Pot, https://github.com/rf-peixoto/phishing_pot (honeypot-collected
         .eml with full headers; maintainer https://www.linkedin.com/in/rf-peixoto). CC BY-NC 4.0:
         non-commercial research only, attribution required. Opt-in (--only pot) because the whole
         corpus is ~1.6 GB: a seeded random sample (--pot-sample, default 3000) is fetched from a
         pinned commit, so every machine gets the same files.

Integrity
- Neither project publishes checksums we can pin from here, so verification is trust-on-first-use:
  the SHA-256 of every downloaded file is written to data/external/checksums.json, and later runs
  refuse a file whose hash changed. Pass --expect-sha256 NAME=HEX to pin a hash you obtained
  out of band.
- Phishing Pot needs no trust-on-first-use: every file is checked against the git blob hash that
  GitHub lists for the pinned commit, so a changed or truncated download is refused.
- Archives are extracted with safe_extract(): no absolute paths, no "..", no links or devices,
  bounded member count and total size. Mbox files must parse with the stdlib mailbox module.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import mailbox
import pathlib
import random
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
POT_REPO = "rf-peixoto/phishing_pot"
POT_COMMIT = "78be141545ed9e56eefb857808ac78e83eb81b81"  # pinned 2026-11-20; 12,864 .eml files
POT_TREE = f"https://api.github.com/repos/{POT_REPO}/git/trees/{POT_COMMIT}?recursive=1"
POT_RAW = f"https://raw.githubusercontent.com/{POT_REPO}/{POT_COMMIT}/"
POT_SAMPLE = 3000
POT_SEED = 20261120
POT_MAX_BYTES = 2_000_000  # phishguard.readonly.eml.MAX_RAW_BYTES: larger mail is rejected unparsed anyway


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


def git_blob_sha(data: bytes) -> str:
    """The SHA-1 git stores for a file: sha1(b"blob <len>\\0" + content)."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _get(url: str, limit: int = MAX_DOWNLOAD) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError(f"{url} larger than {limit} bytes")
    return data


def pot_listing() -> list[dict]:
    """Every .eml under email/ at the pinned commit: [{"path", "sha", "size"}], sorted by path."""
    tree = json.loads(_get(POT_TREE, 50_000_000))
    if tree.get("truncated"):
        raise RuntimeError("GitHub returned a truncated tree listing")
    files = [
        {"path": t["path"], "sha": t["sha"], "size": int(t.get("size", 0))}
        for t in tree.get("tree", [])
        if t.get("type") == "blob" and re.fullmatch(r"email/[\w.-]+\.eml", t.get("path", ""))
    ]
    return sorted(files, key=lambda f: f["path"])


def pot_sample(files: list[dict], n: int, seed: int = POT_SEED) -> list[dict]:
    pool = sorted(files, key=lambda f: f["path"])
    return pool if n >= len(pool) else random.Random(seed).sample(pool, n)


def fetch_pot(dest: pathlib.Path, n: int = POT_SAMPLE, seed: int = POT_SEED, workers: int = 8) -> dict:
    """Download a seeded sample of Phishing Pot into dest/pot/ and write dest/pot/manifest.json.

    Files bigger than the parser's limit are listed in the manifest but not downloaded (they would be
    rejected unparsed), so the evaluation can still count them instead of dropping them silently."""
    out_dir = dest / "pot"
    out_dir.mkdir(parents=True, exist_ok=True)
    chosen = pot_sample(pot_listing(), n, seed)
    too_large = [f for f in chosen if f["size"] > POT_MAX_BYTES]
    wanted = [f for f in chosen if f["size"] <= POT_MAX_BYTES]

    def one(f: dict) -> str:
        target = out_dir / pathlib.PurePosixPath(f["path"]).name
        if target.exists() and git_blob_sha(target.read_bytes()) == f["sha"]:
            return "kept"
        data = _get(POT_RAW + f["path"], POT_MAX_BYTES)
        if git_blob_sha(data) != f["sha"]:
            raise ChecksumMismatch(f"{f['path']}: content does not match git blob {f['sha']}")
        target.write_bytes(data)
        target.chmod(0o600)
        return "fetched"

    done: dict[str, int] = {}
    failures: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(one, f): f for f in wanted}
        for fut in concurrent.futures.as_completed(futs):
            try:
                r = fut.result()
                done[r] = done.get(r, 0) + 1
            except (OSError, RuntimeError, ChecksumMismatch) as e:
                failures.append(f"{futs[fut]['path']}: {type(e).__name__}: {e}")
    manifest = {
        "source": f"https://github.com/{POT_REPO}",
        "maintainer": "https://www.linkedin.com/in/rf-peixoto",
        "license": "CC BY-NC 4.0 (non-commercial research only; attribution required)",
        "commit": POT_COMMIT,
        "seed": seed,
        "requested": n,
        "sample": [
            {"path": f["path"], "sha": f["sha"], "size": f["size"]} for f in sorted(chosen, key=lambda f: f["path"])
        ],
        "too_large_not_downloaded": [f["path"] for f in too_large],
        "failures": failures,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=1))
    return {"sampled": len(chosen), "too_large": len(too_large), "failures": len(failures), **done}


def clean_pot(dest: pathlib.Path) -> int:
    """Delete the downloaded Phishing Pot mail; the manifest stays so the same sample can be re-fetched."""
    removed = 0
    for p in (dest / "pot").glob("*.eml"):
        p.unlink()
        removed += 1
    return removed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=["ham", "phish", "pot"])
    ap.add_argument("--pot-sample", type=int, default=POT_SAMPLE, help="Phishing Pot: messages to sample")
    ap.add_argument("--pot-clean", action="store_true", help="delete downloaded Phishing Pot mail, keep manifest")
    ap.add_argument("--dest", default=str(DEST))
    ap.add_argument("--expect-sha256", action="append", default=[], metavar="NAME=HEX")
    a = ap.parse_args(argv)
    dest = pathlib.Path(a.dest)
    if a.pot_clean:
        print(f"removed {clean_pot(dest)} Phishing Pot files; manifest kept in {dest / 'pot'}")
        return 0
    if a.only == "pot":
        r = fetch_pot(dest, a.pot_sample)
        print(f"Phishing Pot @ {POT_COMMIT[:12]}: {r}")
        return 1 if r["failures"] else 0
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
