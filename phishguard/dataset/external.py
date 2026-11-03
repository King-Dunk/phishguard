"""Load the public corpora fetched by scripts/download_datasets.py (data/external/).

Layout: ham/<corpus>/**/<message files>   (SpamAssassin easy_ham, easy_ham_2, hard_ham)
        phish/*.mbox                      (Nazario phishing corpus)
Every message goes through the same .eml parser the API uses. Unparseable or oversized
messages are counted and skipped, never silently relabeled.
"""

from __future__ import annotations

import functools
import hashlib
import mailbox
import pathlib
import random
from dataclasses import dataclass, field

from ..readonly import EmlRejected, parse_eml
from .generator import LabeledEmail

DEFAULT_DIR = pathlib.Path(__file__).resolve().parents[2] / "data" / "external"


class ExternalDataMissing(FileNotFoundError):
    pass


@dataclass
class ExternalSet:
    items: list[LabeledEmail]
    skipped: dict[str, int] = field(default_factory=dict)

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(sorted({i.category for i in self.items}))


def _ham_category(path: pathlib.Path, ham_root: pathlib.Path) -> str:
    top = path.relative_to(ham_root).parts[0]
    return "hard_ham" if "hard" in top else "easy_ham"


def load_external(data_dir: str | pathlib.Path | None = None, limit_per_class: int | None = None, seed: int = 42):
    root = pathlib.Path(data_dir or DEFAULT_DIR)
    ham_root, phish_root = root / "ham", root / "phish"
    if not ham_root.is_dir() or not phish_root.is_dir():
        raise ExternalDataMissing(f"{root} has no ham/ and phish/; run: python scripts/download_datasets.py")
    raw: list[tuple[bytes, str, int]] = []
    for p in sorted(ham_root.rglob("*")):
        if p.is_file() and not p.name.startswith(("cmds", ".")):
            raw.append((p.read_bytes(), _ham_category(p, ham_root), 0))
    for mb in sorted(phish_root.glob("*.mbox")):
        # Use the raw stored bytes: re-serialising with as_bytes() crashes on
        # real-world messages carrying non-ASCII in headers or MIME parts.
        box = mailbox.mbox(str(mb), create=False)
        try:
            for key in box.iterkeys():
                raw.append((box.get_bytes(key), "nazario_phish", 1))
        finally:
            box.close()
    rng = random.Random(seed)
    if limit_per_class:
        by_label: dict[int, list] = {0: [], 1: []}
        for r in raw:
            by_label[r[2]].append(r)
        raw = []
        for lst in by_label.values():
            rng.shuffle(lst)
            raw += lst[:limit_per_class]
    out = ExternalSet([])
    for i, (data, cat, label) in enumerate(raw):
        try:
            email = parse_eml(data)
        except (EmlRejected, ValueError) as e:
            out.skipped[type(e).__name__] = out.skipped.get(type(e).__name__, 0) + 1
            continue
        email = email.model_copy(update={"id": f"{cat}-{i}"})
        out.items.append(LabeledEmail(email, cat, label))
    if not out.items:
        raise ExternalDataMissing(f"no messages parsed under {root}")
    return out


SPLIT_SEED = 20261103
DEV_FRACTION = 0.70


def split_of(email, seed: int = SPLIT_SEED, dev_fraction: float = DEV_FRACTION) -> str:
    """'dev' or 'test', from a salted hash of the message content (not its position in the corpus).

    Hashing content means the same message lands in the same split on every machine, whatever
    the file order or --limit, and exact duplicates (common in phishing corpora) can never sit
    on both sides, which would leak test answers into calibration.
    """
    key = f"{seed}|{email.sender_email}|{email.subject}|{email.body[:4000]}".encode("utf-8", "replace")
    bucket = int.from_bytes(hashlib.sha256(key).digest()[:8], "big") / 2**64
    return "dev" if bucket < dev_fraction else "test"


def split_items(items: list[LabeledEmail], split: str, seed: int = SPLIT_SEED) -> list[LabeledEmail]:
    if split not in ("dev", "test"):
        raise ValueError("split must be 'dev' or 'test'")
    return [it for it in items if split_of(it.email, seed) == split]


@functools.lru_cache(maxsize=4)
def load_external_cached(data_dir: str | None, limit_per_class: int | None, seed: int) -> ExternalSet:
    return load_external(data_dir, limit_per_class, seed)
