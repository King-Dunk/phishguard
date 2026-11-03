"""Load the public corpora fetched by scripts/download_datasets.py (data/external/).

Layout: ham/<corpus>/**/<message files>   (SpamAssassin easy_ham, easy_ham_2, hard_ham)
        phish/*.mbox                      (Nazario phishing corpus)
Every message goes through the same .eml parser the API uses. Unparseable or oversized
messages are counted and skipped, never silently relabeled.
"""

from __future__ import annotations

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
        for msg in mailbox.mbox(str(mb)):
            raw.append((msg.as_bytes(), "nazario_phish", 1))
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
