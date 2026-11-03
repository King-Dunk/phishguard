import socket
import subprocess
import sys

from phishguard.dataset.evaluate import evaluate
from phishguard.dataset.generator import CATEGORIES, generate_dataset


def test_generator_deterministic_and_balanced():
    a = generate_dataset(30, seed=7)
    b = generate_dataset(30, seed=7)
    assert [x.to_dict() for x in a] == [x.to_dict() for x in b]
    assert [x.to_dict() for x in a] != [x.to_dict() for x in generate_dataset(30, seed=8)]
    assert {c: sum(x.category == c for x in a) for c in CATEGORIES} == {c: 30 for c in CATEGORIES}
    assert {x.label for x in a if x.category == "bec"} == {1}
    assert {x.label for x in a if x.category == "collaboration"} == {0}
    assert {x.label for x in a if x.category == "payment_chasing"} == {0, 1}
    e = a[0].email
    assert e.timestamp and e.sender_reputation is not None and e.sender_domain_age_days is not None


def test_eval_meets_floor_and_makes_no_network_calls(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    m = evaluate(60, seed=42)
    assert m["accuracy"] >= 0.9 and m["recall"] >= 0.85 and m["precision"] >= 0.9


def test_eval_script_never_imports_anthropic_sdk():
    r = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from phishguard.dataset.evaluate import evaluate; evaluate(10); "
            "sys.exit(1 if 'anthropic' in sys.modules else 0)",
        ],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
