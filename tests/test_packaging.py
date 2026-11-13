"""The API image installs exactly requirements.txt (so new dependencies can't be forgotten) and runs non-root."""

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_dockerfile_installs_requirements_and_drops_root():
    lines = [ln.strip() for ln in (ROOT / "Dockerfile").read_text().splitlines()]
    assert "COPY requirements.txt ." in lines
    assert "RUN pip install --no-cache-dir -r requirements.txt" in lines
    pip = [ln for ln in lines if ln.startswith("RUN pip")]
    assert len(pip) == 1  # no second, hand-written package list
    user = [ln for ln in lines if ln.startswith("USER ")]
    assert user and user[-1] != "USER root"


def test_requirements_cover_connector_dependencies():
    req = (ROOT / "requirements.txt").read_text().lower()
    for dep in ("httpx", "pyjwt[crypto]", "cryptography", "webauthn", "argon2-cffi"):
        assert dep in req, dep
