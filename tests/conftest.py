import os
import tempfile

# Set before any agentshield import, whichever test file pytest collects first.
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{tempfile.mkdtemp()}/test.db"
os.environ["APPROVAL_TIMEOUT_S"] = "3"

import pytest


@pytest.fixture(autouse=True)
def isolate_from_dotenv(monkeypatch):
    """litellm loads .env on import; keep tests deterministic and offline whatever it contains."""
    from agentshield import detect, llm

    monkeypatch.setattr(detect, "CLASSIFIER", None)
    monkeypatch.setattr(detect, "JUDGE", None)
    monkeypatch.setattr(llm, "EMBED_MODEL", None)
