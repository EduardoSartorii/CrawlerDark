"""Unit tests for OPSEC transport HTTP operations."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from threat_hunting.infrastructure.opsec.transport import (
    OpsecProfile,
    OpsecProfileRegistry,
    OpsecTransport,
    RetryPolicy,
)


@pytest.mark.asyncio
async def test_opsec_transport_get():
    profile = OpsecProfile(name="test")
    transport = OpsecTransport(profile)

    mock_response = MagicMock()
    mock_response.status_code = 200

    with patch.object(transport, "_get_client") as mock_client:
        client = AsyncMock()
        client.request = AsyncMock(return_value=mock_response)
        mock_client.return_value = client

        response = await transport.get("https://example.com")
        assert response.status_code == 200
        await transport.close()


@pytest.mark.asyncio
async def test_opsec_transport_post():
    transport = OpsecTransport(OpsecProfile(name="test"))
    mock_response = MagicMock()
    mock_response.status_code = 201

    with patch.object(transport, "_get_client") as mock_client:
        client = AsyncMock()
        client.request = AsyncMock(return_value=mock_response)
        mock_client.return_value = client

        response = await transport.post("https://example.com", json={"key": "value"})
        assert response.status_code == 201
        await transport.close()


def test_opsec_profile_registry():
    registry = OpsecProfileRegistry()
    registry.register(OpsecProfile(name="darkweb", socks5_proxy="socks5://127.0.0.1:9050"))
    profile = registry.get("darkweb")
    assert profile.socks5_proxy == "socks5://127.0.0.1:9050"
    assert "default" in registry.list_profiles()


def test_build_proxies():
    transport = OpsecTransport(OpsecProfile(
        name="test",
        http_proxy="http://proxy:8080",
        https_proxy="https://proxy:8080",
        socks5_proxy="socks5://127.0.0.1:9050",
    ))
    proxies = transport._build_proxies()
    assert proxies is not None
    assert "http://" in proxies
