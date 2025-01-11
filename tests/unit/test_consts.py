import os

import pytest


def test_default_values():
    """Test default values when environment variables are not set."""
    # Clear relevant environment variables
    for var in ["PROXY_SERVER_ADDRESS", "PROXY_SERVER_PORT",
                "PROXY_CLIENT_ADDRESS", "PROXY_CLIENT_PORT",
                "PROXY_CLIENT_SOCKS5_PORT"]:
        if var in os.environ:
            del os.environ[var]

    # Reimport to get defaults
    from importlib import reload
    import dns_tunnel.consts
    reload(dns_tunnel.consts)

    assert dns_tunnel.consts.PROXY_SERVER_ADDRESS == "0.0.0.0"
    assert dns_tunnel.consts.PROXY_SERVER_PORT == 54
    assert dns_tunnel.consts.PROXY_CLIENT_ADDRESS == "0.0.0.0"
    assert dns_tunnel.consts.PROXY_CLIENT_PORT == 52
    assert dns_tunnel.consts.PROXY_CLIENT_SOCKS5_PORT == 1080


def test_environment_override():
    """Test that environment variables override defaults."""
    os.environ["PROXY_SERVER_ADDRESS"] = "127.0.0.1"
    os.environ["PROXY_SERVER_PORT"] = "8053"
    os.environ["PROXY_CLIENT_ADDRESS"] = "127.0.0.1"
    os.environ["PROXY_CLIENT_PORT"] = "8054"
    os.environ["PROXY_CLIENT_SOCKS5_PORT"] = "8055"

    # Reimport to get new values
    from importlib import reload
    import dns_tunnel.consts
    reload(dns_tunnel.consts)

    assert dns_tunnel.consts.PROXY_SERVER_ADDRESS == "127.0.0.1"
    assert dns_tunnel.consts.PROXY_SERVER_PORT == 8053
    assert dns_tunnel.consts.PROXY_CLIENT_ADDRESS == "127.0.0.1"
    assert dns_tunnel.consts.PROXY_CLIENT_PORT == 8054
    assert dns_tunnel.consts.PROXY_CLIENT_SOCKS5_PORT == 8055


def test_invalid_port_numbers():
    """Test handling of invalid port numbers in environment variables."""
    os.environ["PROXY_SERVER_PORT"] = "invalid"

    with pytest.raises(ValueError):
        from importlib import reload
        import dns_tunnel.consts
        reload(dns_tunnel.consts)
