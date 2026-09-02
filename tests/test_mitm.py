"""Tests for the MITM module."""

import asyncio

import pytest

from backrooms.modules.mitm.core import TcpForwarder, classify


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ("POST /login password=secret HTTP/1.1", "password"),
        ("username=admin&passwd=hunter2", "passwd"),
        ("GET /index.html HTTP/1.1", None),
        ("", None),
    ],
)
def test_classify(payload: str, expected: str | None) -> None:
    assert classify(payload) == expected


@pytest.mark.asyncio
async def test_forwarder_relays_and_captures() -> None:
    """A client to the forwarder should reach the backend and creds should be seen."""

    async def _echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while data := await reader.read(1024):
            writer.write(data)
            await writer.drain()

    backend = await asyncio.start_server(_echo, "127.0.0.1", 0)
    backend_port = backend.sockets[0].getsockname()[1]

    # reserve a free local listen port for the forwarder
    probe = await asyncio.start_server(lambda *_: None, "127.0.0.1", 0)
    fwd_port = probe.sockets[0].getsockname()[1]
    probe.close()
    await probe.wait_closed()

    forwarder = TcpForwarder()
    fwd_task = asyncio.create_task(
        forwarder.run("127.0.0.1", fwd_port, "127.0.0.1", backend_port)
    )
    await asyncio.sleep(0.1)

    reader, writer = await asyncio.open_connection("127.0.0.1", fwd_port)
    writer.write(b"password=swordfish\r\n")
    await writer.drain()
    reply = await asyncio.wait_for(reader.read(1024), timeout=2)
    assert b"password=swordfish" in reply
    writer.close()

    fwd_task.cancel()
    try:
        await fwd_task
    except asyncio.CancelledError:
        pass
    backend.close()

    assert any(h.marker == "password" for h in forwarder.hits)


def test_forwarder_no_hits_without_creds() -> None:
    fwd = TcpForwarder()
    fwd._capture("1.2.3.4:1", "c->s", b"GET /x HTTP/1.1\r\n")
    assert fwd.hits == []
