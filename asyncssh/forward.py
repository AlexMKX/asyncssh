# Copyright (c) 2013-2025 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""SSH port forwarding handlers"""

import asyncio
import socket
from types import TracebackType
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Optional
from typing import Protocol, Type, cast, runtime_checkable
from typing_extensions import Self

from .misc import ChannelOpenError, SockAddr


if TYPE_CHECKING:
    # pylint: disable=cyclic-import
    from .connection import SSHConnection


SSHForwarderCoro = Callable[..., Awaitable]


@runtime_checkable
class ForwardTracker(Protocol):
    """Optional hooks for observing local-forward connection lifecycle.

    Each method is called from within the asyncio loop. Implementations
    MUST NOT block (no I/O, no sleep). All hooks are best-effort -
    asyncssh swallows any exception they raise (logged at debug level).

    Pass an instance to :meth:`SSHClientConnection.forward_local_port`
    to observe per-connection events on the local listener.
    """

    def connection_made(self, orig_host: str, orig_port: int) -> None:
        """A new client TCP connection was accepted on the local listener."""

    def connection_lost(self, orig_host: str, orig_port: int,
                        exc: Optional[Exception]) -> None:
        """A previously-accepted connection has closed (clean exc=None
           or with an error)."""


class SSHForwarder(asyncio.BaseProtocol):
    """SSH port forwarding connection handler"""

    def __init__(self, peer: Optional['SSHForwarder'] = None,
                 extra: Optional[Dict[str, Any]] = None):
        self._peer = peer
        self._transport: Optional[asyncio.Transport] = None
        self._inpbuf = b''
        self._eof_received = False

        if peer:
            peer.set_peer(self)

        if extra is None:
            extra = {}

        self._extra = extra

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, _exc_type: Optional[Type[BaseException]],
                        _exc_value: Optional[BaseException],
                        _traceback: Optional[TracebackType]) -> bool:
        self.close()
        return False

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        """Get additional information about the forwarder

           This method returns extra information about the forwarder.
           Currently, the only information available is the value
           ``interface`` for TUN/TAP forwarders, returning the name of the
           local TUN/TAP network interface created for this forwarder.

        """

        return self._extra.get(name, default)

    def set_peer(self, peer: 'SSHForwarder') -> None:
        """Set the peer forwarder to exchange data with"""

        self._peer = peer

    def write(self, data: bytes) -> None:
        """Write data to the transport"""

        if not self._transport:
            return # pragma: no cover

        try:
            self._transport.write(data)
        except OSError: # pragma: no cover
            pass

    def write_eof(self) -> None:
        """Write end of file to the transport"""

        if not self._transport:
            return # pragma: no cover

        try:
            self._transport.write_eof()
        except OSError: # pragma: no cover
            pass

    def was_eof_received(self) -> bool:
        """Return whether end of file has been received or not"""

        return self._eof_received

    def pause_reading(self) -> None:
        """Pause reading from the transport"""

        assert self._transport is not None
        self._transport.pause_reading()

    def resume_reading(self) -> None:
        """Resume reading on the transport"""

        assert self._transport is not None
        self._transport.resume_reading()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a newly opened connection"""

        self._transport = cast(Optional['asyncio.Transport'], transport)

        sock = cast(socket.socket, transport.get_extra_info('socket'))

        if sock and sock.family in {socket.AF_INET, socket.AF_INET6}:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Handle an incoming connection close"""

        # pylint: disable=unused-argument

        self.close()

    def session_started(self) -> None:
        """Handle session start"""

    def data_received(self, data: bytes,
                      datatype: Optional[int] = None) -> None:
        """Handle incoming data from the transport"""

        # pylint: disable=unused-argument

        if self._peer:
            self._peer.write(data)
        else:
            self._inpbuf += data

    def eof_received(self) -> bool:
        """Handle an incoming end of file from the transport"""

        self._eof_received = True

        if self._peer:
            self._peer.write_eof()

            return not self._peer.was_eof_received()
        else:
            return True

    def pause_writing(self) -> None:
        """Pause writing by asking peer to pause reading"""

        if self._peer: # pragma: no branch
            self._peer.pause_reading()

    def resume_writing(self) -> None:
        """Resume writing by asking peer to resume reading"""

        if self._peer: # pragma: no branch
            self._peer.resume_reading()

    def close(self) -> None:
        """Close this port forwarder"""

        if self._transport:
            self._transport.close()
            self._transport = None

        if self._peer:
            peer = self._peer
            self._peer = None
            peer.close()


class SSHLocalForwarder(SSHForwarder):
    """Local forwarding connection handler"""

    def __init__(self, conn: 'SSHConnection', coro: SSHForwarderCoro):
        super().__init__()
        self._conn = conn
        self._coro = coro

    async def _forward(self, *args: object) -> None:
        """Begin local forwarding"""

        def session_factory() -> SSHForwarder:
            """Return an SSH forwarder"""

            return SSHForwarder(self)

        try:
            await self._coro(session_factory, *args)
        except ChannelOpenError as exc:
            self.connection_lost(exc)
            return

        assert self._peer is not None

        if self._inpbuf:
            self._peer.write(self._inpbuf)
            self._inpbuf = b''

        if self._eof_received:
            self._peer.write_eof()

    def forward(self, *args: object) -> None:
        """Start a task to begin local forwarding"""

        self._conn.create_task(self._forward(*args))


class SSHLocalPortForwarder(SSHLocalForwarder):
    """Local TCP port forwarding connection handler"""

    def __init__(self, conn: 'SSHConnection', coro: SSHForwarderCoro,
                 tracker: Optional[ForwardTracker] = None):
        super().__init__(conn, coro)
        self._tracker = tracker
        self._orig_host: str = ''
        self._orig_port: int = 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a newly opened connection"""

        super().connection_made(transport)

        peername = cast(SockAddr, transport.get_extra_info('peername'))

        if peername: # pragma: no branch
            self._orig_host, self._orig_port = peername[:2]

        if self._tracker is not None:
            try:
                self._tracker.connection_made(self._orig_host,
                                              self._orig_port)
            except Exception: # pylint: disable=broad-exception-caught
                # Tracker is an observer; a buggy one must not break
                # the forwarder. Swallow silently (asyncssh has no
                # logger on the protocol class itself).
                pass

        self.forward(self._orig_host, self._orig_port)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Handle a closed connection"""

        if self._tracker is not None:
            try:
                self._tracker.connection_lost(self._orig_host,
                                              self._orig_port, exc)
            except Exception: # pylint: disable=broad-exception-caught
                pass

        super().connection_lost(exc)


class SSHLocalPathForwarder(SSHLocalForwarder):
    """Local UNIX domain socket forwarding connection handler"""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle a newly opened connection"""

        super().connection_made(transport)
        self.forward()
