# Copyright 2011 Midokura KK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Implementation of the OpenFlow 1.0.0 operations.
"""

import collections
import logging
import random
import struct
import threading
from twisted.internet import error
import twisted.internet.reactor

from openfaucet import oferror
from openfaucet import ofproto


class Callable(collections.namedtuple('Callable', (
    'callable', 'args', 'kwargs'))):
    """A decorator of a callable to pass it additional arguments when called.

    The additional arguments to the callable are passed in addition to
    the arguments given by the caller, and are set as attributes of
    this object:
        args: The (possibly empty) sequence of additional positional
            arguments.
        kwargs: The (possibly empty) dict of additional keyword
            arguments. If None, no keyword arguments are passed,
            equivalent to an empty dict.
    """

    @classmethod
    def make_callable(cls, callable, *args, **kwargs):
        """Create a Callable with the given callable and additional args.

        Args:
            callable: A callable.
            args: The (possibly empty) sequence of additional
                positional arguments.
            kwargs: The (possibly empty) dict of additional keyword
                arguments.
        """
        return Callable(callable, args, kwargs)

    def __call__(self, *first_args, **first_kwargs):
        """Call this callable with the given args and additional args.

        Args:
            first_args: The sequence of the first positional args to
                pass in the call, before this Callable's additional
                args and keyword arguments. Defaults to an empty
                sequence.
            first_kwargs: The dict of keyword arguments to pass in the
                call, in addition to this Callable's additional
                keyword arguments. Defaults to an empty dict. If this
                dict and this Callable's additional arg dict have
                identical keys, the items in the additional arg dict
                with those keys are ignored.
        """
        if not self.args:
            args = first_args
        elif not first_args:
            args = self.args
        else:
            args = first_args + self.args

        if not self.kwargs:
            kwargs = first_kwargs
        elif not first_kwargs:
            kwargs = self.kwargs
        else:
            kwargs = self.kwargs.copy()
            kwargs.update(first_kwargs)

        self.callable(*args, **kwargs)


# The state of a pending operation, consisting of the following attributes:
#     cookie: An opaque value given at operation initiation, and that
#         must be equal to the cookie given at operation
#         termination. This is used to detect invalid XIDs in replies,
#         e.g. replies with a type incompatible with the request sent
#         with the same XID.
#     success_callback: The callable called when the operation
#         successfully terminates.
#     timeout_callback: The callable called when the operation timeouts.
#     timeout_delayed_call: The DelayedCall to trigger the operation's
#         timeout.
#
# Note: Operations are directly associated with callables, and not
# Twisted Deferred objects, since a Deferred can be called back at
# most once, and thus can't be used to perform linked replies,
# i.e. multiple calls to the same callable, as must be done for
# instance in get_stats_port operations in ofcontroller.py.
PendingOperation = collections.namedtuple('PendingOperation', (
    'cookie', 'success_callback', 'timeout_callback', 'timeout_delayed_call'))


class OpenflowProtocolOperations(ofproto.OpenflowProtocol):
    """An implementation of the OpenFlow 1.0 protocol to abstract operations.

    This class extends OpenflowProtocol to keep track of pending
    operations (request / reply pairs) and to periodically initiate
    echo operations.

    This protocol is configured by setting attributes, in addition to
    the attributes defined in class OpenflowProtocol:
        reactor: An object implementing Twisted's IReactorTime
            interface, used to do delayed calls. Defaults to Twisted's
            default reactor.
        default_op_timeout: The default period, in seconds, before an
            operation times out. This is also used as the timeout for
            echo operations. Defaults to 3.0 (seconds).
        echo_op_period: The period, in seconds, between two echo
            operations. Defaults to 5.0 (seconds).
    """

    def __init__(self):
        """Initialize this OpenFlow protocol handler.
        """
        ofproto.OpenflowProtocol.__init__(self)
        self._pending_ops_lock = threading.Lock()
        self.reactor = twisted.internet.reactor
        self.default_op_timeout = 3.0
        self.echo_op_period = 5.0

    def connectionMade(self):
        """Initialize resources to manage the newly opened OpenFlow connection.

        Send a OFPT_HELLO message to the other end and start
        initiating periodic echo operations.
        """
        ofproto.OpenflowProtocol.connectionMade(self)
        self.logger.info(
            'protocol operations configuration: reactor=%r, '
            'default_op_timeout=%r, echo_op_period=%r', self.reactor,
            self.default_op_timeout, self.echo_op_period, extra=self.log_extra)

        self._next_xid = 0
        # Maintain a dictionary mapping of XIDs to PendingOperation
        # objects.
        self._pending_ops = {}
        self.send_hello()
        self._echo()

    def connectionLost(self, reason):
        """Release resources used to manage the connection that was just lost.

        Silently cancel all pending operations.

        Args:
            reason: A twisted.python.failure.Failure that wraps a
                twisted.internet.error.ConnectionDone or
                twisted.internet.error.ConnectionLost instance (or a
                subclass of one of those).
        """
        ofproto.OpenflowProtocol.connectionLost(self, reason)

        with self._pending_ops_lock:
            for pending_op in self._pending_ops.itervalues():
                _, _, _, timeout_delayed_call = pending_op
                timeout_delayed_call.cancel()
            self._pending_ops.clear()

    # ----------------------------------------------------------------------
    # Generic request handling API. Those methods should be called by
    # subclasses to manage requests.
    # ----------------------------------------------------------------------

    def _get_next_xid(self):
        """Get the next transaction ID to send in a request message

        Lock self._pending_ops_lock must be aquired before calling
        this method.

        Returns:
            The next transaction ID, to be associated with the sent
            request, as a 32-bit unsigned integer.
        """
        xid = self._next_xid
        # Simply increment, and wrap to 32-bit.
        self._next_xid = (self._next_xid + 1) & 0xffffffff
        return xid

    def initiate_operation(self, success_callback, timeout_callback,
                           timeout=None, cookie=None):
        """Register an operation which request is about to be sent.

        This method can be called by vendor handlers to initiate
        vendor-specific operations.

        Args:
            success_callback: The callable to call when the
                operation's reply is received, and its extra args.The
                handling of this callable must be done in each
                reply-specific handler.
            timeout_callback: The callable to call if the operation
                times out.
            timeout: The period, in seconds, before the operation
                times out. If None (default), defaults to the
                default_op_timeout.
            cookie: An opaque value that must be equal to the cookie
                given at operation termination. This should typically
                be the OFPT_* request message type. Defaults to None.

        Returns:
            The next transaction ID, to be associated with the sent
            request, as a 32-bit unsigned integer.
        """
        xid = None
        with self._pending_ops_lock:
            first_xid = xid = self._get_next_xid()
            while xid in self._pending_ops:
                xid = self._get_next_xid()
                if first_xid == xid:  # tried all values
                    raise ValueError('no unused XID')
            if timeout is None:
                timeout = self.default_op_timeout
            timeout_delayed_call = self.reactor.callLater(
                timeout, self._timeout_operation, xid)
            self._pending_ops[xid] = PendingOperation(
                cookie, success_callback, timeout_callback,
                timeout_delayed_call)
        return xid

    def terminate_operation(self, xid, reply_more=False, cookie=None):
        """Handle an operation's successful termination.

        This method should be called in every handle_*_reply() method.

        This method can be called by vendor handlers to terminate
        vendor-specific operations.

        Args:
            xid: The transaction ID of the operation.
            reply_more: If True, more replies are expected to
                terminate this operation, so keep the status of the
                operation as pending. Defaults to False.
            cookie: An opaque value that must be equal to the cookie
                given at operation initiation for the operation with
                the same XID. This should typically be the OFPT_*
                request message type. Defaults to None.

        Returns:
            The callable to call. None if no pending operation has the
            given XID, which is interpreted as the operation having
            already timed out.

        Raises:
            OpenflowError: The pending operation with the given XID
                was initiated with a different cookie.
        """
        with self._pending_ops_lock:
            pending_op = self._pending_ops.get(xid, None)
            # If callbacks is None, either the XID is invalid or the
            # operation already expired. Assume the latter and no
            # nothing.
            if pending_op is not None:
                if pending_op.cookie != cookie:
                    # The most meaningful error we can send back in
                    # this case is "bad type", meaning that we believe
                    # the reply has a valid XID, but its type is
                    # wrong.
                    self.logger.error(
                        'operation with xid=%i has cookie mistmatch %r != %r',
                        xid, pending_op.cookie, cookie, extra=self.log_extra)
                    self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                                  oferror.OFPBRC_BAD_TYPE)
                if not reply_more:
                    del self._pending_ops[xid]
                    try:
                        pending_op.timeout_delayed_call.cancel()
                    except error.AlreadyCalled:
                        return None
                return pending_op.success_callback

    def _timeout_operation(self, xid):
        """Handle an operation's timeout.

        Args:
            xid: The transaction ID of the timed out operation.
        """
        pending_op = None
        with self._pending_ops_lock:
            pending_op = self._pending_ops.pop(xid, None)
        if pending_op is not None:
            self.logger.info('operation with xid=%i timed out', xid,
                             extra=self.log_extra)
            if pending_op.timeout_callback is not None:
                pending_op.timeout_callback()

    # TODO(romain): Handle the reception of errors whose XIDs match
    # pending operations?

    # ----------------------------------------------------------------------
    # OFPT_ECHO_* request handling.
    # ----------------------------------------------------------------------

    def handle_echo_request(self, xid, data):
        """Handle the reception of a OFPT_ECHO_REQUEST message.

        Reply to the request by sending back an OFPT_ECHO_REPLY
        message with the same XID and data.

        Args:
            xid: The transaction ID associated with the request, as a
                32-bit unsigned integer.

            data: The data attached in the echo request, as a binary
                string.
        """
        self.send_echo_reply(xid, (data,))

    def handle_echo_reply(self, xid, data):
        """Handle the reception of a OFPT_ECHO_REPLY message.

        Args:
            xid: The transaction ID associated with the request, as a
                32-bit unsigned integer.
            data: The data attached in the echo reply, as a binary
                string.
        """
        success_callable = self.terminate_operation(
            xid, cookie=ofproto.OFPT_ECHO_REQUEST)
        if success_callable is not None:
            success_callable(data)

    def _echo(self):
        """Initiate an echo operation.

        The request's payload is 32 bits of pseudo-random data.
        """
        sent_data = struct.pack('!L', random.getrandbits(32))
        xid = self.initiate_operation(
            Callable.make_callable(self._handle_echo_termination, sent_data),
            self._handle_echo_timeout,
            timeout=None, cookie=ofproto.OFPT_ECHO_REQUEST)
        self.send_echo_request(xid, sent_data)

    def _handle_echo_termination(self, data, sent_data):
        """Handle the completion of an echo operation.

        Check that the received data is the data sent in the
        request. Schedule the next operation.

        Args:
            data: The data attached in the echo reply, as a binary
                string.
            sent_data: The data that was sent in the echo request, as
                a binary string.
        """
        if data != sent_data:
            self.logger.error('echo reply with invalid data',
                              extra=self.log_extra)
            self.transport.loseConnection()
            raise ValueError('OFPT_ECHO_REPLY message has invalid data')
        # Schedule the next request.
        self.reactor.callLater(self.echo_op_period, self._echo)

    def _handle_echo_timeout(self):
        """Handle the timeout of an echo request by closing the connection.

        This method may be redefined in subclasses.
        """
        self.logger.error('echo request timed out', extra=self.log_extra)
        self.transport.loseConnection()


class OpenflowProtocolOperationsFactory(ofproto.OpenflowProtocolFactory):
    """A Twisted factory of OpenflowProtocolOperations objects.
    """

    def __init__(self, protocol=OpenflowProtocolOperations,
                 error_data_bytes=64, logger=logging.getLogger(''),
                 vendor_handlers=(), reactor=twisted.internet.reactor,
                 default_op_timeout=3.0, echo_op_period=5.0):
        """Initialize this OpenFlow protocol factory.

        Args:
            protocol: The class of protocol objects to
                create. Defaults to class OpenflowProtocolOperations.
            error_data_bytes: The maximum number of bytes of erroneous
                requests to send back in an error message. Must be >=
                64.  Defaults to 64.
            logger: The Python logger used for logging in every
                created protocol object. Defaults to the root logger.
            vendor_handlers: A sequence of vendor handler classes. One
                instance of every class is instantiated (with no
                arguments) and passed to every created protocol
                object. Defaults to an empty sequence.
            reactor: An object implementing Twisted's IReactorTime
                interface, used to do delayed calls. Defaults to
                Twisted's default reactor.
            default_op_timeout: The default period, in seconds, before
                an operation times out. This is also used as the
                timeout for echo operations. Defaults to 3.0
                (seconds).
            echo_op_period: The period, in seconds, between two echo
                operations. Defaults to 5.0 (seconds).
        """
        ofproto.OpenflowProtocolFactory.__init__(
            self, protocol=protocol, error_data_bytes=error_data_bytes,
            logger=logger, vendor_handlers=vendor_handlers)
        self._reactor = reactor
        self._default_op_timeout = default_op_timeout
        self._echo_op_period = echo_op_period
        self._logger.info(
            'protocol operations factory configuration: reactor=%r, '
            'default_op_timeout=%r, echo_op_period=%r', self._reactor,
            self._default_op_timeout, self._echo_op_period)

    def buildProtocol(self, addr):
        """Create a protocol to handle an established connection.

        Args:
            addr: The address of the newly-established connection, as
                a twisted.internet.interfaces.IAddress object.

        Returns:
            An OpenflowProtocolOperations object.
        """
        p = ofproto.OpenflowProtocolFactory.buildProtocol(self, addr)
        p.reactor = self._reactor
        p.default_op_timeout = self._default_op_timeout
        p.echo_op_period = self._echo_op_period
        return p
