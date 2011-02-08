# Copyright (C) 2011 Midokura KK

# Implementation of the OpenFlow 1.0.0 operations.

import collections
import logging
import random
import struct
import threading
from twisted.internet import error
import twisted.internet.reactor

from openfaucet import oferror
from openfaucet import ofproto


class Callback(collections.namedtuple('Callback', (
    'callable', 'args', 'kwargs'))):
  """A callable and its arguments.

  The callable arguments are:
    args: The (possibly empty) sequence of positional arguments.
    kwargs: The (possibly empty) dict of keyword arguments. If None,
        no keyword arguments are passed, equivalent to an empty dict.
  """

  @classmethod
  def make_callback(cls, callable, *args, **kwargs):
    """Create a Callback with the given callable and args.

    Args:
      callable: A callable.
      args: The (possibly empty) sequence of positional arguments.
      kwargs: The (possibly empty) dict of keyword arguments. If None,
          no keyword arguments are passed, equivalent to an empty dict.
    """
    return Callback(callable, args, kwargs)

  def call(self, *first_args):
    """Call this callable with the initial args and additional args.

    Args:
      first_args: The sequence of the first positional args to pass
          the callable, before this Callback's args and
          kwargs. Defaults to an empty sequence.
    """
    if not self.args:
      args = first_args
    elif not first_args:
      args = self.args
    else:
      args = first_args + self.args

    self.callable(*args, **self.kwargs)


# The state of a pending operation, consisting of the following attributes:
#   cookie: An opaque value given at operation initiation, and that
#       must be equal to the cookie given at operation
#       termination. This is used to detect invalid xids in replies,
#       e.g. replies with a type incompatible with the request sent
#       with the same xid.
#   success_callback: The Callback called when the operation
#       successfully terminates.
#   timeout_callback: The Callback called when the operation timeouts.
#   timeout_delayed_call: The DelayedCall to trigger the operation's
#       timeout.
PendingOperation = collections.namedtuple('PendingOperation', (
    'cookie', 'success_callback', 'timeout_callback', 'timeout_delayed_call'))


class OpenflowProtocolOperations(ofproto.OpenflowProtocol):
  """An implementation of the OpenFlow 1.0 protocol that abstracts operations.

  This class extends OpenflowProtocol to keep track of pending
  operations (request / reply pairs) and to periodically initiate echo
  operations.

  This protocol is configured by setting attributes, in addition to
  the attributes defined in class OpenflowProtocol:
    reactor: An object implementing Twisted's IReactorTime interface,
        used to do delayed calls. Defaults to Twisted's default
        reactor.
    default_op_timeout: The default period, in seconds, before an
        operation times out. This is also used as the timeout for echo
        operations. Defaults to 3.0 (seconds).
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
    """Initialize the resources to manage the newly opened OpenFlow connection.

    Send a OFPT_HELLO message to the other end and start initiating
    periodic echo operations.
    """
    ofproto.OpenflowProtocol.connectionMade(self)
    self._next_xid = 0
    # Maintain a dictionary mapping of XIDs to PendingOperation
    # objects.
    self._pending_ops = {}
    self.send_hello()
    self._echo()

  # TODO(romain): Notify the callback that the connection has been
  # made.

  # TODO(romain): Notify the callback that the connection has been
  # lost.

  # TODO(romain): Make all operations time out in connectionLost().

  # ----------------------------------------------------------------------
  # Generic request handling API. Those methods should be called by
  # subclasses to manage requests.
  # ----------------------------------------------------------------------

  def _get_next_xid(self):
    """Get the next transaction id to send in a request message

    Lock self._pending_ops_lock must be aquired before calling this
    method.

    Returns:
      The next transaction id, to be associated with the sent request,
      as a 32-bit unsigned integer.
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
      success_callback: The Callback to call when the operation's
          reply is received, and its extra args. The positional and
          keyword arguments in the Callback are passed in addition to
          the positional args that are specific to the type of
          request. The handling of this callable must be done in each
          reply-specific handler.
      timeout_callback: The Callback to call if the operation times
          out.
      timeout: The period, in seconds, before the operation times
          out. If None (default), defaults to the default_op_timeout.
      cookie: An opaque value that must be equal to the cookie given
          at operation termination. This should typically be the
          OFPT_* request message type. Defaults to None.

    Returns:
      The next transaction id, to be associated with the sent request,
      as a 32-bit unsigned integer.
    """
    xid = None
    with self._pending_ops_lock:
      first_xid = xid = self._get_next_xid()
      while self._pending_ops.has_key(xid):
        xid = self._get_next_xid()
        if first_xid == xid:  # tried all values
          raise ValueError('no unused XID')
      if timeout is None:
        timeout = self.default_op_timeout
      timeout_delayed_call = self.reactor.callLater(
          timeout, self._timeout_operation, xid)
      self._pending_ops[xid] = PendingOperation(
          cookie, success_callback, timeout_callback, timeout_delayed_call)
    return xid

  def terminate_operation(self, xid, reply_more=False, cookie=None):
    """Handle an operation's successful termination.

    This method should be called in every handle_*_reply() method.

    This method can be called by vendor handlers to terminate
    vendor-specific operations.

    Args:
      xid: The transaction id of the operation.
      reply_more: If True, more replies are expected to terminate this
          operation, so keep the status of the operation as
          pending. Defaults to False.
      cookie: An opaque value that must be equal to the cookie given
          at operation initiation for the operation with the same
          xid. This should typically be the OFPT_* request message
          type. Defaults to None.

    Returns:
      The Callback to call. None if no pending operation has the given
      xid, which is interpreted as the operation having already timed
      out.

    Raises:
      OpenflowError if the pending operation with the given xid was
      initiated with a different cookie.
    """
    with self._pending_ops_lock:
      pending_op = self._pending_ops.get(xid, None)
      # If callbacks is None, either the xid is invalid or the
      # operation already expired. Assume the latter and no nothing.
      if pending_op is not None:
        if pending_op.cookie != cookie:
          # The most meaningful error we can send back in this case is
          # "bad type", meaning that we believe the reply has a valid
          # xid, but its type is wrong.
          self.logger.error(
              'operation with xid=%i has cookie mistmatch (%r != %r)',
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
      xid: The transaction id of the timed out operation.
    """
    pending_op = None
    with self._pending_ops_lock:
      pending_op = self._pending_ops.pop(xid, None)
    if pending_op is not None and pending_op.timeout_callback is not None:
      pending_op.timeout_callback.call()

  # TODO(romain): Handle the reception of errors whose xids match
  # pending operations?

  # ----------------------------------------------------------------------
  # OFPT_ECHO_* request handling.
  # ----------------------------------------------------------------------

  def handle_echo_request(self, xid, data):
    """Handle the reception of a OFPT_ECHO_REQUEST message.

    Reply to the request by sending back an OFPT_ECHO_REPLY message
    with the same xid and data.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      data: The data attached in the echo request, as a byte buffer.
    """
    self.send_echo_reply(xid, (data,))

  def handle_echo_reply(self, xid, data):
    """Handle the reception of a OFPT_ECHO_REPLY message.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      data: The data attached in the echo reply, as a byte buffer.
    """
    success_callable = self.terminate_operation(
        xid, cookie=ofproto.OFPT_ECHO_REQUEST)
    if success_callable is not None:
      success_callable.call(data)

  def _echo(self):
    """Initiate an echo operation.

    The request's payload is 32 bits of pseudo-random data.
    """
    sent_data = struct.pack('!L', random.getrandbits(32))
    xid = self.initiate_operation(
        Callback.make_callback(self._handle_echo_termination, sent_data),
        Callback.make_callback(self._handle_echo_timeout),
        timeout=None, cookie=ofproto.OFPT_ECHO_REQUEST)
    self.send_echo_request(xid, sent_data)

  def _handle_echo_termination(self, data, sent_data):
    """Handle the completion of an echo operation.

    Check that the received data is the data sent in the
    request. Schedule the next operation.

    Args:
      data: The data attached in the echo reply, as a byte buffer.
      sent_data: The data that was sent in the echo request, as a byte buffer.
    """
    if data != sent_data:
      self.logger.error('echo reply with invalid data', extra=self.log_extra)
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

  def __init__(self, protocol=OpenflowProtocolOperations, error_data_bytes=64,
               logger=logging.getLogger(''), vendor_handlers=(),
               reactor=twisted.internet.reactor, default_op_timeout=3.0,
               echo_op_period=5.0):
    """Initialize this OpenFlow protocol factory.

    Args:
      protocol: The class of protocol objects to create. Defaults to
          class OpenflowProtocolOperations.
      error_data_bytes: The maximum number of bytes of erroneous
          requests to send back in an error message. Must be >= 64.
          Defaults to 64.
      logger: The Python logger used for logging in every created
          protocol object. Defaults to the root logger.
      vendor_handlers: A sequence of vendor handler classes. One
          instance of every class is instantiated (with no arguments)
          and passed to every created protocol object. Defaults to an
          empty sequence.
      reactor: An object implementing Twisted's IReactorTime
          interface, used to do delayed calls. Defaults to Twisted's
          default reactor.
      default_op_timeout: The default period, in seconds, before an
          operation times out. This is also used as the timeout for
          echo operations. Defaults to 3.0 (seconds).
      echo_op_period: The period, in seconds, between two echo
          operations. Defaults to 5.0 (seconds).
    """
    ofproto.OpenflowProtocolFactory.__init__(
        self, protocol=protocol, error_data_bytes=error_data_bytes,
        logger=logger, vendor_handlers=vendor_handlers)
    self._reactor = reactor
    self._default_op_timeout = default_op_timeout
    self._echo_op_period = echo_op_period

  def buildProtocol(self, addr):
    """Create a protocol to handle a connection established to the given address.

    Args:
      addr: The address of the newly-established connection, as a
          twisted.internet.interfaces.IAddress object.

    Returns:
      An OpenflowProtocolOperations object.
    """
    p = ofproto.OpenflowProtocolFactory.buildProtocol(self, addr)
    p.reactor = self._reactor
    p.default_op_timeout = self._default_op_timeout
    p.echo_op_period = self._echo_op_period
    return p
