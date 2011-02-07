# Copyright (C) 2010, 2011 Midokura KK

# Implementation of the OpenFlow protocol version 1.0.0.
#
# This implements can be extended to support multiple vendor
# extensions.  A vendor extension can be implemented as an object that
# implements the following methods:
# TODO(romain): Document the vendor callback methods.

import collections
import logging
import struct
import weakref
from twisted.internet import error
from twisted.internet import interfaces
from twisted.internet import protocol
from zope.interface import implements

from openfaucet import buffer
from openfaucet import ofaction
from openfaucet import ofconfig
from openfaucet import oferror
from openfaucet import ofmatch
from openfaucet import ofstats


# The format of the header on all OpenFlow packets.
OFP_HEADER_FORMAT = '!BBHL'
OFP_HEADER_LENGTH = 8

# The version code for the OpenFlow Protocol version 1.0.0.
OFP_VERSION_1_0_0 = 0x01

# OpenFlow message types.
# Immutable messages.
OFPT_HELLO = 0               # Symmetric message.
OFPT_ERROR = 1               # Symmetric message.
OFPT_ECHO_REQUEST = 2        # Symmetric message.
OFPT_ECHO_REPLY = 3          # Symmetric message.
OFPT_VENDOR = 4              # Symmetric message.
# Switch configuration messages.
OFPT_FEATURES_REQUEST = 5    # Controller/switch message.
OFPT_FEATURES_REPLY = 6      # Controller/switch message.
OFPT_GET_CONFIG_REQUEST = 7  # Controller/switch message.
OFPT_GET_CONFIG_REPLY = 8    # Controller/switch message.
OFPT_SET_CONFIG = 9          # Controller/switch message.
# Asynchronous messages.
OFPT_PACKET_IN = 10           # Async message.
OFPT_FLOW_REMOVED = 11        # Async message.
OFPT_PORT_STATUS = 12         # Async message.
# Controller command messages.
OFPT_PACKET_OUT = 13          # Controller/switch message.
OFPT_FLOW_MOD = 14            # Controller/switch message.
OFPT_PORT_MOD = 15            # Controller/switch message.
# Statistics messages.
OFPT_STATS_REQUEST = 16       # Controller/switch message.
OFPT_STATS_REPLY = 17         # Controller/switch message.
# Barrier messages.
OFPT_BARRIER_REQUEST = 18     # Controller/switch message.
OFPT_BARRIER_REPLY = 19       # Controller/switch message.
# Queue Configuration messages.
OFPT_QUEUE_GET_CONFIG_REQUEST = 20  # Controller/switch message.
OFPT_QUEUE_GET_CONFIG_REPLY = 21    # Controller/switch message.

# Reasons for OFPT_PACKET_IN messages.
OFPR_NO_MATCH = 0
OFPR_ACTION = 1

# Reasons for OFPT_FLOW_REMOVED messages.
OFPRR_IDLE_TIMEOUT = 0
OFPRR_HARD_TIMEOUT = 1
OFPRR_DELETE = 2

# Reasons for OFPT_PORT_STATUS messages.
OFPPR_ADD = 0
OFPPR_DELETE = 1
OFPPR_MODIFY = 2

# Port numbers. Physical ports are numbered starting from 1.
# Maximum number of physical switch ports.
OFPP_MAX = 0xff00
# Send the packet out the input port. This virtual port must be
# explicitly used in order to send back out of the input port.
OFPP_IN_PORT = 0xfff8
# Perform actions in the flow table. This can be the destination port
# only for OFPT_PACKET_OUT messages.
OFPP_TABLE = 0xfff9
# Process with normal L2/L3 switching.
OFPP_NORMAL = 0xfffa
# All physical ports except input port and those disabled by STP.
OFPP_FLOOD = 0xfffb
# All physical ports except input port.
OFPP_ALL = 0xfffc
# Send to controller.
OFPP_CONTROLLER = 0xfffd
# Local openflow "port".
OFPP_LOCAL = 0xfffe
# Not associated with a physical port.
OFPP_NONE = 0xffff

# OFPT_FLOW_MOD message commands.
OFPFC_ADD = 0
OFPFC_MODIFY = 1
OFPFC_MODIFY_STRICT = 2
OFPFC_DELETE = 3
OFPFC_DELETE_STRICT = 4

# OFPT_FLOW_MOD message flags.
OFPFF_SEND_FLOW_REM = 1 << 0
OFPFF_CHECK_OVERLAP = 1 << 1
OFPFF_EMERG = 1 << 2

# OFPT_STATS_REQUEST / OFPT_STATS_REPLY stats types.
OFPST_DESC = 0
OFPST_FLOW = 1
OFPST_AGGREGATE = 2
OFPST_TABLE = 3
OFPST_PORT = 4
OFPST_QUEUE = 5
OFPST_VENDOR = 0xffff

# OFPT_STATS_REPLY flags.
OFPSF_REPLY_MORE = 1 << 0  # More replies to follow.


class OpenflowProtocol(object):
  """An implementation of the OpenFlow 1.0 protocol.

  This protocol implementation is stateless and only implements
  message encoding / decoding.

  This protocol is configured by setting attributes:
    error_data_bytes: The maximum number of bytes of erroneous
        requests to send back in an error message. Must be >= 64.
        Defaults to 64.
    logger: The Python logger used for logging in this protocol.
        Defaults to the root logger.
    log_extra: A dictionary of additional data to add to every
        log. The keys in this dictionary should not clash with the
        keys used by the logging system. Defaults to an empty
        dictionary.
    vendor_handlers: A sequence of vendor handler objects. Defaults to
        an empty sequence.
  """

  implements(interfaces.IProtocol)
  # Note: OpenflowProtocol should normally extend class
  # protocol.Protocol, but that is an old-style Python class, i.e. it
  # doesn't support properties, slots, etc. So we extend object
  # instead, and implement interface IProtocol completely ourselves.

  def __init__(self):
    """Initialize this OpenFlow protocol handler.
    """
    self.error_data_bytes = 64
    self.logger = logging.getLogger('')
    self.log_extra = {}
    self._vendor_handlers = {}

  def get_vendor_handlers(self):
    """Get the sequence of vendor handlers for this connection.

    Returns:
      The sequence of vendor handler objects.
    """
    return self._vendor_handlers.values()

  def set_vendor_handlers(self, vendor_handlers):
    """Set the vendor handlers for this connection.

    Args:
      vendor_handlers: A sequence of vendor handler objects.
    """
    # Index the vendor handlers by vendor ID.
    # TODO(romain): Specify clearly that a vendor handler must have a
    # vendor_id attribute or property.
    self._vendor_handlers = dict((v.vendor_id, v) for v in vendor_handlers)

  vendor_handlers = property(get_vendor_handlers, set_vendor_handlers)

  def get_vendor_handler(self, vendor_id):
    """Get a vendor handler with a given vendor id.

    Args:
      vendor_id: The vendor id of the handler to return.

    Return:
      The vendor handler object for the given vendor id, or None if not found.
    """
    return self._vendor_handlers.get(vendor_id)

  def makeConnection(self, transport):
    """Make a connection to a transport and a server.

    Set the transport attribute of this Protocol, and call the
    connectionMade() callback.
    """
    self.connected = True
    self.transport = transport
    self.connectionMade()

  def connectionMade(self):
    """Initialize the resources to manage the newly opened OpenFlow connection.
    """
    self.logger.debug('connection made', extra=self.log_extra)
    self._buffer = buffer.ReceiveBuffer()
    for v in self._vendor_handlers.itervalues():
      v.connection_made()

  def connectionLost(self, reason):
    """Release any resources used to manage the connection that was just lost.

    Args:
      reason: A twisted.python.failure.Failure that wraps a
          twisted.internet.error.ConnectionDone or
          twisted.internet.error.ConnectionLost instance (or a
          subclass of one of those).
    """
    self.logger.debug('connection lost with reason %r', reason,
                      extra=self.log_extra)
    for v in self._vendor_handlers.itervalues():
      v.connection_lost(reason)
    self.connected = False
    self._buffer = None

  def dataReceived(self, data):
    """Handle bytes received over the connection.

    Args:
      data: A string of indeterminate length containing the received bytes.
    """
    self._buffer.append(data)

    # Loop while we can at least decode a header.
    while len(self._buffer) >= OFP_HEADER_LENGTH:

      self._buffer.set_message_boundaries(OFP_HEADER_LENGTH)
      version, msg_type, msg_length, xid = \
          self._buffer.unpack_inplace(OFP_HEADER_FORMAT)

      if msg_length > len(self._buffer):
        # Not enough data has been received to decode the whole
        # message. Wait until more data is received. If one or more
        # message have been decoded in this loop, compact the buffer
        # to drop read bytes.
        self._buffer.compact()
        return

      self._buffer.set_message_boundaries(msg_length)

      try:
        self._handle_message()
      except oferror.OpenflowError, e:
        # TODO(romain): Print the stacktrace.
        self.logger.error('openflow error %r', e, extra=self.log_extra)
        # Always set the xid to the message that failed, as this is
        # required for at least some error types.
        self.send_error(e, xid=xid)
      except Exception, e:
        # TODO(romain): Print the stacktrace.
        self.logger.error('message decoding error %r', e,
                          extra=self.log_extra)

      if self._buffer.message_bytes_left > 0:
        self.logger.error('message not completely decoded, %i bytes left',
                          self._buffer.message_bytes_left,
                          extra=self.log_extra)
        self._buffer.skip_bytes(self._buffer.message_bytes_left)

  def raise_error_with_request(self, error_type, error_code):
    raise oferror.OpenflowError(
        oferror.OFPET_BAD_REQUEST, oferror.OFPBRC_BAD_LEN,
        (self._buffer.get_first_message_bytes(self.error_data_bytes),))

  def _log_handle_msg(self, msg_type_str, **kwargs):
    """Log a message handling debug message.

    Args:
      msg_type_str: The string describing the message type.
      kwargs: The dict of args passed to the handle_* method.
    """
    if self.logger.isEnabledFor(logging.DEBUG):
      msg = ['handle message of type %s' % msg_type_str]
      msg.extend(['%s=%r' % (k, v) for k, v in kwargs.iteritems()])
      self.logger.debug(', '.join(msg), extra=self.log_extra)

  def _log_send_msg(self, msg_type_str, **kwargs):
    """Log a message sending debug message.

    Args:
      msg_type_str: The string describing the message type.
      kwargs: The dict of args passed to the send_* method.
    """
    if self.logger.isEnabledFor(logging.DEBUG):
      msg = ['send message of type %s' % msg_type_str]
      msg.extend(['%s=%r' % (k, v) for k, v in kwargs.iteritems()])
      self.logger.debug(', '.join(msg), extra=self.log_extra)

  def _handle_message(self):
    """Handle a received OpenFlow message.
    """
    version, msg_type, msg_length, xid = self._buffer.unpack(OFP_HEADER_FORMAT)
    self.logger.debug(
        'received message with version %i, type %i, lenth %i, xid %i',
        version, msg_type, msg_length, xid, extra=self.log_extra)

    if version != OFP_VERSION_1_0_0:
      if msg_type == OFPT_HELLO:
        self.logger.error('OFPT_HELLO message has wrong version %i',
                          version, extra=self.log_extra)
        raise oferror.OpenflowError(
            oferror.OFPET_HELLO_FAILED, oferror.OFPHFC_INCOMPATIBLE,
            ('invalid version %i in OFPT_HELLO message' % version,))
      else:
        self.logger.error('message has wrong version %i', version,
                          extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_VERSION)

    if msg_type == OFPT_HELLO:
        self._handle_hello(msg_length, xid)
    elif msg_type == OFPT_ERROR:
        self._handle_error(msg_length, xid)
    elif msg_type == OFPT_ECHO_REQUEST:
        self._handle_echo_request(msg_length, xid)
    elif msg_type == OFPT_ECHO_REPLY:
        self._handle_echo_reply(msg_length, xid)
    elif msg_type == OFPT_VENDOR:
        self._handle_vendor(msg_length, xid)
    elif msg_type == OFPT_FEATURES_REQUEST:
        self._handle_features_request(msg_length, xid)
    elif msg_type == OFPT_FEATURES_REPLY:
        self._handle_features_reply(msg_length, xid)
    elif msg_type == OFPT_GET_CONFIG_REQUEST:
        self._handle_get_config_request(msg_length, xid)
    elif msg_type == OFPT_GET_CONFIG_REPLY:
        self._handle_get_config_reply(msg_length, xid)
    elif msg_type == OFPT_SET_CONFIG:
        self._handle_set_config(msg_length, xid)
    elif msg_type == OFPT_PACKET_IN:
        self._handle_packet_in(msg_length, xid)
    elif msg_type == OFPT_FLOW_REMOVED:
        self._handle_flow_removed(msg_length, xid)
    elif msg_type == OFPT_PORT_STATUS:
        self._handle_port_status(msg_length, xid)
    elif msg_type == OFPT_PACKET_OUT:
        self._handle_packet_out(msg_length, xid)
    elif msg_type == OFPT_FLOW_MOD:
        self._handle_flow_mod(msg_length, xid)
    elif msg_type == OFPT_PORT_MOD:
        self._handle_port_mod(msg_length, xid)
    elif msg_type == OFPT_STATS_REQUEST:
        self._handle_stats_request(msg_length, xid)
    elif msg_type == OFPT_STATS_REPLY:
        self._handle_stats_reply(msg_length, xid)
    elif msg_type == OFPT_BARRIER_REQUEST:
        self._handle_barrier_request(msg_length, xid)
    elif msg_type == OFPT_BARRIER_REPLY:
        self._handle_barrier_reply(msg_length, xid)
    elif msg_type == OFPT_QUEUE_GET_CONFIG_REQUEST:
        self._handle_queue_get_config_request(msg_length, xid)
    elif msg_type == OFPT_QUEUE_GET_CONFIG_REPLY:
        self._handle_queue_get_config_reply(msg_length, xid)
    else:
      self.logger.error('message has unknown type %i', msg_type,
                        extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_TYPE)

  def _handle_hello(self, msg_length, xid):
    # A OFPT_HELLO message has no body in the current version.
    # Implementations must be prepared to receive a hello message that
    # includes a body, ignoring its contents, to allow for later
    # extensions.
    if msg_length > OFP_HEADER_LENGTH:
      self._buffer.skip_bytes(msg_length - OFP_HEADER_LENGTH)
      self.logger.debug('received OFPT_HELLO message with %i bytes of data',
                        msg_length - OFP_HEADER_LENGTH, extra=self.log_extra)
    self._log_handle_msg('OFPT_HELLO')
    self.handle_hello()

  def _handle_error(self, msg_length, xid):
    if msg_length < 12:
      self.logger.error('OFPT_ERROR message too short with length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)

    error = oferror.OpenflowError.deserialize(self._buffer)
    # TODO(romain): Handle error decoding errors.
    self._log_handle_msg('OFPT_ERROR', error=error)
    self.handle_error(xid, error)

  def _handle_echo_request(self, msg_length, xid):
    if msg_length > OFP_HEADER_LENGTH:
      data = self._buffer.read_bytes(msg_length - OFP_HEADER_LENGTH)
    else:
      data = ''
    self._log_handle_msg('OFPT_ECHO_REQUEST', data=data)
    self.handle_echo_request(xid, data)

  def _handle_echo_reply(self, msg_length, xid):
    if msg_length > OFP_HEADER_LENGTH:
      data = self._buffer.read_bytes(msg_length - OFP_HEADER_LENGTH)
    else:
      data = ''
    self._log_handle_msg('OFPT_ECHO_REPLY', data=data)
    self.handle_echo_reply(xid, data)

  def _handle_vendor(self, msg_length, xid):
    if msg_length < 12:
      self.logger.error('OFPT_VENDOR message has invalid length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)

    vendor_id = self._buffer.unpack('!L')[0]
    vendor_handler = self._vendor_handlers.get(vendor_id)
    if vendor_handler is None:
      self.logger.error('OFPT_VENDOR message has unknown vendor id %i',
                        vendor_id, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_VENDOR)

    # TODO(romain): Specify clearly that exactly msg_length-12 bytes
    # must be consumed by this call. Check that this is the case after
    # the call returns.
    self._log_handle_msg('OFPT_VENDOR', vendor_id=vendor_id)
    vendor_handler.handle_vendor_message(msg_length, xid, self._buffer)

  def _handle_features_request(self, msg_length, xid):
    if msg_length != OFP_HEADER_LENGTH:
      self.logger.error('OFPT_FEATURES_REQUEST message has invalid length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)
    self._log_handle_msg('OFPT_FEATURES_REQUEST')
    self.handle_features_request(xid)

  def _handle_features_reply(self, msg_length, xid):
    if msg_length < 8 + ofconfig.SwitchFeatures.FORMAT_LENGTH:
      self.logger.error('OFPT_FEATURES_REPLY message too short with length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)
    if ((msg_length - 8 - ofconfig.SwitchFeatures.FORMAT_LENGTH)
        % ofconfig.PhyPort.FORMAT_LENGTH) != 0:
      self.logger.error('OFPT_FEATURES_REPLY message not aligned properly',
                        extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)
    switch_features = ofconfig.SwitchFeatures.deserialize(self._buffer)
    self._log_handle_msg('OFPT_FEATURES_REPLY',
                         switch_features=switch_features)
    self.handle_features_reply(xid, switch_features)

  def _handle_get_config_request(self, msg_length, xid):
    if msg_length > OFP_HEADER_LENGTH:
      self.logger.error(
          'OFPT_GET_CONFIG_REQUEST message has invalid length %i',
          msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)
    self._log_handle_msg('OFPT_GET_CONFIG_REQUEST')
    self.handle_get_config_request(xid)

  def _handle_get_config_reply(self, msg_length, xid):
    if msg_length != OFP_HEADER_LENGTH + ofconfig.SwitchConfig.FORMAT_LENGTH:
      self.logger.error('OFPT_GET_CONFIG_REPLY message has invalid length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)
    switch_config = ofconfig.SwitchConfig.deserialize(self._buffer)
    self._log_handle_msg('OFPT_GET_CONFIG_REPLY',
                         switch_config=switch_config)
    self.handle_get_config_reply(xid, switch_config)

  def _handle_set_config(self, msg_length, xid):
    if msg_length != OFP_HEADER_LENGTH + ofconfig.SwitchConfig.FORMAT_LENGTH:
      self.logger.error('OFPT_SET_CONFIG message has invalid length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)
    switch_config = ofconfig.SwitchConfig.deserialize(self._buffer)
    self._log_handle_msg('OFPT_SET_CONFIG', switch_config=switch_config)
    self.handle_set_config(switch_config)

  def _handle_packet_in(self, msg_length, xid):
    if msg_length < 20:
      self.logger.error('OFPT_PACKET_IN message too short with length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)
    buffer_id, total_len, in_port, reason = self._buffer.unpack('!LHHBx')
    if reason not in (OFPR_NO_MATCH, OFPR_ACTION):
      raise ValueError('OFPT_PACKET_IN message has invalid reason', reason)
    data = self._buffer.read_bytes(msg_length - 18)
    self._log_handle_msg(
        'OFPT_PACKET_IN', buffer_id=buffer_id, total_len=total_len,
        in_port=in_port, reason=reason, data=data)
    self.handle_packet_in(buffer_id, total_len, in_port, reason, data)

  def _handle_flow_removed(self, msg_length, xid):
    if msg_length != 88:
      self.logger.error('OFPT_FLOW_REMOVED message has invalid length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)
    # This is almost the same as an ofp_flow_stats structure, but has
    # one field added (reason), and several fields removed
    # (hard_timeout, table_id), so just deserialize those fields by
    # hand instead of creating a FlowStats object.
    match = ofmatch.Match.deserialize(self._buffer)
    (cookie, priority, reason, duration_sec, duration_nsec, idle_timeout,
     packet_count, byte_count) = self._buffer.unpack('!QHBxLLH2xQQ')
    if reason not in (OFPRR_IDLE_TIMEOUT, OFPRR_HARD_TIMEOUT, OFPRR_DELETE):
      raise ValueError('OFPT_FLOW_REMOVED message has invalid reason', reason)
    self._log_handle_msg(
        'OFPT_FLOW_REMOVED', match=match, cookie=cookie, priority=priority,
        reason=reason, duration_sec=duration_sec, duration_nsec=duration_nsec,
        idle_timeout=idle_timeout, packet_count=packet_count,
        byte_count=byte_count)
    self.handle_flow_removed(
        match, cookie, priority, reason, duration_sec, duration_nsec,
        idle_timeout, packet_count, byte_count)

  def _handle_port_status(self, msg_length, xid):
    if msg_length != 64:
      self.logger.error('OFPT_PORT_STATUS message has invalid length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)
    (reason,) = self._buffer.unpack('!B7x')
    if reason not in (OFPPR_ADD, OFPPR_DELETE, OFPPR_MODIFY):
      raise ValueError('OFPT_PORT_STATUS message has invalid reason', reason)
    desc = ofconfig.PhyPort.deserialize(self._buffer)
    self._log_handle_msg('OFPT_PORT_STATUS', reason=reason, desc=desc)
    self.handle_port_status(reason, desc)

  def _handle_packet_out(self, msg_length, xid):
    if msg_length < 16:
      self.logger.error('OFPT_PACKET_OUT message too short with length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)
    buffer_id, in_port, actions_len = self._buffer.unpack('!LHH')

    if msg_length < (16 + actions_len * 8):
      self.logger.error('OFPT_PACKET_OUT message has too small actions '
                        'length %i for message length %i',
                        actions_len, msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_ACTION,
                                    oferror.OFPBAC_BAD_LEN)

    actions = tuple(self.deserialize_action(self._buffer)
                    for i in xrange(actions_len))
    data = self._buffer.read_bytes(self._buffer.message_bytes_left)
    self._log_handle_msg(
        'OFPT_PACKET_OUT', buffer_id=buffer_id, in_port=in_port,
        actions=actions, data=data)
    self.handle_packet_out(buffer_id, in_port, actions, data)

  def _handle_flow_mod(self, msg_length, xid):
    if msg_length < 72:
      self.logger.error('OFPT_FLOW_MOD message too short with length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)

    match = ofmatch.Match.deserialize(self._buffer)
    (cookie, command, idle_timeout, hard_timeout, priority, buffer_id,
     out_port, flags) = self._buffer.unpack('!QHHHHLHH')

    if cookie == 0xffffffffffffffff:
      raise ValueError('reserved cookie', cookie)
    if command not in (OFPFC_ADD, OFPFC_MODIFY, OFPFC_MODIFY_STRICT,
                       OFPFC_DELETE, OFPFC_DELETE_STRICT):
      raise ValueError('invalid command', command)
    if flags & ~(OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP | OFPFF_EMERG):
      # Be liberal. Ignore those bits instead of raising an exception.
      # TODO(romain): Log this.
      # ('undefined flag bits set', flags)
      pass
    # TODO(romain): Check that the port is valid for this message
    # type. E.g. *_TABLE should be invalid?

    send_flow_rem = bool(flags & OFPFF_SEND_FLOW_REM)
    check_overlap = bool(flags & OFPFF_CHECK_OVERLAP)
    emerg = bool(flags & OFPFF_EMERG)
    actions = []
    while self._buffer.message_bytes_left > 0:
      actions.append(self.deserialize_action(self._buffer))
    actions = tuple(actions)
    self._log_handle_msg(
        'OFPT_FLOW_MOD', match=match, cookie=cookie, command=command,
        idle_timeout=idle_timeout, hard_timeout=hard_timeout, priority=priority,
        buffer_id=buffer_id, out_port=out_port, send_flow_rem=send_flow_rem,
        check_overlap=check_overlap, emerg=emerg, actions=actions)
    self.handle_flow_mod(match, cookie, command, idle_timeout, hard_timeout,
                         priority, buffer_id, out_port, send_flow_rem,
                         check_overlap, emerg, actions)

  def _handle_port_mod(self, msg_length, xid):
    if msg_length != 32:
      self.logger.error('OFPT_PORT_MOD message has invalid length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)

    port_no, hw_addr, config_ser, mask_ser, advertise_ser = \
        self._buffer.unpack('!H6sLLL4x')

    if port_no < 1 or port_no >= OFPP_MAX:
      raise ValueError('invalid physical port number', port_no)

    # For cleanliness, mask the config with the mask.
    config = ofconfig.PortConfig.deserialize(config_ser & mask_ser)
    mask = ofconfig.PortConfig.deserialize(mask_ser)
    if advertise_ser == 0:
      advertise = None
    else:
      advertise = ofconfig.PortFeatures.deserialize(advertise_ser)
    self._log_handle_msg('OFPT_PORT_MOD', port_no=port_no, hw_addr=hw_addr,
                         config=config, mask=mask, advertise=advertise)
    self.handle_port_mod(port_no, hw_addr, config, mask, advertise)

  def _handle_stats_request(self, msg_length, xid):
    if msg_length < 12:
      self.logger.error('OFPT_STATS_REQUEST message too short with length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)

    type, flags = self._buffer.unpack('!HH')
    if type not in (OFPST_DESC, OFPST_FLOW, OFPST_AGGREGATE, OFPST_TABLE,
                    OFPST_PORT, OFPST_QUEUE, OFPST_VENDOR):
      self.logger.error('OFPT_STATS_REQUEST message has invalid stats type %i',
                        type, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_STAT)
    if flags != 0:  # No flags are currently defined.
      # Be liberal. Ignore those bits instead of raising an exception.
      self.logger.debug(
          'OFPT_STATS_REQUEST message has undefined flag bits set %i',
          flags, extra=self.log_extra)

    # Decode the request body depending on the stats type.
    if type == OFPST_DESC:
      if msg_length != 12:
        self.logger.error('OFPT_STATS_REQUEST message has invalid length %i'
                          ' for OFPST_DESC stats',
                          msg_length, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_LEN)
      self._log_handle_msg('OFPT_STATS_REQUEST / OFPST_DESC')
      self.handle_stats_request_desc(xid)
    elif type == OFPST_FLOW:
      if msg_length != (12 + 44):
        self.logger.error('OFPT_STATS_REQUEST message has invalid length %i'
                          ' for OFPST_FLOW stats',
                          msg_length, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_LEN)
      match = ofmatch.Match.deserialize(self._buffer)
      table_id, out_port = self._buffer.unpack('!BxH')
      self._log_handle_msg('OFPT_STATS_REQUEST / OFPST_FLOW', match=match,
                           table_id=table_id, out_port=out_port)
      self.handle_stats_request_flow(xid, match, table_id, out_port)
    elif type == OFPST_AGGREGATE:
      if msg_length != (12 + 44):
        self.logger.error('OFPT_STATS_REQUEST message has invalid length %i'
                          ' for OFPST_AGGREGATE stats',
                          msg_length, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_LEN)
      match = ofmatch.Match.deserialize(self._buffer)
      table_id, out_port = self._buffer.unpack('!BxH')
      self._log_handle_msg('OFPT_STATS_REQUEST / OFPST_AGGREGATE', match=match,
                           table_id=table_id, out_port=out_port)
      self.handle_stats_request_aggregate(xid, match, table_id, out_port)
    elif type == OFPST_TABLE:
      if msg_length != 12:
        self.logger.error('OFPT_STATS_REQUEST message has invalid length %i'
                          ' for OFPST_TABLE stats',
                          msg_length, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_LEN)
      self._log_handle_msg('OFPT_STATS_REQUEST / OFPST_TABLE')
      self.handle_stats_request_table(xid)
    elif type == OFPST_PORT:
      if msg_length != (12 + 8):
        self.logger.error('OFPT_STATS_REQUEST message has invalid length %i'
                          ' for OFPST_PORT stats',
                          msg_length, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_LEN)
      port_no = self._buffer.unpack('!H6x')[0]
      self._log_handle_msg('OFPT_STATS_REQUEST / OFPST_PORT', port_no=port_no)
      self.handle_stats_request_port(xid, port_no)
    elif type == OFPST_QUEUE:
      if msg_length != (12 + 8):
        self.logger.error('OFPT_STATS_REQUEST message has invalid length %i'
                          ' for OFPST_QUEUE stats',
                          msg_length, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_LEN)
      port_no, queue_id = self._buffer.unpack('!H2xL')
      self._log_handle_msg('OFPT_STATS_REQUEST / OFPST_QUEUE', port_no=port_no,
                           queue_id=queue_id)
      self.handle_stats_request_queue(xid, port_no, queue_id)
    elif type == OFPST_VENDOR:
      if msg_length < (12 + 4):
        self.logger.error('OFPT_STATS_REQUEST message too short with length '
                          '%i for OFPST_VENDOR stats',
                          msg_length, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_LEN)
      vendor_id = self._buffer.unpack('!L')[0]
      vendor_handler = self._vendor_handlers.get(vendor_id)
      if vendor_handler is None:
        self.logger.error(
            'OFPT_STATS_REQUEST message has unknown vendor id %i',
            vendor_id, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_VENDOR)
      self._log_handle_msg('OFPT_STATS_REQUEST / OFPST_VENDOR',
                           vendor_id=vendor_id)
      vendor_handler.handle_vendor_stats_request(
          msg_length, xid, self._buffer)

  def _handle_stats_reply(self, msg_length, xid):
    if msg_length < 12:
      self.logger.error('OFPT_STATS_REPLY message too short with length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)

    type, flags = self._buffer.unpack('!HH')
    if type not in (OFPST_DESC, OFPST_FLOW, OFPST_AGGREGATE, OFPST_TABLE,
                    OFPST_PORT, OFPST_QUEUE, OFPST_VENDOR):
      raise ValueError('invalid stats type', type)
    if flags & ~OFPSF_REPLY_MORE:
      # Be liberal. Ignore those bits instead of raising an exception.
      self.logger.debug(
          'OFPT_STATS_REPLY message has undefined flag bits set %i',
          flags, extra=self.log_extra)
    reply_more = bool(flags & OFPSF_REPLY_MORE)

    # Decode the request body depending on the stats type.
    if type == OFPST_DESC:
      if reply_more:
        raise ValueError('OFPSF_REPLY_MORE bit set for OFPST_DESC stats')
      if msg_length != (12 + 1056):
        self.logger.error('OFPT_STATS_REPLY message has invalid length %i'
                          ' for OFPST_DESC stats',
                          msg_length, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_LEN)
      desc_stats = ofstats.DescriptionStats.deserialize(self._buffer)
      self._log_handle_msg('OFPT_STATS_REPLY / OFPST_DESC',
                           desc_stats=desc_stats)
      self.handle_stats_reply_desc(xid, desc_stats)
    elif type == OFPST_FLOW:
      flow_stats = []
      while self._buffer.message_bytes_left > 0:
        flow_stats.append(ofstats.FlowStats.deserialize(
            self._buffer, self.deserialize_action))
      flow_stats = tuple(flow_stats)
      self._log_handle_msg('OFPT_STATS_REPLY / OFPST_FLOW',
                           flow_stats=flow_stats, reply_more=reply_more)
      self.handle_stats_reply_flow(xid, flow_stats, reply_more)
    elif type == OFPST_AGGREGATE:
      if reply_more:
        raise ValueError('OFPSF_REPLY_MORE bit set for OFPST_AGGREGATE stats')
      if msg_length != (12 + 24):
        self.logger.error('OFPT_STATS_REPLY message has invalid length %i'
                          ' for OFPST_AGGREGATE stats',
                          msg_length, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_LEN)
      packet_count, byte_count, flow_count = self._buffer.unpack('!QQL4x')
      self._log_handle_msg('OFPT_STATS_REPLY / OFPST_AGGREGATE',
                           packet_count=packet_count, byte_count=byte_count,
                           flow_count=flow_count)
      self.handle_stats_reply_aggregate(xid, packet_count, byte_count,
                                        flow_count)
    elif type == OFPST_TABLE:
      if (msg_length - 12) % 64 != 0:
        self.logger.error('OFPT_STATS_REPLY message has invalid length %i'
                          ' for OFPST_TABLE stats',
                          msg_length, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_LEN)
      table_stats = []
      while self._buffer.message_bytes_left > 0:
        table_stats.append(ofstats.TableStats.deserialize(self._buffer))
      table_stats = tuple(table_stats)
      self._log_handle_msg('OFPT_STATS_REPLY / OFPST_TABLE',
                           table_stats=table_stats, reply_more=reply_more)
      self.handle_stats_reply_table(xid, table_stats, reply_more)
    elif type == OFPST_PORT:
      if (msg_length - 12) % 104 != 0:
        self.logger.error('OFPT_STATS_REPLY message has invalid length %i'
                          ' for OFPST_PORT stats',
                          msg_length, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_LEN)
      port_stats = []
      while self._buffer.message_bytes_left > 0:
        port_stats.append(ofstats.PortStats.deserialize(self._buffer))
      port_stats = tuple(port_stats)
      self._log_handle_msg('OFPT_STATS_REPLY / OFPST_PORT',
                           port_stats=port_stats, reply_more=reply_more)
      self.handle_stats_reply_port(xid, port_stats, reply_more)
    elif type == OFPST_QUEUE:
      if (msg_length - 12) % 32 != 0:
        self.logger.error('OFPT_STATS_REPLY message has invalid length %i'
                          ' for OFPST_QUEUE stats',
                          msg_length, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_LEN)
      queue_stats = []
      while self._buffer.message_bytes_left > 0:
        queue_stats.append(ofstats.QueueStats.deserialize(self._buffer))
      queue_stats = tuple(queue_stats)
      self._log_handle_msg('OFPT_STATS_REPLY / OFPST_QUEUE',
                           queue_stats=queue_stats, reply_more=reply_more)
      self.handle_stats_reply_queue(xid, queue_stats, reply_more)
    elif type == OFPST_VENDOR:
      if msg_length < (12 + 4):
        self.logger.error('OFPT_STATS_REPLY message too short with length '
                          '%i for OFPST_VENDOR stats',
                          msg_length, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_LEN)
      vendor_id = self._buffer.unpack('!L')[0]
      vendor_handler = self._vendor_handlers.get(vendor_id)
      if vendor_handler is None:
        self.logger.error(
            'OFPT_STATS_REPLY message has unknown vendor id %i',
            vendor_id, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_LEN)
      self._log_handle_msg('OFPT_STATS_REPLY / OFPST_VENDOR',
                           vendor_id=vendor_id)
      vendor_handler.handle_vendor_stats_reply(
          msg_length, xid, self._buffer, reply_more)

  def _handle_barrier_request(self, msg_length, xid):
    if msg_length != OFP_HEADER_LENGTH:
      self.logger.error('OFPT_BARRIER_REQUEST message has invalid length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)
    self._log_handle_msg('OFPT_BARRIER_REQUEST')
    self.handle_barrier_request(xid)

  def _handle_barrier_reply(self, msg_length, xid):
    if msg_length != OFP_HEADER_LENGTH:
      self.logger.error('OFPT_BARRIER_REPLY message has invalid length %i',
                        msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)
    self._log_handle_msg('OFPT_BARRIER_REPLY')
    self.handle_barrier_reply(xid)

  def _handle_queue_get_config_request(self, msg_length, xid):
    if msg_length != 12:
      self.logger.error(
          'OFPT_QUEUE_GET_CONFIG_REQUEST message has invalid length %i',
          msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)
    port_no = self._buffer.unpack('!H2x')[0]
    self._log_handle_msg('OFPT_QUEUE_GET_CONFIG_REQUEST',
                         port_no=port_no)
    self.handle_queue_get_config_request(xid, port_no)

  def _handle_queue_get_config_reply(self, msg_length, xid):
    if msg_length < 16:
      self.logger.error(
          'OFPT_QUEUE_GET_CONFIG_REPLY message has invalid length %i',
          msg_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                    oferror.OFPBRC_BAD_LEN)
    port_no = self._buffer.unpack('!H6x')[0]
    if port_no >= OFPP_MAX:
      raise ValueError('invalid port number', port_no)
    queues = []
    while self._buffer.message_bytes_left > 0:
      queues.append(ofconfig.PacketQueue.deserialize(self._buffer))
    queues = tuple(queues)
    self._log_handle_msg('OFPT_QUEUE_GET_CONFIG_REPLY',
                         port_no=port_no, queues=queues)
    self.handle_queue_get_config_reply(xid, port_no, queues)

  def handle_hello(self):
    """Handle the reception of a OFPT_HELLO message.

    This method does nothing and should be redefined in subclasses.
    """
    pass

  def handle_error(self, xid, error):
    """Handle the reception of a OFPT_ERROR message.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the erroneous message,
          as a 32-bit unsigned integer.
      error: The OpenflowError object that describes the error.
    """
    pass

  def handle_echo_request(self, xid, data):
    """Handle the reception of a OFPT_ECHO_REQUEST message.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      data: The data attached in the echo request, as a byte buffer.
    """
    pass

  def handle_echo_reply(self, xid, data):
    """Handle the reception of a OFPT_ECHO_REPLY message.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      data: The data attached in the echo reply, as a byte buffer.
    """
    pass

  def handle_features_request(self, xid):
    """Handle the reception of a OFPT_FEATURES_REQUEST message.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
    """
    pass

  def handle_features_reply(self, xid, switch_features):
    """Handle the reception of a OFPT_FEATURES_REPLY message.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      switch_features: A SwitchFeatures object containing the switch
          features.
    """
    pass

  def handle_get_config_request(self, xid):
    """Handle the reception of a OFPT_GET_CONFIG_REQUEST message.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
    """
    pass

  def handle_get_config_reply(self, xid, switch_config):
    """Handle the reception of a OFPT_GET_CONFIG_REPLY message.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      switch_config: A SwitchConfig object containing the switch
          configuration.
    """
    pass

  def handle_set_config(self, switch_config):
    """Handle the reception of a OFPT_SET_CONFIG message.

    This method does nothing and should be redefined in subclasses.

    Args:
      switch_config: A SwitchConfig object containing the switch configuration.
    """
    pass

  def handle_packet_in(self, buffer_id, total_len, in_port, reason, data):
    """Handle the reception of a OFPT_PACKET_IN message.

    This method does nothing and should be redefined in subclasses.

    Args:
      buffer_id: The buffer ID assigned by datapath.
      total_len: The full length of the frame.
      in_port: The port on which the frame was received.
      reason: The reason why the frame is being sent, either
          OFPR_NO_MATCH (no matching flow) or OFPR_ACTION (action
          explicitly output to controller)
      data: The Ethernet frame, as a sequence of byte buffers. The
          total length must be aligned on a 4*N+2 bytes boundary.
    """
    pass

  def handle_flow_removed(
      self, match, cookie, priority, reason, duration_sec, duration_nsec,
      idle_timeout, packet_count, byte_count):
    """Handle the reception of a OFPT_FLOW_REMOVED message.

    This method does nothing and should be redefined in subclasses.

    Args:
      match: A Match object describing the fields of the flow.
      cookie: An opaque 64-bit unsigned integer issued by the controller.
      priority: The priority level of the expired flow entry, as a
          16-bit unsigned integer.
      reason: The reason why the flow entry expired, either
          OFPRR_IDLE_TIMEOUT (flow idle time exceeded idle_timeout),
          OFPRR_HARD_TIMEOUT (time exceeded hard_timeout), or
          OFPRR_DELETE (victed by a DELETE flow mod message).
      duration_sec: Time the flow was alive in seconds, as a 32-bit
          unsigned integer.
      duration_nsec: Time flow was alive in nanoseconds beyond
          duration_sec, as a 32-bit unsigned integer.
      idle_timeout: The idle timeout from the original flow mod, as a
          16-bit unsigned integer.
      packet_count: The number of packets in the flow, as a 64-bit unsigned
          integer.
      byte_count: The number of bytes in packets in the flow, as a 64-bit
          unsigned integer.
    """
    pass

  def handle_port_status(self, reason, desc):
    """Handle the reception of a OFPT_PORT_STATUS message.

    This method does nothing and should be redefined in subclasses.

    Args:
      reason: The reason for the port status change, either OFPPR_ADD
          (the port was added), OFPPR_DELETE (the port was removed),
          or OFPPR_MODIFY (some attribute of the port has changed).
      desc: A PhyPort object defining the physical port.
    """
    pass

  def handle_packet_out(self, buffer_id, in_port, actions, data):
    """Handle the reception of a OFPT_PACKET_OUT message.

    This method does nothing and should be redefined in subclasses.

    Args:
      buffer_id: The buffer ID assigned by the datapath, as a 32-bit
          unsigned integer. If 0xffffffff, the frame is not buffered,
          and the entire frame is passed in data.
      in_port: The port from which the frame is to be sent. OFPP_NONE
          if none.
      actions: The tuple of Action* objects specifying the actions to
          perform on the frame.
      data: The entire Ethernet frame, as a sequence of byte
          buffers. Should be of length 0 if buffer_id is -1, and
          should be of length >0 otherwise.
    """
    pass

  def handle_flow_mod(
      self, match, cookie, command, idle_timeout, hard_timeout, priority,
      buffer_id, out_port, send_flow_rem, check_overlap, emerg, actions):
    """Handle the reception of a OFPT_FLOW_MOD message.

    This method does nothing and should be redefined in subclasses.

    Args:
      match: A Match object describing the fields of the flow.
      cookie: An opaque 64-bit unsigned integer issued by the
          controller. 0xffffffffffffffff is reserved and must not be
          used.
      command: The action to perform by the datapath, either
          OFPFC_ADD (add a new flow),
          OFPFC_MODIFY (modify all matching flows),
          OFPFC_MODIFY_STRICT (modify flows strictly matching wildcards),
          OFPFC_DELETE (delete all matching flows),
          or OFPFC_DELETE_STRICT (delete flows strictly matching wildcards).
      idle_timeout: The idle time before discarding in seconds, as a
          16-bit unsigned integer.
      hard_timeout: The maximum time before discarding in seconds, as
          a 16-bit unsigned integer.
      priority: The priority level of the flow entry, as a 16-bit
          unsigned integer.
      buffer_id: The buffer ID assigned by the datapath of a buffered
          packet to apply the flow to, as a 32-bit unsigned
          integer. If 0xffffffff, no buffered packet is to be applied
          the flow actions.
      out_port: For OFPFC_DELETE* commands, an output port that is
          required to be included in matching flows. If OFPP_NONE, no
          restriction applies in matching. For other commands, this is
          ignored.
      send_flow_rem: If True, send a OFPT_FLOW_REMOVED message when
          the flow expires or is deleted.
      check_overlap: If True, check for overlapping entries first,
          i.e. if there are conflicting entries with the same
          priority, the flow is not added and the modification fails.
      emerg: if True, the switch must consider this flow entry as an
          emergency entry, and only use it for forwarding when
          disconnected from the controller.
      actions: The sequence of Action* objects specifying the actions
          to perform on the flow's packets.
    """
    pass

  def handle_port_mod(self, port_no, hw_addr, config, mask, advertise):
    """Handle the reception of a OFPT_PORT_MOD message.

    The config and mask arguments can be passed in a call to patch()
    on a PortConfig object to obtain an up-to-date PortConfig.

    This method does nothing and should be redefined in subclasses.

    Args:
      port_no: The port's unique number, as a 16-bit unsigned
          integer. Must be between 1 and OFPP_MAX.
      hw_addr: The port's MAC address, as a binary string. The
          hardware address is not configurable. This is used only to
          sanity-check the request, so it must be the same as returned
          in PhyPort object.
      config: The PortConfig containing the new values of fields to
          replace. Only the fields which are True in mask are
          replaced, the others are ignored.
      mask: The PortConfig indicating which fields are to be replaced
          with values from config.
      advertise: The PortFeatures indicating the features to be
          advertised by the port. If None, the advertised features are
          not replaced.
    """
    pass

  def handle_stats_request_desc(self, xid):
    """Handle the reception of a OFPT_STATS_REQUEST / OFPST_DESC message.

    The OFPST_DESC stats contain a description of the OpenFlow switch.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
    """
    pass

  def handle_stats_request_flow(self, xid, match, table_id, out_port):
    """Handle the reception of a OFPT_STATS_REQUEST / OFPST_FLOW message.

    The OFPST_FLOW stats contain individual flow statistics.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      match: A Match object describing the fields of the flows to match.
      table_id: The ID of the table to read, as an 8-bit unsigned
          integer. 0xff for all tables or 0xfe for emergency.
      out_port: Require matching flows to include this as an output
          port. A value of OFPP_NONE indicates no restriction.
    """
    pass

  def handle_stats_request_aggregate(self, xid, match, table_id, out_port):
    """Handle the reception of a OFPT_STATS_REQUEST / OFPST_AGGREGATE message.

    The OFPST_AGGREGATE stats contain aggregate flow statistics.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      match: A Match object describing the fields of the flows to match.
      table_id: The ID of the table to read, as an 8-bit unsigned
          integer. 0xff for all tables or 0xfe for emergency.
      out_port: Require matching flows to include this as an output
          port. A value of OFPP_NONE indicates no restriction.
    """
    pass

  def handle_stats_request_table(self, xid):
    """Handle the reception of a OFPT_STATS_REQUEST / OFPST_TABLE message.

    The OFPST_TABLE stats contain flow table statistics.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
    """
    pass

  def handle_stats_request_port(self, xid, port_no):
    """Handle the reception of a OFPT_STATS_REQUEST / OFPST_PORT message.

    The OFPST_PORT stats contain statistics for a all ports (if
    port_no is OFPP_NONE) or for a single port.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      port_no: The port's unique number, as a 16-bit unsigned
          integer. If OFPP_NONE, stats for all ports are replied.
    """
    pass

  def handle_stats_request_queue(self, xid, port_no, queue_id):
    """Handle the reception of a OFPT_STATS_REQUEST / OFPST_QUEUE message.

    The OFPST_QUEUE stats contain queue statistics for a port.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      port_no: The port's unique number, as a 16-bit unsigned
          integer. If OFPP_ALL, stats for all ports are replied.
      queue_id: The queue's ID. If OFPQ_ALL, stats for all queues are
          replied.
    """
    pass

  def handle_stats_reply_desc(self, xid, desc_stats):
    """Handle the reception of a OFPT_STATS_REPLY / OFPST_DESC message.

    The OFPST_DESC stats contain a description of the OpenFlow switch.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the OFPT_STATS_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      desc_stats: A DescriptionStats that contains the switch description
          stats.
    """
    pass

  def handle_stats_reply_flow(self, xid, flow_stats, reply_more):
    """Handle the reception of a OFPT_STATS_REPLY / OFPST_FLOW message.

    The OFPST_FLOW stats contain individual flow statistics.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the OFPT_STATS_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      flow_stats: A tuple of FlowStats objects containing each the
          stats for an individual flow.
      reply_more: If True, more OFPT_STATS_REPLY will be sent after
          this one to completely reply the request. If False, this is
          the last reply to the request.
    """
    pass

  def handle_stats_reply_aggregate(self, xid, packet_count, byte_count,
                                   flow_count):
    """Handle the reception of a OFPT_STATS_REPLY / OFPST_AGGREGATE message.

    The OFPST_AGGREGATE stats contain aggregate flow statistics.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the OFPT_STATS_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      packet_count: The number of packets in aggregated flows, as a
          64-bit unsigned integer.
      byte_count: The number of bytes in aggregated flows, as a 64-bit
          unsigned integer.
      flow_count: The number of aggregated flows, as a 32-bit unsigned
          integer.
    """
    pass

  def handle_stats_reply_table(self, xid, table_stats, reply_more):
    """Handle the reception of a OFPT_STATS_REPLY / OFPST_TABLE message.

    The OFPST_TABLE stats contain flow table statistics.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the OFPT_STATS_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      table_stats: A tuple of TableStats objects containing each the
          stats for an individual table.
      reply_more: If True, more OFPT_STATS_REPLY will be sent after
          this one to completely reply the request. If False, this is
          the last reply to the request.
    """
    pass

  def handle_stats_reply_port(self, xid, port_stats, reply_more):
    """Handle the reception of a OFPT_STATS_REPLY / OFPST_PORT message.

    The OFPST_PORT stats contain statistics for individual ports.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the OFPT_STATS_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      port_stats: A tuple of PortStats objects containing each the
          stats for an individual port.
      reply_more: If True, more OFPT_STATS_REPLY will be sent after
          this one to completely reply the request. If False, this is
          the last reply to the request.
    """
    pass

  def handle_stats_reply_queue(self, xid, queue_stats, reply_more):
    """Handle the reception of a OFPT_STATS_REPLY / OFPST_QUEUE message.

    The OFPST_QUEUE stats contain queue statistics for individual queues.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the OFPT_STATS_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      queue_stats: A tuple of QueueStats objects containing each the
          stats for an individual queue.
      reply_more: If True, more OFPT_STATS_REPLY will be sent after
          this one to completely reply the request. If False, this is
          the last reply to the request.
    """
    pass

  def handle_barrier_request(self, xid):
    """Handle the reception of a OFPT_BARRIER_REQUEST message.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
    """
    pass

  def handle_barrier_reply(self, xid):
    """Handle the reception of a OFPT_BARRIER_REPLY message.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the OFPT_BARRIER_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
    """
    pass

  def handle_queue_get_config_request(self, xid, port_no):
    """Handle the reception of a OFPT_QUEUE_GET_CONFIG_REQUEST message.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      port_no: The port's unique number, as a 16-bit unsigned
          integer. This is a valid physical port, i.e. < OFPP_MAX.
    """
    pass

  def handle_queue_get_config_reply(self, xid, port_no, queues):
    """Handle the reception of a OFPT_QUEUE_GET_CONFIG_REPLY message.

    This method does nothing and should be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      port_no: The port's unique number, as a 16-bit unsigned
          integer. Must be a valid physical port, i.e. < OFPP_MAX.
      queues: A sequence of PacketQueue objects describing the port's
          queues.
    """
    pass

  def serialize_action(self, a):
    """Serialize a single action.

    Args:
      a: The Action* object to serialize into data.

    Returns:
      The sequence of byte buffers representing the serialized action,
      including the ofp_action_header.
    """
    a_ser = a.serialize()
    if a.type == ofaction.OFPAT_VENDOR:
      # If the actions is a OFPAT_VENDOR action, generate an
      # ofp_action_vendor_header for the action.
      header = struct.pack('!HHL', a.type, 8+len(a_ser), a.vendor_id)
    else:
      # Otherwise, generate an ofp_action_header for the action.
      header = struct.pack('!HH', a.type, 4+len(a_ser))
    if (len(header) + len(a_ser)) % 8 != 0:
      raise ValueError('action length not a multiple of 8', a)
    return (header, a_ser)

  def deserialize_action(self, buf):
    """Deserialize a single action from a buffer.

    Args:
      buf: A ReceiveBuffer object that contains the bytes that are the
          serialized form of the action.

    Returns:
      A new Action* object deserialized from the buffer
    """
    action_type, action_length = buf.unpack('!HH')
    if action_length < 8:
      self.logger.error('action is too short with length %i',
                        action_length, extra=self.log_extra)
      self.raise_error_with_request(oferror.OFPET_BAD_ACTION,
                                    oferror.OFPBAC_BAD_LEN)

    # Delegate the OFPAT_VENDOR actions deserialization to the
    # vendor handler.
    if action_type == ofaction.OFPAT_VENDOR:
      vendor_id = buf.unpack('!L')[0]
      vendor_handler = self._vendor_handlers.get(vendor_id)
      if vendor_handler is None:
        self.logger.error('OFPAT_VENDOR action has unknown vendor id %i',
                          vendor_id, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_ACTION,
                                      oferror.OFPBAC_BAD_VENDOR)
      a = vendor_handler.deserialize_vendor_action(action_length, buf)
      # TODO(romain): Test that the vendor handler deserialized
      # exactly action_length bytes.

    else:  # Standard action type.
      action_class = ofaction.ACTION_CLASSES.get(action_type)
      if action_class is None:
        self.logger.error('action has unknown type %i',
                          action_type, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_ACTION,
                                      oferror.OFPBAC_BAD_TYPE)
      if action_length != 4 + action_class.format_length:
        self.logger.error('action has invalid lenth %i for type %i',
                          action_length, action_type, extra=self.log_extra)
        self.raise_error_with_request(oferror.OFPET_BAD_ACTION,
                                      oferror.OFPBAC_BAD_LEN)
      a = action_class.deserialize(buf)

    return a

  def _send_message(self, type, xid=0, data=()):
    """Send an OpenFlow message prepended with a generated header.

    Args:
      type: The message type, as one of the OFPT_* constants.
      xid: The transaction id associated with this message, as a
          32-bit unsigned integer. Defaults to 0.
      data: The data in the message sent after the header, as a
          sequence of byte buffers. Defaults to an empty sequence.
    """
    length = OFP_HEADER_LENGTH + sum(len(d) for d in data)
    header = struct.pack(OFP_HEADER_FORMAT,
                         OFP_VERSION_1_0_0, type, length, xid)
    all_data = [header]
    all_data.extend(data)
    self.transport.writeSequence(all_data)

  def send_hello(self):
    """Send a OFPT_HELLO message.
    """
    self._log_send_msg('OFPT_HELLO')

    self._send_message(OFPT_HELLO)

  def send_error(self, error, xid=0):
    """Send a OFPT_ERROR message.

    Args:
      error: The OpenflowError object that describes the error.
      xid: The transaction id associated with the erroneous message,
          as a 32-bit unsigned integer. Defaults to 0.
    """
    self._log_send_msg('OFPT_ERROR', error=error)

    self._send_message(OFPT_ERROR, xid=xid, data=error.serialize())

  def send_echo_request(self, xid, data):
    """Send a OFPT_ECHO_REQUEST message.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      data: A sequence of arbitrary byte buffers to send as payload.
    """
    self._log_send_msg('OFPT_ECHO_REQUEST', data=data)

    self._send_message(OFPT_ECHO_REQUEST, xid=xid, data=data)

  def send_echo_reply(self, xid, data):
    """Send a OFPT_ECHO_REPLY message.

    Args:
      xid: The transaction id associated with the OFPT_ECHO_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      data: The payload received in the OFPT_ECHO_REQUEST message, as
          a sequence of byte buffers.
    """
    self._log_send_msg('OFPT_ECHO_REPLY', data=data)

    self._send_message(OFPT_ECHO_REPLY, xid=xid, data=data)

  def send_vendor(self, vendor_id, xid=0, data=()):
    """Send a OFPT_VENDOR message.

    Args:
      vendor_id: The OpenFlow vendor ID, as a 32-bit unsigned integer.
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer. Defaults to 0.
      data: The data in the message sent after the header, as a
          sequence of byte buffers. Defaults to an empty sequence.
    """
    self._log_send_msg('OFPT_VENDOR', vendor_id=vendor_id)

    vendor_header_data = struct.pack('!L', vendor_id)
    all_data = [vendor_header_data]
    all_data.extend(data)
    self._send_message(OFPT_VENDOR, xid=xid, data=all_data)
    # TODO(romain): Support vendor messages that require a new, unique
    # xid. In that case, generate one and return it. Otherwise, return
    # None.

  def send_features_request(self, xid):
    """Send a OFPT_FEATURES_REQUEST message.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
    """
    self._log_send_msg('OFPT_FEATURES_REQUEST')

    self._send_message(OFPT_FEATURES_REQUEST, xid=xid)

  def send_features_reply(self, xid, switch_features):
    """Send a OFPT_FEATURES_REPLY message.

    Args:
      xid: The transaction id associated with the OFPT_FEATURES_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      switch_features: A SwitchFeatures object containing the switch features.
    """
    self._log_send_msg('OFPT_FEATURES_REPLY', switch_features=switch_features)

    self._send_message(OFPT_FEATURES_REPLY, xid=xid,
                       data=switch_features.serialize())

  def send_get_config_request(self, xid):
    """Send a OFPT_GET_CONFIG_REQUEST message.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
    """
    self._log_send_msg('OFPT_GET_CONFIG_REQUEST')

    self._send_message(OFPT_GET_CONFIG_REQUEST, xid=xid)

  def send_get_config_reply(self, xid, switch_config):
    """Send a OFPT_GET_CONFIG_REPLY message.

    Args:
      xid: The transaction id associated with the OFPT_GET_CONFIG_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      switch_config: A SwitchConfig object containing the switch configuration.
    """
    self._log_send_msg('OFPT_GET_CONFIG_REPLY', switch_config=switch_config)

    self._send_message(OFPT_GET_CONFIG_REPLY, xid=xid,
                       data=switch_config.serialize())

  def send_set_config(self, switch_config):
    """Send a OFPT_SET_CONFIG message.

    Args:
      switch_config: A SwitchConfig object containing the switch configuration.
    """
    self._log_send_msg('OFPT_SET_CONFIG', switch_config=switch_config)

    self._send_message(OFPT_SET_CONFIG, data=switch_config.serialize())

  def send_packet_in(self, buffer_id, total_len, in_port, reason, data):
    """Send a OFPT_PACKET_IN message.

    Args:
      buffer_id: The buffer ID assigned by the datapath, as a 32-bit
          unsigned integer. If 0xffffffff, the frame is not buffered,
          and the entire frame must be passed in data.
      total_len: The full length of the frame.
      in_port: The port on which the frame was received.
      reason: The reason why the frame is being sent, either
          OFPR_NO_MATCH (no matching flow) or OFPR_ACTION (action
          explicitly output to controller).
      data: The Ethernet frame, as a sequence of byte buffers. The
          total length must 2 bytes minimum.
    """
    self._log_send_msg(
        'OFPT_PACKET_IN', buffer_id=buffer_id, total_len=total_len,
        in_port=in_port, reason=reason, data=data)

    if reason not in (OFPR_NO_MATCH, OFPR_ACTION):
      raise ValueError('invalid reason', reason)
    total_length = sum(len(s) for s in data)
    if total_length < 2:
      raise ValueError('data too short', total_length)
    packet_in_header_data = struct.pack('!LHHBx', buffer_id, total_len,
                                        in_port, reason)
    all_data = [packet_in_header_data]
    all_data.extend(data)
    self._send_message(OFPT_PACKET_IN, data=all_data)

  def send_flow_removed(self, match, cookie, priority, reason, duration_sec,
                        duration_nsec, idle_timeout, packet_count, byte_count):
    """Send a OFPT_FLOW_REMOVED message.

    Args:
      match: A Match object describing the fields of the flow.
      cookie: An opaque 64-bit unsigned integer issued by the controller.
      priority: The priority level of the expired flow entry, as a
          16-bit unsigned integer.
      reason: The reason why the flow entry expired, either
          OFPRR_IDLE_TIMEOUT (flow idle time exceeded idle_timeout),
          OFPRR_HARD_TIMEOUT (time exceeded hard_timeout), or
          OFPRR_DELETE (victed by a DELETE flow mod message).
      duration_sec: Time the flow was alive in seconds, as a 32-bit
          unsigned integer.
      duration_nsec: Time flow was alive in nanoseconds beyond
          duration_sec, as a 32-bit unsigned integer.
      idle_timeout: The idle timeout from the original flow mod, as a
          16-bit unsigned integer.
      packet_count: The number of packets in the flow, as a 64-bit unsigned
          integer.
      byte_count: The number of bytes in packets in the flow, as a 64-bit
          unsigned integer.
    """
    self._log_send_msg(
        'OFPT_FLOW_REMOVED', match=match, cookie=cookie, priority=priority,
        reason=reason, duration_sec=duration_sec, duration_nsec=duration_nsec,
        idle_timeout=idle_timeout, packet_count=packet_count,
        byte_count=byte_count)

    if reason not in (OFPRR_IDLE_TIMEOUT, OFPRR_HARD_TIMEOUT, OFPRR_DELETE):
      raise ValueError('invalid reason', reason)
    # This is almost the same as an ofp_flow_stats structure, but has
    # one field added (reason), and several fields removed
    # (hard_timeout, table_id), so just serialize those fields by hand
    # instead of getting a FlowStats object.
    all_data = (match.serialize(),
                struct.pack('!QHBxLLH2xQQ', cookie, priority, reason,
                            duration_sec, duration_nsec, idle_timeout,
                            packet_count, byte_count))
    self._send_message(OFPT_FLOW_REMOVED, data=all_data)

  def send_port_status(self, reason, desc):
    """Send a OFPT_PORT_STATUS message.

    Args:
      reason: The reason for the port status change, either OFPPR_ADD
          (the port was added), OFPPR_DELETE (the port was removed),
          or OFPPR_MODIFY (some attribute of the port has changed).
      desc: A PhyPort object defining the physical port.
    """
    self._log_send_msg('OFPT_PORT_STATUS', reason=reason, desc=desc)

    if reason not in (OFPPR_ADD, OFPPR_DELETE, OFPPR_MODIFY):
      raise ValueError('invalid reason', reason)
    all_data = (struct.pack('!B7x', reason), desc.serialize())
    self._send_message(OFPT_PORT_STATUS, data=all_data)

  def send_packet_out(self, buffer_id, in_port, actions, data):
    """Send a OFPT_PACKET_OUT message.

    Args:
      buffer_id: The buffer ID assigned by the datapath, as a 32-bit
          unsigned integer. If 0xffffffff, the frame is not buffered,
          and the entire frame must be passed in data.
      in_port: The port from which the frame is to be sent. OFPP_NONE
          if none.
      actions: The sequence of Action* objects specifying the actions
          to perform on the frame.
      data: The entire Ethernet frame, as a sequence of byte
          buffers. Should be of length 0 if buffer_id is -1, and
          should be of length >0 otherwise.
    """
    self._log_send_msg(
        'OFPT_PACKET_OUT', buffer_id=buffer_id, in_port=in_port,
        actions=actions, data=data)

    data_len = sum(len(d) for d in data)
    if buffer_id == 0xffffffff:
      if data_len == 0:
        raise ValueError('data non-empty for non-buffered frame')
    else:
      if data_len > 0:
        # TODO(romain): Check that the length is greater than the
        # minimum length of an Ethernet packet, although this is not
        # imposed by the OpenFlow 1.0.0 spec.
        raise ValueError('data empty for buffered frame')

    if in_port < 1 or (in_port > OFPP_MAX and in_port not in (
        OFPP_IN_PORT, OFPP_TABLE, OFPP_NORMAL, OFPP_FLOOD, OFPP_ALL,
        OFPP_CONTROLLER, OFPP_LOCAL, OFPP_NONE)):
      raise ValueError('invalid in_port', in_port)

    all_data = [struct.pack('!LHH', buffer_id, in_port, len(actions))]
    for a in actions:
      all_data.extend(self.serialize_action(a))
    all_data.extend(data)
    self._send_message(OFPT_PACKET_OUT, data=all_data)

  def send_flow_mod(self, match, cookie, command, idle_timeout, hard_timeout,
                    priority, buffer_id, out_port, send_flow_rem, check_overlap,
                    emerg, actions):
    """Send a OFPT_FLOW_MOD message.

    Args:
      match: A Match object describing the fields of the flow.
      cookie: An opaque 64-bit unsigned integer issued by the
          controller. 0xffffffffffffffff is reserved and must not be
          used.
      command: The action to perform by the datapath, either
          OFPFC_ADD (add a new flow),
          OFPFC_MODIFY (modify all matching flows),
          OFPFC_MODIFY_STRICT (modify flows strictly matching wildcards),
          OFPFC_DELETE (delete all matching flows),
          or OFPFC_DELETE_STRICT (delete flows strictly matching wildcards).
      idle_timeout: The idle time before discarding in seconds, as a
          16-bit unsigned integer.
      hard_timeout: The maximum time before discarding in seconds, as
          a 16-bit unsigned integer.
      priority: The priority level of the flow entry, as a 16-bit
          unsigned integer.
      buffer_id: The buffer ID assigned by the datapath of a buffered
          packet to apply the flow to, as a 32-bit unsigned
          integer. If 0xffffffff, no buffered packet is to be applied
          the flow actions.
      out_port: For OFPFC_DELETE* commands, an output port that is
          required to be included in matching flows. If OFPP_NONE, no
          restriction applies in matching. For other commands, this is
          ignored.
      send_flow_rem: If True, send a OFPT_FLOW_REMOVED message when
          the flow expires or is deleted.
      check_overlap: If True, check for overlapping entries first,
          i.e. if there are conflicting entries with the same
          priority, the flow is not added and the modification fails.
      emerg: if True, the switch must consider this flow entry as an
          emergency entry, and only use it for forwarding when
          disconnected from the controller.
      actions: The sequence of Action* objects specifying the actions
          to perform on the flow's packets.
    """
    self._log_send_msg(
        'OFPT_FLOW_MOD', match=match, cookie=cookie, command=command,
        idle_timeout=idle_timeout, hard_timeout=hard_timeout, priority=priority,
        buffer_id=buffer_id, out_port=out_port, send_flow_rem=send_flow_rem,
        check_overlap=check_overlap, emerg=emerg, actions=actions)

    if cookie == 0xffffffffffffffff:
      raise ValueError('reserved cookie', cookie)

    if command not in (OFPFC_ADD, OFPFC_MODIFY, OFPFC_MODIFY_STRICT,
                       OFPFC_DELETE, OFPFC_DELETE_STRICT):
      raise ValueError('invalid command', command)

    # TODO(romain): Check that the port is valid for this message
    # type. E.g. *_TABLE should be invalid?

    flags = ((OFPFF_SEND_FLOW_REM if send_flow_rem else 0)
             | (OFPFF_CHECK_OVERLAP if check_overlap else 0)
             | (OFPFF_EMERG if emerg else 0))

    all_data = [match.serialize(),
                struct.pack('!QHHHHLHH', cookie, command, idle_timeout,
                            hard_timeout, priority, buffer_id, out_port, flags)]
    for a in actions:
      all_data.extend(self.serialize_action(a))
    self._send_message(OFPT_FLOW_MOD, data=all_data)

  def send_port_mod(self, port_no, hw_addr, config, mask, advertise):
    """Send a OFPT_PORT_MOD message.

    The config and mask arguments can be obtained by calling
    get_diff() on a PortConfig object.

    Args:
      port_no: The port's unique number, as a 16-bit unsigned
          integer. Must be between 1 and OFPP_MAX.
      hw_addr: The port's MAC address, as a binary string. The
          hardware address is not configurable. This is used only to
          sanity-check the request, so it must be the same as returned
          in PhyPort object.
      config: The PortConfig containing the new values of fields to
          replace. Only the fields which are True in mask are
          replaced, the others are ignored.
      mask: The PortConfig indicating which fields are to be replaced
          with values from config.
      advertise: The PortFeatures indicating the features to be
          advertised by the port. If None or all fields are False, the
          advertised features are not replaced.
    """
    self._log_send_msg('OFPT_PORT_MOD', port_no=port_no, hw_addr=hw_addr,
                       config=config, mask=mask, advertise=advertise)

    if port_no < 1 or port_no > OFPP_MAX:
      raise ValueError('invalid physical port number', port_no)

    if advertise is None:
      advertise_ser = 0
    else:
      advertise_ser = advertise.serialize()
    # For cleanliness, mask the config with the mask.
    mask_ser = mask.serialize()
    config_ser = config.serialize() & mask_ser
    self._send_message(OFPT_PORT_MOD, data=(
        struct.pack('!H6sLLL4x', port_no, hw_addr, config_ser, mask_ser,
                    advertise_ser),))

  def _send_stats_request(self, xid, type, data=()):
    """Send a OFPT_STATS_REQUEST message to query for stats.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      type: The type of stats requested, either OFPST_DESC,
          OFPST_FLOW, OFPST_AGGREGATE, OFPST_TABLE, OFPST_PORT,
          OFPST_QUEUE, or OFPST_VENDOR.
      data: The data in the message sent after the header, as a
          sequence of byte buffers. Defaults to an empty sequence.
    """
    if type not in (OFPST_DESC, OFPST_FLOW, OFPST_AGGREGATE, OFPST_TABLE,
                    OFPST_PORT, OFPST_QUEUE, OFPST_VENDOR):
      raise ValueError('invalid stats type', type)

    # Send a ofp_stats_request structure.
    flags = 0  # No flags are currently defined.
    all_data = [struct.pack('!HH', type, flags)]
    all_data.extend(data)
    self._send_message(OFPT_STATS_REQUEST, xid=xid, data=all_data)

  def send_stats_request_desc(self, xid):
    """Send a OFPT_STATS_REQUEST message to query for switch stats.

    The OFPST_DESC stats contain a description of the OpenFlow switch.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
    """
    self._log_send_msg('OFPT_STATS_REQUEST / OFPST_DESC')

    self._send_stats_request(xid, OFPST_DESC)

  def send_stats_request_flow(self, xid, match, table_id, out_port):
    """Send a OFPT_STATS_REQUEST message to query for individual flow stats.

    The OFPST_FLOW stats contain individual flow statistics.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      match: A Match object describing the fields of the flows to match.
      table_id: The ID of the table to read, as an 8-bit unsigned
          integer. 0xff for all tables or 0xfe for emergency.
      out_port: Require matching flows to include this as an output
          port. A value of OFPP_NONE indicates no restriction.
    """
    self._log_send_msg('OFPT_STATS_REQUEST / OFPST_FLOW', match=match,
                         table_id=table_id, out_port=out_port)

    # Send a ofp_flow_stats_request structure.
    self._send_stats_request(xid, OFPST_FLOW, data=(
        match.serialize(),
        struct.pack('!BxH', table_id, out_port)))

  def send_stats_request_aggregate(self, xid, match, table_id, out_port):
    """Send a OFPT_STATS_REQUEST message to query for aggregate flow stats.

    The OFPST_AGGREGATE stats contain aggregate flow statistics.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      match: A Match object describing the fields of the flows to match.
      table_id: The ID of the table to read, as an 8-bit unsigned
          integer. 0xff for all tables or 0xfe for emergency.
      out_port: Require matching flows to include this as an output
          port. A value of OFPP_NONE indicates no restriction.
    """
    self._log_send_msg('OFPT_STATS_REQUEST / OFPST_AGGREGATE', match=match,
                       table_id=table_id, out_port=out_port)

    # Send a ofp_aggregate_stats_request structure.
    self._send_stats_request(xid, OFPST_AGGREGATE, data=(
        match.serialize(),
        struct.pack('!BxH', table_id, out_port)))

  def send_stats_request_table(self, xid):
    """Send a OFPT_STATS_REQUEST message to query for table stats.

    The OFPST_TABLE stats contain flow table statistics.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
    """
    self._log_send_msg('OFPT_STATS_REQUEST / OFPST_TABLE')

    self._send_stats_request(xid, OFPST_TABLE)

  def send_stats_request_port(self, xid, port_no):
    """Send a OFPT_STATS_REQUEST message to query for port stats.

    The OFPST_PORT stats contain statistics for a all ports (if
    port_no is OFPP_NONE) or for a single port.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      port_no: The port's unique number, as a 16-bit unsigned
          integer. If OFPP_NONE, stats for all ports are replied.
    """
    self._log_send_msg('OFPT_STATS_REQUEST / OFPST_PORT', port_no=port_no)

    # Send a ofp_port_stats_request structure.
    self._send_stats_request(xid, OFPST_PORT, data=(
        struct.pack('!H6x', port_no),))

  def send_stats_request_queue(self, xid, port_no, queue_id):
    """Send a OFPT_STATS_REQUEST message to query for queue stats.

    The OFPST_QUEUE stats contain queue statistics for a queue.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      port_no: The port's unique number, as a 16-bit unsigned
          integer. If OFPP_ALL, stats for all ports are replied.
      queue_id: The queue's ID. If OFPQ_ALL, stats for all queues are
          replied.
    """
    self._log_send_msg('OFPT_STATS_REQUEST / OFPST_QUEUE', port_no=port_no,
                       queue_id=queue_id)

    # Send a ofp_queue_stats_request structure.
    self._send_stats_request(xid, OFPST_QUEUE, data=(
        struct.pack('!H2xL', port_no, queue_id),))

  def send_stats_request_vendor(self, xid, vendor_id, data=()):
    """Send a OFPT_STATS_REQUEST message to query for vendor stats.

    The OFPST_VENDOR stats contain vendor-specific stats.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      vendor_id: The OpenFlow vendor ID, as a 32-bit unsigned integer.
      data: The data in the message sent after the header, as a
          sequence of byte buffers. Defaults to an empty sequence.
    """
    self._log_send_msg('OFPT_STATS_REQUEST / OFPST_VENDOR',
                       vendor_id=vendor_id)

    all_data = [struct.pack('!L', vendor_id)]
    all_data.extend(data)
    self._send_stats_request(xid, OFPST_VENDOR, data=all_data)

  def _send_stats_reply(self, xid, type, reply_more=False, data=()):
    """Send a OFPT_STATS_REPLY message to query for switch stats.

    Args:
      xid: The transaction id associated with the OFPT_STATS_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      type: The type of stats replied, either OFPST_DESC,
          OFPST_FLOW, OFPST_AGGREGATE, OFPST_TABLE, OFPST_PORT,
          OFPST_QUEUE, or OFPST_VENDOR.
      reply_more: If True, more OFPT_STATS_REPLY will be sent after
          this one to completely reply the request. If False, this is
          the last reply to the request.
      data: The data in the message sent after the header, as a
          sequence of byte buffers. Defaults to an empty sequence.
    """
    if type not in (OFPST_DESC, OFPST_FLOW, OFPST_AGGREGATE, OFPST_TABLE,
                    OFPST_PORT, OFPST_QUEUE, OFPST_VENDOR):
      raise ValueError('invalid stats type', type)
    # TODO(romain): Raise an exception if not reply_mode and data is empty.
    flags = (OFPSF_REPLY_MORE if reply_more else 0)
    all_data = [struct.pack('!HH', type, flags)]
    all_data.extend(data)
    self._send_message(OFPT_STATS_REPLY, xid=xid, data=all_data)

  def send_stats_reply_desc(self, xid, desc_stats):
    """Send a OFPT_STATS_REPLY message to reply switch stats.

    The OFPST_DESC stats contain a description of the OpenFlow switch.

    Args:
      xid: The transaction id associated with the OFPT_STATS_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      desc_stats: A DescriptionStats that contains the switch description
          stats.
    """
    self._log_send_msg('OFPT_STATS_REPLY / OFPST_DESC', desc_stats=desc_stats)

    self._send_stats_reply(xid, OFPST_DESC, data=(desc_stats.serialize(),))

  def send_stats_reply_flow(self, xid, flow_stats, reply_more=False):
    """Send a OFPT_STATS_REPLY message to reply individual flow stats.

    The OFPST_FLOW stats contain individual flow statistics.

    Args:
      xid: The transaction id associated with the OFPT_STATS_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      flow_stats: A sequence of FlowStats objects containing each the
          stats for an individual flow.
      reply_more: If True, more OFPT_STATS_REPLY will be sent after
          this one to completely reply the request. If False, this is
          the last reply to the request.
    """
    self._log_send_msg('OFPT_STATS_REPLY / OFPST_FLOW',
                       flow_stats=flow_stats, reply_more=reply_more)

    all_data = []
    for fs in flow_stats:
      all_data.extend(fs.serialize(self.serialize_action))
    self._send_stats_reply(xid, OFPST_FLOW, reply_more=reply_more,
                           data=all_data)

  def send_stats_reply_aggregate(self, xid, packet_count, byte_count,
                                 flow_count):
    """Send a OFPT_STATS_REPLY message to reply aggregate flow stats.

    The OFPST_AGGREGATE stats contain aggregate flow statistics.

    Args:
      xid: The transaction id associated with the OFPT_STATS_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      packet_count: The number of packets in aggregated flows, as a
          64-bit unsigned integer.
      byte_count: The number of bytes in aggregated flows, as a 64-bit
          unsigned integer.
      flow_count: The number of aggregated flows, as a 32-bit unsigned
          integer.
    """
    self._log_send_msg('OFPT_STATS_REPLY / OFPST_AGGREGATE',
                       packet_count=packet_count, byte_count=byte_count,
                       flow_count=flow_count)

    self._send_stats_reply(xid, OFPST_AGGREGATE, data=(
        struct.pack('!QQL4x', packet_count, byte_count, flow_count),))

  def send_stats_reply_table(self, xid, table_stats, reply_more=False):
    """Send a OFPT_STATS_REPLY message to reply table stats.

    The OFPST_TABLE stats contain flow table statistics.

    Args:
      xid: The transaction id associated with the OFPT_STATS_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      table_stats: A sequence of TableStats objects containing each the
          stats for an individual table.
      reply_more: If True, more OFPT_STATS_REPLY will be sent after
          this one to completely reply the request. If False, this is
          the last reply to the request.
    """
    self._log_send_msg('OFPT_STATS_REPLY / OFPST_TABLE',
                       table_stats=table_stats, reply_more=reply_more)

    self._send_stats_reply(
        xid, OFPST_TABLE, reply_more=reply_more,
        data=[ts.serialize() for ts in table_stats])

  def send_stats_reply_port(self, xid, port_stats, reply_more=False):
    """Send a OFPT_STATS_REPLY message to reply port stats.

    The OFPST_PORT stats contain statistics for individual ports.

    Args:
      xid: The transaction id associated with the OFPT_STATS_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      port_stats: A sequence of PortStats objects containing each the
          stats for an individual port.
      reply_more: If True, more OFPT_STATS_REPLY will be sent after
          this one to completely reply the request. If False, this is
          the last reply to the request.
    """
    self._log_send_msg('OFPT_STATS_REPLY / OFPST_PORT',
                       port_stats=port_stats, reply_more=reply_more)

    self._send_stats_reply(
        xid, OFPST_PORT, reply_more=reply_more,
        data=[ps.serialize() for ps in port_stats])

  def send_stats_reply_queue(self, xid, queue_stats, reply_more=False):
    """Send a OFPT_STATS_REPLY message to reply queue stats.

    The OFPST_QUEUE stats contain queue statistics for individual queues.

    Args:
      xid: The transaction id associated with the OFPT_STATS_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      queue_stats: A sequence of QueueStats objects containing each the
          stats for an individual queue.
      reply_more: If True, more OFPT_STATS_REPLY will be sent after
          this one to completely reply the request. If False, this is
          the last reply to the request.
    """
    self._log_send_msg('OFPT_STATS_REPLY / OFPST_QUEUE',
                       queue_stats=queue_stats, reply_more=reply_more)

    self._send_stats_reply(
        xid, OFPST_QUEUE, reply_more=reply_more,
        data=[qs.serialize() for qs in queue_stats])

  def send_stats_reply_vendor(self, xid, vendor_id, data=(), reply_more=False):
    """Send a OFPT_STATS_REPLY message to reply vendor stats.

    The OFPST_VENDOR stats contain vendor-specific stats.

    Args:
      xid: The transaction id associated with the OFPT_STATS_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      vendor_id: The OpenFlow vendor ID, as a 32-bit unsigned integer.
      data: The data in the message sent after the header, as a
          sequence of byte buffers. Defaults to an empty sequence.
      reply_more: If True, more OFPT_STATS_REPLY will be sent after
          this one to completely reply the request. If False, this is
          the last reply to the request.

    Returns:
      The transaction id associated with the sent request, as a 32-bit
      unsigned integer.
    """
    self._log_send_msg('OFPT_STATS_REPLY / OFPST_VENDOR', vendor_id=vendor_id)

    all_data = [struct.pack('!L', vendor_id)]
    all_data.extend(data)
    return self._send_stats_reply(xid, OFPST_VENDOR, reply_more=reply_more,
                                  data=all_data)

  def send_barrier_request(self, xid):
    """Send a OFPT_BARRIER_REQUEST message.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
    """
    self._log_send_msg('OFPT_BARRIER_REQUEST')

    self._send_message(OFPT_BARRIER_REQUEST, xid=xid)

  def send_barrier_reply(self, xid):
    """Send a OFPT_BARRIER_REPLY message.

    Args:
      xid: The transaction id associated with the OFPT_BARRIER_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
    """
    self._log_send_msg('OFPT_BARRIER_REPLY')

    self._send_message(OFPT_BARRIER_REPLY, xid=xid)

  def send_queue_get_config_request(self, xid, port_no):
    """Send a OFPT_QUEUE_GET_CONFIG_REQUEST message.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      port_no: The port's unique number, as a 16-bit unsigned
          integer. Must be a valid physical port, i.e. < OFPP_MAX.
    """
    self._log_send_msg('OFPT_QUEUE_GET_CONFIG_REQUEST', port_no=port_no)

    if port_no >= OFPP_MAX:
      raise ValueError('invalid port number', port_no)
    self._send_message(OFPT_QUEUE_GET_CONFIG_REQUEST, xid=xid,
                       data=struct.pack('!H2x', port_no))

  def send_queue_get_config_reply(self, xid, port_no, queues):
    """Send a OFPT_QUEUE_GET_CONFIG_REPLY message.

    Args:
      xid: The transaction id associated with the
          OFPT_QUEUE_GET_CONFIG_REQUEST message this is a reply to, as
          a 32-bit unsigned integer.
      port_no: The port's unique number, as a 16-bit unsigned
          integer. Must be a valid physical port, i.e. < OFPP_MAX.
      queues: A sequence of PacketQueue objects describing the port's
          queues.
    """
    self._log_send_msg('OFPT_QUEUE_GET_CONFIG_REPLY',
                       port_no=port_no, queues=queues)

    if port_no >= OFPP_MAX:
      raise ValueError('invalid port number', port_no)
    all_data = [struct.pack('!H6x', port_no)]
    for q in queues:
      all_data.extend(q.serialize())
    self._send_message(OFPT_QUEUE_GET_CONFIG_REPLY, xid=xid, data=all_data)


class OpenflowProtocolFactory(object):
  """A Twisted factory of OpenflowProtocol objects.
  """

  implements(interfaces.IProtocolFactory)
  # Note: OpenflowProtocolFactory should normally extend class
  # protocol.Factory, but that is an old-style Python class, i.e. it
  # doesn't support properties, slots, etc. So we extend object
  # instead, and implement interface IProtocolFactory completely
  # ourselves.

  def __init__(self, protocol=OpenflowProtocol, error_data_bytes=64,
               logger=logging.getLogger(''), vendor_handlers=()):
    """Initialize this OpenFlow protocol factory.

    Args:
      protocol: The class of protocol objects to create. Defaults to
          class OpenflowProtocol.
      error_data_bytes: The maximum number of bytes of erroneous
          requests to send back in an error message. Must be >= 64.
          Defaults to 64.
      logger: The Python logger used for logging in every created
          protocol object. Defaults to the root logger.
      vendor_handlers: A sequence of vendor handler classes. One
          instance of every class is instantiated (with no arguments)
          and passed to every created protocol object. Defaults to an
          empty sequence.
    """
    self._protocol = protocol
    self._error_data_bytes = error_data_bytes
    self._logger = logger
    self._vendor_handlers = vendor_handlers

  def doStart(self):
    """Called every time this is connected to a Port or Connector.
    """
    pass

  def doStop(self):
    """Called every time this is unconnected from a Port or Connector.
    """
    pass

  def buildProtocol(self, addr):
    """Create a protocol to handle a connection established to the given address.

    Args:
      addr: The address of the newly-established connection, as a
          twisted.internet.interfaces.IAddress object.

    Returns:
      An OpenflowProtocol object.
    """
    p = self._protocol()
    p.factory = self
    p.error_data_bytes = self._error_data_bytes
    p.logger = self._logger
    # TODO(romain): Also get the local host and port.
    p.log_extra={'remote_host': addr.host,
                 'remote_port': addr.port}
    # Create a protocol handler instance of every class. Set their
    # protocol attributes to the created protocol object, as a weak
    # reference to avoid hard circular references and to ease GC.
    vendor_handlers = [c() for c in self._vendor_handlers]
    for vh in vendor_handlers:
      vh.protocol = weakref.ref(p)
    p.vendor_handlers = vendor_handlers
    return p
