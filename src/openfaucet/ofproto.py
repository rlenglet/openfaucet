# Copyright (C) 2011 Midokura KK

# Implementation of the OpenFlow protocol version 1.0.0.
#
# This implements can be extended to support multiple vendor
# extensions.  A vendor extension can be implemented as an object that
# implements the following methods:
# TODO(romain): Document the vendor callback methods.

import binascii
import collections
import random
import struct
import threading
from twisted.internet import error
from twisted.internet import protocol

from openfaucet import buffer
from openfaucet import ofaction
from openfaucet import ofconfig
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

# OpenFlow error types.
OFPET_HELLO_FAILED = 0        # Hello protocol failed.
OFPET_BAD_REQUEST = 1         # Request was not understood.
OFPET_BAD_ACTION = 2          # Error in action description.
OFPET_FLOW_MOD_FAILED = 3     # Problem modifying flow entry.
OFPET_PORT_MOD_FAILED = 4     # Port mod request failed.
OFPET_QUEUE_OP_FAILED = 5     # Queue operation failed.
# OpenFlow error codes for type OFPET_HELLO_FAILED.
OFPHFC_INCOMPATIBLE = 0
OFPHFC_EPERM = 1
# OpenFlow error codes for type OFPET_BAD_REQUEST.
OFPBRC_BAD_VERSION = 0
OFPBRC_BAD_TYPE = 1
OFPBRC_BAD_STAT = 2
OFPBRC_BAD_VENDOR = 3
OFPBRC_BAD_SUBTYPE = 4
OFPBRC_EPERM = 5
OFPBRC_BAD_LEN = 6
OFPBRC_BUFFER_EMPTY = 7
OFPBRC_BUFFER_UNKNOWN = 8
# OpenFlow error codes for type OFPET_BAD_ACTION.
OFPBAC_BAD_TYPE = 0
OFPBAC_BAD_LEN = 1
OFPBAC_BAD_VENDOR = 2
OFPBAC_BAD_VENDOR_TYPE = 3
OFPBAC_BAD_OUT_PORT = 4
OFPBAC_BAD_ARGUMENT = 5
OFPBAC_EPERM = 6
OFPBAC_TOO_MANY = 7
OFPBAC_BAD_QUEUE = 8
# OpenFlow error codes for type OFPET_FLOW_MOD_FAILED.
OFPFMFC_ALL_TABLES_FULL = 0
OFPFMFC_OVERLAP = 1
OFPFMFC_EPERM = 2
OFPFMFC_BAD_EMERG_TIMEOUT = 3
OFPFMFC_BAD_COMMAND = 4
OFPFMFC_UNSUPPORTED = 5
# OpenFlow error codes for type OFPET_PORT_MOD_FAILED.
OFPPMFC_BAD_PORT = 0
OFPPMFC_BAD_HW_ADDR = 1
# OpenFlow error codes for type OFPET_QUEUE_OP_FAILED.
OFPQOFC_BAD_PORT = 0
OFPQOFC_BAD_QUEUE = 1
OFPQOFC_EPERM = 2

OFP_ERROR_MESSAGES = {
  OFPET_HELLO_FAILED: ('hello protocol failed', {
    OFPHFC_INCOMPATIBLE: 'no compatible version',
    OFPHFC_EPERM: 'permissions error',
    }),
  OFPET_BAD_REQUEST: ('request was not understood', {
    OFPBRC_BAD_VERSION: 'ofp_header.version not supported',
    OFPBRC_BAD_TYPE: 'ofp_header.type not supported',
    OFPBRC_BAD_STAT: 'ofp_stats_request.type not supported',
    OFPBRC_BAD_VENDOR: 'vendor not supported',
    OFPBRC_BAD_SUBTYPE: 'vendor subtype not supported',
    OFPBRC_EPERM: 'permissions error',
    OFPBRC_BAD_LEN: 'wrong request length for type',
    OFPBRC_BUFFER_EMPTY: 'specified buffer has already been used',
    OFPBRC_BUFFER_UNKNOWN: 'specified buffer does not exist',
    }),
  OFPET_BAD_ACTION: ('error in action description', {
    OFPBAC_BAD_TYPE: 'unknown action type',
    OFPBAC_BAD_LEN: 'length problem in actions',
    OFPBAC_BAD_VENDOR: 'unknown vendor id specified',
    OFPBAC_BAD_VENDOR_TYPE: 'unknown action type for vendor id',
    OFPBAC_BAD_OUT_PORT: 'problem validating output action',
    OFPBAC_BAD_ARGUMENT: 'bad action argument',
    OFPBAC_EPERM: 'permissions error',
    OFPBAC_TOO_MANY: 'can\'t handle this many actions',
    OFPBAC_BAD_QUEUE: 'problem validating output queue',
    }),
  OFPET_FLOW_MOD_FAILED: ('problem modifying flow entry', {
    OFPFMFC_ALL_TABLES_FULL: 'flow not added because of full tables',
    OFPFMFC_OVERLAP:
        'attempted to add overlapping flow with CHECK_OVERLAP flag set',
    OFPFMFC_EPERM: 'permissions error',
    OFPFMFC_BAD_EMERG_TIMEOUT:
        'flow not added because of non-zero idle/hard timeout',
    OFPFMFC_BAD_COMMAND: 'unknown command',
    OFPFMFC_UNSUPPORTED:
        'unsupported action list - cannot process in the order specified',
    }),
  OFPET_PORT_MOD_FAILED: ('port mod request failed', {
    OFPPMFC_BAD_PORT: 'specified port does not exist',
    OFPPMFC_BAD_HW_ADDR: 'specified hardware address is wrong',
    }),
  OFPET_QUEUE_OP_FAILED: ('queue operation failed', {
    OFPQOFC_BAD_PORT: 'invalid port (or port does not exist)',
    OFPQOFC_BAD_QUEUE: 'queue does not exist',
    OFPQOFC_EPERM: 'permissions error',
    }),
  }

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


class OpenflowProtocol(protocol.Protocol):
  """An implementation of the OpenFlow 1.0 protocol.

  This protocol implementation is stateless and only implements
  message encoding / decoding.
  """

  __slots__ = ('_buffer', '_vendor_handlers', '_error_data_bytes')

  def __init__(self, vendor_handlers=(), error_data_bytes=64):
    """Initialize this OpenFlow protocol handler.

    Args:
      vendor_handlers: A sequence of vendor handler objects. Defaults
          to an empty sequence.
      error_data_bytes: The maximum number of bytes of erroneous
          requests to send back in error messages. Must be >= 64.
    """
    # Index the vendor handlers by vendor ID.
    # TODO(romain): Specify clearly that a vendor handler must have a
    # vendor_id attribute or property.
    self._vendor_handlers = dict((v.vendor_id, v) for v in vendor_handlers)
    self._error_data_bytes = error_data_bytes

  def connectionMade(self):
    """Initialize the resources to manage the newly opened OpenFlow connection.
    """
    self._buffer = buffer.ReceiveBuffer()
    # TODO(romain): Notify that the connection has been made?

  def connectionLost(reason):
    """Release any resources used to manage the connection that was just lost.

    Args:
      reason: A twisted.python.failure.Failure that wraps a
          twisted.internet.error.ConnectionDone or
          twisted.internet.error.ConnectionLost instance (or a
          subclass of one of those).
    """
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
      _, _, msg_length, _ = self._buffer.unpack_inplace(OFP_HEADER_FORMAT)

      if msg_length > len(self._buffer):
        # Not enough data has been received to decode the whole
        # message. Wait until more data is received. If one or more
        # message have been decoded in this loop, compact the buffer
        # to drop read bytes.
        self._buffer.compact()
        return

      self._buffer.set_message_boundaries(msg_length)

      self._handle_message()

      if self._buffer.message_bytes_left > 0:
        # TODO(romain): Log and close the connection.
        self.error_and_close('message not completely decoded')
        self._buffer.skip_bytes(self._buffer.message_bytes_left)

  def _handle_message(self):
    """Handle a received OpenFlow message.
    """
    version, msg_type, msg_length, xid = self._buffer.unpack_inplace(
        OFP_HEADER_FORMAT)
    # Keep the header for sending it back as data in error messages.
    self._received_message_header = self._buffer.read_bytes(OFP_HEADER_LENGTH)

    if version != OFP_VERSION_1_0_0:
      # TODO(romain): Log and close the connection.
      self.error_and_close('message has wrong version')

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
      # TODO(romain): Log and close the connection.
      self.error_and_close('unknown type:' + msg_type)

  def _handle_hello(self, msg_length, xid):
    # A OFPT_HELLO message has no body in the current version.
    # Implementations must be prepared to receive a hello message that
    # includes a body, ignoring its contents, to allow for later
    # extensions.
    if msg_length > OFP_HEADER_LENGTH:
      self._buffer.skip_bytes(msg_length - OFP_HEADER_LENGTH)
    self.handle_hello()

  def _handle_error(self, msg_length, xid):
    if msg_length < 12:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_ERROR message too short')
    error_type, error_code = self._buffer.unpack('!HH')

    error_type_data = OFP_ERROR_MESSAGES.get(error_type)
    if error_type_data is None:
      error_type_txt = 'unknown error type %i' % error_type
      error_code_txt = 'unknown error code %i' % error_code
    else:
      error_type_txt, error_code_txts = error_type_data
      error_code_txt = error_code_txts.get(error_code)
      if error_code_txt is None:
        error_code_txt = 'unknown error code %i' % error_code

    # Get details from the message data.
    if error_type == OFPET_HELLO_FAILED:
      if msg_length > 12:
        detail_txt = self._buffer.read_bytes(msg_length - 12)
        error_txt = '%s: %s (%s)' % (error_type_txt, error_code_txt, detail_txt)
      else:
        error_txt = '%s: %s' % (error_type_txt, error_code_txt)
    elif error_type in (OFPET_BAD_REQUEST, OFPET_BAD_ACTION,
                        OFPET_FLOW_MOD_FAILED, OFPET_PORT_MOD_FAILED,
                        OFPET_QUEUE_OP_FAILED):
      if msg_length < 76:  # data is >=64 bytes of the failed requests
        # TODO(romain): Log and close the connection.
        raise ValueError('error message of type %i too short (%i bytes)' % (
            error_type, msg_length))
      failed_req = self._buffer.read_bytes(msg_length - 12)
      error_txt = '%s: %s (%s)' % (error_type_txt, error_code_txt,
                                   binascii.b2a_hex(failed_req))

    # TODO(romain): Log the error text.

    self.handle_error(error_type, error_code, error_text, error_type_data)

  def _handle_echo_request(self, msg_length, xid):
    if msg_length > OFP_HEADER_LENGTH:
      data = self._buffer.read_bytes(msg_length - OFP_HEADER_LENGTH)
    else:
      data = ''
    self.handle_echo_request(xid, data)

  def _handle_echo_reply(self, msg_length, xid):
    if msg_length > OFP_HEADER_LENGTH:
      data = self._buffer.read_bytes(msg_length - OFP_HEADER_LENGTH)
    else:
      data = ''
    self.handle_echo_reply(xid, data)

  def _handle_vendor(self, msg_length, xid):
    if msg_length < 12:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_VENDOR message has invalid length')
    vendor_id = self._buffer.unpack('!L')[0]
    vendor_handler = self._vendor_handlers.get(vendor_id)
    if vendor_handler is None:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_VENDOR message with unknown vendor id', vendor_id)
    # TODO(romain): Specify clearly that exactly msg_length-12 bytes
    # must be consumed by this call. Check that this is the case after
    # the call returns.
    vendor_handler.handle_vendor_message(self, msg_length, xid, self._buffer)

  def _handle_features_request(self, msg_length, xid):
    if msg_length != OFP_HEADER_LENGTH:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_FEATURES_REQUEST message has invalid length')
    self.handle_features_request(xid)

  def _handle_features_reply(self, msg_length, xid):
    if msg_length < 8 + ofconfig.SwitchFeatures.FORMAT_LENGTH:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_FEATURES_REPLY message too short')
    if ((msg_length - 8 - ofconfig.SwitchFeatures.FORMAT_LENGTH)
        % ofconfig.PhyPort.FORMAT_LENGTH) != 0:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_FEATURES_REPLY message not aligned properly')
    switch_features = ofconfig.SwitchFeatures.deserialize(self._buffer)
    self.handle_features_reply(xid, switch_features)

  def _handle_get_config_request(self, msg_length, xid):
    if msg_length > OFP_HEADER_LENGTH:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_GET_CONFIG_REQUEST message has invalid length')
    self.handle_get_config_request(xid)

  def _handle_get_config_reply(self, msg_length, xid):
    if msg_length != OFP_HEADER_LENGTH + ofconfig.SwitchConfig.FORMAT_LENGTH:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_GET_CONFIG_REPLY message has invalid length')
    switch_config = ofconfig.SwitchConfig.deserialize(self._buffer)
    self.handle_get_config_reply(xid, switch_config)

  def _handle_set_config(self, msg_length, xid):
    if msg_length != OFP_HEADER_LENGTH + ofconfig.SwitchConfig.FORMAT_LENGTH:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_SET_CONFIG message has invalid length')
    switch_config = ofconfig.SwitchConfig.deserialize(self._buffer)
    self.handle_set_config(switch_config)

  def _handle_packet_in(self, msg_length, xid):
    if msg_length < 20:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_PACKET_IN message too short')
    buffer_id, total_len, in_port, reason = self._buffer.unpack('!LHHBx')
    if reason not in (OFPR_NO_MATCH, OFPR_ACTION):
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_PACKET_IN message has invalid reason', reason)
    data = self._buffer.read_bytes(msg_length - 18)
    self.handle_packet_in(buffer_id, total_len, in_port, reason, data)

  def _handle_flow_removed(self, msg_length, xid):
    if msg_length != 88:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_FLOW_REMOVED message has invalid length')
    # This is almost the same as an ofp_flow_stats structure, but has
    # one field added (reason), and several fields removed
    # (hard_timeout, table_id), so just deserialize those fields by
    # hand instead of creating a FlowStats object.
    match = ofmatch.Match.deserialize(self._buffer)
    (cookie, priority, reason, duration_sec, duration_nsec, idle_timeout,
     packet_count, byte_count) = self._buffer.unpack('!QHBxLLH2xQQ')
    if reason not in (OFPRR_IDLE_TIMEOUT, OFPRR_HARD_TIMEOUT, OFPRR_DELETE):
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_FLOW_REMOVED message has invalid reason', reason)
    self.handle_flow_removed(
        match, cookie, priority, reason, duration_sec, duration_nsec,
        idle_timeout, packet_count, byte_count)

  def _handle_port_status(self, msg_length, xid):
    if msg_length != 64:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_PORT_STATUS message has invalid length')
    (reason,) = self._buffer.unpack('!B7x')
    if reason not in (OFPPR_ADD, OFPPR_DELETE, OFPPR_MODIFY):
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_PORT_STATUS message has invalid reason', reason)
    desc = ofconfig.PhyPort.deserialize(self._buffer)
    self.handle_port_status(reason, desc)

  def _handle_packet_out(self, msg_length, xid):
    if msg_length < 16:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_PACKET_OUT message has invalid length')
    buffer_id, in_port, actions_len = self._buffer.unpack('!LHH')

    if msg_length < (16 + actions_len * 8):
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_PACKET_OUT message has invalid actions length')

    actions = tuple(self.deserialize_action(self._buffer)
                    for i in xrange(actions_len))
    data = self._buffer.read_bytes(self._buffer.message_bytes_left)
    self.handle_packet_out(buffer_id, in_port, actions, data)

  def _handle_flow_mod(self, msg_length, xid):
    if msg_length < 72:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_FLOW_MOD message has invalid length')

    match = ofmatch.Match.deserialize(self._buffer)
    (cookie, command, idle_timeout, hard_timeout, priority, buffer_id,
     out_port, flags) = self._buffer.unpack('!QHHHHLHH')

    if cookie == 0xffffffffffffffff:
      # TODO(romain): Log and close the connection.
      raise ValueError('reserved cookie', cookie)
    if command not in (OFPFC_ADD, OFPFC_MODIFY, OFPFC_MODIFY_STRICT,
                       OFPFC_DELETE, OFPFC_DELETE_STRICT):
      # TODO(romain): Log and close the connection.
      raise ValueError('invalid command', command)
    if flags & ~(OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP | OFPFF_EMERG):
      # Be liberal. Ignore those bits instead of raising an exception.
      # TODO(romain): Log this.
      # ('undefined flag bits set', flags)
      pass
    # TODO(romain): Check that the port is valid for this message
    # type. E.g. *_TABLE should be invalid?

    send_flow_rem = flags & OFPFF_SEND_FLOW_REM
    check_overlap = flags & OFPFF_CHECK_OVERLAP
    emerg = flags & OFPFF_EMERG
    actions = []
    while self._buffer.message_bytes_left > 0:
      actions.append(self.deserialize_action(self._buffer))
    actions = tuple(actions)
    self.handle_flow_mod(match, cookie, command, idle_timeout, hard_timeout,
                         priority, buffer_id, out_port, send_flow_rem,
                         check_overlap, emerg, actions)

  def _handle_port_mod(self, msg_length, xid):
    if msg_length != 32:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_PORT_MOD message has invalid length')

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
    self.handle_port_mod(port_no, hw_addr, config, mask, advertise)

  def _handle_stats_request(self, msg_length, xid):
    if msg_length < 12:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_STATS_REQUEST message too short')

    type, flags = self._buffer.unpack('!HH')
    if type not in (OFPST_DESC, OFPST_FLOW, OFPST_AGGREGATE, OFPST_TABLE,
                    OFPST_PORT, OFPST_QUEUE, OFPST_VENDOR):
      # TODO(romain): Log and close the connection.
      raise ValueError('invalid stats type', type)
    if flags != 0:  # No flags are currently defined.
      # Be liberal. Ignore those bits instead of raising an exception.
      # TODO(romain): Log this.
      # ('undefined flag bits set', flags)
      pass

    # Decode the request body depending on the stats type.
    if type == OFPST_DESC:
      if msg_length != 12:
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REQUEST message has invalid length'
                         ' for OFPST_DESC stats')
      self.handle_stats_request_desc(xid)
    elif type == OFPST_FLOW:
      if msg_length != (12 + 44):
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REQUEST message has invalid length'
                         ' for OFPST_FLOW stats')
      match = ofmatch.Match.deserialize(self._buffer)
      table_id, out_port = self._buffer.unpack('!BxH')
      self.handle_stats_request_flow(xid, match, table_id, out_port)
    elif type == OFPST_AGGREGATE:
      if msg_length != (12 + 44):
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REQUEST message has invalid length'
                         ' for OFPST_AGGREGATE stats')
      match = ofmatch.Match.deserialize(self._buffer)
      table_id, out_port = self._buffer.unpack('!BxH')
      self.handle_stats_request_aggregate(xid, match, table_id, out_port)
    elif type == OFPST_TABLE:
      if msg_length != 12:
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REQUEST message has invalid length'
                         ' for OFPST_TABLE stats')
      self.handle_stats_request_table(xid)
    elif type == OFPST_PORT:
      if msg_length != (12 + 8):
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REQUEST message has invalid length'
                         ' for OFPST_PORT stats')
      port_no = self._buffer.unpack('!H6x')[0]
      self.handle_stats_request_port(xid, port_no)
    elif type == OFPST_QUEUE:
      if msg_length != (12 + 8):
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REQUEST message has invalid length'
                         ' for OFPST_QUEUE stats')
      port_no, queue_id = self._buffer.unpack('!H2xL')
      self.handle_stats_request_queue(xid, port_no, queue_id)
    elif type == OFPST_VENDOR:
      if msg_length < (12 + 4):
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REQUEST message too short'
                         ' for OFPST_VENDOR stats')
      vendor_id = self._buffer.unpack('!L')[0]
      vendor_handler = self._vendor_handlers.get(vendor_id)
      if vendor_handler is None:
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REQUEST message with unknown vendor id',
                         vendor_id)
      vendor_handler.handle_vendor_stats_request(self, msg_length, xid,
                                                 self._buffer)

  def _handle_stats_reply(self, msg_length, xid):
    if msg_length < 12:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_STATS_REPLY message too short')

    type, flags = self._buffer.unpack('!HH')
    if type not in (OFPST_DESC, OFPST_FLOW, OFPST_AGGREGATE, OFPST_TABLE,
                    OFPST_PORT, OFPST_QUEUE, OFPST_VENDOR):
      # TODO(romain): Log and close the connection.
      raise ValueError('invalid stats type', type)
    if flags & ~OFPSF_REPLY_MORE:
      # Be liberal. Ignore those bits instead of raising an exception.
      # TODO(romain): Log this.
      # ('undefined flag bits set', flags)
      pass
    reply_more = bool(flags & OFPSF_REPLY_MORE)

    # Decode the request body depending on the stats type.
    if type == OFPST_DESC:
      if reply_more:
        raise ValueError('OFPSF_REPLY_MORE bit set for OFPST_DESC stats')
      if msg_length != (12 + 1056):
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REPLY message has invalid length'
                         ' for OFPST_DESC stats')
      desc_stats = ofstats.DescriptionStats.deserialize(self._buffer)
      self.handle_stats_reply_desc(xid, desc_stats)
    elif type == OFPST_FLOW:
      flow_stats = []
      while self._buffer.message_bytes_left > 0:
        flow_stats.append(ofstats.FlowStats.deserialize(
            self._buffer, self.deserialize_action))
      self.handle_stats_reply_flow(xid, tuple(flow_stats), reply_more)
    elif type == OFPST_AGGREGATE:
      if reply_more:
        raise ValueError('OFPSF_REPLY_MORE bit set for OFPST_AGGREGATE stats')
      if msg_length != (12 + 24):
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REPLY message has invalid length'
                         ' for OFPST_AGGREGATE stats')
      packet_count, byte_count, flow_count = self._buffer.unpack('!QQL4x')
      self.handle_stats_reply_aggregate(xid, packet_count, byte_count,
                                        flow_count)
    elif type == OFPST_TABLE:
      if (msg_length - 12) % 64 != 0:
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REPLY message has invalid length'
                         ' for OFPST_TABLE stats')
      table_stats = []
      while self._buffer.message_bytes_left > 0:
        table_stats.append(ofstats.TableStats.deserialize(self._buffer))
      self.handle_stats_reply_table(xid, tuple(table_stats), reply_more)
    elif type == OFPST_PORT:
      if (msg_length - 12) % 104 != 0:
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REPLY message has invalid length'
                         ' for OFPST_PORT stats')
      port_stats = []
      while self._buffer.message_bytes_left > 0:
        port_stats.append(ofstats.PortStats.deserialize(self._buffer))
      self.handle_stats_reply_port(xid, tuple(port_stats), reply_more)
    elif type == OFPST_QUEUE:
      if (msg_length - 12) % 32 != 0:
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REPLY message has invalid length'
                         ' for OFPST_QUEUE stats')
      queue_stats = []
      while self._buffer.message_bytes_left > 0:
        queue_stats.append(ofstats.QueueStats.deserialize(self._buffer))
      self.handle_stats_reply_queue(xid, tuple(queue_stats), reply_more)
    elif type == OFPST_VENDOR:
      if msg_length < (12 + 4):
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REPLY message too short'
                         ' for OFPST_VENDOR stats')
      vendor_id = self._buffer.unpack('!L')[0]
      vendor_handler = self._vendor_handlers.get(vendor_id)
      if vendor_handler is None:
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPT_STATS_REQUEST message with unknown vendor id',
                         vendor_id)
      vendor_handler.handle_vendor_stats_reply(self, msg_length, xid,
                                               self._buffer, reply_more)

  def _handle_barrier_request(self, msg_length, xid):
    if msg_length != OFP_HEADER_LENGTH:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_BARRIER_REQUEST message has invalid length')
    self.handle_barrier_request(xid)

  def _handle_barrier_reply(self, msg_length, xid):
    if msg_length != OFP_HEADER_LENGTH:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_BARRIER_REPLY message has invalid length')
    self.handle_barrier_reply(xid)

  def _handle_queue_get_config_request(self, msg_length, xid):
    if msg_length != 12:
      # TODO(romain): Log and close the connection.
      raise ValueError(
          'OFPT_QUEUE_GET_CONFIG_REQUEST message has invalid length')
    port_no = self._buffer.unpack('!H2x')[0]
    self.handle_queue_get_config_request(xid, port_no)

  def _handle_queue_get_config_reply(self, msg_length, xid):
    if msg_length < 16:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_QUEUE_GET_CONFIG_REPLY message too short')
    port_no = self._buffer.unpack('!H6x')[0]
    if port_no >= OFPP_MAX:
      raise ValueError('invalid port number', port_no)
    queues = []
    while self._buffer.message_bytes_left > 0:
      queues.append(ofconfig.PacketQueue.deserialize(self._buffer))
    self.handle_queue_get_config_reply(xid, port_no, tuple(queues))

  def handle_hello(self):
    """Handle the reception of a OFPT_HELLO message.

    This method does nothing and may be redefined in subclasses.
    """
    pass

  def handle_error(self, error_type, error_code, error_text, data):
    """Handle the reception of a OFPT_ERROR message.

    This method does nothing and should be redefined in subclasses.

    Args:
      error_type: The error type, as one of the OFPET_* constants.
      error_code: The error code, as one of the OFP* error code constants.
      error_text: A text representation of the error type and code.
      data: The data attached in the error message, as a byte buffer.
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

    This method does nothing and should be redefined in subclasses.

    The config and mask arguments can be passed in a call to patch()
    on a PortConfig object to obtain an up-to-date PortConfig.

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
      # TODO(romain): Log and close the connection.
      raise ValueError('invalid action length', action_length)

    # Delegate the OFPAT_VENDOR actions deserialization to the
    # vendor handler.
    if action_type == ofaction.OFPAT_VENDOR:
      vendor_id = buf.unpack('!L')[0]
      vendor_handler = self._vendor_handlers.get(vendor_id)
      if vendor_handler is None:
        # TODO(romain): Log and close the connection.
        raise ValueError('OFPAT_VENDOR action with unknown vendor id',
                         vendor_id)
      a = vendor_handler.deserialize_vendor_action(action_length, buf)
      # TODO(romain): Test that the vendor handler deserialized
      # exactly action_length bytes.

    else:  # Standard action type.
      action_class = ofaction.ACTION_TYPES.get(action_type)
      # TODO(romain): Implement support for VENDOR actions.
      if action_class is None:
        # TODO(romain): Log and close the connection.
        raise ValueError('invalid action type', action_type)
      if action_length != 4 + action_class.format_length:
        # TODO(romain): Log and close the connection.
        raise ValueError('invalid action length for type', action_type,
                         action_length)
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
    self._send_message(OFPT_HELLO)

  def send_error(self, error_type, error_code, data):
    """Send a OFPT_ERROR message.

    Args:
      error_type: The error type, as one of the OFPET_* constants.
      error_code: The error code, as one of the OFP* error code constants.
      data: The data to send in the error message, as a sequence of
          byte buffers.
    """
    error_header_data = struct.pack('!HH', error_type, error_code)
    all_data = [error_header_data]
    all_data.extend(data)
    self._send_message(OFPT_ERROR, data=all_data)

  def send_echo_request(self, xid, data):
    """Send a OFPT_ECHO_REQUEST message.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      data: A sequence of arbitrary byte buffers to send as payload.
    """
    self._send_message(OFPT_ECHO_REQUEST, xid=xid, data=data)

  def send_echo_reply(self, xid, data):
    """Send a OFPT_ECHO_REPLY message.

    Args:
      xid: The transaction id associated with the OFPT_ECHO_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      data: The payload received in the OFPT_ECHO_REQUEST message, as
          a sequence of byte buffers.
    """
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
    self._send_message(OFPT_FEATURES_REQUEST, xid=xid)

  def send_features_reply(self, xid, switch_features):
    """Send a OFPT_FEATURES_REPLY message.

    Args:
      xid: The transaction id associated with the OFPT_FEATURES_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      switch_features: A SwitchFeatures object containing the switch features.
    """
    self._send_message(OFPT_FEATURES_REPLY, xid=xid,
                       data=switch_features.serialize())

  def send_get_config_request(self, xid):
    """Send a OFPT_GET_CONFIG_REQUEST message.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
    """
    self._send_message(OFPT_GET_CONFIG_REQUEST, xid=xid)

  def send_get_config_reply(self, xid, switch_config):
    """Send a OFPT_GET_CONFIG_REPLY message.

    Args:
      xid: The transaction id associated with the OFPT_GET_CONFIG_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      switch_config: A SwitchConfig object containing the switch configuration.
    """
    self._send_message(OFPT_GET_CONFIG_REPLY, xid=xid,
                       data=switch_config.serialize())

  def send_set_config(self, switch_config):
    """Send a OFPT_SET_CONFIG message.

    Args:
      switch_config: A SwitchConfig object containing the switch configuration.
    """
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
    self._send_message(OFPT_BARRIER_REQUEST, xid=xid)

  def send_barrier_reply(self, xid):
    """Send a OFPT_BARRIER_REPLY message.

    Args:
      xid: The transaction id associated with the OFPT_BARRIER_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
    """
    self._send_message(OFPT_BARRIER_REPLY, xid=xid)

  def send_queue_get_config_request(self, xid, port_no):
    """Send a OFPT_QUEUE_GET_CONFIG_REQUEST message.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      port_no: The port's unique number, as a 16-bit unsigned
          integer. Must be a valid physical port, i.e. < OFPP_MAX.
    """
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
    if port_no >= OFPP_MAX:
      raise ValueError('invalid port number', port_no)
    all_data = [struct.pack('!H6x', port_no)]
    for q in queues:
      all_data.extend(q.serialize())
    self._send_message(OFPT_QUEUE_GET_CONFIG_REPLY, xid=xid, data=all_data)


class Callback(collections.namedtuple('Callback', (
    'callable', 'args', 'kwargs'))):
  """A callable and its arguments.

  The callable arguments are:
    args: The (possibly empty) sequence of positional arguments.
    kwargs: The dict of keyword arguments. If None, no keyword
        arguments are passed, equivalent to an empty dict.
  """

  def call(self, first_args=()):
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

    if self.kwargs is None:
      self.callable(*args)
    else:
      self.callable(*args, **kwargs)


TerminationCallbacks = collections.namedtuple('TerminationCallbacks', (
    'success_callback', 'timeout_callback', 'timeout_delayed_call'))


class OpenflowProtocolOperations(OpenflowProtocol):
  """An implementation of the OpenFlow 1.0 protocol that abstracts operations.

  This class extends OpenflowProtocol to keep track of pending
  operations (request / reply pairs) and to periodically initiate echo
  operations.
  """

  __slots__ = OpenflowProtocol.__slots__ + (
      '_reactor', '_next_xid', '_default_op_timeout',
      '_echo_op_period', '_pending_ops', '_pending_ops_lock')

  def __init__(self, reactor, vendor_handlers=(), error_data_bytes=64,
               default_op_timeout=3.0, echo_op_period=5.0):
    """Initialize this OpenFlow protocol handler.

    Args:
      reactor: An object implementing Twisted's IReactorTime
          interface, used to do delayed calls.
      vendor_handlers: A sequence of vendor handler objects. Defaults
          to an empty sequence.
      error_data_bytes: The maximum number of bytes of erroneous
          requests to send back in error messages. Must be >= 64.
      default_op_timeout: The default period, in seconds, before an
          operation times out. This value is used as the timeout for
          echo operations. Defaults to 3.0 (seconds).
      echo_op_period: The period, in seconds, between two echo
          operations. Defaults to 5 (seconds).
    """
    OpenflowProtocol.__init__(self, vendor_handlers=vendor_handlers,
                              error_data_bytes=error_data_bytes)
    self._reactor = reactor
    self._default_op_timeout = default_op_timeout
    self._echo_op_period = echo_op_period
    # Maintain a dictionary mapping XIDs and TerminationCallbacks objects.
    self._pending_ops = {}
    self._pending_ops_lock = threading.Lock()

  def connectionMade(self):
    """Initialize the resources to manage the newly opened OpenFlow connection.

    Send a OFPT_HELLO message to the other end and start initiating
    periodic echo operations.
    """
    OpenflowProtocol.connectionMade(self)
    self._next_xid = 0
    self.send_hello()
    self._echo()

  # ----------------------------------------------------------------------
  # Generic request handling API. Those methods should be called by
  # subclasses to manage requests.
  # ----------------------------------------------------------------------

  def _get_next_xid(self):
    """Get the next transaction id to send in a request message

    Returns:
      The next transaction id, to be associated with the sent request,
      as a 32-bit unsigned integer.
    """
    xid = self._next_xid
    # Simply increment, and wrap to 32-bit.
    self._next_xid = (self._next_xid + 1) & 0xffffffff
    return xid

  def _initiate_operation(self, success_callback, timeout_callback,
                          timeout=None):
    """Register an operation which request is about to be sent.

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
          out. If None, defaults to the default_op_timeout passed to
          the constructor.

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
        timeout = self._default_op_timeout
      timeout_delayed_call = self._reactor.callLater(
          timeout, self._timeout_operation, xid)
      self._pending_ops[xid] = TerminationCallbacks(
          success_callback, timeout_callback, timeout_delayed_call)
    return xid

  def _terminate_operation(self, xid, reply_more=False):
    """Handle an operation's successful termination.

    This method should be called in every handle_*_reply() method.

    Args:
      xid: The transaction id of the operation.
      reply_more: If True, more replies are expected to terminate this
          operation, so keep the status of the operation as
          pending. Defaults to False.

    Returns:
      The Callback to call. None if the operation already timed out.
    """
    with self._pending_ops_lock:
      callbacks = self._pending_ops.get(xid, None)
      if callbacks is not None:
        if not reply_more:
          del self._pending_ops[xid]
          try:
            callbacks.timeout_delayed_call.cancel()
          except error.AlreadyCalled:
            return None
        return callbacks.success_callback

  def _timeout_operation(self, xid):
    """Handle an operation's timeout.

    Args:
      xid: The transaction id of the timed out operation.
    """
    callbacks = None
    with self._pending_ops_lock:
      callbacks = self._pending_ops.pop(xid, None)
    if callbacks is not None:
      callbacks.timeout_callback.call()

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
    success_callable = self._terminate_operation(xid)
    if success_callable is not None:
      success_callable.call(first_args=(data,))

  def _echo(self):
    """Initiate an echo operation.

    The request's payload is 32 bits of pseudo-random data.
    """
    sent_data = struct.pack('!L', random.getrandbits(32))
    xid = self._initiate_operation(
        Callback(self._handle_echo_termination, (sent_data,), None),
        Callback(self._handle_echo_timeout, (), None),
        timeout=None)  # default timeout
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
      # TODO(romain): Log and close the connection, like in
      # handle_echo_timeout().
      raise ValueError('OFPT_ECHO_REPLY message has invalid data')
    # Schedule the next request.
    self._reactor.callLater(self._echo_op_period, self._echo)

  def _handle_echo_timeout(self):
    """Handle the timeout of an echo request by closing the connection.

    This method may be redefined in subclasses.
    """
    # TODO(romain): Log and close the connection.
    self.transport.loseConnection()
