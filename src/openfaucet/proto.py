# Copyright (C) 2011 Midokura KK

# Implementation of the OpenFlow protocol version 1.0.0.
#
# This implements can be extended to support multiple vendor
# extensions.  A vendor extension can be implemented as an object that
# implements the following methods:
# TODO(romain): Document the vendor callback methods.

import binascii
import collections
import struct
from twisted.internet import protocol

from openfaucet import buffer


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

# Physical port config flags.
OFPPC_PORT_DOWN = 1 << 0
OFPPC_NO_STP = 1 << 1
OFPPC_NO_RECV = 1 << 2
OFPPC_NO_RECV_STP = 1 << 3
OFPPC_NO_FLOOD = 1 << 4
OFPPC_NO_FWD = 1 << 5
OFPPC_NO_PACKET_IN = 1 << 6

# Physical port state flags and constants.
OFPPS_LINK_DOWN	= 1 << 0
OFPPS_STP_LISTEN = 0 << 8  # Not learning or relaying frames.
OFPPS_STP_LEARN = 1 << 8  # Learning but not relaying frames.
OFPPS_STP_FORWARD = 2 << 8  # Learning and relaying frames.
OFPPS_STP_BLOCK = 3 << 8  # Not part of spanning tree.
OFPPS_STP_MASK = 3 << 8

# Physical port features flags.
OFPPF_10MB_HD = 1 << 0
OFPPF_10MB_FD = 1 << 1
OFPPF_100MB_HD = 1 << 2
OFPPF_100MB_FD = 1 << 3
OFPPF_1GB_HD = 1 << 4
OFPPF_1GB_FD = 1 << 5
OFPPF_10GB_FD = 1 << 6
OFPPF_COPPER = 1 << 7
OFPPF_FIBER = 1 << 8
OFPPF_AUTONEG = 1 << 9
OFPPF_PAUSE = 1 << 10
OFPPF_PAUSE_ASYM = 1 << 11

# Datapath features capabilities flags.
OFPC_FLOW_STATS = 1 << 0
OFPC_TABLE_STATS = 1 << 1
OFPC_PORT_STATS = 1 << 2
OFPC_STP = 1 << 3
OFPC_RESERVED = 1 << 4
OFPC_IP_REASM = 1 << 5
OFPC_QUEUE_STATS = 1 << 6
OFPC_ARP_MATCH_IP = 1 << 7

# Datapath config flags.
OFPC_FRAG_NORMAL = 0
OFPC_FRAG_DROP = 1
OFPC_FRAG_REASM = 2
OFPC_FRAG_MASK = 3

# Reasons for OFPT_PACKET_IN messages.
OFPR_NO_MATCH = 0
OFPR_ACTION = 1

# Flow match wildcard flags.
OFPFW_IN_PORT = 1 << 0
OFPFW_DL_VLAN = 1 << 1
OFPFW_DL_SRC = 1 << 2
OFPFW_DL_DST = 1 << 3
OFPFW_DL_TYPE = 1 << 4
OFPFW_NW_PROTO = 1 << 5
OFPFW_TP_SRC = 1 << 6
OFPFW_TP_DST = 1 << 7
OFPFW_NW_SRC_SHIFT = 8
OFPFW_NW_SRC_BITS = 6
OFPFW_NW_SRC_MASK = ((1 << OFPFW_NW_SRC_BITS) - 1) << OFPFW_NW_SRC_SHIFT
OFPFW_NW_SRC_ALL = 32 << OFPFW_NW_SRC_SHIFT
OFPFW_NW_DST_SHIFT = 14
OFPFW_NW_DST_BITS = 6
OFPFW_NW_DST_MASK = ((1 << OFPFW_NW_DST_BITS) - 1) << OFPFW_NW_DST_SHIFT
OFPFW_NW_DST_ALL = 32 << OFPFW_NW_DST_SHIFT
OFPFW_DL_VLAN_PCP = 1 << 20
OFPFW_NW_TOS = 1 << 21
OFPFW_ALL = ((1 << 22) - 1)

# Reasons for OFPT_FLOW_REMOVED messages.
OFPRR_IDLE_TIMEOUT = 0
OFPRR_HARD_TIMEOUT = 1
OFPRR_DELETE = 2

# Reasons for OFPT_PORT_STATUS messages.
OFPPR_ADD = 0
OFPPR_DELETE = 1
OFPPR_MODIFY = 2


class PortFeatures(collections.namedtuple('PortFeatures', (
    # Flags to indicate the link modes.
    'mode_10mb_hd', 'mode_10mb_fd', 'mode_100mb_hd', 'mode_100mb_fd',
    'mode_1gb_hd', 'mode_1gb_fd', 'mode_10gb_fd',
    # Flags to indicate the link types.
    'copper', 'fiber',
    # Flags to indicate the link features.
    'autoneg', 'pause', 'pause_asym'))):
  """The description of the features of a physical port of an OpenFlow switch.

  The attributes of a physical port are:
    boolean flags indicating link modes:
        mode_10mb_hd: 10 Mbps half-duplex rate support.
        mode_10mb_fd: 10 Mbps full-duplex rate support.
        mode_100mb_hd: 100 Mbps half-duplex rate support.
        mode_100mb_fd: 100 Mbps full-duplex rate support.
        mode_1gb_hd: 1 Gbps half-duplex rate support.
        mode_1gb_fd: 1 Gbps full-duplex rate support.
        mode_10gb_fd: 10 Gbps full-duplex rate support.
    boolean flags indicating the link types:
        copper: Copper medium.
        fiber: Fiber medium.
    boolean flags indicating the link features:
        autoneg: Auto-negotiation.
        pause: Pause.
        pause_asym: Asymmetric pause.
  """

  __slots__ = ()

  def serialize(self):
    """Serialize this object into a 32-bit unsigned integer.

    The returned integer can be passed to deserialize() to recreate a
    copy of this object.

    Returns:
      A 32-bit unsigned integer that is a serialized form of this
      object.
    """
    return ((OFPPF_10MB_HD if self.mode_10mb_hd else 0)
            | (OFPPF_10MB_FD if self.mode_10mb_fd else 0)
            | (OFPPF_100MB_HD if self.mode_100mb_hd else 0)
            | (OFPPF_100MB_FD if self.mode_100mb_fd else 0)
            | (OFPPF_1GB_HD if self.mode_1gb_hd else 0)
            | (OFPPF_1GB_FD if self.mode_1gb_fd else 0)
            | (OFPPF_10GB_FD if self.mode_10gb_fd else 0)
            | (OFPPF_COPPER if self.copper else 0)
            | (OFPPF_FIBER if self.fiber else 0)
            | (OFPPF_AUTONEG if self.autoneg else 0)
            | (OFPPF_PAUSE if self.pause else 0)
            | (OFPPF_PAUSE_ASYM if self.pause_asym else 0))

  @classmethod
  def deserialize(cls, v):
    """Returns a PortFeatures object deserialized from an integer.

    Args:
      v: A 32-bit unsigned integer that is a serialized form of a
          PortFeatures object.

    Returns:
      A new PortFeatures object deserialized from the integer.

    Raises:
      ValueError if the integer has undefined bits set.
    """
    if v & ~((1 << 12)-1):
      # Be liberal. Ignore those bits instead of raising an exception.
      # TODO(romain): Log this.
      # ('undefined bits set', v)
      pass
    # The boolean flags are in the same order as the bits, from LSB to MSB.
    args = [bool(v & (1 << i)) for i in xrange(0, 12)]
    return PortFeatures(*args)


class PhyPort(collections.namedtuple('PhyPort', (
    'port_no', 'hw_addr', 'name',
    # Flags to indicate the behavior of the physical port.
    'config_port_down', 'config_no_stp', 'config_no_recv', 'config_no_recv_stp',
    'config_no_flood', 'config_no_fwd', 'config_no_packet_in',
    # Flags to indicate the current state of the physical port.
    'state_link_down', 'state_stp',
    'curr', 'advertised', 'supported', 'peer'))):
  """The description of a physical port of an OpenFlow switch.

  The attributes of a physical port are:
    port_no: The port's unique number, as a 16-bit unsigned integer.
    hw_addr: The port's MAC address, as a binary string.
    name: The port's human-readable name, limited to 16 characters.
    config_*: Boolean flags indicating the configuration of the port:
        config_port_down: Port is administratively down.
        config_no_stp: Disable 802.1D spanning tree on port.', '
        config_no_recv: Drop all packets except 802.1D spanning tree packets.
        config_no_recv_stp: Drop received 802.1D STP packets.
        config_no_flood: Do not include this port when flooding.', '
        config_no_fwd: Drop packets forwarded to port.
        config_no_packet_in: Do not send packet-in messages for port.
    state_*: Flags and values to indicate the current state of the port:
        state_link_down: A boolean value indicating that no physical link is
            present.
        state_stp: Indicate the STP state, either
            OFPPS_STP_LISTEN (not learning or relaying frames),
            OFPPS_STP_LEARN (learning but not relaying frames),
            OFPPS_STP_FORWARD (learning and relaying frames),
            or OFPPS_STP_BLOCK (not part of spanning tree).
    port features, as PortFeatures objects:
        curr: Current features.
        advertised: Features being advertised by the port.
        supported: Features supported by the port.
        peer: Features advertised by peer.
  """

  __slots__ = ()

  FORMAT = '!H6s16sLLLLLL'

  FORMAT_LENGTH = struct.calcsize(FORMAT)

  def serialize(self):
    """Serialize this object into an OpenFlow ofp_pyy_port.

    The returned string can be passed to deserialize() to recreate a
    copy of this object.

    Returns:
      A binary string that is a serialized form of this object into an
      OpenFlow ofp_phy_port.
    """
    config_ser = ((OFPPC_PORT_DOWN if self.config_port_down else 0)
                  | (OFPPC_NO_STP if self.config_no_stp else 0)
                  | (OFPPC_NO_RECV if self.config_no_recv else 0)
                  | (OFPPC_NO_RECV_STP if self.config_no_recv_stp else 0)
                  | (OFPPC_NO_FLOOD if self.config_no_flood else 0)
                  | (OFPPC_NO_FWD if self.config_no_fwd else 0)
                  | (OFPPC_NO_PACKET_IN if self.config_no_packet_in else 0))
    state_ser = ((OFPPS_LINK_DOWN if self.state_link_down else 0)
                 | (self.state_stp & OFPPS_STP_MASK))
    return struct.pack(
        self.FORMAT, self.port_no, self.hw_addr, self.name, config_ser,
        state_ser, self.curr.serialize(), self.advertised.serialize(),
        self.supported.serialize(), self.peer.serialize())

  @classmethod
  def deserialize(cls, buf):
    """Returns a PhyPort object deserialized from a sequence of bytes.

    Args:
      buf: A ReceiveBuffer object that contains the bytes that are the
          serialized form of the PhyPort object.

    Returns:
      A new PhyPort object deserialized from the buffer.

    Raises:
      ValueError if the buffer has an invalid number of available
      bytes, or if some elements cannot be deserialized.
    """
    (port_no, hw_addr, name, config_ser, state_ser, curr_ser, advertised_ser,
     supported_ser, peer_ser) = buf.unpack(cls.FORMAT)

    if config_ser & ~((1 << 7)-1):
      # Be liberal. Ignore those bits instead of raising an exception.
      # TODO(romain): Log this.
      # ('undefined config bits set', config_ser)
      pass
    if state_ser & ~(OFPPS_LINK_DOWN | OFPPS_STP_MASK):
      # Be liberal. Ignore those bits instead of raising an exception.
      # TODO(romain): Log this.
      # ('undefined state bits set', state_ser)
      pass

    args = [port_no, hw_addr, name.rstrip('\x00')]
    # The boolean flags are in the same order as the bits, from LSB to MSB.
    args.extend(bool(config_ser & (1 << i)) for i in xrange(0, 7))
    args.extend([bool(state_ser & OFPPS_LINK_DOWN), state_ser & OFPPS_STP_MASK,
                 PortFeatures.deserialize(curr_ser),
                 PortFeatures.deserialize(advertised_ser),
                 PortFeatures.deserialize(supported_ser),
                 PortFeatures.deserialize(peer_ser)])
    return PhyPort(*args)


class SwitchFeatures(collections.namedtuple('SwitchFeatures', (
    'datapath_id', 'n_buffers', 'n_tables',
    # Flags to indicate supported capabilities.
    'cap_flow_stats', 'cap_table_stats', 'cap_port_stats', 'cap_stp',
    'cap_ip_reasm', 'cap_queue_stats', 'cap_arp_match_ip',
    'actions', 'ports'))):
  """The features of an OpenFlow switch.

  The attributes of a datapath are:
    datapath_id: The datapath's unique ID, as a binary string.
    n_buffers: The maximum number of packets buffered at once.
    n_tables: The number of tables supported by the datapath.
    cap_*: Boolean flags indicating each the support of not of a capability:
        cap_flow_stats: Flow statistics.
        cap_table_stats: Table statistics.
        cap_port_stats: Port statistics.
        cap_stp: 802.1d spanning tree.
        cap_ip_reasm: Can reassemble IP fragments.
        cap_queue_stats: Queue statistics.
        cap_arp_match_ip: Match IP addresses in ARP packets.
    actions: The frozen set of action types that is supported by the switch.
    ports: A tuple of PhyPort objects defining the physical ports of the switch.
  """

  __slots__ = ()

  FORMAT = '!QLB3xLL'

  FORMAT_LENGTH = struct.calcsize(FORMAT)

  def serialize(self):
    """Serialize this object into an OpenFlow ofp_switch_features.

    The returned string can be passed to deserialize() to recreate a
    copy of this object.

    Returns:
      A new list of binary strings that is a serialized form of this
      object into an OpenFlow ofp_switch_features. The ofp_header
      structure is not included in the generated strings.
    """
    # Encode the ports.
    features_ser = [port.serialize() for port in self.ports]
    # Encode the rest of the features.
    capabilities_ser = ((OFPC_FLOW_STATS if self.cap_flow_stats else 0)
                        | (OFPC_TABLE_STATS if self.cap_table_stats else 0)
                        | (OFPC_PORT_STATS if self.cap_port_stats else 0)
                        | (OFPC_STP if self.cap_stp else 0)
                        | (OFPC_IP_REASM if self.cap_ip_reasm else 0)
                        | (OFPC_QUEUE_STATS if self.cap_queue_stats else 0)
                        | (OFPC_ARP_MATCH_IP if self.cap_arp_match_ip else 0))
    actions_ser = 0
    for action in self.actions:
      actions_ser |= 1 << action
    features_ser.insert(0, struct.pack(
        self.FORMAT, self.datapath_id, self.n_buffers, self.n_tables,
        capabilities_ser, actions_ser))
    return features_ser

  @classmethod
  def deserialize(cls, buf):
    """Returns a SwitchFeatures object deserialized from a sequence of bytes.

    Args:
      buf: A ReceiveBuffer object that contains the bytes that are the
          serialized form of the SwitchFeatures object.

    Returns:
      A new SwitchFeatures object deserialized from the buffer.

    Raises:
      ValueError if the buffer has an invalid number of available
      bytes, or if some elements cannot be deserialized.
    """
    (datapath_id, n_buffers, n_tables, capabilities_ser,
     actions_ser) = buf.unpack(cls.FORMAT)
    args = [datapath_id, n_buffers, n_tables]

    if capabilities_ser & OFPC_RESERVED:
      # Be liberal. Ignore those bits instead of raising an exception.
      # TODO(romain): Log this.
      # ('reserved capabilities bit set', capabilities_ser)
      pass
    if capabilities_ser & ~((1 << 8) - 1):
      # Be liberal. Ignore those bits instead of raising an exception.
      # TODO(romain): Log this.
      # ('undefined capabilities bits set', capabilities_ser)
      pass

    # The boolean flags are in the same order as the bits, from LSB to MSB.
    # Skip bit 4 as it is reserved.
    args.extend(bool(capabilities_ser & (1 << i)) for i in xrange(0, 8)
                if i != 4)

    # We don't check that all action codes are valid in OpenFlow 1.0,
    # as the spec specifies only that *should* be the case, not
    # *must*.
    actions = []
    for action in xrange(0, 32):
      if actions_ser & (1 << action):
        actions.append(action)
    args.append(frozenset(actions))
    # TODO(romain): Test that all mandatory actions are in the set.

    # Decode all ports.
    ports = []
    while buf.message_bytes_left > 0:
      # This will expectedly fail if the message is not correctly
      # aligned on 32+48*num_ports bytes.
      ports.append(PhyPort.deserialize(buf))
    args.append(tuple(ports))

    return SwitchFeatures(*args)


class SwitchConfig(collections.namedtuple('SwitchConfig', (
    'config_frag', 'miss_send_len'))):
  """The configuration of an OpenFlow switch.

  The configuration attributes of a datapath are:
    config_frag: Indicates how IP fragments should be treated, either
        OFPC_FRAG_NORMAL (no special handling for fragments),
        OFPC_FRAG_DROP (drop fragments),
        or OFPC_FRAG_REASM (reassemble, only if supported).
    miss_send_len: The maximum number of bytes of new flow that the
        datapath should send to the controller.
  """

  __slots__ = ()

  FORMAT = '!HH'

  FORMAT_LENGTH = struct.calcsize(FORMAT)

  def serialize(self):
    """Serialize this object into an OpenFlow ofp_switch_config.

    The returned string can be passed to deserialize() to recreate a
    copy of this object.

    Returns:
      A binary string that is a serialized form of this object into an
      OpenFlow ofp_switch_config. The ofp_header structure is not
      included in the generated string.
    """
    return struct.pack(self.FORMAT, self.config_frag & OFPC_FRAG_MASK,
                       self.miss_send_len)

  @classmethod
  def deserialize(cls, buf):
    """Returns a SwitchConfig object deserialized from a sequence of bytes.

    Args:
      buf: A ReceiveBuffer object that contains the bytes that are the
          serialized form of the SwitchConfig object.

    Returns:
      A new SwitchConfig object deserialized from the buffer.

    Raises:
      ValueError if the buffer has an invalid number of available
      bytes.
    """
    config_frag, miss_send_len = buf.unpack(cls.FORMAT)
    if config_frag & ~OFPC_FRAG_MASK:
      # TODO(romain): Be liberal? Zero out those bits instead of
      # raising an exception?
      raise ValueError('undefined config bits set', config_frag)
    return SwitchConfig(config_frag=config_frag, miss_send_len=miss_send_len)


class Match(collections.namedtuple('Match', (
    'in_port', 'dl_src', 'dl_dst', 'dl_vlan', 'dl_vlan_pcp', 'dl_type',
    'nw_tos', 'nw_proto', 'nw_src', 'nw_dst', 'tp_src', 'tp_dst'))):
  """The description of an OpenFlow flow entry.

  Any attribute set to None is considered wildcarded.

  The attributes of a flow entry are:
    in_port: The input port, as a 16-bit unsigned integer.
    dl_src: The MAC source address, as a binary string.
    dl_dst: The MAC destination address, as a binary string.
    dl_vlan: The input VLAN id, as a 16-bit unsigned integer.
    dl_vlan_pcp: The input VLAN priority, as a 8-bit unsigned integer.
    dl_type: The Ethernet frame type, as a 16-bit unsigned integer.
    nw_tos: The IP ToS (only the DSCP field's 6 bits), as an 8-bit
        unsigned integer.
    nw_proto: The IP protocol, or the lower 8 bits of the ARP opcode, as an
        8-bit unsigned integer.
    nw_src: The IP source address, as a tuple (address,
        prefix_length), where address is the address as a binary
        string, and prefix_length is the number of bits to match in
        the address. prefix_length must be > 0.
    nw_dst: The IP destination address, as a tuple (address,
        prefix_length), where address is the address as a binary
        string, and prefix_length is the number of bits to match in
        the address. prefix_length must be > 0.
    tp_src: The TCP/UDP source port, as a 16-bit unsigned integer.
    tp_dst: The TCP/UDP destination port, as a 16-bit unsigned integer.
  """

  __slots__ = ()

  FORMAT = '!LH6s6sHBxHBB2x4s4sHH'

  FORMAT_LENGTH = struct.calcsize(FORMAT)

  @classmethod
  def create_wildcarded(cls, in_port=None, dl_src=None, dl_dst=None,
                        dl_vlan=None, dl_vlan_pcp=None, dl_type=None,
                        nw_tos=None, nw_proto=None, nw_src=None, nw_dst=None,
                        tp_src=None, tp_dst=None):
    """Create a new Match with flow attributes wildcarded unless specified.

    Returns:
      A new Match object which attributes are set to the given values,
      or None (i.e. wildcarded) if not specified.
    """
    return Match(in_port=in_port, dl_src=dl_src, dl_dst=dl_dst,
                 dl_vlan=dl_vlan, dl_vlan_pcp=dl_vlan_pcp, dl_type=dl_type,
                 nw_tos=nw_tos, nw_proto=nw_proto, nw_src=nw_src,
                 nw_dst=nw_dst, tp_src=tp_src, tp_dst=tp_dst)

  @property
  def wildcards(self):
    """Compute the wildcard fields.

    Any attribute set to None is considered to be wildcarded.

    Returns:
      A 32-bit integer containing the wildcard flags.
    """
    wildcard_bits = ((OFPFW_IN_PORT if self.in_port is None else 0)
                     | (OFPFW_DL_VLAN if self.dl_vlan is None else 0)
                     | (OFPFW_DL_SRC if self.dl_src is None else 0)
                     | (OFPFW_DL_DST if self.dl_dst is None else 0)
                     | (OFPFW_DL_TYPE if self.dl_type is None else 0)
                     | (OFPFW_NW_PROTO if self.nw_proto is None else 0)
                     | (OFPFW_TP_SRC if self.tp_src is None else 0)
                     | (OFPFW_TP_DST if self.tp_dst is None else 0)
                     | (OFPFW_DL_VLAN_PCP if self.dl_vlan_pcp is None else 0)
                     | (OFPFW_NW_TOS if self.nw_tos is None else 0))

    if self.nw_src is None:
      wildcard_bits |= OFPFW_NW_SRC_ALL
    else:
      _, prefix_length = self.nw_src
      if prefix_length < 1 or prefix_length > 32:
        raise ValueError('invalid nw_src prefix_length', prefix_length)
      wildcard_bits |= (32 - prefix_length) << OFPFW_NW_SRC_SHIFT

    if self.nw_dst is None:
      wildcard_bits |= OFPFW_NW_DST_ALL
    else:
      _, prefix_length = self.nw_dst
      if prefix_length < 1 or prefix_length > 32:
        raise ValueError('invalid nw_dst prefix_length', prefix_length)
      wildcard_bits |= (32 - prefix_length) << OFPFW_NW_DST_SHIFT

    return wildcard_bits

  def serialize(self):
    """Serialize this object into an OpenFlow ofp_match.

    The returned string can be passed to deserialize() to recreate a
    copy of this object.

    Returns:
      A binary string that is a serialized form of this object into an
      OpenFlow ofp_match.
    """
    return struct.pack(
        self.FORMAT, self.wildcards,
        self.in_port if self.in_port is not None else 0,
        self.dl_src if self.dl_src is not None else '',
        self.dl_dst if self.dl_dst is not None else '',
        self.dl_vlan if self.dl_vlan is not None else 0,
        self.dl_vlan_pcp if self.dl_vlan_pcp is not None else 0,
        self.dl_type if self.dl_type is not None else 0,
        self.nw_tos & 0xfc if self.nw_tos is not None else 0,
        self.nw_proto if self.nw_proto is not None else 0,
        self.nw_src[0] if self.nw_src is not None else '',
        self.nw_dst[0] if self.nw_dst is not None else '',
        self.tp_src if self.tp_src is not None else 0,
        self.tp_dst if self.tp_dst is not None else 0)

  @classmethod
  def deserialize(cls, buf):
    """Returns a Match object deserialized from a sequence of bytes.

    Args:
      buf: A ReceiveBuffer object that contains the bytes that are the
          serialized form of the Match object.

    Returns:
      A new Match object deserialized from the buffer.

    Raises:
      ValueError if the buffer has an invalid number of available
      bytes, or if some elements cannot be deserialized.
    """
    (wildcards, in_port, dl_src, dl_dst, dl_vlan, dl_vlan_pcp, dl_type, nw_tos,
     nw_proto, nw_src, nw_dst, tp_src, tp_dst) = buf.unpack(cls.FORMAT)

    # Be liberal. Ignore undefined wildcards bits that are set.

    # In OpenFlow 1.0.0, the "nw_tos" field doesn't contain the whole
    # IP TOS field, only the 6 bits of the DSCP field in mask
    # 0xfc. The 2 LSBs don't have any meaning and must be ignored.
    if nw_tos & 0x03:
      # Be liberal. Zero out those bits instead of raising an exception.
      # TODO(romain): Log this.
      # ('unused lower bits in nw_tos are set', nw_tos)
      nw_tos &= 0xfc

    nw_src_prefix_length = 32 - (
        (wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT)
    nw_dst_prefix_length = 32 - (
        (wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT)
    return Match(
        None if wildcards & OFPFW_IN_PORT else in_port,
        None if wildcards & OFPFW_DL_SRC else dl_src,
        None if wildcards & OFPFW_DL_DST else dl_dst,
        None if wildcards & OFPFW_DL_VLAN else dl_vlan,
        None if wildcards & OFPFW_DL_VLAN_PCP else dl_vlan_pcp,
        None if wildcards & OFPFW_DL_TYPE else dl_type,
        None if wildcards & OFPFW_NW_TOS else nw_tos,
        None if wildcards & OFPFW_NW_PROTO else nw_proto,
        (nw_src, nw_src_prefix_length) if nw_src_prefix_length > 0 else None,
        (nw_dst, nw_dst_prefix_length) if nw_dst_prefix_length > 0 else None,
        None if wildcards & OFPFW_TP_SRC else tp_src,
        None if wildcards & OFPFW_TP_DST else tp_dst)


class OpenflowProtocol(protocol.Protocol):
  """An implementation of the OpenFlow 1.0 protocol.

  This protocol implementation is stateless and only implements
  message encoding / decoding.
  """

  __slots__ = ('_buffer', '_next_xid', '_vendor_handlers', '_error_data_bytes')

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
    self._next_xid = 0
    # TODO(romain): Notify that the connection has been made?

  def _get_next_xid(self):
    """Get the next transaction id to send in a request message

    Returns:
      The next transaction id as a 32-bit unsigned integer.
    """
    xid = self._next_xid
    # Simply increment, and wrap to 32-bit.
    self._next_xid = (self._next_xid + 1) & 0xffffffff
    return xid

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
    if msg_length < 8 + SwitchFeatures.FORMAT_LENGTH:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_FEATURES_REPLY message too short')
    if ((msg_length - 8 - SwitchFeatures.FORMAT_LENGTH)
        % PhyPort.FORMAT_LENGTH) != 0:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_FEATURES_REPLY message not aligned properly')
    switch_features = SwitchFeatures.deserialize(self._buffer)
    self.handle_features_reply(xid, switch_features)

  def _handle_get_config_request(self, msg_length, xid):
    if msg_length > OFP_HEADER_LENGTH:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_GET_CONFIG_REQUEST message has invalid length')
    self.handle_get_config_request(xid)

  def _handle_get_config_reply(self, msg_length, xid):
    if msg_length != OFP_HEADER_LENGTH + SwitchConfig.FORMAT_LENGTH:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_GET_CONFIG_REPLY message has invalid length')
    switch_config = SwitchConfig.deserialize(self._buffer)
    self.handle_get_config_reply(xid, switch_config)

  def _handle_set_config(self, msg_length, xid):
    if msg_length != OFP_HEADER_LENGTH + SwitchConfig.FORMAT_LENGTH:
      # TODO(romain): Log and close the connection.
      raise ValueError('OFPT_SET_CONFIG message has invalid length')
    switch_config = SwitchConfig.deserialize(self._buffer)
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
    match = Match.deserialize(self._buffer)
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
    desc = PhyPort.deserialize(self._buffer)
    self.handle_port_status(reason, desc)

  def _handle_packet_out(self, msg_length, xid):
    pass


  def _handle_flow_mod(self, msg_length, xid):
    pass


  def _handle_port_mod(self, msg_length, xid):
    pass


  def _handle_stats_request(self, msg_length, xid):
    pass


  def _handle_stats_reply(self, msg_length, xid):
    pass


  def _handle_barrier_request(self, msg_length, xid):
    pass


  def _handle_barrier_reply(self, msg_length, xid):
    pass


  def _handle_queue_get_config_request(self, msg_length, xid):
    pass


  def _handle_queue_get_config_reply(self, msg_length, xid):
    pass



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
      switch_features: A SwitchFeatures object containing the switch features.
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
      switch_config: A SwitchConfig object containing the switch configuration.
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

  def handle_packet_out(self):
    """Handle the reception of a OFPT_FIXME message.

    This method does nothing and should be redefined in subclasses.
    """

  def handle_flow_mod(self):
    """Handle the reception of a OFPT_FIXME message.

    This method does nothing and should be redefined in subclasses.
    """

  def handle_port_mod(self):
    """Handle the reception of a OFPT_FIXME message.

    This method does nothing and should be redefined in subclasses.
    """

  def handle_stats_request(self):
    """Handle the reception of a OFPT_FIXME message.

    This method does nothing and should be redefined in subclasses.
    """

  def handle_stats_reply(self):
    """Handle the reception of a OFPT_FIXME message.

    This method does nothing and should be redefined in subclasses.
    """

  def handle_barrier_request(self):
    """Handle the reception of a OFPT_FIXME message.

    This method does nothing and should be redefined in subclasses.
    """

  def handle_barrier_reply(self):
    """Handle the reception of a OFPT_FIXME message.

    This method does nothing and should be redefined in subclasses.
    """

  def handle_queue_get_config_request(self):
    """Handle the reception of a OFPT_FIXME message.

    This method does nothing and should be redefined in subclasses.
    """

  def handle_queue_get_config_reply(self):
    """Handle the reception of a OFPT_FIXME message.

    This method does nothing and should be redefined in subclasses.
    """



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

  def send_echo_request(self, data):
    """Send a OFPT_ECHO_REQUEST message.

    Args:
      data: A sequence of arbitrary byte buffers to send as payload.

    Returns:
      The transaction id associated with the sent request, as a 32-bit
      unsigned integer.
    """
    xid = self._get_next_xid()
    self._send_message(OFPT_ECHO_REQUEST, xid=xid, data=data)
    return xid

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
    # FIXME: Support vendor messages that require a new, unique
    # xid. In that case, generate one and return it. Otherwise, return
    # None.

  def send_features_request(self):
    """Send a OFPT_FEATURES_REQUEST message.

    Returns:
      The transaction id associated with the sent request, as a 32-bit
      unsigned integer.
    """
    xid = self._get_next_xid()
    self._send_message(OFPT_FEATURES_REQUEST, xid=xid)
    return xid

  def send_features_reply(self, xid, switch_features):
    """Send a OFPT_FEATURES_REPLY message.

    Args:
      xid: The transaction id associated with the OFPT_FEATURES_REQUEST
          message this is a reply to, as a 32-bit unsigned integer.
      switch_features: A SwitchFeatures object containing the switch features.
    """
    self._send_message(OFPT_FEATURES_REPLY, xid=xid,
                       data=switch_features.serialize())

  def send_get_config_request(self):
    """Send a OFPT_GET_CONFIG_REQUEST message.

    Returns:
      The transaction id associated with the sent request, as a 32-bit
      unsigned integer.
    """
    xid = self._get_next_xid()
    self._send_message(OFPT_GET_CONFIG_REQUEST, xid=xid)
    return xid

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
      actions: The list of Action* objects specifying the actions to
          perform on the frame.
      data: The entire Ethernet frame, as a sequence of byte
          buffers. Must be None if buffer_id is -1, and not None
          otherwise.
    """
    FIXME


class OpenflowProtocolRequestTracker(OpenflowProtocol):
  """An implementation of the OpenFlow 1.0 protocol.

  This class extends OpenflowProtocol to keep track of pending
  requests and to perform periodical echo requests.
  """

  def connectionMade(self):
    """Initialize the resources to manage the newly opened OpenFlow connection.

    Send a OFPT_HELLO message to the other end and start sending echo requests.
    """
    OpenflowProtocol.connectionMade(self)
    self.send_hello()
    # TODO(romain): Start sending echo requests.

  def handle_echo_request(self, xid, data):
    """Handle the reception of a OFPT_ECHO_REQUEST message.

    This method replies to the request by sending back an
    OFPT_ECHO_REPLY message with the same xid and data. This method
    may be redefined in subclasses.

    Args:
      xid: The transaction id associated with the request, as a 32-bit
          unsigned integer.
      data: The data attached in the echo request, as a byte buffer.
    """
    self.send_echo_reply(xid, (data,))
