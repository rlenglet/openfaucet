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

"""Encoding/decoding of OpenFlow 1.0.0 switch and port configuration.
"""

import collections
import struct


# Physical port config flags.
OFPPC_PORT_DOWN = 1 << 0
OFPPC_NO_STP = 1 << 1
OFPPC_NO_RECV = 1 << 2
OFPPC_NO_RECV_STP = 1 << 3
OFPPC_NO_FLOOD = 1 << 4
OFPPC_NO_FWD = 1 << 5
OFPPC_NO_PACKET_IN = 1 << 6

# Physical port state flags and constants.
OFPPS_LINK_DOWN = 1 << 0
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

# Properties of packet queues.
OFPQT_NONE = 0  # No property defined for queue.
OFPQT_MIN_RATE = 1  # Minimum datarate guaranteed.


class PortConfig(collections.namedtuple('PortConfig', (
    # Flags to indicate the behavior of the physical port.
    'port_down', 'no_stp', 'no_recv', 'no_recv_stp', 'no_flood', 'no_fwd',
    'no_packet_in'))):
    """The description of the config of a physical port of an OpenFlow switch.

    The configuration attributes of a physical port are boolean flags:
        port_down: Port is administratively down.
        no_stp: Disable 802.1D spanning tree on port.
        no_recv: Drop all packets except 802.1D spanning tree packets.
        no_recv_stp: Drop received 802.1D STP packets.
        no_flood: Do not include this port when flooding.
        no_fwd: Drop packets forwarded to port.
        no_packet_in: Do not send packet-in messages for port.
    """

    def get_diff(self, prev_config):
        """Get the difference between another PortConfig and this one.

        The returned config and mask can be passed in a call to
        patch() on prev_config to obtain an exact copy of this
        PortConfig, or sent in an OFPT_PORT_MOD message.

        Args:
            prev_config: The other PortConfig to compare with this one.

        Returns:
            A (config, mask) tuple, where config and mask are both
            PortConfig objects, that encodes the difference between
            prev_config and this PortConfig. The config and mask
            correspond to the config and mask fields of OpenFlow's
            ofp_port_mod struct.  The returned config and mask are
            opaque to the user, and should only be passed either to a
            call to patch() or in an OFPT_PORT_MOD message.
        """
        mask = PortConfig(*[prev_config[i] ^ self[i] for i in xrange(0, 7)])
        config = self
        # If we wanted to set to false all flags that are not set in mask,
        # we'd create a new PortConfig like
        # config = PortConfig(*[self[i] if mask[i] else False
        #                       for i in xrange(0, 7)])
        return (config, mask)

    def patch(self, config, mask):
        """Get a copy of this PortConfig with attributes replaced using a diff.

        A diff (config, mask) can be obtained by calling get_diff() on
        a PortConfig, or received in an OFPT_PORT_MOD message.

        Args:
            config: The PortConfig containing the new values of fields
                to replace. Only the fields which are True in mask are
                replaced, the others are ignored.
            mask: The PortConfig indicating which fields are to be
                replaced with values from config.

        Returns:
            A new PortConfig with fields replaced according to the diff.
        """
        return PortConfig(*[config[i] if mask[i] else self[i]
                            for i in xrange(0, 7)])

    def serialize(self):
        """Serialize this object into a 32-bit unsigned integer.

        The returned integer can be passed to deserialize() to
        recreate a copy of this object.

        Returns:
            A 32-bit unsigned integer that is a serialized form of
            this object.
        """
        return ((OFPPC_PORT_DOWN if self.port_down else 0)
                | (OFPPC_NO_STP if self.no_stp else 0)
                | (OFPPC_NO_RECV if self.no_recv else 0)
                | (OFPPC_NO_RECV_STP if self.no_recv_stp else 0)
                | (OFPPC_NO_FLOOD if self.no_flood else 0)
                | (OFPPC_NO_FWD if self.no_fwd else 0)
                | (OFPPC_NO_PACKET_IN if self.no_packet_in else 0))

    @classmethod
    def deserialize(cls, v):
        """Returns a PortConfig object deserialized from an integer.

        Args:
            v: A 32-bit unsigned integer that is a serialized form of
                a PortConfig object.

        Returns:
            A new PortConfig object deserialized from the integer.
        """
        if v & ~((1 << 7) - 1):
            # Be liberal. Ignore those bits instead of raising an
            # exception.
            # TODO(romain): Log this.
            # ('undefined bits set', v)
            pass
        # The boolean flags are in the same order as the bits, from
        # LSB to MSB.
        args = [bool(v & (1 << i)) for i in xrange(0, 7)]
        return PortConfig(*args)


class PortFeatures(collections.namedtuple('PortFeatures', (
    # Flags to indicate the link modes.
    'mode_10mb_hd', 'mode_10mb_fd', 'mode_100mb_hd', 'mode_100mb_fd',
    'mode_1gb_hd', 'mode_1gb_fd', 'mode_10gb_fd',
    # Flags to indicate the link types.
    'copper', 'fiber',
    # Flags to indicate the link features.
    'autoneg', 'pause', 'pause_asym'))):
    """The description of features of a physical port of an OpenFlow switch.

    The feature attributes of a physical port are:
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

    def serialize(self):
        """Serialize this object into a 32-bit unsigned integer.

        The returned integer can be passed to deserialize() to
        recreate a copy of this object.

        Returns:

            A 32-bit unsigned integer that is a serialized form of
            this object.
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
            v: A 32-bit unsigned integer that is a serialized form of
                a PortFeatures object.

        Returns:
            A new PortFeatures object deserialized from the integer.
        """
        if v & ~((1 << 12) - 1):
            # Be liberal. Ignore those bits instead of raising an
            # exception.
            # TODO(romain): Log this.
            # ('undefined bits set', v)
            pass
        # The boolean flags are in the same order as the bits, from
        # LSB to MSB.
        args = [bool(v & (1 << i)) for i in xrange(0, 12)]
        return PortFeatures(*args)


class PhyPort(collections.namedtuple('PhyPort', (
    'port_no', 'hw_addr', 'name', 'config',
    # Flags to indicate the current state of the physical port.
    'state_link_down', 'state_stp',
    'curr', 'advertised', 'supported', 'peer'))):
    """The description of a physical port of an OpenFlow switch.

    The attributes of a physical port are:
        port_no: The port's unique number, as a 16-bit unsigned
            integer. Must be between 1 and OFPP_MAX.
        hw_addr: The port's MAC address, as a binary string.
        name: The port's human-readable name, limited to 16 characters.
        config: A PortConfig object indicating the configuration of
            the port.
        state_*: Flags and values to indicate the port's current state:
            state_link_down: A boolean value indicating that no
                physical link is present.
            state_stp: Indicates the STP state, either
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

    FORMAT = '!H6s16sLLLLLL'

    FORMAT_LENGTH = struct.calcsize(FORMAT)

    def serialize(self):
        """Serialize this object into an OpenFlow ofp_phy_port.

        The returned string can be passed to deserialize() to recreate
        a copy of this object.

        Returns:
            A binary string that is a serialized form of this object
            into an OpenFlow ofp_phy_port.
        """
        state_ser = ((OFPPS_LINK_DOWN if self.state_link_down else 0)
                     | (self.state_stp & OFPPS_STP_MASK))
        return struct.pack(
            self.FORMAT, self.port_no, self.hw_addr, self.name,
            self.config.serialize(), state_ser, self.curr.serialize(),
            self.advertised.serialize(), self.supported.serialize(),
            self.peer.serialize())

    @classmethod
    def deserialize(cls, buf):
        """Returns a PhyPort object deserialized from a sequence of bytes.

        Args:
            buf: A ReceiveBuffer object that contains the bytes that
                are the serialized form of the PhyPort object.

        Returns:
            A new PhyPort object deserialized from the buffer.

        Raises:
            ValueError: The buffer has an invalid number of available
                bytes, or some elements cannot be deserialized.
        """
        (port_no, hw_addr, name, config_ser, state_ser, curr_ser,
         advertised_ser, supported_ser, peer_ser) = buf.unpack(cls.FORMAT)

        if state_ser & ~(OFPPS_LINK_DOWN | OFPPS_STP_MASK):
            # Be liberal. Ignore those bits instead of raising an
            # exception.
            # TODO(romain): Log this.
            # ('undefined state bits set', state_ser)
            pass

        return PhyPort(port_no, hw_addr, name.rstrip('\x00'),
                       PortConfig.deserialize(config_ser),
                       bool(state_ser & OFPPS_LINK_DOWN),
                       state_ser & OFPPS_STP_MASK,
                       PortFeatures.deserialize(curr_ser),
                       PortFeatures.deserialize(advertised_ser),
                       PortFeatures.deserialize(supported_ser),
                       PortFeatures.deserialize(peer_ser))


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
        cap_*: Boolean flags indicating each the support of not of a
            capability:
            cap_flow_stats: Flow statistics.
            cap_table_stats: Table statistics.
            cap_port_stats: Port statistics.
            cap_stp: 802.1d spanning tree.
            cap_ip_reasm: Can reassemble IP fragments.
            cap_queue_stats: Queue statistics.
            cap_arp_match_ip: Match IP addresses in ARP packets.
        actions: The frozen set of action types that is supported by
            the switch.
        ports: A tuple of PhyPort objects defining the physical ports
            of the switch.
    """

    FORMAT = '!QLB3xLL'

    FORMAT_LENGTH = struct.calcsize(FORMAT)

    def serialize(self):
        """Serialize this object into an OpenFlow ofp_switch_features.

        The returned string can be passed to deserialize() to recreate
        a copy of this object.

        Returns:
            A new list of binary strings that is a serialized form of
            this object into an OpenFlow ofp_switch_features. The
            ofp_header structure is not included in the generated
            strings.
        """
        # Encode the ports.
        features_ser = [port.serialize() for port in self.ports]
        # Encode the rest of the features.
        capabilities_ser = (
            (OFPC_FLOW_STATS if self.cap_flow_stats else 0)
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
        """Returns a SwitchFeatures object deserialized from a bytes sequence.

        Args:
            buf: A ReceiveBuffer object that contains the bytes that
                are the serialized form of the SwitchFeatures object.

        Returns:
            A new SwitchFeatures object deserialized from the buffer.

        Raises:
            ValueError: The buffer has an invalid number of available
                bytes, or some elements cannot be deserialized.
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

        # The boolean flags are in the same order as the bits, from
        # LSB to MSB.  Skip bit 4 as it is reserved.
        args.extend(bool(capabilities_ser & (1 << i)) for i in xrange(0, 8)
                    if i != 4)

        # We don't check that all action codes are valid in OpenFlow
        # 1.0, as the spec specifies only that *should* be the case,
        # not *must*.
        actions = []
        for action in xrange(0, 32):
            if actions_ser & (1 << action):
                actions.append(action)
        args.append(frozenset(actions))
        # TODO(romain): Test that all mandatory actions are in the set.

        # Decode all ports.
        ports = []
        while buf.message_bytes_left > 0:
            # This will expectedly fail if the message is not
            # correctly aligned on 32+48*num_ports bytes.
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
        miss_send_len: The maximum number of bytes of new flow packets
            that the datapath should send to the controller in
            OFPT_PACKET_IN messages.
    """

    FORMAT = '!HH'

    FORMAT_LENGTH = struct.calcsize(FORMAT)

    def serialize(self):
        """Serialize this object into an OpenFlow ofp_switch_config.

        The returned string can be passed to deserialize() to recreate
        a copy of this object.

        Returns:
            A binary string that is a serialized form of this object
            into an OpenFlow ofp_switch_config. The ofp_header
            structure is not included in the generated string.
        """
        return struct.pack(self.FORMAT, self.config_frag & OFPC_FRAG_MASK,
                           self.miss_send_len)

    @classmethod
    def deserialize(cls, buf):
        """Returns a SwitchConfig object deserialized from a sequence of bytes.

        Args:
            buf: A ReceiveBuffer object that contains the bytes that
                are the serialized form of the SwitchConfig object.

        Returns:
            A new SwitchConfig object deserialized from the buffer.

        Raises:
            ValueError: The buffer has an invalid number of available
                bytes.
        """
        config_frag, miss_send_len = buf.unpack(cls.FORMAT)
        if config_frag & ~OFPC_FRAG_MASK:
            # TODO(romain): Be liberal? Zero out those bits instead of
            # raising an exception?
            raise ValueError('undefined config bits set', config_frag)
        return SwitchConfig(config_frag=config_frag,
                            miss_send_len=miss_send_len)


class PacketQueue(collections.namedtuple('PacketQueue', (
    'queue_id', 'min_rate'))):
    """The description of an OpenFlow packet queue.

    The attributes of a queue description are:
        queue_id: The queue's ID, as 32-bit unsigned integer.
        min_rate: If specified for this queue, the minimum data rate
            guaranteed, as a 16-bit unsigned integer. This value is
            given in 1/10 of a percent. If >1000, the queuing is
            disabled. If None, this property is not available for this
            queue.
    """

    FORMAT = '!LH2x'

    FORMAT_LENGTH = struct.calcsize(FORMAT)

    def serialize(self):
        """Serialize this object into an OpenFlow ofp_packet_queue.

        The returned string can be passed to deserialize() to recreate
        a copy of this object.

        Returns:
            A sequence of binary strings that is a serialized form of
            this object into an OpenFlow ofp_packet_queue and (if
            min_rate is not None) an OpenFlow ofp_queue_prop_min_rate.
        """
        all_data = []
        # There are only 2 simple types of properties currently
        # defined in the standard, one being OFPQT_NONE, so encode /
        # decode them directly here.
        if self.min_rate is not None:
            all_data.append(struct.pack('!HH4xH6x', OFPQT_MIN_RATE, 16,
                                        self.min_rate))
        length = self.FORMAT_LENGTH + sum(len(s) for s in all_data)
        all_data.insert(0, struct.pack(self.FORMAT, self.queue_id, length))
        return all_data

    @classmethod
    def deserialize(cls, buf):
        """Returns a PacketQueue object deserialized from a sequence of bytes.

        Args:
            buf: A ReceiveBuffer object that contains the bytes that
                are the serialized form of the PacketQueue object.

        Returns:
            A new PacketQueue object deserialized from the buffer.

        Raises:
            ValueError: The buffer has an invalid number of available
                bytes.
        """
        queue_id, length = buf.unpack(cls.FORMAT)
        if length < cls.FORMAT_LENGTH:
            raise ValueError('ofp_packet_queue has invalid length')
        until_bytes_left = buf.message_bytes_left + cls.FORMAT_LENGTH - length
        min_rate = None
        while buf.message_bytes_left > until_bytes_left:
            property, prop_length = buf.unpack('!HH4x')
            if property not in (OFPQT_NONE, OFPQT_MIN_RATE):
                raise ValueError('ofp_queue_prop_header has invalid property',
                                 property)
            if prop_length < 8:
                raise ValueError('ofp_queue_prop_header has invalid length',
                                 prop_length)
            if property == OFPQT_MIN_RATE:
                if prop_length != 16:
                    raise ValueError(
                        'OFPQT_MIN_RATE property has invalid length',
                        prop_length)
                min_rate = buf.unpack('!H6x')[0]
        return PacketQueue(queue_id=queue_id, min_rate=min_rate)
