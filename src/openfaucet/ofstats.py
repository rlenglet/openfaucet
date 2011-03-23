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

"""Representations and encoding/decoding of OpenFlow 1.0.0 statistics.

Vendor stats are handled specially by the OpenflowProtocol
implementation, and are not handled in this module.
"""

import collections
import struct

from openfaucet import ofmatch


class DescriptionStats(collections.namedtuple('DescriptionStats', (
    'mfr_desc', 'hw_desc', 'sw_desc', 'serial_num', 'dp_desc'))):
    """The description of an OpenFlow switch.

    The attributes of the description are:
        mfr_desc: Manufacturer description, as a string up to 256 characters.
        hw_desc: Hardware description, as a string up to 256 characters.
        sw_desc: Software description, as a string up to 256 characters.
        serial_num: Serial number, as a string up to 32 characters.
        dp_desc: Human readable description of the datapath, for
            debugging purposes, e.g. 'switch3 in room 3120', as a
            string up to 256 characters.
    """

    FORMAT = '!256s256s256s32s256s'

    FORMAT_LENGTH = struct.calcsize(FORMAT)

    def serialize(self):
        """Serialize this object into an OpenFlow ofp_desc_stats.

        The returned string can be passed to deserialize() to recreate
        a copy of this object.

        Returns:
            A binary string that is a serialized form of this object
            into an OpenFlow ofp_desc_stats. The ofp_stats_reply
            structure is not included in the generated string.
        """
        return struct.pack(self.FORMAT, self.mfr_desc, self.hw_desc,
                           self.sw_desc, self.serial_num, self.dp_desc)

    @classmethod
    def deserialize(cls, buf):
        """Returns a DescriptionStats object deserialized from a sequence of
        bytes.

        Args:
            buf: A ReceiveBuffer object that contains the bytes that
                are the serialized form of the DescriptionStats
                object.

        Returns:
            A new DescriptionStats object deserialized from the buffer.

        Raises:
            ValueError: The buffer has an invalid number of available
                bytes.
        """
        return DescriptionStats(*[s.rstrip('\x00')
                                  for s in buf.unpack(cls.FORMAT)])


class FlowStats(collections.namedtuple('FlowStats', (
    'table_id', 'match', 'duration_sec', 'duration_nsec', 'priority',
    'idle_timeout', 'hard_timeout', 'cookie', 'packet_count', 'byte_count',
    'actions'))):
    """The stats about an individual flow.

    The attributes of the flow statistics are:
        table_id: The ID of the table the flow came from.
        match: A Match object describing the fields of the flow.
        duration_sec: Time the flow has been alive in seconds, as a
            32-bit unsigned integer.
        duration_nsec: Time flow has been alive in nanoseconds beyond
            duration_sec, as a 32-bit unsigned integer.
        priority: The priority level of the flow entry, as a 16-bit
            unsigned integer.
        idle_timeout: Number of seconds idle before the flow expires,
            as a 16-bit unsigned integer.
        hard_timeout: Number of seconds before the flow expires, as a
            16-bit unsigned integer.
        cookie: An opaque 64-bit unsigned integer issued by the
            controller.
        packet_count: The number of packets in the flow, as a 64-bit
            unsigned integer.
        byte_count: The number of bytes in packets in the flow, as a
            64-bit unsigned integer.
        actions: The sequence of Action* objects specifying the
            actions to perform on the flow's packets.
    """

    FORMAT1 = '!HBx'

    FORMAT1_LENGTH = struct.calcsize(FORMAT1)

    FORMAT2 = '!LLHHH6xQQQ'

    FORMAT2_LENGTH = struct.calcsize(FORMAT2)

    def serialize(self, serialize_action):
        """Serialize this object into an OpenFlow ofp_flow_stats.

        The returned string can be passed to deserialize() to recreate
        a copy of this object.

        Args:
            serialize_action: A callable with signature
                serialize_action(action) that takes an Action* object
                and returns the serialized form of the action as a
                sequence of binary strings.

        Returns:
            A sequence of binary strings that is a serialized form of
            this object into an OpenFlow ofp_flow_stats. The
            ofp_stats_reply structure is not included in the generated
            strings.
        """
        all_data = [
            self.match.serialize(),
            struct.pack(self.FORMAT2, self.duration_sec, self.duration_nsec,
                        self.priority, self.idle_timeout, self.hard_timeout,
                        self.cookie, self.packet_count, self.byte_count)]
        for a in self.actions:
            all_data.extend(serialize_action(a))
        length = self.FORMAT1_LENGTH + sum(len(d) for d in all_data)
        all_data.insert(0, struct.pack(self.FORMAT1, length, self.table_id))
        return all_data

    @classmethod
    def deserialize(cls, buf, deserialize_action):
        """Returns a FlowStats object deserialized from a sequence of bytes.

        Args:
            buf: A ReceiveBuffer object that contains the bytes that
                are the serialized form of the FlowStats object.
            deserialize_action: A callable with signature
                deserialize_action(buffer) that takes a ReceiveBuffer
                object and returns the Action* object deserialized
                from the buffer.

        Returns:
            A new FlowStats object deserialized from the buffer.

        Raises:
            ValueError: The buffer has an invalid number of available
                bytes.
        """
        length, table_id = buf.unpack(cls.FORMAT1)
        if length < 88:
            raise ValueError('FlowStats too short', length)
        until_bytes_left = buf.message_bytes_left + cls.FORMAT1_LENGTH - length
        match = ofmatch.Match.deserialize(buf)
        (duration_sec, duration_nsec, priority, idle_timeout, hard_timeout,
         cookie, packet_count, byte_count) = buf.unpack(cls.FORMAT2)
        actions = []
        while buf.message_bytes_left > until_bytes_left:
            actions.append(deserialize_action(buf))
        if buf.message_bytes_left != until_bytes_left:
            # The length was wrong, or an action was wrongly decoded.
            raise ValueError('FlowStats too short', length)
        actions = tuple(actions)
        return FlowStats(
            table_id, match, duration_sec, duration_nsec, priority,
            idle_timeout, hard_timeout, cookie, packet_count, byte_count,
            actions)


class TableStats(collections.namedtuple('TableStats', (
    'table_id', 'name', 'wildcards', 'max_entries', 'active_count',
    'lookup_count', 'matched_count'))):
    """The stats about an individual table.

    The attributes of the table statistics are:
        table_id: Identifier of the table, as a 8-bit unsigned
            integer.
        name: Name of the table, as a string up to 32 characters.
        wildcards: A Wildcards object that indicates which field
            wildcards are supported by the table: if an attribute is
            True, that attribute can be wildcarded in that table's
            flows entries.
        max_entries: The maximum number of entries supported in the
            table, as a 32-bit unsigned integer.
        active_count: The number of active entries in the table, as a
            32-bit unsigned integer.
        lookup_count: The number of packets looked up in the table, as
            a 64-bit unsigned integer.
        matched_count: The number of packets hit the table, as a
            64-bit unsigned integer.
    """

    FORMAT = '!B3x32sLLLQQ'

    FORMAT_LENGTH = struct.calcsize(FORMAT)

    def serialize(self):
        """Serialize this object into an OpenFlow ofp_table_stats.

        The returned string can be passed to deserialize() to recreate
        a copy of this object.

        Returns:
            A binary string that is a serialized form of this object
            into an OpenFlow ofp_table_stats. The ofp_stats_reply
            structure is not included in the generated string.
        """
        return struct.pack(
            self.FORMAT, self.table_id, self.name, self.wildcards.serialize(),
            self.max_entries, self.active_count, self.lookup_count,
            self.matched_count)

    @classmethod
    def deserialize(cls, buf):
        """Returns a TableStats object deserialized from a sequence of bytes.

        Args:
            buf: A ReceiveBuffer object that contains the bytes that
                are the serialized form of the TableStats object.

        Returns:
            A new TableStats object deserialized from the buffer.

        Raises:
            ValueError: The buffer has an invalid number of available
                bytes.
        """
        (table_id, name, wildcards_ser, max_entries, active_count,
         lookup_count, matched_count) = buf.unpack(cls.FORMAT)
        return TableStats(
            table_id, name.rstrip('\x00'),
            ofmatch.Wildcards.deserialize(wildcards_ser), max_entries,
            active_count, lookup_count, matched_count)


class PortStats(collections.namedtuple('PortStats', (
    'port_no', 'rx_packets', 'tx_packets', 'rx_bytes', 'tx_bytes',
    'rx_dropped', 'tx_dropped', 'rx_errors', 'tx_errors', 'rx_frame_err',
    'rx_over_err', 'rx_crc_err', 'collisions'))):
    """The stats about an individual port.

    The attributes of the port statistics are:
        port_no: The port's unique number, as a 16-bit unsigned
            integer. Must be between 1 and OFPP_MAX.
        rx_packets: The number of received packets, as a 64-bit
            unsigned integer.
        tx_packets: The number of transmitted packets, as a 64-bit
            unsigned integer.
        rx_bytes: The number of received bytes, as a 64-bit unsigned
            integer.
        tx_bytes: The number of transmitted bytes, as a 64-bit
            unsigned integer.
        rx_dropped: The number of packets dropped by the receiver, as
            a 64-bit unsigned integer.
        tx_dropped: The number of packets dropped by the transmitter,
            as a 64-bit unsigned integer.
        rx_errors: The number of receive errors, as a 64-bit unsigned
            integer. This is a super-set of more specific receive
            errors and should be greater than or equal to the sum of
            all rx_*_err values.
        tx_errors: The number of transmit errors, as a 64-bit unsigned
            integer.
        rx_frame_err: The number of frame alignment errors, as a
            64-bit unsigned integer.
        rx_over_err: The number of packets with receive overrun, as a
            64-bit unsigned integer.
        rx_crc_err: The number of CRC errors, as a 64-bit unsigned
            integer.
        collisions: The number of collisions, as a 64-bit unsigned
            integer.

    A rx_* or tx_* or collisions attribute is None if that counter is
    unavailable.
    """

    FORMAT = '!H6xQQQQQQQQQQQQ'

    FORMAT_LENGTH = struct.calcsize(FORMAT)

    _UNAVAILABLE = 0xffffffffffffffff

    def serialize(self):
        """Serialize this object into an OpenFlow ofp_port_stats.

        The returned string can be passed to deserialize() to recreate
        a copy of this object.

        Returns:
            A binary string that is a serialized form of this object
            into an OpenFlow ofp_port_stats. The ofp_stats_reply
            structure is not included in the generated string.
        """
        return struct.pack(
            self.FORMAT, self.port_no,
            self._UNAVAILABLE if self.rx_packets is None
                              else self.rx_packets,
            self._UNAVAILABLE if self.tx_packets is None
                              else self.tx_packets,
            self._UNAVAILABLE if self.rx_bytes is None
                              else self.rx_bytes,
            self._UNAVAILABLE if self.tx_bytes is None
                              else self.tx_bytes,
            self._UNAVAILABLE if self.rx_dropped is None
                              else self.rx_dropped,
            self._UNAVAILABLE if self.tx_dropped is None
                              else self.tx_dropped,
            self._UNAVAILABLE if self.rx_errors is None
                              else self.rx_errors,
            self._UNAVAILABLE if self.tx_errors is None
                              else self.tx_errors,
            self._UNAVAILABLE if self.rx_frame_err is None
                              else self.rx_frame_err,
            self._UNAVAILABLE if self.rx_over_err is None
                              else self.rx_over_err,
            self._UNAVAILABLE if self.rx_crc_err is None
                              else self.rx_crc_err,
            self._UNAVAILABLE if self.collisions is None
                              else self.collisions)

    @classmethod
    def deserialize(cls, buf):
        """Returns a PortStats object deserialized from a sequence of bytes.

        Args:
            buf: A ReceiveBuffer object that contains the bytes that
                are the serialized form of the PortStats object.

        Returns:
            A new PortStats object deserialized from the buffer.

        Raises:
            ValueError: The buffer has an invalid number of available
                bytes.
        """
        (port_no, rx_packets, tx_packets, rx_bytes, tx_bytes, rx_dropped,
         tx_dropped, rx_errors, tx_errors, rx_frame_err, rx_over_err,
         rx_crc_err, collisions) = buf.unpack(cls.FORMAT)
        return PortStats(
            port_no,
            None if rx_packets == cls._UNAVAILABLE else rx_packets,
            None if tx_packets == cls._UNAVAILABLE else tx_packets,
            None if rx_bytes == cls._UNAVAILABLE else rx_bytes,
            None if tx_bytes == cls._UNAVAILABLE else tx_bytes,
            None if rx_dropped == cls._UNAVAILABLE else rx_dropped,
            None if tx_dropped == cls._UNAVAILABLE else tx_dropped,
            None if rx_errors == cls._UNAVAILABLE else rx_errors,
            None if tx_errors == cls._UNAVAILABLE else tx_errors,
            None if rx_frame_err == cls._UNAVAILABLE else rx_frame_err,
            None if rx_over_err == cls._UNAVAILABLE else rx_over_err,
            None if rx_crc_err == cls._UNAVAILABLE else rx_crc_err,
            None if collisions == cls._UNAVAILABLE else collisions)


class QueueStats(collections.namedtuple('QueueStats', (
    'port_no', 'queue_id', 'tx_bytes', 'tx_packets', 'tx_errors'))):
    """The stats about an individual queue.

    The attributes of the queue statistics are:
        port_no: The port's unique number, as a 16-bit unsigned
            integer. Must be between 1 and OFPP_MAX.
        queue_id: The queue's ID, as a 32-bit unsigned integer.
        tx_bytes: The number of transmitted bytes, as a 64-bit
            unsigned integer.
        tx_packets: The number of transmitted packets, as a 64-bit
            unsigned integer.
        tx_errors: The number of transmit errors due to overrun, as a
            64-bit unsigned integer.
    """

    FORMAT = '!H2xLQQQ'

    FORMAT_LENGTH = struct.calcsize(FORMAT)

    def serialize(self):
        """Serialize this object into an OpenFlow ofp_queue_stats.

        The returned string can be passed to deserialize() to recreate
        a copy of this object.

        Returns:
            A binary string that is a serialized form of this object
            into an OpenFlow ofp_queue_stats. The ofp_stats_reply
            structure is not included in the generated string.
        """
        return struct.pack(
            self.FORMAT, self.port_no, self.queue_id, self.tx_bytes,
            self.tx_packets, self.tx_errors)

    @classmethod
    def deserialize(cls, buf):
        """Returns a QueueStats object deserialized from a sequence of bytes.

        Args:
            buf: A ReceiveBuffer object that contains the bytes that
                are the serialized form of the QueueStats object.

        Returns:
            A new QueueStats object deserialized from the buffer.

        Raises:
            ValueError: The buffer has an invalid number of available
                bytes.
        """
        return QueueStats(*buf.unpack(cls.FORMAT))
