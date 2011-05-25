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

"""Encoding/decoding of switch and port configuration common to OpenFlow
1.0.0 and 1.1.0..
"""

import collections
import struct


# Properties of packet queues.
OFPQT_NONE = 0  # No property defined for queue.
OFPQT_MIN_RATE = 1  # Minimum datarate guaranteed.


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
