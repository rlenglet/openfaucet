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

"""Protocol buffer management.
"""


import struct


class ReceiveBuffer(object):
    """A byte buffer providing efficient struct unpacking and bytes skipping.
    """

    # TODO(romain): Internally store the bytes as a sequence of
    # arrays, for efficiency.

    __slots__ = ('_buffer', '_offset', '_msg_start', '_msg_length',
                 '_msg_bytes_left')

    def __init__(self):
        self._buffer = bytearray()
        self._offset = 0
        self._msg_start = 0
        self._msg_length = 0
        self._msg_bytes_left = 0

    def append(self, data):
        """Append received bytes at the end this buffer.

        Args:
            data: An array of bytes to append to this buffer as unread
                bytes.
        """
        self._buffer += data

    def set_message_boundaries(self, length):
        """Set the number of bytes that can be read for the next message.

        Set the current offset as the start of the next message.  Set
        the message length to the given length.  The length is
        decremented in every read done by calling unpack() or
        read_bytes().

        Args:
            length: The maximum number of bytes that can be read for
                the next message. Must be lower or equal to the length
                of this buffer, i.e. the number of unread bytes.

        Raises:
            IndexError: length is greater than the number of available
                bytes.
        """
        if length > len(self):
            raise IndexError('message length greater than buffer length',
                             length, len(self))
        self._msg_start = self._offset
        self._msg_length = length
        self._msg_bytes_left = length

    def get_first_message_bytes(self, num):
        """Get up until num bytes from the beginning of the message.

        Get the first num message bytes, even if bytes already read.

        Args:
            num: The maximum number of bytes of the message to return.

        Returns:
            An array of up to num bytes. The actual number of bytes
            may be lower than num if the message is shorter than num
            bytes; in that case, the whole message is returned.
        """
        if self._msg_start < 0:
            raise IndexError(
                'buffer was compacted but message boundaries not reset')
        if num > self._msg_length:
            num = self._msg_length
        return self._buffer[self._msg_start:self._msg_start + num]

    def __len__(self):
        """Get the number of unread bytes stored in this buffer.

        Returns:
            The number of bytes.
        """
        return len(self._buffer) - self._offset

    @property
    def message_bytes_left(self):
        """Get the number of unread bytes left in the current message.

        Returns:
            The number of bytes left.
        """
        return self._msg_bytes_left

    def compact(self):
        """Drop the bytes already read from this buffer.

        After calling this method, set_message_boundaries() must be
        called to correctly reset the message boundaries before
        reading any bytes from this buffer.
        """
        self._msg_start -= self._offset  # TODO(romain): May be wrongly <0.

        if self._offset > 0:
            if len(self._buffer) == self._offset:
                self._buffer = bytearray()
            else:
                self._buffer = self._buffer[self._offset:]
            self._offset = 0

    def unpack(self, format):
        """Unpack bytes and mark them as read.

        Args:
            format: The struct format string to use to unpack the
                bytes.

        Raises:
            IndexError: The format's length is greater than the limit
                or the number of available bytes.
        """
        format_length = struct.calcsize(format)
        if format_length > self._msg_bytes_left or format_length > len(self):
            raise IndexError('format too long')
        # TODO(romain): Avoid having to convert the buffer into a
        # buffer, as unpack requires a string or read-only buffer, and
        # doesn't take bytearrays.
        res = struct.unpack_from(format, buffer(self._buffer), self._offset)
        self._offset += format_length
        self._msg_bytes_left -= format_length
        return res

    def unpack_inplace(self, format):
        """Unpack bytes and keep them marked as unread.

        Args:
            format: The struct format string to use to unpack the
                bytes.

        Raises:
            IndexError: The format's length is greater than the limit
                or the number of available bytes.
        """
        format_length = struct.calcsize(format)
        if format_length > self._msg_bytes_left or format_length > len(self):
            raise IndexError('format too long')
        # TODO(romain): Avoid having to convert the buffer into a
        # buffer, as unpack requires a string or read-only buffer, and
        # doesn't take bytearrays.
        return struct.unpack_from(format, buffer(self._buffer), self._offset)

    def read_bytes(self, num):
        """Get bytes and mark them as read.

        Args:
            num: The number of bytes to get. Must be lower or equal
                than the limit and the number of unread bytes.

        Returns:
            The next num unread bytes.

        Raises:
            IndexError: The format's length is greater than the limit
                or the number of available bytes.
        """
        if num > self._msg_bytes_left or num > len(self):
            raise IndexError('not enough unread bytes')
        res = self._buffer[self._offset:self._offset + num]
        self._offset += num
        self._msg_bytes_left -= num
        return res

    def skip_bytes(self, num):
        """Mark bytes as read.

        Args:
            num: The number of bytes to skip. Must be lower or equal
                than the limit and the number of unread bytes.
        """
        if num > self._msg_bytes_left or num > len(self):
            raise IndexError('not enough unread bytes')
        self._offset += num
        self._msg_bytes_left -= num
