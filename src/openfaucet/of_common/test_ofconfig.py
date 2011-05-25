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

"""Unittests for ofconfig.py.
"""

import struct
import unittest2

from openfaucet import buffer
from openfaucet.of_common import ofconfig


class TestPacketQueue(unittest2.TestCase):

    def setUp(self):
        self.buf = buffer.ReceiveBuffer()

    def test_create(self):
        pc = ofconfig.PacketQueue(0x12345678, 0x1002)

    def test_serialize_min_rate(self):
        pc = ofconfig.PacketQueue(0x12345678, 0x1002)
        self.assertEqual('\x12\x34\x56\x78' '\x00\x18\x00\x00'
                         '\x00\x01\x00\x10' '\x00\x00\x00\x00'
                         '\x10\x02' '\x00\x00\x00\x00\x00\x00',
                         ''.join(pc.serialize()))

    def test_serialize_no_min_rate(self):
        pc = ofconfig.PacketQueue(0x12345678, None)
        self.assertEqual('\x12\x34\x56\x78' '\x00\x08\x00\x00',
                         ''.join(pc.serialize()))

    def test_deserialize_min_rate(self):
        self.buf.append('\x12\x34\x56\x78' '\x00\x18\x00\x00'
                        '\x00\x01\x00\x10' '\x00\x00\x00\x00'
                        '\x10\x02' '\x00\x00\x00\x00\x00\x00')
        self.buf.set_message_boundaries(24)
        self.assertTupleEqual((0x12345678, 0x1002),
                              ofconfig.PacketQueue.deserialize(self.buf))

    def test_deserialize_no_prop(self):
        self.buf.append('\x12\x34\x56\x78' '\x00\x08\x00\x00')
        self.buf.set_message_boundaries(8)
        self.assertTupleEqual((0x12345678, None),
                              ofconfig.PacketQueue.deserialize(self.buf))

    def test_deserialize_none(self):
        self.buf.append('\x12\x34\x56\x78' '\x00\x10\x00\x00'
                        '\x00\x00\x00\x08' '\x00\x00\x00\x00')  # OFPQT_NONE
        self.buf.set_message_boundaries(16)
        self.assertTupleEqual((0x12345678, None),
                              ofconfig.PacketQueue.deserialize(self.buf))


if __name__ == '__main__':
    unittest2.main()
