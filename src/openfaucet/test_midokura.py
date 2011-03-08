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

# Unittests for midokura.py.

import unittest2

from openfaucet import buffer
from openfaucet import midokura
from openfaucet import ofproto


class TestMidokura(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()

  def test_serialize_mido_action_tcp_flags(self):
    dummy = ofproto.OpenflowProtocol()
    dummy._vendor_handlers = {
        midokura.MIDOKURA_VENDOR_ID: midokura.MidokuraVendorHandler }
    a = midokura.MidoActionCheckTCPFlags(tcp_flags=0x0a)
    self.assertEqual(0xffff, a.type)
    self.assertEqual(0, a.subtype)
    self.assertEqual('\xff\xff\x00\x10\x00\xac\xca\xba\x00\x00\x0a'
                     '\x00\x00\x00\x00\x00', ''.join(dummy.serialize_action(a)))

  def test_deserialize_mido_action_tcp_flags(self):
    self.buf.append('\x00\x00\x0a\x00\x00\x00\x00\x00')
    self.buf.set_message_boundaries(8)
    mvh = midokura.MidokuraVendorHandler()
    self.assertTupleEqual(midokura.MidoActionCheckTCPFlags(tcp_flags=0x0a),
                          mvh.deserialize_vendor_action(len(self.buf), self.buf)
                         )

  def test_serialize_mido_action_ack_seq_num(self):
    dummy = ofproto.OpenflowProtocol()
    dummy._vendor_handlers = {
        midokura.MIDOKURA_VENDOR_ID: midokura.MidokuraVendorHandler }
    a = midokura.MidoActionCheckAckSeqNum(ack_seq_num=0x12345678)
    self.assertEqual(0xffff, a.type)
    self.assertEqual(1, a.subtype)
    self.assertEqual('\xff\xff\x00\x10\x00\xac\xca\xba\x00\x01'
                     '\x00\x00\x12\x34\x56\x78',
                     ''.join(dummy.serialize_action(a)))

  def test_deserialize_mido_action_ack_seq_num(self):
    self.buf.append('\x00\x01\x00\x00\x12\x34\x56\x79')
    self.buf.set_message_boundaries(8)
    mvh = midokura.MidokuraVendorHandler()
    self.assertTupleEqual(midokura.MidoActionCheckAckSeqNum(
                              ack_seq_num=0x12345679),
                          mvh.deserialize_vendor_action(len(self.buf), self.buf)
                         )


if __name__ == '__main__':
  unittest2.main()
