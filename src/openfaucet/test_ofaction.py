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

"""Unittests for ofaction.py.
"""

import unittest2

from openfaucet import ofaction
from openfaucet import buffer


class TestActions(unittest2.TestCase):

    def setUp(self):
        self.buf = buffer.ReceiveBuffer()

    def test_serialize_action_output(self):
        a = ofaction.ActionOutput(port=0x1234, max_len=0x9abc)
        self.assertEqual(0, a.type)
        self.assertEqual('\x12\x34\x9a\xbc', a.serialize())

    def test_deserialize_action_output(self):
        self.buf.append('\x12\x34\x9a\xbc')
        self.buf.set_message_boundaries(4)
        self.assertTupleEqual((0x1234, 0x9abc),
                              ofaction.ActionOutput.deserialize(self.buf))

    def test_serialize_action_set_vlan_vid(self):
        a = ofaction.ActionSetVlanVid(vlan_vid=0x1234)
        self.assertEqual(1, a.type)
        self.assertEqual('\x12\x34\x00\x00', a.serialize())

    def test_deserialize_action_set_vlan_vid(self):
        self.buf.append('\x12\x34\x00\x00')
        self.buf.set_message_boundaries(4)
        self.assertTupleEqual((0x1234,),
                              ofaction.ActionSetVlanVid.deserialize(self.buf))

    def test_serialize_action_set_vlan_pcp(self):
        a = ofaction.ActionSetVlanPcp(vlan_pcp=0x02)
        self.assertEqual(2, a.type)
        self.assertEqual('\x02\x00\x00\x00', a.serialize())

    def test_serialize_action_set_vlan_pcp_invalid_pcp_0x0a(self):
        a = ofaction.ActionSetVlanPcp(vlan_pcp=0x0a)
        self.assertEqual(2, a.type)
        with self.assertRaises(ValueError):
            a.serialize()

    def test_deserialize_action_set_vlan_pcp(self):
        self.buf.append('\x02\x00\x00\x00')
        self.buf.set_message_boundaries(4)
        self.assertTupleEqual((0x02,),
                              ofaction.ActionSetVlanPcp.deserialize(self.buf))

    def test_deserialize_action_set_vlan_pcp_invalid_pcp_0x0a(self):
        self.buf.append('\x0a\x00\x00\x00')
        self.buf.set_message_boundaries(4)
        self.assertTupleEqual((0x02,),  # Invalid bits are zeroed out.
                              ofaction.ActionSetVlanPcp.deserialize(self.buf))

    def test_serialize_action_strip_vlan(self):
        a = ofaction.ActionStripVlan()
        self.assertEqual(3, a.type)
        self.assertEqual('\x00\x00\x00\x00', a.serialize())

    def test_deserialize_action_strip_vlan(self):
        self.buf.append('\x00\x00\x00\x00')
        self.buf.set_message_boundaries(4)
        self.assertTupleEqual((),
                              ofaction.ActionStripVlan.deserialize(self.buf))

    def test_serialize_action_set_dl_src(self):
        a = ofaction.ActionSetDlSrc(dl_addr='\x12\x34\x56\x78\xab\xcd')
        self.assertEqual(4, a.type)
        self.assertEqual('\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00',
                         a.serialize())

    def test_deserialize_action_set_dl_src(self):
        self.buf.append('\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00')
        self.buf.set_message_boundaries(12)
        self.assertTupleEqual(('\x12\x34\x56\x78\xab\xcd',),
                              ofaction.ActionSetDlSrc.deserialize(self.buf))

    def test_serialize_action_set_dl_dst(self):
        a = ofaction.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')
        self.assertEqual(5, a.type)
        self.assertEqual('\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00',
                         a.serialize())

    def test_deserialize_action_set_dl_dst(self):
        self.buf.append('\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00')
        self.buf.set_message_boundaries(12)
        self.assertTupleEqual(('\x12\x34\x56\x78\xab\xcd',),
                              ofaction.ActionSetDlDst.deserialize(self.buf))

    def test_serialize_action_set_nw_src(self):
        a = ofaction.ActionSetNwSrc(nw_addr='\x12\x34\x56\x78')
        self.assertEqual(6, a.type)
        self.assertEqual('\x12\x34\x56\x78',
                         a.serialize())

    def test_deserialize_action_set_nw_src(self):
        self.buf.append('\x12\x34\x56\x78')
        self.buf.set_message_boundaries(4)
        self.assertTupleEqual(('\x12\x34\x56\x78',),
                              ofaction.ActionSetNwSrc.deserialize(self.buf))

    def test_serialize_action_set_nw_dst(self):
        a = ofaction.ActionSetNwDst(nw_addr='\x12\x34\x56\x78')
        self.assertEqual(7, a.type)
        self.assertEqual('\x12\x34\x56\x78',
                         a.serialize())

    def test_deserialize_action_set_nw_dst(self):
        self.buf.append('\x12\x34\x56\x78')
        self.buf.set_message_boundaries(4)
        self.assertTupleEqual(('\x12\x34\x56\x78',),
                              ofaction.ActionSetNwDst.deserialize(self.buf))

    def test_serialize_action_set_nw_tos(self):
        a = ofaction.ActionSetNwTos(nw_tos=0x8c)
        self.assertEqual(8, a.type)
        self.assertEqual('\x8c\x00\x00\x00',
                         a.serialize())

    def test_serialize_action_set_nw_tos_invalid_tos_0x86(self):
        a = ofaction.ActionSetNwTos(nw_tos=0x86)
        self.assertEqual(8, a.type)
        with self.assertRaises(ValueError):
            a.serialize()

    def test_deserialize_action_set_nw_tos(self):
        self.buf.append('\x8c\x00\x00\x00')
        self.buf.set_message_boundaries(4)
        self.assertTupleEqual((0x8c,),
                              ofaction.ActionSetNwTos.deserialize(self.buf))

    def test_deserialize_action_set_nw_tos_invalid_tos_0x86(self):
        self.buf.append('\x86\x00\x00\x00')
        self.buf.set_message_boundaries(4)
        self.assertTupleEqual((0x84,),  # Invalid bits are zeroed out.
                              ofaction.ActionSetNwTos.deserialize(self.buf))

    def test_serialize_action_set_tp_src(self):
        a = ofaction.ActionSetTpSrc(tp_port=0x1234)
        self.assertEqual(9, a.type)
        self.assertEqual('\x12\x34\x00\x00',
                         a.serialize())

    def test_deserialize_action_set_tp_src(self):
        self.buf.append('\x12\x34\x00\x00')
        self.buf.set_message_boundaries(4)
        self.assertTupleEqual((0x1234,),
                              ofaction.ActionSetTpSrc.deserialize(self.buf))

    def test_serialize_action_set_tp_dst(self):
        a = ofaction.ActionSetTpDst(tp_port=0x1234)
        self.assertEqual(10, a.type)
        self.assertEqual('\x12\x34\x00\x00',
                         a.serialize())

    def test_deserialize_action_set_tp_dst(self):
        self.buf.append('\x12\x34\x00\x00')
        self.buf.set_message_boundaries(4)
        self.assertTupleEqual((0x1234,),
                              ofaction.ActionSetTpDst.deserialize(self.buf))

    def test_serialize_action_enqueue(self):
        a = ofaction.ActionEnqueue(port=0x1234, queue_id=0x13243546)
        self.assertEqual(11, a.type)
        self.assertEqual('\x12\x34\x00\x00\x00\x00\x00\x00\x13\x24\x35\x46',
                         a.serialize())

    def test_deserialize_action_enqueue(self):
        self.buf.append('\x12\x34\x00\x00\x00\x00\x00\x00\x13\x24\x35\x46')
        self.buf.set_message_boundaries(12)
        self.assertTupleEqual((0x1234, 0x13243546,),
                              ofaction.ActionEnqueue.deserialize(self.buf))


if __name__ == '__main__':
    unittest2.main()
