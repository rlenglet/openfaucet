# Copyright 2011 Midokura KK

import unittest2

from openfaucet import action
from openfaucet import buffer


class TestActions(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()

  def test_serialize_action_output(self):
    a = action.ActionOutput(port=0x1234, max_len=0x9abc)
    self.assertEqual(0, a.type)
    self.assertEqual('\x12\x34\x9a\xbc', a.serialize())

  def test_deserialize_action_output(self):
    self.buf.append('\x12\x34\x9a\xbc')
    self.buf.set_message_boundaries(4)
    self.assertTupleEqual((0x1234, 0x9abc),
                          action.ActionOutput.deserialize(self.buf))

  def test_serialize_action_set_vlan_vid(self):
    a = action.ActionSetVlanVid(vlan_vid=0x1234)
    self.assertEqual(1, a.type)
    self.assertEqual('\x12\x34\x00\x00', a.serialize())

  def test_deserialize_action_set_vlan_vid(self):
    self.buf.append('\x12\x34\x00\x00')
    self.buf.set_message_boundaries(4)
    self.assertTupleEqual((0x1234,),
                          action.ActionSetVlanVid.deserialize(self.buf))

  def test_serialize_action_set_vlan_pcp(self):
    a = action.ActionSetVlanPcp(vlan_pcp=0x02)
    self.assertEqual(2, a.type)
    self.assertEqual('\x02\x00\x00\x00', a.serialize())

  def test_serialize_action_set_vlan_pcp_invalid_pcp_0x08(self):
    a = action.ActionSetVlanPcp(vlan_pcp=0x08)
    self.assertEqual(2, a.type)
    with self.assertRaises(ValueError):
      a.serialize()

  def test_deserialize_action_set_vlan_pcp(self):
    self.buf.append('\x02\x00\x00\x00')
    self.buf.set_message_boundaries(4)
    self.assertTupleEqual((0x02,),
                          action.ActionSetVlanPcp.deserialize(self.buf))

  def test_deserialize_action_set_vlan_pcp_invalid_pcp_0x80(self):
    self.buf.append('\x08\x00\x00\x00')
    self.buf.set_message_boundaries(4)
    with self.assertRaises(ValueError):
      action.ActionSetVlanPcp.deserialize(self.buf)

  def test_serialize_action_strip_vlan(self):
    a = action.ActionStripVlan()
    self.assertEqual(3, a.type)
    self.assertEqual('', a.serialize())

  def test_deserialize_action_strip_vlan(self):
    self.buf.set_message_boundaries(0)
    self.assertTupleEqual((),
                          action.ActionStripVlan.deserialize(self.buf))

  def test_serialize_action_set_dl_src(self):
    a = action.ActionSetDlSrc(dl_addr='\x12\x34\x56\x78\xab\xcd')
    self.assertEqual(4, a.type)
    self.assertEqual('\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00',
                     a.serialize())

  def test_deserialize_action_set_dl_src(self):
    self.buf.append('\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00')
    self.buf.set_message_boundaries(12)
    self.assertTupleEqual(('\x12\x34\x56\x78\xab\xcd',),
                          action.ActionSetDlSrc.deserialize(self.buf))

  def test_serialize_action_set_dl_dst(self):
    a = action.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')
    self.assertEqual(5, a.type)
    self.assertEqual('\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00',
                     a.serialize())

  def test_deserialize_action_set_dl_dst(self):
    self.buf.append('\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00')
    self.buf.set_message_boundaries(12)
    self.assertTupleEqual(('\x12\x34\x56\x78\xab\xcd',),
                          action.ActionSetDlDst.deserialize(self.buf))

  def test_serialize_action_set_nw_src(self):
    a = action.ActionSetNwSrc(nw_addr='\x12\x34\x56\x78')
    self.assertEqual(6, a.type)
    self.assertEqual('\x12\x34\x56\x78',
                     a.serialize())

  def test_deserialize_action_set_nw_src(self):
    self.buf.append('\x12\x34\x56\x78')
    self.buf.set_message_boundaries(4)
    self.assertTupleEqual(('\x12\x34\x56\x78',),
                          action.ActionSetNwSrc.deserialize(self.buf))

  def test_serialize_action_set_nw_dst(self):
    a = action.ActionSetNwDst(nw_addr='\x12\x34\x56\x78')
    self.assertEqual(7, a.type)
    self.assertEqual('\x12\x34\x56\x78',
                     a.serialize())

  def test_deserialize_action_set_nw_dst(self):
    self.buf.append('\x12\x34\x56\x78')
    self.buf.set_message_boundaries(4)
    self.assertTupleEqual(('\x12\x34\x56\x78',),
                          action.ActionSetNwDst.deserialize(self.buf))

  def test_serialize_action_set_nw_tos(self):
    a = action.ActionSetNwTos(nw_tos=0x8c)
    self.assertEqual(8, a.type)
    self.assertEqual('\x8c\x00\x00\x00',
                     a.serialize())

  def test_serialize_action_set_nw_tos_invalid_tos_0x02(self):
    a = action.ActionSetNwTos(nw_tos=0x02)
    self.assertEqual(8, a.type)
    with self.assertRaises(ValueError):
      a.serialize()

  def test_deserialize_action_set_nw_tos(self):
    self.buf.append('\x8c\x00\x00\x00')
    self.buf.set_message_boundaries(4)
    self.assertTupleEqual((0x8c,),
                          action.ActionSetNwTos.deserialize(self.buf))

  def test_deserialize_action_set_nw_tos_invalid_tos_0x02(self):
    self.buf.append('\x02\x00\x00\x00')
    self.buf.set_message_boundaries(4)
    with self.assertRaises(ValueError):
      action.ActionSetNwTos.deserialize(self.buf)

  def test_serialize_action_set_tp_src(self):
    a = action.ActionSetTpSrc(tp_port=0x1234)
    self.assertEqual(9, a.type)
    self.assertEqual('\x12\x34\x00\x00',
                     a.serialize())

  def test_deserialize_action_set_tp_src(self):
    self.buf.append('\x12\x34\x00\x00')
    self.buf.set_message_boundaries(4)
    self.assertTupleEqual((0x1234,),
                          action.ActionSetTpSrc.deserialize(self.buf))

  def test_serialize_action_set_tp_dst(self):
    a = action.ActionSetTpDst(tp_port=0x1234)
    self.assertEqual(10, a.type)
    self.assertEqual('\x12\x34\x00\x00',
                     a.serialize())

  def test_deserialize_action_set_tp_dst(self):
    self.buf.append('\x12\x34\x00\x00')
    self.buf.set_message_boundaries(4)
    self.assertTupleEqual((0x1234,),
                          action.ActionSetTpDst.deserialize(self.buf))

  def test_serialize_action_enqueue(self):
    a = action.ActionEnqueue(port=0x1234, queue_id=0x13243546)
    self.assertEqual(11, a.type)
    self.assertEqual('\x12\x34\x00\x00\x13\x24\x35\x46',
                     a.serialize())

  def test_deserialize_action_enqueue(self):
    self.buf.append('\x12\x34\x00\x00\x13\x24\x35\x46')
    self.buf.set_message_boundaries(8)
    self.assertTupleEqual((0x1234, 0x13243546,),
                          action.ActionEnqueue.deserialize(self.buf))


if __name__ == '__main__':
  unittest2.main()
