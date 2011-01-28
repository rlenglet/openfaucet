# Copyright 2011 Midokura KK

import struct
import unittest2

from openfaucet import action
from openfaucet import buffer
from openfaucet import ofmatch
from openfaucet import ofstats


class TestDescriptionStats(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()
    self.mfr_desc = 'Dummy Manufacturer Inc.'
    self.hw_desc = 'DummySwitch'
    self.sw_desc = 'DummyOS'
    self.serial_num = '0000000042'
    self.dp_desc = 'unittest switch'
    self.desc_stats = ofstats.DescriptionStats(
        mfr_desc=self.mfr_desc,
        hw_desc=self.hw_desc,
        sw_desc=self.sw_desc,
        serial_num=self.serial_num,
        dp_desc=self.dp_desc)

  def test_serialize(self):
    self.assertEqual(self.mfr_desc + '\x00'*(256-len(self.mfr_desc))
                     + self.hw_desc + '\x00'*(256-len(self.hw_desc))
                     + self.sw_desc + '\x00'*(256-len(self.sw_desc))
                     + self.serial_num + '\x00'*(32-len(self.serial_num))
                     + self.dp_desc + '\x00'*(256-len(self.dp_desc)),
                     self.desc_stats.serialize())

  def test_deserialize(self):
    self.buf.append(self.mfr_desc + '\x00'*(256-len(self.mfr_desc)))
    self.buf.append(self.hw_desc + '\x00'*(256-len(self.hw_desc)))
    self.buf.append(self.sw_desc + '\x00'*(256-len(self.sw_desc)))
    self.buf.append(self.serial_num + '\x00'*(32-len(self.serial_num)))
    self.buf.append(self.dp_desc + '\x00'*(256-len(self.dp_desc)))
    self.buf.set_message_boundaries(1056)
    self.assertTupleEqual(self.desc_stats,
                          ofstats.DescriptionStats.deserialize(self.buf))


class TestFlowStats(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()
    self.match = ofmatch.Match(
        in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
        dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
        dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
        nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
        tp_src=0x38, tp_dst=0x49)
    self.flow_stats = ofstats.FlowStats(
        0xac, self.match, 0x10203040, 0x11223344, 0x1002, 0x0136, 0x0247,
        0xffeeddccbbaa9988, 0x42, 0x0153, (
            action.ActionOutput(port=0x1234, max_len=0x9abc),
            action.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')))

  def _serialize_action(self, a):
    a_ser = a.serialize()
    header = struct.pack('!HH', a.type, 4+len(a_ser))
    return (header, a_ser)

  def _deserialize_action(self, buf):
    action_type, action_length = buf.unpack('!HH')
    action_class = action.ACTION_TYPES.get(action_type)
    return action_class.deserialize(buf)

  def test_serialize(self):
    self.assertEqual('\x00\x70' '\xac\x00'
                     + self.match.serialize()
                     + '\x10\x20\x30\x40' '\x11\x22\x33\x44'
                     '\x10\x02' '\x01\x36' '\x02\x47'
                     '\x00\x00\x00\x00\x00\x00'
                     '\xff\xee\xdd\xcc\xbb\xaa\x99\x88'
                     '\x00\x00\x00\x00\x00\x00\x00\x42'
                     '\x00\x00\x00\x00\x00\x00\x01\x53'
                     '\x00\x00\x00\x08'
                         '\x12\x34\x9a\xbc'
                     '\x00\x05\x00\x10'
                         '\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00',
                     ''.join(self.flow_stats.serialize(self._serialize_action)))

  def test_deserialize(self):
    self.buf.append('\x00\x70' '\xac\x00')
    self.buf.append(self.match.serialize())
    self.buf.append('\x10\x20\x30\x40' '\x11\x22\x33\x44'
                    '\x10\x02' '\x01\x36' '\x02\x47'
                    '\x00\x00\x00\x00\x00\x00'
                    '\xff\xee\xdd\xcc\xbb\xaa\x99\x88'
                    '\x00\x00\x00\x00\x00\x00\x00\x42'
                    '\x00\x00\x00\x00\x00\x00\x01\x53'
                    '\x00\x00\x00\x08'
                        '\x12\x34\x9a\xbc'
                    '\x00\x05\x00\x10'
                        '\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00')
    self.buf.set_message_boundaries(112)
    self.assertTupleEqual(self.flow_stats,
                          ofstats.FlowStats.deserialize(
                              self.buf, self._deserialize_action))


class TestTableStats(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()
    self.wildcards = ofmatch.Wildcards(
        in_port=True, dl_src=True, dl_dst=True, dl_vlan=True, dl_vlan_pcp=True,
        dl_type=True, nw_tos=False, nw_proto=False, nw_src=0, nw_dst=0,
        tp_src=False, tp_dst=False)
    self.table_stats = ofstats.TableStats(
        0xac, 'eth_wildcards', self.wildcards, 0x100000, 0x1234, 0x5678,
        0x9abcd)

  def test_serialize(self):
    self.assertEqual('\xac\x00\x00\x00'
                     'eth_wildcards' + '\x00'*(32-len('eth_wildcards'))
                     + '\x00\x10\x00\x1f'
                     '\x00\x10\x00\x00' '\x00\x00\x12\x34'
                     '\x00\x00\x00\x00\x00\x00\x56\x78'
                     '\x00\x00\x00\x00\x00\x09\xab\xcd',
                     ''.join(self.table_stats.serialize()))

  def test_deserialize(self):
    self.buf.append('\xac\x00\x00\x00'
                     'eth_wildcards')
    self.buf.append('\x00'*(32-len('eth_wildcards')))
    self.buf.append('\x00\x10\x00\x1f'
                    '\x00\x10\x00\x00' '\x00\x00\x12\x34'
                    '\x00\x00\x00\x00\x00\x00\x56\x78'
                    '\x00\x00\x00\x00\x00\x09\xab\xcd')
    self.buf.set_message_boundaries(64)
    self.assertTupleEqual(self.table_stats,
                          ofstats.TableStats.deserialize(self.buf))


class TestPortStats(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()
    self.port_stats = ofstats.PortStats(
        port_no=0xabcd, rx_packets=0x1234, tx_packets=0x5678, rx_bytes=0x1324,
        tx_bytes=0x5768, rx_dropped=0x1a2b, tx_dropped=0x3c4d, rx_errors=0xab12,
        tx_errors=0xcd34, rx_frame_err=0x1432, rx_over_err=0x2543,
        rx_crc_err=0x3654, collisions=0x4765)

  def test_serialize(self):
    self.assertEqual('\xab\xcd\x00\x00\x00\x00\x00\x00'
                     '\x00\x00\x00\x00\x00\x00\x12\x34'
                     '\x00\x00\x00\x00\x00\x00\x56\x78'
                     '\x00\x00\x00\x00\x00\x00\x13\x24'
                     '\x00\x00\x00\x00\x00\x00\x57\x68'
                     '\x00\x00\x00\x00\x00\x00\x1a\x2b'
                     '\x00\x00\x00\x00\x00\x00\x3c\x4d'
                     '\x00\x00\x00\x00\x00\x00\xab\x12'
                     '\x00\x00\x00\x00\x00\x00\xcd\x34'
                     '\x00\x00\x00\x00\x00\x00\x14\x32'
                     '\x00\x00\x00\x00\x00\x00\x25\x43'
                     '\x00\x00\x00\x00\x00\x00\x36\x54'
                     '\x00\x00\x00\x00\x00\x00\x47\x65',
                     self.port_stats.serialize())

  def test_serialize_every_counter_unavailable(self):
    index = 8
    port_stats_ser = ('\xab\xcd\x00\x00\x00\x00\x00\x00'
                      '\x00\x00\x00\x00\x00\x00\x12\x34'
                      '\x00\x00\x00\x00\x00\x00\x56\x78'
                      '\x00\x00\x00\x00\x00\x00\x13\x24'
                      '\x00\x00\x00\x00\x00\x00\x57\x68'
                      '\x00\x00\x00\x00\x00\x00\x1a\x2b'
                      '\x00\x00\x00\x00\x00\x00\x3c\x4d'
                      '\x00\x00\x00\x00\x00\x00\xab\x12'
                      '\x00\x00\x00\x00\x00\x00\xcd\x34'
                      '\x00\x00\x00\x00\x00\x00\x14\x32'
                      '\x00\x00\x00\x00\x00\x00\x25\x43'
                      '\x00\x00\x00\x00\x00\x00\x36\x54'
                      '\x00\x00\x00\x00\x00\x00\x47\x65')
    for attr in ('rx_packets', 'tx_packets', 'rx_bytes', 'tx_bytes',
                 'rx_dropped', 'tx_dropped', 'rx_errors', 'tx_errors',
                 'rx_frame_err', 'rx_over_err', 'rx_crc_err', 'collisions'):
      ps = self.port_stats._replace(**{attr: None})  # set as unavailable
      self.assertEqual(port_stats_ser[:index]
                       + '\xff\xff\xff\xff\xff\xff\xff\xff'
                       + port_stats_ser[index+8:], ps.serialize())
      index += 8

  def test_deserialize(self):
    self.buf.append('\xab\xcd\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x12\x34'
                    '\x00\x00\x00\x00\x00\x00\x56\x78'
                    '\x00\x00\x00\x00\x00\x00\x13\x24'
                    '\x00\x00\x00\x00\x00\x00\x57\x68'
                    '\x00\x00\x00\x00\x00\x00\x1a\x2b'
                    '\x00\x00\x00\x00\x00\x00\x3c\x4d'
                    '\x00\x00\x00\x00\x00\x00\xab\x12'
                    '\x00\x00\x00\x00\x00\x00\xcd\x34'
                    '\x00\x00\x00\x00\x00\x00\x14\x32'
                    '\x00\x00\x00\x00\x00\x00\x25\x43'
                    '\x00\x00\x00\x00\x00\x00\x36\x54'
                    '\x00\x00\x00\x00\x00\x00\x47\x65')
    self.buf.set_message_boundaries(104)
    self.assertTupleEqual(self.port_stats,
                          ofstats.PortStats.deserialize(self.buf))

  def test_deserialize_every_counter_unavailable(self):
    index = 8
    port_stats_ser = ('\xab\xcd\x00\x00\x00\x00\x00\x00'
                      '\x00\x00\x00\x00\x00\x00\x12\x34'
                      '\x00\x00\x00\x00\x00\x00\x56\x78'
                      '\x00\x00\x00\x00\x00\x00\x13\x24'
                      '\x00\x00\x00\x00\x00\x00\x57\x68'
                      '\x00\x00\x00\x00\x00\x00\x1a\x2b'
                      '\x00\x00\x00\x00\x00\x00\x3c\x4d'
                      '\x00\x00\x00\x00\x00\x00\xab\x12'
                      '\x00\x00\x00\x00\x00\x00\xcd\x34'
                      '\x00\x00\x00\x00\x00\x00\x14\x32'
                      '\x00\x00\x00\x00\x00\x00\x25\x43'
                      '\x00\x00\x00\x00\x00\x00\x36\x54'
                      '\x00\x00\x00\x00\x00\x00\x47\x65')
    for attr in ('rx_packets', 'tx_packets', 'rx_bytes', 'tx_bytes',
                 'rx_dropped', 'tx_dropped', 'rx_errors', 'tx_errors',
                 'rx_frame_err', 'rx_over_err', 'rx_crc_err', 'collisions'):
      self.buf.append(port_stats_ser[:index])
      self.buf.append('\xff\xff\xff\xff\xff\xff\xff\xff')
      self.buf.append(port_stats_ser[index+8:])
      self.buf.set_message_boundaries(104)
      self.assertTupleEqual(self.port_stats._replace(**{attr: None}),
                            ofstats.PortStats.deserialize(self.buf))
      index += 8


class TestQueueStats(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()
    self.queue_stats = ofstats.QueueStats(
        port_no=0xabcd, queue_id=0x10203040, tx_bytes=0x5768, tx_packets=0x5678,
        tx_errors=0xcd34)

  def test_serialize(self):
    self.assertEqual('\xab\xcd\x00\x00' '\x10\x20\x30\x40'
                     '\x00\x00\x00\x00\x00\x00\x57\x68'
                     '\x00\x00\x00\x00\x00\x00\x56\x78'
                     '\x00\x00\x00\x00\x00\x00\xcd\x34',
                     self.queue_stats.serialize())

  def test_deserialize(self):
    self.buf.append('\xab\xcd\x00\x00' '\x10\x20\x30\x40'
                    '\x00\x00\x00\x00\x00\x00\x57\x68'
                    '\x00\x00\x00\x00\x00\x00\x56\x78'
                    '\x00\x00\x00\x00\x00\x00\xcd\x34')
    self.buf.set_message_boundaries(32)
    self.assertTupleEqual(self.queue_stats,
                          ofstats.QueueStats.deserialize(self.buf))


if __name__ == '__main__':
  unittest2.main()
