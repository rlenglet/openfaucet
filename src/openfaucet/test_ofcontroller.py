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

# Unittests for ofcontroller.py.

import re
import struct
import unittest2
import weakref
import twisted.internet.address
import zope.interface

from openfaucet import ofaction
from openfaucet import ofconfig
from openfaucet import ofcontroller
from openfaucet import ofmatch
from openfaucet import ofproto
from openfaucet import ofprotoops
from openfaucet import ofstats

from openfaucet import mock_ofcontroller
from openfaucet import mock_twisted
from openfaucet import mock_vendor
# TODO(romain): Move mock classes out of test_ofproto.
from openfaucet import test_ofproto


class TestOpenflowControllerStub(unittest2.TestCase):

  def setUp(self):
    self.transport = mock_twisted.MockTransport()
    self.reactor = mock_twisted.MockReactorTime()
    self.vendor_handler = mock_vendor.MockVendorHandler()
    self.default_op_timeout = 3
    self.echo_op_period = 5
    self.controller = mock_ofcontroller.MockOpenflowController()

    self.proto = ofcontroller.OpenflowControllerStub()
    self.proto.vendor_handlers = (self.vendor_handler,)
    self.proto.reactor = self.reactor
    self.proto.default_op_timeout = self.default_op_timeout
    self.proto.echo_op_period = self.echo_op_period
    self.proto.transport = self.transport
    self.proto.controller = self.controller

    self.vendor_handler.protocol = weakref.ref(self.proto)
    self.controller.protocol = weakref.ref(self.proto)

    self.callbacks_made = []

    self.phyport1 = ofconfig.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config=test_ofproto._create_port_config(
          no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofconfig.OFPPS_STP_FORWARD,
      curr=test_ofproto._create_port_features(
          mode_1gb_fd=True, fiber=True),
      advertised=test_ofproto._create_port_features(
          mode_1gb_fd=True, fiber=True, pause=True),
      supported=test_ofproto._create_port_features(
          mode_1gb_fd=True, fiber=True, pause=True, pause_asym=True),
      peer=test_ofproto._create_port_features(
          mode_1gb_fd=True, fiber=True, autoneg=True))

    self.phyport2 = ofconfig.PhyPort(
      port_no=0x43, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
      config=test_ofproto._create_port_config(
          no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofconfig.OFPPS_STP_FORWARD,
      curr=test_ofproto._create_port_features(
          mode_1gb_fd=True, fiber=True),
      advertised=test_ofproto._create_port_features(
          mode_1gb_fd=True, fiber=True, pause=True),
      supported=test_ofproto._create_port_features(
          mode_1gb_fd=True, fiber=True, pause=True, pause_asym=True),
      peer=test_ofproto._create_port_features(
          mode_1gb_fd=True, fiber=True, autoneg=True))

    self.features1 = ofconfig.SwitchFeatures(
        datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
        cap_table_stats=False, cap_port_stats=True, cap_stp=False,
        cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
        actions=frozenset((0, 2, 3, 5, 8)), ports=(self.phyport1,))

    self.match1 = ofmatch.Match(
        in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
        dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
        dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
        nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
        tp_src=0x38, tp_dst=0x49)

  def _get_next_sent_message(self):
    """Get the undecoded next message sent by the protocol.

    Returns:
      A byte array containing a single message, or None if no message
      was received.
    """
    buf = self.transport.buffer
    if len(buf) == 0:
      return None
    self.assertGreaterEqual(len(buf), ofproto.OFP_HEADER_LENGTH)
    buf.set_message_boundaries(ofproto.OFP_HEADER_LENGTH)
    _, _, msg_length, _ = buf.unpack_inplace(ofproto.OFP_HEADER_FORMAT)
    self.assertGreaterEqual(len(buf), msg_length)
    buf.set_message_boundaries(msg_length)
    return buf.read_bytes(msg_length)

  def test_connection_made_send_features_request(self):
    self.proto.connectionMade()
    # Sent initial OFPT_HELLO with XID 0.
    self.assertEqual('\x01\x00\x00\x08\x00\x00\x00\x00',
                     self._get_next_sent_message())
    # Sent initial OFPT_ECHO_REQUEST with XID 0.
    self.assertRegexpMatches(
        self._get_next_sent_message(),
        re.compile(r'\x01\x02\x00\x0c\x00\x00\x00\x00'
                   '....',  # 32-bit random data
                   re.DOTALL))
    # Sent initial OFPT_FEATURES_REQUEST with XID 1.
    self.assertEqual('\x01\x05\x00\x08\x00\x00\x00\x01',
                     self._get_next_sent_message())

  def test_switch_features_handshake(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    # Send the OFPT_FEATURES_REPLY message to complete the handshake.
    self.proto.dataReceived('\x01\x06\x00\x50\x00\x00\x00\x01')
    self.proto.dataReceived(''.join(self.features1.serialize()))

    self.assertTupleEqual(self.features1, self.proto.features)

  def test_handshake_timeout_lose_connection(self):
    self.proto.connectionMade()
    self.assertTrue(self.transport.open)
    self.reactor.increment_time(self.default_op_timeout)
    self.assertFalse(self.transport.open)

  def test_get_features(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    def _callback(switch_features, callbacks_made=self.callbacks_made):
      callbacks_made.append(('get_features', switch_features))

    self.proto.get_features(_callback)

    # Sent OFPT_FEATURES_REQUEST with XID 2.
    self.assertEqual('\x01\x05\x00\x08\x00\x00\x00\x02',
                     self._get_next_sent_message())

    # Send the OFPT_FEATURES_REPLY message to answer the request.
    self.proto.dataReceived('\x01\x06\x00\x50\x00\x00\x00\x02')
    self.proto.dataReceived(''.join(self.features1.serialize()))

    self.assertItemsEqual([('get_features', self.features1)],
                          self.callbacks_made)

  def test_get_config(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    def _callback(switch_config, callbacks_made=self.callbacks_made):
      callbacks_made.append(('get_config', switch_config))

    self.proto.get_config(_callback)

    # Sent OFPT_GET_CONFIG_REQUEST with XID 2.
    self.assertEqual('\x01\x07\x00\x08\x00\x00\x00\x02',
                     self._get_next_sent_message())

    # Send the OFPT_GET_CONFIG_REPLY message to answer the request.
    sc = ofconfig.SwitchConfig(config_frag=ofconfig.OFPC_FRAG_DROP,
                               miss_send_len=128)
    self.proto.dataReceived('\x01\x08\x00\x0c\x00\x00\x00\x02')
    self.proto.dataReceived(''.join(sc.serialize()))

    self.assertItemsEqual([('get_config', sc)], self.callbacks_made)

  def test_get_stats_desc(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    def _callback(desc_stats, callbacks_made=self.callbacks_made):
      callbacks_made.append(('get_stats_desc', desc_stats))

    self.proto.get_stats_desc(_callback)

    # Sent OFPT_STATS_REQUEST with XID 2.
    self.assertEqual('\x01\x10\x00\x0c\x00\x00\x00\x02'
                     '\x00\x00' '\x00\x00',
                     self._get_next_sent_message())

    # Send the OFPT_STATS_REPLY message to answer the request.
    desc_stats = ofstats.DescriptionStats(
        mfr_desc='Dummy Manufacturer Inc.',
        hw_desc='DummySwitch',
        sw_desc='DummyOS',
        serial_num='0000000042',
        dp_desc='unittest switch')
    self.proto.dataReceived('\x01\x11\x04\x2c\x00\x00\x00\x02'
                            '\x00\x00' '\x00\x00')
    self.proto.dataReceived(desc_stats.serialize())

    self.assertItemsEqual([('get_stats_desc', desc_stats)],
                          self.callbacks_made)

  def test_get_stats_flow(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    def _callback(flow_stats, reply_more, callbacks_made=self.callbacks_made):
      callbacks_made.append(('get_stats_flow', flow_stats, reply_more))

    self.proto.get_stats_flow(self.match1, 0x0a, 0xabcd, _callback)

    # Sent OFPT_STATS_REQUEST with XID 2.
    self.assertEqual('\x01\x10\x00\x38\x00\x00\x00\x02'
                     '\x00\x01' '\x00\x00'
                     + self.match1.serialize()
                     + '\x0a\x00' '\xab\xcd',
                     self._get_next_sent_message())

    # Send 2 OFPT_STATS_REPLY messages to answer the request.
    flow_stats1 = ofstats.FlowStats(
        0xac, self.match1, 0x10203040, 0x11223344, 0x1002, 0x0136, 0x0247,
        0xffeeddccbbaa9988, 0x42, 0x0153, (
            ofaction.ActionOutput(port=0x1234, max_len=0x9abc),
            ofaction.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')))
    flow_stats2 = ofstats.FlowStats(
        0xad, self.match1, 0x10203040, 0x11223344, 0x1003, 0x0136, 0x0247,
        0xffeeddccbbaa9988, 0x42, 0x0153, ())
    self.proto.dataReceived('\x01\x11\x00\x7c\x00\x00\x00\x02'
                            '\x00\x01' '\x00\x01')
    self.proto.dataReceived(
        ''.join(flow_stats1.serialize(self.proto.serialize_action)))
    self.proto.dataReceived('\x01\x11\x00\x64\x00\x00\x00\x02'
                            '\x00\x01' '\x00\x00')
    self.proto.dataReceived(
        ''.join(flow_stats2.serialize(self.proto.serialize_action)))

    self.assertItemsEqual([('get_stats_flow', (flow_stats1,), True),
                           ('get_stats_flow', (flow_stats2,), False)],
                          self.callbacks_made)

  def test_get_stats_aggregate(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    def _callback(packet_count, byte_count, flow_count,
                  callbacks_made=self.callbacks_made):
      callbacks_made.append(('get_stats_aggregate', packet_count, byte_count,
                             flow_count))

    self.proto.get_stats_aggregate(self.match1, 0x0a, 0xabcd, _callback)

    # Sent OFPT_STATS_REQUEST with XID 2.
    self.assertEqual('\x01\x10\x00\x38\x00\x00\x00\x02'
                     '\x00\x02' '\x00\x00'
                     + self.match1.serialize()
                     + '\x0a\x00' '\xab\xcd',
                     self._get_next_sent_message())

    # Send the OFPT_STATS_REPLY message to answer the request.
    self.proto.dataReceived('\x01\x11\x00\x24\x00\x00\x00\x02'
                            '\x00\x02' '\x00\x00'
                            '\x00\x00\x00\x00\x00\x00\x12\x34'
                            '\x00\x00\x00\x00\x00\x00\x13\x24'
                            '\x00\x00\x01\x23' '\x00\x00\x00\x00')

    self.assertItemsEqual([('get_stats_aggregate', 0x1234, 0x1324, 0x0123)],
                          self.callbacks_made)

  def test_get_stats_table(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    def _callback(table_stats, reply_more, callbacks_made=self.callbacks_made):
      callbacks_made.append(('get_stats_table', table_stats, reply_more))

    self.proto.get_stats_table(_callback)

    # Sent OFPT_STATS_REQUEST with XID 2.
    self.assertEqual('\x01\x10\x00\x0c\x00\x00\x00\x02'
                     '\x00\x03' '\x00\x00',
                     self._get_next_sent_message())

    # Send 2 OFPT_STATS_REPLY messages to answer the request.
    wildcards1 = ofmatch.Wildcards(
        in_port=False, dl_src=False, dl_dst=False, dl_vlan=False,
        dl_vlan_pcp=False, dl_type=False, nw_tos=False, nw_proto=False,
        nw_src=0, nw_dst=0, tp_src=False, tp_dst=False)
    table_stats1 = ofstats.TableStats(
        0xab, 'no_wildcards', wildcards1, 0x100000, 0x1234, 0x5678,
        0x9abcd)
    wildcards2 = ofmatch.Wildcards(
        in_port=True, dl_src=True, dl_dst=True, dl_vlan=True, dl_vlan_pcp=True,
        dl_type=True, nw_tos=False, nw_proto=False, nw_src=0, nw_dst=0,
        tp_src=False, tp_dst=False)
    table_stats2 = ofstats.TableStats(
        0xac, 'eth_wildcards', wildcards2, 0x100000, 0x1234, 0x5678,
        0x9abcd)
    self.proto.dataReceived('\x01\x11\x00\x4c\x00\x00\x00\x02'
                            '\x00\x03' '\x00\x01')
    self.proto.dataReceived(table_stats1.serialize())
    self.proto.dataReceived('\x01\x11\x00\x4c\x00\x00\x00\x02'
                            '\x00\x03' '\x00\x00')
    self.proto.dataReceived(table_stats2.serialize())

    self.assertItemsEqual([('get_stats_table', (table_stats1,), True),
                           ('get_stats_table', (table_stats2,), False)],
                          self.callbacks_made)

  def test_get_stats_port(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    def _callback(port_stats, reply_more, callbacks_made=self.callbacks_made):
      callbacks_made.append(('get_stats_port', port_stats, reply_more))

    self.proto.get_stats_port(ofproto.OFPP_NONE, _callback)

    # Sent OFPT_STATS_REQUEST with XID 2.
    self.assertEqual('\x01\x10\x00\x14\x00\x00\x00\x02'
                     '\x00\x04' '\x00\x00'
                     '\xff\xff\x00\x00\x00\x00\x00\x00',
                     self._get_next_sent_message())

    # Send 2 OFPT_STATS_REPLY messages to answer the request.
    port_stats1 = ofstats.PortStats(
        port_no=0xab01, rx_packets=0x1234, tx_packets=0x5678, rx_bytes=0x1324,
        tx_bytes=0x5768, rx_dropped=0x1a2b, tx_dropped=0x3c4d, rx_errors=0xab12,
        tx_errors=0xcd34, rx_frame_err=0x1432, rx_over_err=0x2543,
        rx_crc_err=0x3654, collisions=0x4765)
    port_stats2 = ofstats.PortStats(
        port_no=0xab02, rx_packets=0x1234, tx_packets=0x5678, rx_bytes=0x1324,
        tx_bytes=0x5768, rx_dropped=0x1a2b, tx_dropped=0x3c4d, rx_errors=0xab12,
        tx_errors=0xcd34, rx_frame_err=0x1432, rx_over_err=0x2543,
        rx_crc_err=0x3654, collisions=0x4765)
    self.proto.dataReceived('\x01\x11\x00\x74\x00\x00\x00\x02'
                            '\x00\x04' '\x00\x01')
    self.proto.dataReceived(port_stats1.serialize())
    self.proto.dataReceived('\x01\x11\x00\x74\x00\x00\x00\x02'
                            '\x00\x04' '\x00\x00')
    self.proto.dataReceived(port_stats2.serialize())

    self.assertItemsEqual([('get_stats_port', (port_stats1,), True),
                           ('get_stats_port', (port_stats2,), False)],
                          self.callbacks_made)

  def test_get_stats_queue(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    def _callback(queue_stats, reply_more, callbacks_made=self.callbacks_made):
      callbacks_made.append(('get_stats_queue', queue_stats, reply_more))

    self.proto.get_stats_queue(ofproto.OFPP_ALL, ofproto.OFPQ_ALL, _callback)

    # Sent OFPT_STATS_REQUEST with XID 2.
    self.assertEqual('\x01\x10\x00\x14\x00\x00\x00\x02'
                     '\x00\x05' '\x00\x00'
                     '\xff\xfc\x00\x00' '\xff\xff\xff\xff',
                     self._get_next_sent_message())

    # Send 2 OFPT_STATS_REPLY messages to answer the request.
    queue_stats1 = ofstats.QueueStats(
        port_no=0xab01, queue_id=0x11111111, tx_bytes=0x5768, tx_packets=0x5678,
        tx_errors=0xcd34)
    queue_stats2 = ofstats.QueueStats(
        port_no=0xab01, queue_id=0x22222222, tx_bytes=0x5768, tx_packets=0x5678,
        tx_errors=0xcd34)
    self.proto.dataReceived('\x01\x11\x00\x2c\x00\x00\x00\x02'
                            '\x00\x05' '\x00\x01')
    self.proto.dataReceived(queue_stats1.serialize())
    self.proto.dataReceived('\x01\x11\x00\x2c\x00\x00\x00\x02'
                            '\x00\x05' '\x00\x00')
    self.proto.dataReceived(queue_stats2.serialize())

    self.assertItemsEqual([('get_stats_queue', (queue_stats1,), True),
                           ('get_stats_queue', (queue_stats2,), False)],
                          self.callbacks_made)

  def test_get_stats_queue_stats_type_mismatch(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    def _callback(queue_stats, reply_more, callbacks_made=self.callbacks_made):
      callbacks_made.append(('get_stats_queue', queue_stats, reply_more))

    self.proto.get_stats_queue(ofproto.OFPP_ALL, ofproto.OFPQ_ALL, _callback)

    # Sent OFPT_STATS_REQUEST with XID 2.
    self.assertEqual('\x01\x10\x00\x14\x00\x00\x00\x02'
                     '\x00\x05' '\x00\x00'
                     '\xff\xfc\x00\x00' '\xff\xff\xff\xff',
                     self._get_next_sent_message())

    # Send 2 OFPT_STATS_REPLY messages to answer the request.
    queue_stats1 = ofstats.QueueStats(
        port_no=0xab01, queue_id=0x11111111, tx_bytes=0x5768, tx_packets=0x5678,
        tx_errors=0xcd34)
    self.proto.dataReceived('\x01\x11\x00\x2c\x00\x00\x00\x02'
                            '\x00\x05' '\x00\x01')
    self.proto.dataReceived(queue_stats1.serialize())
    # Send an OFPT_STATS_REPLY message with the wrong stats type
    # (OFPST_AGGREGATE instead of OFPST_QUEUE).
    self.proto.dataReceived('\x01\x11\x00\x24\x00\x00\x00\x02'
                            '\x00\x02' '\x00\x00'
                            '\x00\x00\x00\x00\x00\x00\x12\x34'
                            '\x00\x00\x00\x00\x00\x00\x13\x24'
                            '\x00\x00\x01\x23' '\x00\x00\x00\x00')

    self.assertItemsEqual([('get_stats_queue', (queue_stats1,), True)],
                          self.callbacks_made)

    # An OFPET_BAD_REQUEST / OFPBRC_BAD_TYPE error has been sent back,
    # with the same XID.
    self.assertEqual('\x01\x01\x00\x30\x00\x00\x00\x02'
                     '\x00\x01' '\x00\x01'
                     '\x01\x11\x00\x24\x00\x00\x00\x02'
                     '\x00\x02' '\x00\x00'
                     '\x00\x00\x00\x00\x00\x00\x12\x34'
                     '\x00\x00\x00\x00\x00\x00\x13\x24'
                     '\x00\x00\x01\x23' '\x00\x00\x00\x00',
                     self._get_next_sent_message())

  def test_barrier(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    def _callback(callbacks_made=self.callbacks_made):
      callbacks_made.append(('barrier',))

    self.proto.barrier(_callback)

    # Sent OFPT_BARRIER_REQUEST with XID 2.
    self.assertEqual('\x01\x12\x00\x08\x00\x00\x00\x02',
                     self._get_next_sent_message())

    # Send the OFPT_BARRIER_REPLY message to answer the request.
    self.proto.dataReceived('\x01\x13\x00\x08\x00\x00\x00\x02')

    self.assertItemsEqual([('barrier',)], self.callbacks_made)

  def test_get_queue_config(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    def _callback(port_no, queues, callbacks_made=self.callbacks_made):
      callbacks_made.append(('get_queue_config', port_no, queues))

    self.proto.get_queue_config(0xabcd, _callback)

    # Sent OFPT_GET_CONFIG_REQUEST with XID 2.
    self.assertEqual('\x01\x14\x00\x0c\x00\x00\x00\x02'
                     '\xab\xcd\x00\x00',
                     self._get_next_sent_message())

    # Send the OFPT_GET_CONFIG_REPLY message to answer the request.
    queue1 = ofconfig.PacketQueue(0x1234, None)
    queue2 = ofconfig.PacketQueue(0x5678, 0x1002)
    self.proto.dataReceived('\x01\x15\x00\x30\x00\x00\x00\x02'
                            '\xab\xcd\x00\x00\x00\x00\x00\x00')
    self.proto.dataReceived(''.join(queue1.serialize()))
    self.proto.dataReceived(''.join(queue2.serialize()))

    self.assertItemsEqual([('get_queue_config', 0xabcd, (queue1, queue2))],
                          self.callbacks_made)

  def test_handle_packet_in(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    self.proto.dataReceived('\x01\x0a\x00\x18\x00\x00\x00\x00'
                            '\x00\x00\x13\x24\x01\x00\x00\x42\x01\x00'
                            'abcdef')
    self.assertListEqual([('handle_packet_in', 0x1324, 0x100, 0x42,
                           ofproto.OFPR_ACTION, 'abcdef')],
                         self.controller.calls_made)

  def test_handle_flow_removed(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    self.proto.dataReceived('\x01\x0b\x00\x58\x00\x00\x00\x00')
    self.proto.dataReceived(self.match1.serialize())
    self.proto.dataReceived(
        '\x00\x00\x00\x00\x12\x34\x56\x78'
        '\x10\x00' '\x02\x00' '\x00\x30\x20\x10' '\x00\x03\x02\x01'
        '\x42\x31\x00\x00' '\x00\x00\x00\x00\x00\x63\x52\x41'
        '\x00\x00\x00\x00\x00\x55\x44\x33')
    self.assertListEqual(
        [('handle_flow_removed', self.match1, 0x12345678, 0x1000,
          ofproto.OFPRR_DELETE, 0x302010, 0x030201, 0x4231, 0x635241,
          0x554433)],
        self.controller.calls_made)

  def test_handle_port_status_add(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    # Send the OFPT_FEATURES_REPLY message to complete the handshake,
    # with only phyport1.
    self.proto.dataReceived('\x01\x06\x00\x50\x00\x00\x00\x04')
    self.proto.dataReceived(''.join(self.features1.serialize()))

    # Send a PORT_STATUS to add phyport2.
    self.proto.dataReceived('\x01\x0c\x00\x40\x00\x00\x00\x00'
                            '\x00\x00\x00\x00\x00\x00\x00\x00')
    self.proto.dataReceived(self.phyport2.serialize())

    # The features has been updated.
    self.assertEqual(
        self.features1._replace(ports=(self.phyport1, self.phyport2)),
        self.proto.features)

    # The controller has been called back.
    self.assertListEqual([('handle_port_status', ofproto.OFPPR_ADD,
                           self.phyport2)],
                         self.controller.calls_made)

  def test_handle_port_status_delete(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    # Send the OFPT_FEATURES_REPLY message to complete the handshake,
    # with both phyport1 and phyport2.
    sf = self.features1._replace(ports=(self.phyport1, self.phyport2))
    self.proto.dataReceived('\x01\x06\x00\x80\x00\x00\x00\x01')
    self.proto.dataReceived(''.join(sf.serialize()))

    # Send a PORT_STATUS to remove phyport2.
    self.proto.dataReceived('\x01\x0c\x00\x40\x00\x00\x00\x00'
                            '\x01\x00\x00\x00\x00\x00\x00\x00')
    self.proto.dataReceived(self.phyport2.serialize())

    # The features has been updated.
    self.assertEqual(self.features1, self.proto.features)

    # The controller has been called back.
    self.assertListEqual([('handle_port_status', ofproto.OFPPR_DELETE,
                           self.phyport2)],
                         self.controller.calls_made)

  def test_handle_port_status_modify(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    # Send the OFPT_FEATURES_REPLY message to complete the handshake.
    self.proto.dataReceived('\x01\x06\x00\x50\x00\x00\x00\x04')
    self.proto.dataReceived(''.join(self.features1.serialize()))

    # Send a PORT_STATUS to modify phyport1.
    p = self.phyport1._replace(state_link_down=False)
    self.assertNotEqual(self.phyport1, p)
    self.proto.dataReceived('\x01\x0c\x00\x40\x00\x00\x00\x00'
                            '\x02\x00\x00\x00\x00\x00\x00\x00')
    self.proto.dataReceived(p.serialize())

    # The features has been updated.
    self.assertEqual(self.features1._replace(ports=(p,)), self.proto.features)

    # The controller has been called back.
    self.assertListEqual([('handle_port_status', ofproto.OFPPR_MODIFY, p)],
                         self.controller.calls_made)

  def test_handle_features_request(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    self._get_next_sent_message()  # Initial OFPT_FEATURES_REQUEST.

    self.proto.dataReceived('\x01\x05\x00\x08\x00\x00\x00\x04')

    # An OFPET_BAD_REQUEST / OFPBRC_BAD_TYPE error has been sent back,
    # with the same XID.
    self.assertEqual('\x01\x01\x00\x14\x00\x00\x00\x04'
                     '\x00\x01' '\x00\x01'
                     '\x01\x05\x00\x08\x00\x00\x00\x04',
                     self._get_next_sent_message())


class TestOpenflowControllerStubFactory(unittest2.TestCase):

  def setUp(self):
    self.vendor_handler_classes = (mock_vendor.MockVendorHandler,)
    self.reactor = mock_twisted.MockReactorTime()
    self.factory = ofcontroller.OpenflowControllerStubFactory(
        controller=mock_ofcontroller.MockOpenflowController,
        protocol=ofcontroller.OpenflowControllerStub,
        error_data_bytes=64, vendor_handlers=self.vendor_handler_classes,
        reactor=self.reactor, default_op_timeout=4.0, echo_op_period=6.0)

    self.addr = twisted.internet.address.IPv4Address('TCP', '192.168.1.1',
                                                     '14123')

  def test_build_protocol_controller(self):
    self.factory.doStart()
    proto = self.factory.buildProtocol(self.addr)
    self.assertEqual(mock_ofcontroller.MockOpenflowController,
                     proto.controller.__class__)
    self.assertEqual(proto, proto.controller.protocol())
    self.factory.doStop()


if __name__ == '__main__':
  # Disable logging during unittests.
  import logging
  logging.basicConfig(level=logging.CRITICAL)
  #logging.basicConfig(level=logging.DEBUG,
  #                    format='%(asctime)s %(levelname)s %(message)s',
  #                    filename='unittest.log',
  #                    filemode='w')
  unittest2.main()
