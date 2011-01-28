# Copyright 2011 Midokura KK

import struct
import unittest2

from openfaucet import buffer
from openfaucet import ofaction
from openfaucet import ofmatch
from openfaucet import ofproto
from openfaucet import ofstats


def _create_port_config(
    port_down=False, no_stp=False, no_recv=False, no_recv_stp=False,
    no_flood=False, no_fwd=False, no_packet_in=False):
  return ofproto.PortConfig(
      port_down=port_down, no_stp=no_stp, no_recv=no_recv,
      no_recv_stp=no_recv_stp, no_flood=no_flood, no_fwd=no_fwd,
      no_packet_in=no_packet_in)


def _create_port_features(
    mode_10mb_hd=False, mode_10mb_fd=False, mode_100mb_hd=False,
    mode_100mb_fd=False, mode_1gb_hd=False, mode_1gb_fd=False,
    mode_10gb_fd=False, copper=False, fiber=False, autoneg=False, pause=False,
    pause_asym=False):
  return ofproto.PortFeatures(
      mode_10mb_hd=mode_10mb_hd, mode_10mb_fd=mode_10mb_fd,
      mode_100mb_hd=mode_100mb_hd, mode_100mb_fd=mode_100mb_fd,
      mode_1gb_hd=mode_1gb_hd, mode_1gb_fd=mode_1gb_fd,
      mode_10gb_fd=mode_10gb_fd, copper=copper, fiber=fiber, autoneg=autoneg,
      pause=pause, pause_asym=pause_asym)


class TestPortConfig(unittest2.TestCase):

  def test_create(self):
    pc = ofproto.PortConfig(port_down=False, no_stp=True, no_recv=False,
                            no_recv_stp=True, no_flood=True, no_fwd=False,
                            no_packet_in=False)

  def test_serialize(self):
    pc = ofproto.PortConfig(port_down=False, no_stp=True, no_recv=False,
                            no_recv_stp=True, no_flood=True, no_fwd=False,
                            no_packet_in=False)
    self.assertEqual(0x1a, pc.serialize())

  def test_serialize_every_flag(self):
    for i in xrange(0, 7):
      flag = 1 << i
      args = [False]*6
      args.insert(i, True)
      pc = ofproto.PortConfig(*args)
      self.assertEqual(flag, pc.serialize())

  def test_serialize_deserialize(self):
    pc = ofproto.PortConfig(port_down=False, no_stp=True, no_recv=False,
                            no_recv_stp=True, no_flood=True, no_fwd=False,
                            no_packet_in=False)
    self.assertTupleEqual(pc, ofproto.PortConfig.deserialize(pc.serialize()))

  def test_deserialize(self):
    self.assertTupleEqual((False, True, False, True, True, False, False),
                          ofproto.PortConfig.deserialize(0x1a))

  def test_deserialize_every_invalid_bit(self):
    for i in xrange(7, 32):
      flags = (1 << i) | 0x0000001a
      # The invalid bit is ignored.
      self.assertTupleEqual((False, True, False, True, True, False, False),
                            ofproto.PortConfig.deserialize(flags))

  def test_get_diff_every_flag_true(self):
    all_false = ofproto.PortConfig(*([False]*7))
    for i in xrange(0, 7):
      args = [False]*6
      args.insert(i, True)
      pc = ofproto.PortConfig(*args)
      config, mask = pc.get_diff(all_false)
      args = tuple(args)
      self.assertEqual(True, config[i])
      self.assertTupleEqual(args, mask)

  def test_get_diff_every_flag_false(self):
    all_true = ofproto.PortConfig(*([True]*7))
    for i in xrange(0, 7):
      args = [True]*6
      args.insert(i, False)
      pc = ofproto.PortConfig(*args)
      config, mask = pc.get_diff(all_true)
      self.assertEqual(False, config[i])
      expected_mask = [False]*6
      expected_mask.insert(i, True)
      expected_mask = tuple(expected_mask)
      self.assertTupleEqual(expected_mask, mask)

  def test_patch_every_flag_true(self):
    all_false = ofproto.PortConfig(*([False]*7))
    for i in xrange(0, 7):
      args = [False]*6
      args.insert(i, True)
      config = ofproto.PortConfig(*args)
      mask = ofproto.PortConfig(*args)
      args = tuple(args)
      self.assertTupleEqual(args, all_false.patch(config, mask))

  def test_patch_every_flag_false(self):
    all_true = ofproto.PortConfig(*([True]*7))
    for i in xrange(0, 7):
      config_args = [False]*7
      config = ofproto.PortConfig(*config_args)
      mask_args = [False]*6
      mask_args.insert(i, True)
      mask = ofproto.PortConfig(*mask_args)
      expected_args = [True]*6
      expected_args.insert(i, False)
      expected_args = tuple(expected_args)
      self.assertTupleEqual(expected_args, all_true.patch(config, mask))


class TestPortFeatures(unittest2.TestCase):

  def test_create(self):
    pf = ofproto.PortFeatures(
        mode_10mb_hd=False, mode_10mb_fd=True, mode_100mb_hd=False,
        mode_100mb_fd=True, mode_1gb_hd=False, mode_1gb_fd=True,
        mode_10gb_fd=True, copper=False, fiber=True, autoneg=True, pause=True,
        pause_asym=False)

  def test_serialize(self):
    pf = ofproto.PortFeatures(
        mode_10mb_hd=False, mode_10mb_fd=True, mode_100mb_hd=False,
        mode_100mb_fd=True, mode_1gb_hd=False, mode_1gb_fd=True,
        mode_10gb_fd=True, copper=False, fiber=True, autoneg=True, pause=True,
        pause_asym=False)
    self.assertEqual(0x0000076a, pf.serialize())

  def test_serialize_every_flag(self):
    for i in xrange(0, 12):
      flag = 1 << i
      args = [False]*11
      args.insert(i, True)
      pf = ofproto.PortFeatures(*args)
      self.assertEqual(flag, pf.serialize())

  def test_serialize_deserialize(self):
    pf = ofproto.PortFeatures(
        mode_10mb_hd=False, mode_10mb_fd=True, mode_100mb_hd=False,
        mode_100mb_fd=True, mode_1gb_hd=False, mode_1gb_fd=True,
        mode_10gb_fd=True, copper=False, fiber=True, autoneg=True, pause=True,
        pause_asym=False)
    self.assertTupleEqual(pf, ofproto.PortFeatures.deserialize(pf.serialize()))

  def test_deserialize(self):
    self.assertTupleEqual((False, True, False, True, False, True, True,
                           False, True, True, True, False),
                          ofproto.PortFeatures.deserialize(0x0000076a))

  def test_deserialize_every_flag(self):
    for i in xrange(0, 12):
      flag = 1 << i
      args = [False]*11
      args.insert(i, True)
      args = tuple(args)
      self.assertTupleEqual(args, ofproto.PortFeatures.deserialize(flag))

  def test_deserialize_every_invalid_bit(self):
    for i in xrange(12, 32):
      flags = (1 << i) | 0x0000076a
      # The invalid bit is ignored.
      self.assertTupleEqual((False, True, False, True, False, True, True,
                             False, True, True, True, False),
                            ofproto.PortFeatures.deserialize(flags))


class TestPhyPort(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()

  def test_create(self):
    pp = ofproto.PhyPort(
        port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
        config=_create_port_config(no_stp=True, no_recv_stp=True,
                                   no_flood=True),
        state_link_down=False, state_stp=ofproto.OFPPS_STP_FORWARD,
        curr=_create_port_features(mode_1gb_fd=True, fiber=True),
        advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
        supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                        pause=True, pause_asym=True),
        peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                   autoneg=True))

  def test_serialize(self):
    pp = ofproto.PhyPort(
        port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
        config=_create_port_config(no_stp=True, no_recv_stp=True,
                                   no_flood=True),
        state_link_down=True, state_stp=ofproto.OFPPS_STP_FORWARD,
        curr=_create_port_features(mode_1gb_fd=True, fiber=True),
        advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
        supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                        pause=True, pause_asym=True),
        peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                   autoneg=True))
    self.assertEqual('\x00\x42' '\xab\xcd\xef\xa0\xb1\xc2'
                     'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                     '\x00\x00\x00\x1a'
                     '\x00\x00\x02\x01'
                     '\x00\x00\x01\x20'
                     '\x00\x00\x05\x20'
                     '\x00\x00\x0d\x20'
                     '\x00\x00\x03\x20',
                     pp.serialize())

  def test_serialize_every_state_stp(self):
    for i in (ofproto.OFPPS_STP_LISTEN, ofproto.OFPPS_STP_LEARN,
              ofproto.OFPPS_STP_FORWARD, ofproto.OFPPS_STP_BLOCK):
      state_ser = i | 1  # state_link_down=True
      pp = ofproto.PhyPort(
          port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
          config=_create_port_config(no_stp=True, no_recv_stp=True,
                                     no_flood=True),
          state_link_down=True, state_stp=i,
          curr=_create_port_features(mode_1gb_fd=True, fiber=True),
          advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                           pause=True),
          supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                          pause=True, pause_asym=True),
          peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                     autoneg=True))
      self.assertEqual('\x00\x42' '\xab\xcd\xef\xa0\xb1\xc2'
                       'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                       '\x00\x00\x00\x1a'
                       + struct.pack('!L', state_ser)
                       + '\x00\x00\x01\x20'
                       '\x00\x00\x05\x20'
                       '\x00\x00\x0d\x20'
                       '\x00\x00\x03\x20', pp.serialize())

  def test_serialize_deserialize(self):
    pp = ofproto.PhyPort(
        port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
        config=_create_port_config(no_stp=True, no_recv_stp=True,
                                   no_flood=True),
        state_link_down=True, state_stp=ofproto.OFPPS_STP_FORWARD,
        curr=_create_port_features(mode_1gb_fd=True, fiber=True),
        advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
        supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                        pause=True, pause_asym=True),
        peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                   autoneg=True))
    self.buf.append(pp.serialize())
    self.buf.set_message_boundaries(48)
    self.assertTupleEqual(pp, ofproto.PhyPort.deserialize(self.buf))

  def test_deserialize(self):
    self.buf.append('\x00\x42' '\xab\xcd\xef\xa0\xb1\xc2'
                    'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x1a' '\x00\x00\x02\x01'
                    '\x00\x00\x01\x20' '\x00\x00\x05\x20'
                    '\x00\x00\x0d\x20' '\x00\x00\x03\x20')
    self.buf.set_message_boundaries(48)
    self.assertTupleEqual(
        (0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport',
         _create_port_config(no_stp=True, no_recv_stp=True,
                             no_flood=True),
         True, ofproto.OFPPS_STP_FORWARD,
         _create_port_features(mode_1gb_fd=True, fiber=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True,
                               pause_asym=True),
         _create_port_features(mode_1gb_fd=True, fiber=True,
                               autoneg=True)),
      ofproto.PhyPort.deserialize(self.buf))
    # Test that the deserialization consumed all 48 bytes.
    with self.assertRaises(AssertionError):
      self.buf.skip_bytes(1)

  def test_deserialize_every_state_stp(self):
    for i in (ofproto.OFPPS_STP_LISTEN, ofproto.OFPPS_STP_LEARN,
              ofproto.OFPPS_STP_FORWARD, ofproto.OFPPS_STP_BLOCK):
      state_ser = i | 1  # state_link_down=True
      self.buf.append('\x00\x42' '\xab\xcd\xef\xa0\xb1\xc2'
                       'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                       '\x00\x00\x00\x1a' + struct.pack('!L', state_ser)
                       + '\x00\x00\x01\x20' '\x00\x00\x05\x20'
                       '\x00\x00\x0d\x20' '\x00\x00\x03\x20')
      self.buf.set_message_boundaries(48)
      args = (0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport',
              _create_port_config(no_stp=True, no_recv_stp=True,
                                  no_flood=True),
              True, i,
              _create_port_features(mode_1gb_fd=True, fiber=True),
              _create_port_features(mode_1gb_fd=True, fiber=True, pause=True),
              _create_port_features(mode_1gb_fd=True, fiber=True, pause=True,
                                    pause_asym=True),
              _create_port_features(mode_1gb_fd=True, fiber=True, autoneg=True))
      self.assertTupleEqual(args, ofproto.PhyPort.deserialize(self.buf))

  def test_deserialize_invalid_state_stp_0x0601(self):
    self.buf.append('\x00\x42' '\xab\xcd\xef\xa0\xb1\xc2'
                    'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x1a' '\x00\x00\x06\x81'
                    '\x00\x00\x01\x20' '\x00\x00\x05\x20'
                    '\x00\x00\x0d\x20' '\x00\x00\x03\x20')
    self.buf.set_message_boundaries(48)
    # The invalid bit at 0x0400 in the state is ignored.
    self.assertTupleEqual(
        (0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport',
         _create_port_config(no_stp=True, no_recv_stp=True,
                             no_flood=True),
         True, ofproto.OFPPS_STP_FORWARD,
         _create_port_features(mode_1gb_fd=True, fiber=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True,
                               pause_asym=True),
         _create_port_features(mode_1gb_fd=True, fiber=True,
                               autoneg=True)),
      ofproto.PhyPort.deserialize(self.buf))

  def test_deserialize_invalid_state_bit_0x0281(self):
    self.buf.append('\x00\x42' '\xab\xcd\xef\xa0\xb1\xc2'
                    'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x1a' '\x00\x00\x02\x81'
                    '\x00\x00\x01\x20' '\x00\x00\x05\x20'
                    '\x00\x00\x0d\x20' '\x00\x00\x03\x20')
    self.buf.set_message_boundaries(48)
    # The invalid bit at 0x0080 in the state is ignored.
    self.assertTupleEqual(
        (0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport',
         _create_port_config(no_stp=True, no_recv_stp=True,
                             no_flood=True),
         True, ofproto.OFPPS_STP_FORWARD,
         _create_port_features(mode_1gb_fd=True, fiber=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True,
                               pause_asym=True),
         _create_port_features(mode_1gb_fd=True, fiber=True,
                               autoneg=True)),
      ofproto.PhyPort.deserialize(self.buf))


class TestSwitchFeatures(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()

  def test_create(self):
    pp1 = ofproto.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofproto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    pp2 = ofproto.PhyPort(
      port_no=0x43, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofproto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    sf = ofproto.SwitchFeatures(
        datapath_id=123456, n_buffers=42, n_tables=3, cap_flow_stats=True,
        cap_table_stats=False, cap_port_stats=True, cap_stp=False,
        cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
        actions=frozenset((0, 2, 3, 5)), ports=(pp1, pp2))

  def test_serialize_no_port(self):
    sf = ofproto.SwitchFeatures(
        datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
        cap_table_stats=False, cap_port_stats=True, cap_stp=False,
        cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
        actions=frozenset((0, 2, 3, 5, 8)), ports=())
    self.assertEqual('\x00\x00\x00\x00\x00\x12\x34\x56'
                     '\x00\x00\x00\x05'
                     '\x03\x00\x00\x00'
                     '\x00\x00\x00\xa5'
                     '\x00\x00\x01\x2d', ''.join(sf.serialize()))

  def test_serialize_one_port(self):
    pp1 = ofproto.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofproto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    sf = ofproto.SwitchFeatures(
        datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
        cap_table_stats=False, cap_port_stats=True, cap_stp=False,
        cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
        actions=frozenset((0, 2, 3, 5, 8)), ports=(pp1,))
    self.assertEqual('\x00\x00\x00\x00\x00\x12\x34\x56'
                     '\x00\x00\x00\x05'
                     '\x03\x00\x00\x00'
                     '\x00\x00\x00\xa5'
                     '\x00\x00\x01\x2d'
                     + pp1.serialize(), ''.join(sf.serialize()))

  def test_serialize_two_ports(self):
    pp1 = ofproto.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofproto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    pp2 = ofproto.PhyPort(
      port_no=0x43, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofproto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    sf = ofproto.SwitchFeatures(
        datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
        cap_table_stats=False, cap_port_stats=True, cap_stp=False,
        cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
        actions=frozenset((0, 2, 3, 5, 8)), ports=(pp1, pp2))
    self.assertEqual('\x00\x00\x00\x00\x00\x12\x34\x56'
                     '\x00\x00\x00\x05'
                     '\x03\x00\x00\x00'
                     '\x00\x00\x00\xa5'
                     '\x00\x00\x01\x2d'
                     + pp1.serialize()
                     + pp2.serialize(), ''.join(sf.serialize()))

  def test_serialize_every_capability_flag(self):
    for i in xrange(0, 7):
      flag = 1 << i
      # Bit 4 is reserved and not exposed in the structure.
      # Shift all bits to the left from bit 4.
      if i > 3:
        flag = flag << 1
      args = [False]*6
      args.insert(i, True)
      args[0:0] = [0x123456, 5, 3]
      args.extend([frozenset((0, 2, 3, 5, 8)), ()])
      sf = ofproto.SwitchFeatures(*args)
      self.assertEqual('\x00\x00\x00\x00\x00\x12\x34\x56'
                       '\x00\x00\x00\x05'
                       '\x03\x00\x00\x00'
                       + struct.pack('!L', flag)
                       + '\x00\x00\x01\x2d', ''.join(sf.serialize()))

  def test_serialize_every_action(self):
    for i in xrange(0, 32):
      action_flag = 1 << i
      sf = ofproto.SwitchFeatures(
          datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
          cap_table_stats=False, cap_port_stats=True, cap_stp=False,
          cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
          actions=frozenset((i,)), ports=())
      self.assertEqual('\x00\x00\x00\x00\x00\x12\x34\x56'
                       '\x00\x00\x00\x05'
                       '\x03\x00\x00\x00'
                       '\x00\x00\x00\xa5'
                       + struct.pack('!L', action_flag),
                       ''.join(sf.serialize()))

  def test_deserialize_deserialize_two_ports(self):
    pp1 = ofproto.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofproto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    pp2 = ofproto.PhyPort(
      port_no=0x43, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofproto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    sf = ofproto.SwitchFeatures(
        datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
        cap_table_stats=False, cap_port_stats=True, cap_stp=False,
        cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
        actions=frozenset((0, 2, 3, 5, 8)), ports=(pp1, pp2))
    self.buf.append(''.join(sf.serialize()))
    self.buf.set_message_boundaries(24 + 48 * 2)
    self.assertTupleEqual(sf, ofproto.SwitchFeatures.deserialize(self.buf))

  def test_deserialize_two_ports(self):
    pp1 = ofproto.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofproto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    pp2 = ofproto.PhyPort(
      port_no=0x43, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofproto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    self.buf.append('\x00\x00\x00\x00\x00\x12\x34\x56'
                     '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                     '\x00\x00\x00\xa5' '\x00\x00\x01\x2d')
    self.buf.append(pp1.serialize())
    self.buf.append(pp2.serialize())
    self.buf.set_message_boundaries(24 + 48 * 2)
    self.assertTupleEqual((0x123456, 5, 3, True, False, True, False, True,
                           False, True, frozenset((0, 2, 3, 5, 8)), (pp1, pp2)),
                          ofproto.SwitchFeatures.deserialize(self.buf))

  def test_deserialize_every_capability_flag(self):
    for i in xrange(0, 7):
      flag = 1 << i
      # Bit 4 is reserved and not exposed in the structure.
      # Shift all bits to the left from bit 4.
      if i > 3:
        flag = flag << 1
      self.buf.append('\x00\x00\x00\x00\x00\x12\x34\x56'
                      '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                       + struct.pack('!L', flag) + '\x00\x00\x01\x2d')
      self.buf.set_message_boundaries(24)
      args = [False]*6
      args.insert(i, True)
      args[0:0] = [0x123456, 5, 3]
      args.extend([frozenset((0, 2, 3, 5, 8)), ()])
      args = tuple(args)
      self.assertTupleEqual(args, ofproto.SwitchFeatures.deserialize(self.buf))

  def test_deserialize_reserved_capability_flag_0x10(self):
    self.buf.append('\x00\x00\x00\x00\x00\x12\x34\x56'
                     '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                     '\x00\x00\x00\xb5' '\x00\x00\x01\x2d')
    self.buf.set_message_boundaries(24)
    # The reserved bit at 0x00000010 is ignored.
    self.assertTupleEqual((0x123456, 5, 3, True, False, True, False, True,
                           False, True, frozenset((0, 2, 3, 5, 8)), ()),
                          ofproto.SwitchFeatures.deserialize(self.buf))

  def test_deserialize_invalid_capability_flag_0x0100(self):
    self.buf.append('\x00\x00\x00\x00\x00\x12\x34\x56'
                    '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                    '\x00\x00\x01\xa5' '\x00\x00\x01\x2d')
    self.buf.set_message_boundaries(24)
    # The reserved bit at 0x00000100 is ignored.
    self.assertTupleEqual((0x123456, 5, 3, True, False, True, False, True,
                           False, True, frozenset((0, 2, 3, 5, 8)), ()),
                          ofproto.SwitchFeatures.deserialize(self.buf))

  def test_deserialize_every_action(self):
    for i in xrange(0, 32):
      action_flag = 1 << i
      self.buf.append('\x00\x00\x00\x00\x00\x12\x34\x56'
                      '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                      '\x00\x00\x00\xa5' + struct.pack('!L', action_flag))
      self.buf.set_message_boundaries(24)
      self.assertTupleEqual((0x123456, 5, 3, True, False, True, False, True,
                             False, True, frozenset((i,)), ()),
                            ofproto.SwitchFeatures.deserialize(self.buf))


class TestSwitchConfig(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()

  def test_create(self):
    sc = ofproto.SwitchConfig(config_frag=ofproto.OFPC_FRAG_DROP,
                              miss_send_len=128)

  def test_serialize(self):
    sc = ofproto.SwitchConfig(config_frag=ofproto.OFPC_FRAG_DROP,
                              miss_send_len=128)
    self.assertEqual('\x00\x01\x00\x80', sc.serialize())

  def test_serialize_every_config_frag(self):
    for config_frag in (ofproto.OFPC_FRAG_NORMAL, ofproto.OFPC_FRAG_DROP,
                        ofproto.OFPC_FRAG_REASM):
      sc = ofproto.SwitchConfig(config_frag=config_frag, miss_send_len=128)
      self.assertEqual(struct.pack('!H', config_frag) + '\x00\x80',
                       sc.serialize())

  def test_serialize_deserialize(self):
    sc = ofproto.SwitchConfig(config_frag=ofproto.OFPC_FRAG_DROP,
                              miss_send_len=128)
    self.buf.append(sc.serialize())
    self.buf.set_message_boundaries(4)
    self.assertTupleEqual(sc, ofproto.SwitchConfig.deserialize(self.buf))

  def test_deserialize(self):
    self.buf.append('\x00\x01\x00\x80')
    self.buf.set_message_boundaries(4)
    self.assertTupleEqual((ofproto.OFPC_FRAG_DROP, 128),
                          ofproto.SwitchConfig.deserialize(self.buf))

  def test_deserialize_every_config_frag(self):
    for config_frag in (ofproto.OFPC_FRAG_NORMAL, ofproto.OFPC_FRAG_DROP,
                        ofproto.OFPC_FRAG_REASM):
      self.buf.append(struct.pack('!H', config_frag) + '\x00\x80')
      self.buf.set_message_boundaries(4)
      self.assertTupleEqual((config_frag, 128),
                            ofproto.SwitchConfig.deserialize(self.buf))

  def test_deserialize_invalid_config_frag_0x0004(self):
    self.buf.append('\x00\x04\x00\x80')
    self.buf.set_message_boundaries(4)
    with self.assertRaises(ValueError):
      ofproto.SwitchConfig.deserialize(self.buf)


class MockTransport(object):
  """A basic mock of Twisted's ITransport interface.
  """

  __slots__ = ('buffer',)

  def __init__(self):
    self.buffer = buffer.ReceiveBuffer()

  def writeSequence(self, data):
    for buf in data:
      self.buffer.append(buf)


class MockOpenflowProtocolSubclass(ofproto.OpenflowProtocol):

  def __init__(self, *args, **kargs):
    ofproto.OpenflowProtocol.__init__(self, *args, **kargs)
    self.calls_made = []

  def handle_hello(self):
    self.calls_made.append(('handle_hello',))

  def handle_error(self, error_type, error_code, error_text, data):
    self.calls_made.append(('handle_error', error_type, error_code, error_text,
                            data))

  def handle_echo_request(self, xid, data):
    self.calls_made.append(('handle_echo_request', xid, data))

  def handle_echo_reply(self, xid, data):
    self.calls_made.append(('handle_echo_reply', xid, data))

  def handle_features_request(self, xid):
    self.calls_made.append(('handle_features_request', xid))

  def handle_features_reply(self, xid, switch_features):
    self.calls_made.append(('handle_features_reply', xid, switch_features))

  def handle_get_config_request(self, xid):
    self.calls_made.append(('handle_get_config_request', xid))

  def handle_get_config_reply(self, xid, switch_config):
    self.calls_made.append(('handle_get_config_reply', xid, switch_config))

  def handle_set_config(self, switch_config):
    self.calls_made.append(('handle_set_config', switch_config))

  def handle_packet_in(self, buffer_id, total_len, in_port, reason, data):
    self.calls_made.append(('handle_packet_in', buffer_id, total_len, in_port,
                            reason, data))

  def handle_flow_removed(
      self, match, cookie, priority, reason, duration_sec, duration_nsec,
      idle_timeout, packet_count, byte_count):
    self.calls_made.append((
        'handle_flow_removed', match, cookie, priority, reason, duration_sec,
        duration_nsec, idle_timeout, packet_count, byte_count))

  def handle_port_status(self, reason, desc):
    self.calls_made.append(('handle_port_status', reason, desc))

  def handle_packet_out(self, buffer_id, in_port, actions, data):
    self.calls_made.append(('handle_packet_out', buffer_id, in_port, actions,
                            data))

  def handle_flow_mod(
      self, match, cookie, command, idle_timeout, hard_timeout, priority,
      buffer_id, out_port, send_flow_rem, check_overlap, emerg, actions):
    self.calls_made.append((
        'handle_flow_mod', match, cookie, command, idle_timeout, hard_timeout,
        priority, buffer_id, out_port, send_flow_rem, check_overlap, emerg,
        actions))

  def handle_port_mod(self, port_no, hw_addr, config, mask, advertise):
    self.calls_made.append(('handle_port_mod', port_no, hw_addr, config, mask,
                            advertise))

  def handle_stats_request_desc(self, xid):
    self.calls_made.append(('handle_stats_request_desc', xid))

  def handle_stats_request_flow(self, xid, match, table_id, out_port):
    self.calls_made.append(('handle_stats_request_flow', xid, match, table_id,
                            out_port))

  def handle_stats_request_aggregate(self, xid, match, table_id, out_port):
    self.calls_made.append(('handle_stats_request_aggregate', xid, match,
                            table_id, out_port))

  def handle_stats_request_table(self, xid):
    self.calls_made.append(('handle_stats_request_table', xid))

  def handle_stats_request_port(self, xid, port_no):
    self.calls_made.append(('handle_stats_request_port', xid, port_no))

  def handle_stats_request_queue(self, xid, port_no, queue_id):
    self.calls_made.append(('handle_stats_request_queue', xid, port_no,
                            queue_id))

  def handle_stats_reply_desc(self, xid, desc_stats):
    self.calls_made.append(('handle_stats_reply_desc', xid, desc_stats))

  def handle_stats_reply_flow(self, xid, flow_stats, reply_more):
    self.calls_made.append(('handle_stats_reply_flow', xid, flow_stats,
                            reply_more))

  def handle_stats_reply_aggregate(self, xid, packet_count, byte_count,
                                   flow_count):
    self.calls_made.append(('handle_stats_reply_aggregate', xid, packet_count,
                            byte_count, flow_count))

  def handle_stats_reply_table(self, xid, table_stats, reply_more):
    self.calls_made.append(('handle_stats_reply_table', xid, table_stats,
                            reply_more))

  def handle_stats_reply_port(self, xid, port_stats, reply_more):
    self.calls_made.append(('handle_stats_reply_port', xid, port_stats,
                            reply_more))

  def handle_stats_reply_queue(self, xid, queue_stats, reply_more):
    self.calls_made.append(('handle_stats_reply_queue', xid, queue_stats,
                            reply_more))

  def handle_barrier_request(self, xid):
    self.calls_made.append(('handle_barrier_request', xid))

  def handle_barrier_reply(self, xid):
    self.calls_made.append(('handle_barrier_reply', xid))


MockVendorAction = ofaction.vendor_action('MockVendorAction', 0x4242,
                                          '!L4x', ('dummy',))


class MockVendorHandler(object):
  """A mock vendor extension implementation.
  """

  def __init__(self):
    # A list of tuples representing calls.
    self.calls_made = []

  vendor_id = 0x4242

  def handle_vendor_message(self, conn, msg_length, xid, buffer):
    bytes = buffer.read_bytes(msg_length - 12)  # Consume the remaining bytes.
    self.calls_made.append(('handle_vendor_message', conn, msg_length, xid,
                            bytes))

  def deserialize_vendor_action(self, action_length, buffer):
    a = MockVendorAction.deserialize(buffer)
    self.calls_made.append(('deserialize_vendor_action', action_length, a))
    return a

  def handle_vendor_stats_request(self, conn, msg_length, xid, buffer):
    bytes = buffer.read_bytes(msg_length - 16)  # Consume the remaining bytes.
    self.calls_made.append(('handle_vendor_stats_request', conn, msg_length,
                            xid, bytes))

  def handle_vendor_stats_reply(self, conn, msg_length, xid, buffer,
                                reply_more):
    bytes = buffer.read_bytes(msg_length - 16)  # Consume the remaining bytes.
    self.calls_made.append(('handle_vendor_stats_reply', conn, msg_length,
                            xid, bytes, reply_more))


class TestOpenflowProtocol(unittest2.TestCase):

  def setUp(self):
    self.transport = MockTransport()
    self.vendor_handler = MockVendorHandler()
    self.proto = MockOpenflowProtocolSubclass(
        vendor_handlers=(self.vendor_handler,))
    self.proto.transport = self.transport

    self.phyport1 = ofproto.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofproto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))

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

  def test_connection_made(self):
    self.proto.connectionMade()

  def test_send_hello(self):
    self.proto.connectionMade()
    self.proto.send_hello()
    # Sent OFPT_HELLO with xid 0.
    self.assertEqual('\x01\x00\x00\x08\x00\x00\x00\x00',
                     self._get_next_sent_message())

  def test_handle_hello(self):
    self.proto.connectionMade()

    # OFPT_HELLO with xid 0.
    self.proto.dataReceived('\x01\x00\x00\x08\x00\x00\x00\x00')
    self.assertListEqual([('handle_hello',)],
                         self.proto.calls_made)

  # TODO(romain): Test OFPT_ERROR messages.

  def test_send_echo_request(self):
    self.proto.connectionMade()

    self.assertEqual(0, self.proto.send_echo_request(('abcdef',)))
    self.assertEqual('\x01\x02\x00\x0e\x00\x00\x00\x00abcdef',
                     self._get_next_sent_message())
    self.assertEqual(1, self.proto.send_echo_request(('abcdefgh',)))
    self.assertEqual('\x01\x02\x00\x10\x00\x00\x00\x01abcdefgh',
                     self._get_next_sent_message())

  def test_handle_echo_request(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x02\x00\x10\x00\x00\x00\x04abcdefgh')
    self.assertListEqual([('handle_echo_request', 4, 'abcdefgh')],
                         self.proto.calls_made)

  def test_send_echo_reply(self):
    self.proto.connectionMade()

    self.proto.send_echo_reply(4, ('abcdefgh',))
    self.assertEqual('\x01\x03\x00\x10\x00\x00\x00\x04abcdefgh',
                     self._get_next_sent_message())

  def test_handle_echo_reply(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x03\x00\x10\x00\x00\x00\x04abcdefgh')
    self.assertListEqual([('handle_echo_reply', 4, 'abcdefgh')],
                         self.proto.calls_made)

  # TODO(romain): Test sending and handling vendor messages.

  def test_send_features_request(self):
    self.proto.connectionMade()

    self.assertEqual(0, self.proto.send_features_request())
    self.assertEqual('\x01\x05\x00\x08\x00\x00\x00\x00',
                     self._get_next_sent_message())
    self.assertEqual(1, self.proto.send_features_request())
    self.assertEqual('\x01\x05\x00\x08\x00\x00\x00\x01',
                     self._get_next_sent_message())

  def test_handle_features_request(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x05\x00\x08\x00\x00\x00\x04')
    self.assertListEqual([('handle_features_request', 4)],
                         self.proto.calls_made)

  def test_send_features_reply(self):
    self.proto.connectionMade()

    sf = ofproto.SwitchFeatures(
        datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
        cap_table_stats=False, cap_port_stats=True, cap_stp=False,
        cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
        actions=frozenset((0, 2, 3, 5, 8)), ports=(self.phyport1,))
    self.proto.send_features_reply(4, sf)
    self.assertEqual('\x01\x06\x00\x50\x00\x00\x00\x04'
                     + ''.join(sf.serialize()),
                     self._get_next_sent_message())

  def test_handle_features_reply(self):
    self.proto.connectionMade()

    sf = ofproto.SwitchFeatures(
        datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
        cap_table_stats=False, cap_port_stats=True, cap_stp=False,
        cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
        actions=frozenset((0, 2, 3, 5, 8)), ports=(self.phyport1,))
    self.proto.dataReceived('\x01\x06\x00\x50\x00\x00\x00\x04'
                            + ''.join(sf.serialize()))
    self.assertListEqual([('handle_features_reply', 4, sf)],
                         self.proto.calls_made)

  def test_send_get_config_request(self):
    self.proto.connectionMade()

    self.assertEqual(0, self.proto.send_get_config_request())
    self.assertEqual('\x01\x07\x00\x08\x00\x00\x00\x00',
                     self._get_next_sent_message())
    self.assertEqual(1, self.proto.send_get_config_request())
    self.assertEqual('\x01\x07\x00\x08\x00\x00\x00\x01',
                     self._get_next_sent_message())

  def test_handle_get_config_request(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x07\x00\x08\x00\x00\x00\x04')
    self.assertListEqual([('handle_get_config_request', 4)],
                         self.proto.calls_made)

  def test_send_get_config_reply(self):
    self.proto.connectionMade()

    sc = ofproto.SwitchConfig(config_frag=ofproto.OFPC_FRAG_DROP,
                              miss_send_len=128)
    self.proto.send_get_config_reply(4, sc)
    self.assertEqual('\x01\x08\x00\x0c\x00\x00\x00\x04'
                     + ''.join(sc.serialize()),
                     self._get_next_sent_message())

  def test_handle_get_config_reply(self):
    self.proto.connectionMade()

    sc = ofproto.SwitchConfig(config_frag=ofproto.OFPC_FRAG_DROP,
                              miss_send_len=128)
    self.proto.dataReceived('\x01\x08\x00\x0c\x00\x00\x00\x04'
                            + ''.join(sc.serialize()))
    self.assertListEqual([('handle_get_config_reply', 4, sc)],
                         self.proto.calls_made)

  def test_send_set_config(self):
    self.proto.connectionMade()

    sc = ofproto.SwitchConfig(config_frag=ofproto.OFPC_FRAG_DROP,
                              miss_send_len=128)
    self.proto.send_set_config(sc)
    self.assertEqual('\x01\x09\x00\x0c\x00\x00\x00\x00'
                     + ''.join(sc.serialize()),
                     self._get_next_sent_message())

  def test_handle_set_config(self):
    self.proto.connectionMade()

    sc = ofproto.SwitchConfig(config_frag=ofproto.OFPC_FRAG_DROP,
                              miss_send_len=128)
    self.proto.dataReceived('\x01\x09\x00\x0c\x00\x00\x00\x00'
                            + ''.join(sc.serialize()))
    self.assertListEqual([('handle_set_config', sc)],
                         self.proto.calls_made)

  def test_send_packet_in(self):
    self.proto.connectionMade()

    self.proto.send_packet_in(0x1324, 0x100, 0x42, ofproto.OFPR_ACTION,
                              ('abcd', 'ef'))
    self.assertEqual('\x01\x0a\x00\x18\x00\x00\x00\x00'
                     '\x00\x00\x13\x24\x01\x00\x00\x42\x01\x00'
                     'abcdef',
                     self._get_next_sent_message())

  def test_send_packet_in_invalid_action_53(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.send_packet_in(0x1324, 0x100, 0x42, 53,
                                ('abcd', 'ef'))
    self.assertIsNone(self._get_next_sent_message())

  def test_handle_packet_in(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x0a\x00\x18\x00\x00\x00\x00'
                            '\x00\x00\x13\x24\x01\x00\x00\x42\x01\x00'
                            'abcdef')
    self.assertListEqual([('handle_packet_in', 0x1324, 0x100, 0x42,
                           ofproto.OFPR_ACTION, 'abcdef')],
                         self.proto.calls_made)

  def test_handle_packet_in_invalid_action(self):
    self.proto.connectionMade()

    with self.assertRaises(Exception):
      self.proto.dataReceived('\x01\x0a\x00\x18\x00\x00\x00\x00'
                              '\x00\x00\x13\x24\x01\x00\x00\x42\x53\x00'
                              'abcdef')
    self.assertListEqual([], self.proto.calls_made)

  def test_send_flow_removed(self):
    self.proto.connectionMade()

    self.proto.send_flow_removed(
        self.match1, 0x12345678, 0x1000, ofproto.OFPRR_DELETE, 0x302010,
        0x030201, 0x4231, 0x635241, 0x554433)
    self.assertEqual('\x01\x0b\x00\x58\x00\x00\x00\x00'
                     + self.match1.serialize()
                     + '\x00\x00\x00\x00\x12\x34\x56\x78'
                     '\x10\x00' '\x02\x00' '\x00\x30\x20\x10' '\x00\x03\x02\x01'
                     '\x42\x31\x00\x00' '\x00\x00\x00\x00\x00\x63\x52\x41'
                     '\x00\x00\x00\x00\x00\x55\x44\x33',
                     self._get_next_sent_message())

  def test_send_flow_removed_invalid_action_3(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.send_flow_removed(
          self.match1, 0x12345678, 0x1000, 3, 0x302010, 0x030201, 0x4231,
          0x635241, 0x554433)
    self.assertIsNone(self._get_next_sent_message())

  def test_handle_flow_removed(self):
    self.proto.connectionMade()

    self.proto.dataReceived(
        '\x01\x0b\x00\x58\x00\x00\x00\x00'
        + self.match1.serialize()
        + '\x00\x00\x00\x00\x12\x34\x56\x78'
        '\x10\x00' '\x02\x00' '\x00\x30\x20\x10' '\x00\x03\x02\x01'
        '\x42\x31\x00\x00' '\x00\x00\x00\x00\x00\x63\x52\x41'
        '\x00\x00\x00\x00\x00\x55\x44\x33')
    self.assertListEqual(
        [('handle_flow_removed', self.match1, 0x12345678, 0x1000,
          ofproto.OFPRR_DELETE, 0x302010, 0x030201, 0x4231, 0x635241,
          0x554433)],
        self.proto.calls_made)

  def test_handle_flow_removed_invalid_action_3(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.dataReceived(
          '\x01\x0b\x00\x58\x00\x00\x00\x00'
          + self.match1.serialize()
          + '\x00\x00\x00\x00\x12\x34\x56\x78'
          '\x10\x00' '\x03\x00' '\x00\x30\x20\x10' '\x00\x03\x02\x01'
          '\x42\x31\x00\x00' '\x00\x00\x00\x00\x00\x63\x52\x41'
          '\x00\x00\x00\x00\x00\x55\x44\x33')
    self.assertListEqual([], self.proto.calls_made)

  def test_send_port_status(self):
    self.proto.connectionMade()

    self.proto.send_port_status(ofproto.OFPPR_MODIFY, self.phyport1)
    self.assertEqual('\x01\x0c\x00\x40\x00\x00\x00\x00'
                     '\x02\x00\x00\x00\x00\x00\x00\x00'
                     + self.phyport1.serialize(),
                     self._get_next_sent_message())

  def test_send_port_status_invalid_action_3(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.send_port_status(3, self.phyport1)
    self.assertIsNone(self._get_next_sent_message())

  def test_handle_port_status(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x0c\x00\x40\x00\x00\x00\x00'
                            '\x02\x00\x00\x00\x00\x00\x00\x00'
                            + self.phyport1.serialize())
    self.assertListEqual([('handle_port_status', ofproto.OFPPR_MODIFY,
                           self.phyport1)],
                         self.proto.calls_made)

  def test_handle_port_status_invalid_action_3(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.dataReceived('\x01\x0c\x00\x40\x00\x00\x00\x00'
                              '\x03\x00\x00\x00\x00\x00\x00\x00'
                              + self.phyport1.serialize())
    self.assertListEqual([], self.proto.calls_made)

  def test_send_packet_out_buffered_no_actions(self):
    self.proto.connectionMade()

    self.proto.send_packet_out(0x01010101, 0xabcd, (), ())
    self.assertEqual('\x01\x0d\x00\x10\x00\x00\x00\x00'
                     '\x01\x01\x01\x01\xab\xcd\x00\x00'
                     , self._get_next_sent_message())

  def test_send_packet_out_unbuffered_no_actions(self):
    self.proto.connectionMade()

    self.proto.send_packet_out(0xffffffff, 0xabcd, (), ('helloworld',))
    self.assertEqual('\x01\x0d\x00\x1a\x00\x00\x00\x00'
                     '\xff\xff\xff\xff\xab\xcd\x00\x00'
                     'helloworld'
                     , self._get_next_sent_message())

  def test_send_packet_out_buffered_two_actions(self):
    self.proto.connectionMade()

    self.proto.send_packet_out(
        0x01010101, 0xabcd, (
            ofaction.ActionOutput(port=0x1234, max_len=0x9abc),
            ofaction.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')),
        ())
    self.assertEqual('\x01\x0d\x00\x28\x00\x00\x00\x00'
                     '\x01\x01\x01\x01\xab\xcd\x00\x02'
                     '\x00\x00\x00\x08'
                         '\x12\x34\x9a\xbc'
                     '\x00\x05\x00\x10'
                         '\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00',
                     self._get_next_sent_message())

  def test_send_packet_out_unbuffered_two_actions(self):
    self.proto.connectionMade()

    self.proto.send_packet_out(
        0xffffffff, 0xabcd, (
            ofaction.ActionOutput(port=0x1234, max_len=0x9abc),
            ofaction.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')),
        ('helloworld',))
    self.assertEqual('\x01\x0d\x00\x32\x00\x00\x00\x00'
                     '\xff\xff\xff\xff\xab\xcd\x00\x02'
                     '\x00\x00\x00\x08'
                         '\x12\x34\x9a\xbc'
                     '\x00\x05\x00\x10'
                         '\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00'
                     'helloworld',
                     self._get_next_sent_message())

  def test_send_packet_out_unbuffered_vendor_action(self):
    self.proto.connectionMade()

    self.proto.send_packet_out(
        0xffffffff, 0xabcd, (MockVendorAction(dummy=0x15263748),),
        ('helloworld',))
    self.assertEqual('\x01\x0d\x00\x2a\x00\x00\x00\x00'
                     '\xff\xff\xff\xff\xab\xcd\x00\x01'
                     '\x00\x0c\x00\x10' '\x00\x00\x42\x42'
                         '\x15\x26\x37\x48' '\x00\x00\x00\x00'
                     'helloworld',
                     self._get_next_sent_message())

  def test_send_packet_out_unbuffered_no_data(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.send_packet_out(
          0xffffffff, 0xabcd, (
              ofaction.ActionOutput(port=0x1234, max_len=0x9abc),
              ofaction.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')),
          ())
    self.assertIsNone(self._get_next_sent_message())

  def test_send_packet_out_buffered_with_data(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.send_packet_out(
          0x01010101, 0xabcd, (
              ofaction.ActionOutput(port=0x1234, max_len=0x9abc),
              ofaction.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')),
          ('helloworld',))
    self.assertIsNone(self._get_next_sent_message())

  def test_send_packet_out_invalid_port0xff01(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.send_packet_out(
          0x01010101, 0xff01, (
              ofaction.ActionOutput(port=0x1234, max_len=0x9abc),
              ofaction.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')),
          ())
    self.assertIsNone(self._get_next_sent_message())

  def test_handle_packet_out_buffered_two_actions(self):
    self.proto.connectionMade()

    self.proto.dataReceived(
        '\x01\x0d\x00\x28\x00\x00\x00\x00'
        '\x01\x01\x01\x01\xab\xcd\x00\x02'
        '\x00\x00\x00\x08'
            '\x12\x34\x9a\xbc'
        '\x00\x05\x00\x10'
            '\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00')
    self.assertListEqual([(
        'handle_packet_out', 0x01010101, 0xabcd, (
            ofaction.ActionOutput(port=0x1234, max_len=0x9abc),
            ofaction.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')),
        '')], self.proto.calls_made)

  def test_handle_packet_out_unbuffered_two_actions(self):
    self.proto.connectionMade()

    self.proto.dataReceived(
        '\x01\x0d\x00\x32\x00\x00\x00\x00'
        '\xff\xff\xff\xff\xab\xcd\x00\x02'
        '\x00\x00\x00\x08'
            '\x12\x34\x9a\xbc'
        '\x00\x05\x00\x10'
            '\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00'
        'helloworld')
    self.assertListEqual([(
        'handle_packet_out', 0xffffffff, 0xabcd, (
            ofaction.ActionOutput(port=0x1234, max_len=0x9abc),
            ofaction.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')),
        'helloworld')], self.proto.calls_made)

  def test_handle_packet_out_unbuffered_vendor_action(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x0d\x00\x2a\x00\x00\x00\x00'
                            '\xff\xff\xff\xff\xab\xcd\x00\x01'
                            '\x00\x0c\x00\x10' '\x00\x00\x42\x42'
                                '\x15\x26\x37\x48' '\x00\x00\x00\x00'
                            'helloworld')
    self.assertListEqual([('handle_packet_out', 0xffffffff, 0xabcd,
                           (MockVendorAction(dummy=0x15263748),), 'helloworld')],
                          self.proto.calls_made)
    self.assertListEqual([('deserialize_vendor_action', 8+8,
                           MockVendorAction(dummy=0x15263748))],
                         self.vendor_handler.calls_made)

  def test_send_flow_mod(self):
    self.proto.connectionMade()

    self.proto.send_flow_mod(
        self.match1, 0x12345678, ofproto.OFPFC_MODIFY, 0x4231, 0, 0x1000,
        0x01010101, 0xabcd, True, False, False, (
            ofaction.ActionOutput(port=0x1234, max_len=0x9abc),
            ofaction.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')))
    self.assertEqual('\x01\x0e\x00\x60\x00\x00\x00\x00'
                     + self.match1.serialize()
                     + '\x00\x00\x00\x00\x12\x34\x56\x78'
                     '\x00\x01' '\x42\x31\x00\x00' '\x10\x00'
                     '\x01\x01\x01\x01' '\xab\xcd' '\x00\x01'
                     '\x00\x00\x00\x08'
                         '\x12\x34\x9a\xbc'
                     '\x00\x05\x00\x10'
                         '\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00',
                     self._get_next_sent_message())

  def test_send_flow_mod_invalid_cookie_minus1(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.send_flow_mod(
          self.match1, 0xffffffffffffffff, ofproto.OFPFC_MODIFY, 0x4231, 0,
          0x1000, 0x01010101, 0xabcd, True, False, False, ())
    self.assertIsNone(self._get_next_sent_message())

  def test_send_flow_mod_invalid_command_5(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.send_flow_mod(
          self.match1, 0x12345678, 5, 0x4231, 0, 0x1000,
          0x01010101, 0xabcd, True, False, False, ())
    self.assertIsNone(self._get_next_sent_message())

  def test_handle_flow_mod_two_actions(self):
    self.proto.connectionMade()

    self.proto.dataReceived(
        '\x01\x0e\x00\x60\x00\x00\x00\x00'
        + self.match1.serialize()
        + '\x00\x00\x00\x00\x12\x34\x56\x78'
        '\x00\x01' '\x42\x31\x00\x00' '\x10\x00'
        '\x01\x01\x01\x01' '\xab\xcd' '\x00\x01'
        '\x00\x00\x00\x08'
            '\x12\x34\x9a\xbc'
        '\x00\x05\x00\x10'
            '\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00')
    self.assertListEqual(
        [('handle_flow_mod', self.match1, 0x12345678, ofproto.OFPFC_MODIFY,
          0x4231, 0, 0x1000, 0x01010101, 0xabcd, True, False, False, (
              ofaction.ActionOutput(port=0x1234, max_len=0x9abc),
              ofaction.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')))],
        self.proto.calls_made)

  def test_handle_flow_mod_no_actions(self):
    self.proto.connectionMade()

    self.proto.dataReceived(
        '\x01\x0e\x00\x48\x00\x00\x00\x00'
        + self.match1.serialize()
        + '\x00\x00\x00\x00\x12\x34\x56\x78'
        '\x00\x01' '\x42\x31\x00\x00' '\x10\x00'
        '\x01\x01\x01\x01' '\xab\xcd' '\x00\x01')
    self.assertListEqual(
        [('handle_flow_mod', self.match1, 0x12345678, ofproto.OFPFC_MODIFY,
          0x4231, 0, 0x1000, 0x01010101, 0xabcd, True, False, False, ())],
        self.proto.calls_made)

  def test_handle_flow_mod_invalid_cookie_minus1(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.dataReceived(
          '\x01\x0e\x00\x48\x00\x00\x00\x00'
          + self.match1.serialize()
          + '\xff\xff\xff\xff\xff\xff\xff\xff'
          '\x00\x01' '\x42\x31\x00\x00' '\x10\x00'
          '\x01\x01\x01\x01' '\xab\xcd' '\x00\x01')
    self.assertListEqual([], self.proto.calls_made)

  def test_handle_flow_mod_invalid_command_5(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.dataReceived(
          '\x01\x0e\x00\x48\x00\x00\x00\x00'
          + self.match1.serialize()
          + '\x00\x00\x00\x00\x12\x34\x56\x78'
          '\x00\x05' '\x42\x31\x00\x00' '\x10\x00'
          '\x01\x01\x01\x01' '\xab\xcd' '\x00\x01')
    self.assertListEqual([], self.proto.calls_made)

  def test_send_port_mod(self):
    self.proto.connectionMade()

    self.proto.send_port_mod(
        0xabcd, '\x12\x34\x56\x78\xab\xcd',
        _create_port_config(no_flood=True),
        _create_port_config(no_recv=True, no_flood=True),
        _create_port_features(mode_1gb_fd=True, fiber=True, pause=True))
    self.assertEqual('\x01\x0f\x00\x20\x00\x00\x00\x00'
                     '\xab\xcd\x12\x34\x56\x78\xab\xcd'
                     '\x00\x00\x00\x10' '\x00\x00\x00\x14'
                     '\x00\x00\x05\x20' '\x00\x00\x00\x00',
                     self._get_next_sent_message())

  def test_send_port_mod_invalid_port_no_0xff01(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.send_port_mod(
          0xff01, '\x12\x34\x56\x78\xab\xcd',
          _create_port_config(no_flood=True),
          _create_port_config(no_recv=True, no_flood=True),
          _create_port_features(mode_1gb_fd=True, fiber=True, pause=True))
    self.assertIsNone(self._get_next_sent_message())

  def test_send_port_mod_advertise_none(self):
    self.proto.connectionMade()

    self.proto.send_port_mod(
        0xabcd, '\x12\x34\x56\x78\xab\xcd',
        _create_port_config(no_flood=True),
        _create_port_config(no_recv=True, no_flood=True),
        None)
    self.assertEqual('\x01\x0f\x00\x20\x00\x00\x00\x00'
                     '\xab\xcd\x12\x34\x56\x78\xab\xcd'
                     '\x00\x00\x00\x10' '\x00\x00\x00\x14'
                     '\x00\x00\x00\x00' '\x00\x00\x00\x00',
                     self._get_next_sent_message())

  def test_handle_port_mod(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x0f\x00\x20\x00\x00\x00\x00'
                            '\xab\xcd\x12\x34\x56\x78\xab\xcd'
                            '\x00\x00\x00\x10' '\x00\x00\x00\x14'
                            '\x00\x00\x05\x20' '\x00\x00\x00\x00')
    self.assertListEqual(
        [('handle_port_mod', 0xabcd, '\x12\x34\x56\x78\xab\xcd',
          _create_port_config(no_flood=True),
          _create_port_config(no_recv=True, no_flood=True),
          _create_port_features(mode_1gb_fd=True, fiber=True, pause=True))],
        self.proto.calls_made)

  def test_handle_port_mod_invalid_port_no_0xff01(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.dataReceived('\x01\x0f\x00\x20\x00\x00\x00\x00'
                              '\xff\x01\x12\x34\x56\x78\xab\xcd'
                              '\x00\x00\x00\x10' '\x00\x00\x00\x14'
                              '\x00\x00\x05\x20' '\x00\x00\x00\x00')
    self.assertListEqual([], self.proto.calls_made)

  def test_handle_port_mod_advertise_none(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x0f\x00\x20\x00\x00\x00\x00'
                            '\xab\xcd\x12\x34\x56\x78\xab\xcd'
                            '\x00\x00\x00\x10' '\x00\x00\x00\x14'
                            '\x00\x00\x00\x00' '\x00\x00\x00\x00')
    self.assertListEqual(
        [('handle_port_mod', 0xabcd, '\x12\x34\x56\x78\xab\xcd',
          _create_port_config(no_flood=True),
          _create_port_config(no_recv=True, no_flood=True),
          None)],
        self.proto.calls_made)

  def test_send_stats_request_desc(self):
    self.proto.connectionMade()

    self.assertEqual(0, self.proto.send_stats_request_desc())
    self.assertEqual('\x01\x10\x00\x0c\x00\x00\x00\x00'
                     '\x00\x00' '\x00\x00',
                     self._get_next_sent_message())
    self.assertEqual(1, self.proto.send_stats_request_desc())
    self.assertEqual('\x01\x10\x00\x0c\x00\x00\x00\x01'
                     '\x00\x00' '\x00\x00',
                     self._get_next_sent_message())

  def test_send_stats_request_flow(self):
    self.proto.connectionMade()

    self.assertEqual(0, self.proto.send_stats_request_flow(
        self.match1, 0x0a, 0xabcd))
    self.assertEqual('\x01\x10\x00\x38\x00\x00\x00\x00'
                     '\x00\x01' '\x00\x00'
                     + self.match1.serialize()
                     + '\x0a\x00' '\xab\xcd',
                     self._get_next_sent_message())
    self.assertEqual(1, self.proto.send_stats_request_flow(
        self.match1, 0x0a, 0xabcd))
    self.assertEqual('\x01\x10\x00\x38\x00\x00\x00\x01'
                     '\x00\x01' '\x00\x00'
                     + self.match1.serialize()
                     + '\x0a\x00' '\xab\xcd',
                     self._get_next_sent_message())

  def test_send_stats_request_aggregate(self):
    self.proto.connectionMade()

    self.assertEqual(0, self.proto.send_stats_request_aggregate(
        self.match1, 0x0a, 0xabcd))
    self.assertEqual('\x01\x10\x00\x38\x00\x00\x00\x00'
                     '\x00\x02' '\x00\x00'
                     + self.match1.serialize()
                     + '\x0a\x00' '\xab\xcd',
                     self._get_next_sent_message())
    self.assertEqual(1, self.proto.send_stats_request_aggregate(
        self.match1, 0x0a, 0xabcd))
    self.assertEqual('\x01\x10\x00\x38\x00\x00\x00\x01'
                     '\x00\x02' '\x00\x00'
                     + self.match1.serialize()
                     + '\x0a\x00' '\xab\xcd',
                     self._get_next_sent_message())

  def test_send_stats_request_table(self):
    self.proto.connectionMade()

    self.assertEqual(0, self.proto.send_stats_request_table())
    self.assertEqual('\x01\x10\x00\x0c\x00\x00\x00\x00'
                     '\x00\x03' '\x00\x00',
                     self._get_next_sent_message())
    self.assertEqual(1, self.proto.send_stats_request_table())
    self.assertEqual('\x01\x10\x00\x0c\x00\x00\x00\x01'
                     '\x00\x03' '\x00\x00',
                     self._get_next_sent_message())

  def test_send_stats_request_port(self):
    self.proto.connectionMade()

    self.assertEqual(0, self.proto.send_stats_request_port(0xabcd))
    self.assertEqual('\x01\x10\x00\x14\x00\x00\x00\x00'
                     '\x00\x04' '\x00\x00'
                     '\xab\xcd\x00\x00\x00\x00\x00\x00',
                     self._get_next_sent_message())
    self.assertEqual(1, self.proto.send_stats_request_port(0xabcd))
    self.assertEqual('\x01\x10\x00\x14\x00\x00\x00\x01'
                     '\x00\x04' '\x00\x00'
                     '\xab\xcd\x00\x00\x00\x00\x00\x00',
                     self._get_next_sent_message())

  def test_send_stats_request_queue(self):
    self.proto.connectionMade()

    self.assertEqual(0, self.proto.send_stats_request_queue(0xabcd,
                                                            0x12345678))
    self.assertEqual('\x01\x10\x00\x14\x00\x00\x00\x00'
                     '\x00\x05' '\x00\x00'
                     '\xab\xcd\x00\x00' '\x12\x34\x56\x78',
                     self._get_next_sent_message())
    self.assertEqual(1, self.proto.send_stats_request_queue(0xabcd,
                                                            0x12345678))
    self.assertEqual('\x01\x10\x00\x14\x00\x00\x00\x01'
                     '\x00\x05' '\x00\x00'
                     '\xab\xcd\x00\x00' '\x12\x34\x56\x78',
                     self._get_next_sent_message())

  def test_send_stats_request_vendor(self):
    self.proto.connectionMade()

    self.assertEqual(0, self.proto.send_stats_request_vendor(
        0x4242, data=('helloyou',)))
    self.assertEqual('\x01\x10\x00\x18\x00\x00\x00\x00'
                     '\xff\xff' '\x00\x00'
                     '\x00\x00\x42\x42' 'helloyou',
                     self._get_next_sent_message())
    self.assertEqual(1, self.proto.send_stats_request_vendor(
        0x4242, data=('helloyou',)))
    self.assertEqual('\x01\x10\x00\x18\x00\x00\x00\x01'
                     '\xff\xff' '\x00\x00'
                     '\x00\x00\x42\x42' 'helloyou',
                     self._get_next_sent_message())

  def test_handle_stats_request_desc(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x10\x00\x0c\x00\x00\x00\x04'
                            '\x00\x00' '\x00\x00')
    self.assertListEqual([('handle_stats_request_desc', 4)],
                         self.proto.calls_made)

  def test_handle_stats_request_flow(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x10\x00\x38\x00\x00\x00\x04'
                            '\x00\x01' '\x00\x00'
                            + self.match1.serialize()
                            + '\x0a\x00' '\xab\xcd')
    self.assertListEqual([('handle_stats_request_flow', 4, self.match1, 0x0a,
                           0xabcd)],
                         self.proto.calls_made)

  def test_handle_stats_request_aggregate(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x10\x00\x38\x00\x00\x00\x04'
                            '\x00\x02' '\x00\x00'
                            + self.match1.serialize()
                            + '\x0a\x00' '\xab\xcd')
    self.assertListEqual([('handle_stats_request_aggregate', 4, self.match1,
                           0x0a, 0xabcd)],
                         self.proto.calls_made)

  def test_handle_stats_request_table(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x10\x00\x0c\x00\x00\x00\x04'
                            '\x00\x03' '\x00\x00')
    self.assertListEqual([('handle_stats_request_table', 4)],
                         self.proto.calls_made)

  def test_handle_stats_request_port(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x10\x00\x14\x00\x00\x00\x04'
                            '\x00\x04' '\x00\x00'
                            '\xab\xcd\x00\x00\x00\x00\x00\x00')
    self.assertListEqual([('handle_stats_request_port', 4, 0xabcd)],
                         self.proto.calls_made)

  def test_handle_stats_request_queue(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x10\x00\x14\x00\x00\x00\x04'
                            '\x00\x05' '\x00\x00'
                            '\xab\xcd\x00\x00' '\x12\x34\x56\x78')
    self.assertListEqual([('handle_stats_request_queue', 4, 0xabcd,
                           0x12345678)],
                         self.proto.calls_made)

  def test_handle_stats_request_vendor(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x10\x00\x18\x00\x00\x00\x04'
                            '\xff\xff' '\x00\x00'
                            '\x00\x00\x42\x42' 'helloyou')
    self.assertListEqual([], self.proto.calls_made)
    self.assertListEqual([('handle_vendor_stats_request', self.proto, 24, 4,
                           'helloyou')],
                         self.vendor_handler.calls_made)

  def test_send_stats_reply_desc(self):
    self.proto.connectionMade()

    desc_stats = ofstats.DescriptionStats(
        mfr_desc='Dummy Manufacturer Inc.',
        hw_desc='DummySwitch',
        sw_desc='DummyOS',
        serial_num='0000000042',
        dp_desc='unittest switch')
    self.proto.send_stats_reply_desc(4, desc_stats)
    self.assertEqual('\x01\x11\x04\x2c\x00\x00\x00\x04'
                     '\x00\x00' '\x00\x00'
                     + desc_stats.serialize(),
                     self._get_next_sent_message())

  def test_send_stats_reply_flow_two_flows(self):
    self.proto.connectionMade()

    flow_stats1 = ofstats.FlowStats(
        0xac, self.match1, 0x10203040, 0x11223344, 0x1002, 0x0136, 0x0247,
        0xffeeddccbbaa9988, 0x42, 0x0153, (
            ofaction.ActionOutput(port=0x1234, max_len=0x9abc),
            ofaction.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')))
    flow_stats2 = ofstats.FlowStats(
        0xad, self.match1, 0x10203040, 0x11223344, 0x1003, 0x0136, 0x0247,
        0xffeeddccbbaa9988, 0x42, 0x0153, ())
    self.proto.send_stats_reply_flow(4, (flow_stats1, flow_stats2))
    self.assertEqual(
        '\x01\x11\x00\xd4\x00\x00\x00\x04'
        '\x00\x01' '\x00\x00'
        + ''.join(flow_stats1.serialize(self.proto.serialize_action))
        + ''.join(flow_stats2.serialize(self.proto.serialize_action)),
        self._get_next_sent_message())

  def test_send_stats_reply_aggregate(self):
    self.proto.connectionMade()

    self.proto.send_stats_reply_aggregate(4, 0x1234, 0x1324, 0x0123)
    self.assertEqual('\x01\x11\x00\x24\x00\x00\x00\x04'
                     '\x00\x02' '\x00\x00'
                     '\x00\x00\x00\x00\x00\x00\x12\x34'
                     '\x00\x00\x00\x00\x00\x00\x13\x24'
                     '\x00\x00\x01\x23' '\x00\x00\x00\x00',
                     self._get_next_sent_message())

  def test_send_stats_reply_table_two_tables_reply_more(self):
    self.proto.connectionMade()

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
    self.proto.send_stats_reply_table(4, (table_stats1, table_stats2),
                                      reply_more=True)
    self.assertEqual('\x01\x11\x00\x8c\x00\x00\x00\x04'
                     '\x00\x03' '\x00\x01'
                     + table_stats1.serialize()
                     + table_stats2.serialize(),
                     self._get_next_sent_message())

  def test_send_stats_reply_port_two_ports(self):
    self.proto.connectionMade()

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
    self.proto.send_stats_reply_port(4, (port_stats1, port_stats2))
    self.assertEqual('\x01\x11\x00\xdc\x00\x00\x00\x04'
                     '\x00\x04' '\x00\x00'
                     + port_stats1.serialize()
                     + port_stats2.serialize(),
                     self._get_next_sent_message())

  def test_send_stats_reply_queue_two_queues(self):
    self.proto.connectionMade()

    queue_stats1 = ofstats.QueueStats(
        port_no=0xab01, queue_id=0x11111111, tx_bytes=0x5768, tx_packets=0x5678,
        tx_errors=0xcd34)
    queue_stats2 = ofstats.QueueStats(
        port_no=0xab01, queue_id=0x22222222, tx_bytes=0x5768, tx_packets=0x5678,
        tx_errors=0xcd34)
    self.proto.send_stats_reply_queue(4, (queue_stats1, queue_stats2))
    self.assertEqual('\x01\x11\x00\x4c\x00\x00\x00\x04'
                     '\x00\x05' '\x00\x00'
                     + queue_stats1.serialize()
                     + queue_stats2.serialize(),
                     self._get_next_sent_message())

  def test_send_stats_reply_vendor(self):
    self.proto.connectionMade()

    self.proto.send_stats_reply_vendor(4, 0x4242, ('helloyou',))
    self.assertEqual('\x01\x11\x00\x18\x00\x00\x00\x04'
                     '\xff\xff' '\x00\x00'
                     '\x00\x00\x42\x42' 'helloyou',
                     self._get_next_sent_message())

  def test_handle_stats_reply_desc(self):
    self.proto.connectionMade()

    desc_stats = ofstats.DescriptionStats(
        mfr_desc='Dummy Manufacturer Inc.',
        hw_desc='DummySwitch',
        sw_desc='DummyOS',
        serial_num='0000000042',
        dp_desc='unittest switch')
    self.proto.dataReceived('\x01\x11\x04\x2c\x00\x00\x00\x04'
                            '\x00\x00' '\x00\x00'
                            + desc_stats.serialize())
    self.assertListEqual([('handle_stats_reply_desc', 4, desc_stats)],
                         self.proto.calls_made)

  def test_handle_stats_reply_flow_two_flows(self):
    self.proto.connectionMade()

    flow_stats1 = ofstats.FlowStats(
        0xac, self.match1, 0x10203040, 0x11223344, 0x1002, 0x0136, 0x0247,
        0xffeeddccbbaa9988, 0x42, 0x0153, (
            ofaction.ActionOutput(port=0x1234, max_len=0x9abc),
            ofaction.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')))
    flow_stats2 = ofstats.FlowStats(
        0xad, self.match1, 0x10203040, 0x11223344, 0x1003, 0x0136, 0x0247,
        0xffeeddccbbaa9988, 0x42, 0x0153, ())
    self.proto.dataReceived(
        '\x01\x11\x00\xd4\x00\x00\x00\x04'
        '\x00\x01' '\x00\x00'
        + ''.join(flow_stats1.serialize(self.proto.serialize_action))
        + ''.join(flow_stats2.serialize(self.proto.serialize_action)))
    self.assertListEqual([('handle_stats_reply_flow', 4,
                           (flow_stats1, flow_stats2), False)],
                         self.proto.calls_made)

  def test_handle_stats_reply_aggregate(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x11\x00\x24\x00\x00\x00\x04'
                            '\x00\x02' '\x00\x00'
                            '\x00\x00\x00\x00\x00\x00\x12\x34'
                            '\x00\x00\x00\x00\x00\x00\x13\x24'
                            '\x00\x00\x01\x23' '\x00\x00\x00\x00')
    self.assertListEqual([('handle_stats_reply_aggregate', 4, 0x1234, 0x1324,
                           0x0123)],
                         self.proto.calls_made)

  def test_handle_stats_reply_table_two_tables_reply_more(self):
    self.proto.connectionMade()

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
    self.proto.dataReceived('\x01\x11\x00\x8c\x00\x00\x00\x04'
                            '\x00\x03' '\x00\x01'
                            + table_stats1.serialize()
                            + table_stats2.serialize())
    self.assertListEqual([('handle_stats_reply_table', 4,
                           (table_stats1, table_stats2), True)],
                         self.proto.calls_made)

  def test_handle_stats_reply_port_two_ports(self):
    self.proto.connectionMade()

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
    self.proto.dataReceived('\x01\x11\x00\xdc\x00\x00\x00\x04'
                            '\x00\x04' '\x00\x00'
                            + port_stats1.serialize()
                            + port_stats2.serialize())
    self.assertListEqual([('handle_stats_reply_port', 4,
                           (port_stats1, port_stats2), False)],
                         self.proto.calls_made)

  def test_handle_stats_reply_queue_two_queues(self):
    self.proto.connectionMade()

    queue_stats1 = ofstats.QueueStats(
        port_no=0xab01, queue_id=0x11111111, tx_bytes=0x5768, tx_packets=0x5678,
        tx_errors=0xcd34)
    queue_stats2 = ofstats.QueueStats(
        port_no=0xab01, queue_id=0x22222222, tx_bytes=0x5768, tx_packets=0x5678,
        tx_errors=0xcd34)
    self.proto.dataReceived('\x01\x11\x00\x4c\x00\x00\x00\x04'
                            '\x00\x05' '\x00\x00'
                            + queue_stats1.serialize()
                            + queue_stats2.serialize())
    self.assertListEqual([('handle_stats_reply_queue', 4,
                           (queue_stats1, queue_stats2), False)],
                         self.proto.calls_made)

  def test_handle_stats_reply_vendor_reply_more(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x11\x00\x18\x00\x00\x00\x04'
                            '\xff\xff' '\x00\x01'
                            '\x00\x00\x42\x42' 'helloyou')
    self.assertListEqual([], self.proto.calls_made)
    self.assertListEqual([('handle_vendor_stats_reply', self.proto, 24, 4,
                           'helloyou', True)],
                         self.vendor_handler.calls_made)

  def test_send_barrier_request(self):
    self.proto.connectionMade()

    self.assertEqual(0, self.proto.send_barrier_request())
    self.assertEqual('\x01\x12\x00\x08\x00\x00\x00\x00',
                     self._get_next_sent_message())
    self.assertEqual(1, self.proto.send_barrier_request())
    self.assertEqual('\x01\x12\x00\x08\x00\x00\x00\x01',
                     self._get_next_sent_message())

  def test_handle_barrier_request(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x12\x00\x08\x00\x00\x00\x04')
    self.assertListEqual([('handle_barrier_request', 4)],
                         self.proto.calls_made)

  def test_send_barrier_reply(self):
    self.proto.connectionMade()

    self.proto.send_barrier_reply(4)
    self.assertEqual('\x01\x13\x00\x08\x00\x00\x00\x04',
                     self._get_next_sent_message())

  def test_handle_barrier_reply(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x13\x00\x08\x00\x00\x00\x04')
    self.assertListEqual([('handle_barrier_reply', 4)],
                         self.proto.calls_made)


  # TODO(romain): Test handling of bogus messages, with wrong message lengths.

  # TODO(romain): Test proper handling of small chunks of data.


class TestOpenflowProtocolRequestTracker(unittest2.TestCase):

  def setUp(self):
    self.transport = MockTransport()
    self.vendor_handler = MockVendorHandler()
    self.proto = ofproto.OpenflowProtocolRequestTracker(
        vendor_handlers=(self.vendor_handler,))
    self.proto.transport = self.transport

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

  def test_connection_made_send_hello(self):
    self.proto.connectionMade()
    # Sent initial OFPT_HELLO with xid 0.
    self.assertEqual('\x01\x00\x00\x08\x00\x00\x00\x00',
                     self._get_next_sent_message())

  def test_handle_echo_request(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.

    self.proto.dataReceived('\x01\x02\x00\x10\x00\x00\x00\x04abcdefgh')

    # Sent back an OFPT_ECHO_REPLY with same length 8+8, data, and xid 4.
    self.assertEqual('\x01\x03\x00\x10\x00\x00\x00\x04abcdefgh',
                     self._get_next_sent_message())


if __name__ == '__main__':
  unittest2.main()
