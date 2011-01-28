# Copyright 2011 Midokura KK

import struct
import unittest2

from openfaucet import buffer
from openfaucet import ofconfig


def _create_port_config(
    port_down=False, no_stp=False, no_recv=False, no_recv_stp=False,
    no_flood=False, no_fwd=False, no_packet_in=False):
  return ofconfig.PortConfig(
      port_down=port_down, no_stp=no_stp, no_recv=no_recv,
      no_recv_stp=no_recv_stp, no_flood=no_flood, no_fwd=no_fwd,
      no_packet_in=no_packet_in)


def _create_port_features(
    mode_10mb_hd=False, mode_10mb_fd=False, mode_100mb_hd=False,
    mode_100mb_fd=False, mode_1gb_hd=False, mode_1gb_fd=False,
    mode_10gb_fd=False, copper=False, fiber=False, autoneg=False, pause=False,
    pause_asym=False):
  return ofconfig.PortFeatures(
      mode_10mb_hd=mode_10mb_hd, mode_10mb_fd=mode_10mb_fd,
      mode_100mb_hd=mode_100mb_hd, mode_100mb_fd=mode_100mb_fd,
      mode_1gb_hd=mode_1gb_hd, mode_1gb_fd=mode_1gb_fd,
      mode_10gb_fd=mode_10gb_fd, copper=copper, fiber=fiber, autoneg=autoneg,
      pause=pause, pause_asym=pause_asym)


class TestPortConfig(unittest2.TestCase):

  def test_create(self):
    pc = ofconfig.PortConfig(port_down=False, no_stp=True, no_recv=False,
                            no_recv_stp=True, no_flood=True, no_fwd=False,
                            no_packet_in=False)

  def test_serialize(self):
    pc = ofconfig.PortConfig(port_down=False, no_stp=True, no_recv=False,
                            no_recv_stp=True, no_flood=True, no_fwd=False,
                            no_packet_in=False)
    self.assertEqual(0x1a, pc.serialize())

  def test_serialize_every_flag(self):
    for i in xrange(0, 7):
      flag = 1 << i
      args = [False]*6
      args.insert(i, True)
      pc = ofconfig.PortConfig(*args)
      self.assertEqual(flag, pc.serialize())

  def test_serialize_deserialize(self):
    pc = ofconfig.PortConfig(port_down=False, no_stp=True, no_recv=False,
                            no_recv_stp=True, no_flood=True, no_fwd=False,
                            no_packet_in=False)
    self.assertTupleEqual(pc, ofconfig.PortConfig.deserialize(pc.serialize()))

  def test_deserialize(self):
    self.assertTupleEqual((False, True, False, True, True, False, False),
                          ofconfig.PortConfig.deserialize(0x1a))

  def test_deserialize_every_invalid_bit(self):
    for i in xrange(7, 32):
      flags = (1 << i) | 0x0000001a
      # The invalid bit is ignored.
      self.assertTupleEqual((False, True, False, True, True, False, False),
                            ofconfig.PortConfig.deserialize(flags))

  def test_get_diff_every_flag_true(self):
    all_false = ofconfig.PortConfig(*([False]*7))
    for i in xrange(0, 7):
      args = [False]*6
      args.insert(i, True)
      pc = ofconfig.PortConfig(*args)
      config, mask = pc.get_diff(all_false)
      args = tuple(args)
      self.assertEqual(True, config[i])
      self.assertTupleEqual(args, mask)

  def test_get_diff_every_flag_false(self):
    all_true = ofconfig.PortConfig(*([True]*7))
    for i in xrange(0, 7):
      args = [True]*6
      args.insert(i, False)
      pc = ofconfig.PortConfig(*args)
      config, mask = pc.get_diff(all_true)
      self.assertEqual(False, config[i])
      expected_mask = [False]*6
      expected_mask.insert(i, True)
      expected_mask = tuple(expected_mask)
      self.assertTupleEqual(expected_mask, mask)

  def test_patch_every_flag_true(self):
    all_false = ofconfig.PortConfig(*([False]*7))
    for i in xrange(0, 7):
      args = [False]*6
      args.insert(i, True)
      config = ofconfig.PortConfig(*args)
      mask = ofconfig.PortConfig(*args)
      args = tuple(args)
      self.assertTupleEqual(args, all_false.patch(config, mask))

  def test_patch_every_flag_false(self):
    all_true = ofconfig.PortConfig(*([True]*7))
    for i in xrange(0, 7):
      config_args = [False]*7
      config = ofconfig.PortConfig(*config_args)
      mask_args = [False]*6
      mask_args.insert(i, True)
      mask = ofconfig.PortConfig(*mask_args)
      expected_args = [True]*6
      expected_args.insert(i, False)
      expected_args = tuple(expected_args)
      self.assertTupleEqual(expected_args, all_true.patch(config, mask))


class TestPortFeatures(unittest2.TestCase):

  def test_create(self):
    pf = ofconfig.PortFeatures(
        mode_10mb_hd=False, mode_10mb_fd=True, mode_100mb_hd=False,
        mode_100mb_fd=True, mode_1gb_hd=False, mode_1gb_fd=True,
        mode_10gb_fd=True, copper=False, fiber=True, autoneg=True, pause=True,
        pause_asym=False)

  def test_serialize(self):
    pf = ofconfig.PortFeatures(
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
      pf = ofconfig.PortFeatures(*args)
      self.assertEqual(flag, pf.serialize())

  def test_serialize_deserialize(self):
    pf = ofconfig.PortFeatures(
        mode_10mb_hd=False, mode_10mb_fd=True, mode_100mb_hd=False,
        mode_100mb_fd=True, mode_1gb_hd=False, mode_1gb_fd=True,
        mode_10gb_fd=True, copper=False, fiber=True, autoneg=True, pause=True,
        pause_asym=False)
    self.assertTupleEqual(pf, ofconfig.PortFeatures.deserialize(pf.serialize()))

  def test_deserialize(self):
    self.assertTupleEqual((False, True, False, True, False, True, True,
                           False, True, True, True, False),
                          ofconfig.PortFeatures.deserialize(0x0000076a))

  def test_deserialize_every_flag(self):
    for i in xrange(0, 12):
      flag = 1 << i
      args = [False]*11
      args.insert(i, True)
      args = tuple(args)
      self.assertTupleEqual(args, ofconfig.PortFeatures.deserialize(flag))

  def test_deserialize_every_invalid_bit(self):
    for i in xrange(12, 32):
      flags = (1 << i) | 0x0000076a
      # The invalid bit is ignored.
      self.assertTupleEqual((False, True, False, True, False, True, True,
                             False, True, True, True, False),
                            ofconfig.PortFeatures.deserialize(flags))


class TestPhyPort(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()

  def test_create(self):
    pp = ofconfig.PhyPort(
        port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
        config=_create_port_config(no_stp=True, no_recv_stp=True,
                                   no_flood=True),
        state_link_down=False, state_stp=ofconfig.OFPPS_STP_FORWARD,
        curr=_create_port_features(mode_1gb_fd=True, fiber=True),
        advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
        supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                        pause=True, pause_asym=True),
        peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                   autoneg=True))

  def test_serialize(self):
    pp = ofconfig.PhyPort(
        port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
        config=_create_port_config(no_stp=True, no_recv_stp=True,
                                   no_flood=True),
        state_link_down=True, state_stp=ofconfig.OFPPS_STP_FORWARD,
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
    for i in (ofconfig.OFPPS_STP_LISTEN, ofconfig.OFPPS_STP_LEARN,
              ofconfig.OFPPS_STP_FORWARD, ofconfig.OFPPS_STP_BLOCK):
      state_ser = i | 1  # state_link_down=True
      pp = ofconfig.PhyPort(
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
    pp = ofconfig.PhyPort(
        port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
        config=_create_port_config(no_stp=True, no_recv_stp=True,
                                   no_flood=True),
        state_link_down=True, state_stp=ofconfig.OFPPS_STP_FORWARD,
        curr=_create_port_features(mode_1gb_fd=True, fiber=True),
        advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
        supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                        pause=True, pause_asym=True),
        peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                   autoneg=True))
    self.buf.append(pp.serialize())
    self.buf.set_message_boundaries(48)
    self.assertTupleEqual(pp, ofconfig.PhyPort.deserialize(self.buf))

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
         True, ofconfig.OFPPS_STP_FORWARD,
         _create_port_features(mode_1gb_fd=True, fiber=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True,
                               pause_asym=True),
         _create_port_features(mode_1gb_fd=True, fiber=True,
                               autoneg=True)),
      ofconfig.PhyPort.deserialize(self.buf))
    # Test that the deserialization consumed all 48 bytes.
    with self.assertRaises(AssertionError):
      self.buf.skip_bytes(1)

  def test_deserialize_every_state_stp(self):
    for i in (ofconfig.OFPPS_STP_LISTEN, ofconfig.OFPPS_STP_LEARN,
              ofconfig.OFPPS_STP_FORWARD, ofconfig.OFPPS_STP_BLOCK):
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
      self.assertTupleEqual(args, ofconfig.PhyPort.deserialize(self.buf))

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
         True, ofconfig.OFPPS_STP_FORWARD,
         _create_port_features(mode_1gb_fd=True, fiber=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True,
                               pause_asym=True),
         _create_port_features(mode_1gb_fd=True, fiber=True,
                               autoneg=True)),
      ofconfig.PhyPort.deserialize(self.buf))

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
         True, ofconfig.OFPPS_STP_FORWARD,
         _create_port_features(mode_1gb_fd=True, fiber=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True,
                               pause_asym=True),
         _create_port_features(mode_1gb_fd=True, fiber=True,
                               autoneg=True)),
      ofconfig.PhyPort.deserialize(self.buf))


class TestSwitchFeatures(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()

  def test_create(self):
    pp1 = ofconfig.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofconfig.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    pp2 = ofconfig.PhyPort(
      port_no=0x43, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofconfig.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    sf = ofconfig.SwitchFeatures(
        datapath_id=123456, n_buffers=42, n_tables=3, cap_flow_stats=True,
        cap_table_stats=False, cap_port_stats=True, cap_stp=False,
        cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
        actions=frozenset((0, 2, 3, 5)), ports=(pp1, pp2))

  def test_serialize_no_port(self):
    sf = ofconfig.SwitchFeatures(
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
    pp1 = ofconfig.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofconfig.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    sf = ofconfig.SwitchFeatures(
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
    pp1 = ofconfig.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofconfig.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    pp2 = ofconfig.PhyPort(
      port_no=0x43, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofconfig.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    sf = ofconfig.SwitchFeatures(
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
      sf = ofconfig.SwitchFeatures(*args)
      self.assertEqual('\x00\x00\x00\x00\x00\x12\x34\x56'
                       '\x00\x00\x00\x05'
                       '\x03\x00\x00\x00'
                       + struct.pack('!L', flag)
                       + '\x00\x00\x01\x2d', ''.join(sf.serialize()))

  def test_serialize_every_action(self):
    for i in xrange(0, 32):
      action_flag = 1 << i
      sf = ofconfig.SwitchFeatures(
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
    pp1 = ofconfig.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofconfig.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    pp2 = ofconfig.PhyPort(
      port_no=0x43, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofconfig.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    sf = ofconfig.SwitchFeatures(
        datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
        cap_table_stats=False, cap_port_stats=True, cap_stp=False,
        cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
        actions=frozenset((0, 2, 3, 5, 8)), ports=(pp1, pp2))
    self.buf.append(''.join(sf.serialize()))
    self.buf.set_message_boundaries(24 + 48 * 2)
    self.assertTupleEqual(sf, ofconfig.SwitchFeatures.deserialize(self.buf))

  def test_deserialize_two_ports(self):
    pp1 = ofconfig.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofconfig.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    pp2 = ofconfig.PhyPort(
      port_no=0x43, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
      config=_create_port_config(no_stp=True, no_recv_stp=True, no_flood=True),
      state_link_down=True, state_stp=ofconfig.OFPPS_STP_FORWARD,
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
                          ofconfig.SwitchFeatures.deserialize(self.buf))

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
      self.assertTupleEqual(args, ofconfig.SwitchFeatures.deserialize(self.buf))

  def test_deserialize_reserved_capability_flag_0x10(self):
    self.buf.append('\x00\x00\x00\x00\x00\x12\x34\x56'
                     '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                     '\x00\x00\x00\xb5' '\x00\x00\x01\x2d')
    self.buf.set_message_boundaries(24)
    # The reserved bit at 0x00000010 is ignored.
    self.assertTupleEqual((0x123456, 5, 3, True, False, True, False, True,
                           False, True, frozenset((0, 2, 3, 5, 8)), ()),
                          ofconfig.SwitchFeatures.deserialize(self.buf))

  def test_deserialize_invalid_capability_flag_0x0100(self):
    self.buf.append('\x00\x00\x00\x00\x00\x12\x34\x56'
                    '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                    '\x00\x00\x01\xa5' '\x00\x00\x01\x2d')
    self.buf.set_message_boundaries(24)
    # The reserved bit at 0x00000100 is ignored.
    self.assertTupleEqual((0x123456, 5, 3, True, False, True, False, True,
                           False, True, frozenset((0, 2, 3, 5, 8)), ()),
                          ofconfig.SwitchFeatures.deserialize(self.buf))

  def test_deserialize_every_action(self):
    for i in xrange(0, 32):
      action_flag = 1 << i
      self.buf.append('\x00\x00\x00\x00\x00\x12\x34\x56'
                      '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                      '\x00\x00\x00\xa5' + struct.pack('!L', action_flag))
      self.buf.set_message_boundaries(24)
      self.assertTupleEqual((0x123456, 5, 3, True, False, True, False, True,
                             False, True, frozenset((i,)), ()),
                            ofconfig.SwitchFeatures.deserialize(self.buf))


class TestSwitchConfig(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()

  def test_create(self):
    sc = ofconfig.SwitchConfig(config_frag=ofconfig.OFPC_FRAG_DROP,
                              miss_send_len=128)

  def test_serialize(self):
    sc = ofconfig.SwitchConfig(config_frag=ofconfig.OFPC_FRAG_DROP,
                              miss_send_len=128)
    self.assertEqual('\x00\x01\x00\x80', sc.serialize())

  def test_serialize_every_config_frag(self):
    for config_frag in (ofconfig.OFPC_FRAG_NORMAL, ofconfig.OFPC_FRAG_DROP,
                        ofconfig.OFPC_FRAG_REASM):
      sc = ofconfig.SwitchConfig(config_frag=config_frag, miss_send_len=128)
      self.assertEqual(struct.pack('!H', config_frag) + '\x00\x80',
                       sc.serialize())

  def test_serialize_deserialize(self):
    sc = ofconfig.SwitchConfig(config_frag=ofconfig.OFPC_FRAG_DROP,
                              miss_send_len=128)
    self.buf.append(sc.serialize())
    self.buf.set_message_boundaries(4)
    self.assertTupleEqual(sc, ofconfig.SwitchConfig.deserialize(self.buf))

  def test_deserialize(self):
    self.buf.append('\x00\x01\x00\x80')
    self.buf.set_message_boundaries(4)
    self.assertTupleEqual((ofconfig.OFPC_FRAG_DROP, 128),
                          ofconfig.SwitchConfig.deserialize(self.buf))

  def test_deserialize_every_config_frag(self):
    for config_frag in (ofconfig.OFPC_FRAG_NORMAL, ofconfig.OFPC_FRAG_DROP,
                        ofconfig.OFPC_FRAG_REASM):
      self.buf.append(struct.pack('!H', config_frag) + '\x00\x80')
      self.buf.set_message_boundaries(4)
      self.assertTupleEqual((config_frag, 128),
                            ofconfig.SwitchConfig.deserialize(self.buf))

  def test_deserialize_invalid_config_frag_0x0004(self):
    self.buf.append('\x00\x04\x00\x80')
    self.buf.set_message_boundaries(4)
    with self.assertRaises(ValueError):
      ofconfig.SwitchConfig.deserialize(self.buf)


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
