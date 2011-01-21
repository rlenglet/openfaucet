# Copyright 2011 Midokura KK

import struct
import unittest2

from openfaucet import action
from openfaucet import buffer
from openfaucet import proto


def _create_port_features(
    mode_10mb_hd=False, mode_10mb_fd=False, mode_100mb_hd=False,
    mode_100mb_fd=False, mode_1gb_hd=False, mode_1gb_fd=False,
    mode_10gb_fd=False, copper=False, fiber=False, autoneg=False, pause=False,
    pause_asym=False):
  return proto.PortFeatures(
      mode_10mb_hd=mode_10mb_hd, mode_10mb_fd=mode_10mb_fd,
      mode_100mb_hd=mode_100mb_hd, mode_100mb_fd=mode_100mb_fd,
      mode_1gb_hd=mode_1gb_hd, mode_1gb_fd=mode_1gb_fd,
      mode_10gb_fd=mode_10gb_fd, copper=copper, fiber=fiber, autoneg=autoneg,
      pause=pause, pause_asym=pause_asym)


class TestPortFeatures(unittest2.TestCase):

  def test_create(self):
    pf = proto.PortFeatures(
        mode_10mb_hd=False, mode_10mb_fd=True, mode_100mb_hd=False,
        mode_100mb_fd=True, mode_1gb_hd=False, mode_1gb_fd=True,
        mode_10gb_fd=True, copper=False, fiber=True, autoneg=True, pause=True,
        pause_asym=False)

  def test_serialize(self):
    pf = proto.PortFeatures(
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
      pf = proto.PortFeatures(*args)
      self.assertEqual(flag, pf.serialize())

  def test_serialize_deserialize(self):
    pf = proto.PortFeatures(
        mode_10mb_hd=False, mode_10mb_fd=True, mode_100mb_hd=False,
        mode_100mb_fd=True, mode_1gb_hd=False, mode_1gb_fd=True,
        mode_10gb_fd=True, copper=False, fiber=True, autoneg=True, pause=True,
        pause_asym=False)
    self.assertTupleEqual(pf, proto.PortFeatures.deserialize(pf.serialize()))

  def test_deserialize(self):
    self.assertTupleEqual((False, True, False, True, False, True, True,
                           False, True, True, True, False),
                          proto.PortFeatures.deserialize(0x0000076a))

  def test_deserialize_every_flag(self):
    for i in xrange(0, 12):
      flag = 1 << i
      args = [False]*11
      args.insert(i, True)
      args = tuple(args)
      self.assertTupleEqual(args, proto.PortFeatures.deserialize(flag))

  def test_deserialize_every_invalid_bit(self):
    for i in xrange(12, 32):
      flags = (1 << i) | 0x0000076a
      # The invalid bit is ignored.
      self.assertTupleEqual((False, True, False, True, False, True, True,
                             False, True, True, True, False),
                            proto.PortFeatures.deserialize(flags))


class TestPhyPort(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()

  def test_create(self):
    pp = proto.PhyPort(
        port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
        config_port_down=False, config_no_stp=True, config_no_recv=False,
        config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
        config_no_packet_in=False, state_link_down=False,
        state_stp=proto.OFPPS_STP_FORWARD,
        curr=_create_port_features(mode_1gb_fd=True, fiber=True),
        advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
        supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                        pause=True, pause_asym=True),
        peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                   autoneg=True))

  def test_serialize(self):
    pp = proto.PhyPort(
        port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
        config_port_down=False, config_no_stp=True, config_no_recv=False,
        config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
        config_no_packet_in=False, state_link_down=True,
        state_stp=proto.OFPPS_STP_FORWARD,
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

  def test_serialize_every_config_flag(self):
    for i in xrange(0, 7):
      flag = 1 << i
      args = [False]*6
      args.insert(i, True)
      args[0:0] = [0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport']
      args.extend([True, proto.OFPPS_STP_FORWARD,
                   _create_port_features(mode_1gb_fd=True, fiber=True),
                   _create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
                   _create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True, pause_asym=True),
                   _create_port_features(mode_1gb_fd=True, fiber=True,
                                         autoneg=True)])
      pp = proto.PhyPort(*args)
      self.assertEqual('\x00\x42' '\xab\xcd\xef\xa0\xb1\xc2'
                       'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                       + struct.pack('!L', flag)
                       + '\x00\x00\x02\x01'
                       '\x00\x00\x01\x20'
                       '\x00\x00\x05\x20'
                       '\x00\x00\x0d\x20'
                       '\x00\x00\x03\x20', pp.serialize())

  def test_serialize_every_state_stp(self):
    for i in (proto.OFPPS_STP_LISTEN, proto.OFPPS_STP_LEARN,
              proto.OFPPS_STP_FORWARD, proto.OFPPS_STP_BLOCK):
      state_ser = i | 1  # state_link_down=True
      pp = proto.PhyPort(
          port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
          config_port_down=False, config_no_stp=True, config_no_recv=False,
          config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
          config_no_packet_in=False, state_link_down=True, state_stp=i,
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
    pp = proto.PhyPort(
        port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
        config_port_down=False, config_no_stp=True, config_no_recv=False,
        config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
        config_no_packet_in=False, state_link_down=True,
        state_stp=proto.OFPPS_STP_FORWARD,
        curr=_create_port_features(mode_1gb_fd=True, fiber=True),
        advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
        supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                        pause=True, pause_asym=True),
        peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                   autoneg=True))
    self.buf.append(pp.serialize())
    self.buf.set_message_boundaries(48)
    self.assertTupleEqual(pp, proto.PhyPort.deserialize(self.buf))

  def test_deserialize(self):
    self.buf.append('\x00\x42' '\xab\xcd\xef\xa0\xb1\xc2'
                    'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x1a' '\x00\x00\x02\x01'
                    '\x00\x00\x01\x20' '\x00\x00\x05\x20'
                    '\x00\x00\x0d\x20' '\x00\x00\x03\x20')
    self.buf.set_message_boundaries(48)
    self.assertTupleEqual(
        (0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport', False, True, False, True,
         True, False, False, True, proto.OFPPS_STP_FORWARD,
         _create_port_features(mode_1gb_fd=True, fiber=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True,
                               pause_asym=True),
         _create_port_features(mode_1gb_fd=True, fiber=True,
                               autoneg=True)),
      proto.PhyPort.deserialize(self.buf))
    # Test that the deserialization consumed all 48 bytes.
    with self.assertRaises(AssertionError):
      self.buf.skip_bytes(1)

  def test_deserialize_every_config_flag(self):
    for i in xrange(0, 7):
      flag = 1 << i
      self.buf.append('\x00\x42' '\xab\xcd\xef\xa0\xb1\xc2'
                      'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                      + struct.pack('!L', flag) + '\x00\x00\x02\x01'
                      '\x00\x00\x01\x20' '\x00\x00\x05\x20'
                      '\x00\x00\x0d\x20' '\x00\x00\x03\x20')
      self.buf.set_message_boundaries(48)
      args = [False]*6
      args.insert(i, True)
      args[0:0] = [0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport']
      args.extend([True, proto.OFPPS_STP_FORWARD,
                   _create_port_features(mode_1gb_fd=True, fiber=True),
                   _create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
                   _create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True, pause_asym=True),
                   _create_port_features(mode_1gb_fd=True, fiber=True,
                                         autoneg=True)])
      args = tuple(args)
      self.assertTupleEqual(args, proto.PhyPort.deserialize(self.buf))

  def test_deserialize_invalid_config_flag_0x9a(self):
    self.buf.append('\x00\x42' '\xab\xcd\xef\xa0\xb1\xc2'
                    'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x9a' '\x00\x00\x02\x01'
                    '\x00\x00\x01\x20' '\x00\x00\x05\x20'
                    '\x00\x00\x0d\x20' '\x00\x00\x03\x20')
    self.buf.set_message_boundaries(48)
    # The undefined bits in the config bitset are ignored.
    self.assertTupleEqual(
        (0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport', False, True, False, True,
         True, False, False, True, proto.OFPPS_STP_FORWARD,
         _create_port_features(mode_1gb_fd=True, fiber=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True,
                               pause_asym=True),
         _create_port_features(mode_1gb_fd=True, fiber=True,
                               autoneg=True)),
      proto.PhyPort.deserialize(self.buf))

  def test_deserialize_every_state_stp(self):
    for i in (proto.OFPPS_STP_LISTEN, proto.OFPPS_STP_LEARN,
              proto.OFPPS_STP_FORWARD, proto.OFPPS_STP_BLOCK):
      state_ser = i | 1  # state_link_down=True
      self.buf.append('\x00\x42' '\xab\xcd\xef\xa0\xb1\xc2'
                       'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                       '\x00\x00\x00\x1a' + struct.pack('!L', state_ser)
                       + '\x00\x00\x01\x20' '\x00\x00\x05\x20'
                       '\x00\x00\x0d\x20' '\x00\x00\x03\x20')
      self.buf.set_message_boundaries(48)
      args = (0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport', False, True, False,
              True, True, False, False, True, i,
              _create_port_features(mode_1gb_fd=True, fiber=True),
              _create_port_features(mode_1gb_fd=True, fiber=True, pause=True),
              _create_port_features(mode_1gb_fd=True, fiber=True, pause=True,
                                    pause_asym=True),
              _create_port_features(mode_1gb_fd=True, fiber=True, autoneg=True))
      self.assertTupleEqual(args, proto.PhyPort.deserialize(self.buf))

  def test_deserialize_invalid_state_stp_0x0601(self):
    self.buf.append('\x00\x42' '\xab\xcd\xef\xa0\xb1\xc2'
                    'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x1a' '\x00\x00\x06\x81'
                    '\x00\x00\x01\x20' '\x00\x00\x05\x20'
                    '\x00\x00\x0d\x20' '\x00\x00\x03\x20')
    self.buf.set_message_boundaries(48)
    # The invalid bit at 0x0400 in the state is ignored.
    self.assertTupleEqual(
        (0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport', False, True, False, True,
         True, False, False, True, proto.OFPPS_STP_FORWARD,
         _create_port_features(mode_1gb_fd=True, fiber=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True,
                               pause_asym=True),
         _create_port_features(mode_1gb_fd=True, fiber=True,
                               autoneg=True)),
      proto.PhyPort.deserialize(self.buf))

  def test_deserialize_invalid_state_bit_0x0281(self):
    self.buf.append('\x00\x42' '\xab\xcd\xef\xa0\xb1\xc2'
                    'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x1a' '\x00\x00\x02\x81'
                    '\x00\x00\x01\x20' '\x00\x00\x05\x20'
                    '\x00\x00\x0d\x20' '\x00\x00\x03\x20')
    self.buf.set_message_boundaries(48)
    # The invalid bit at 0x0080 in the state is ignored.
    self.assertTupleEqual(
        (0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport', False, True, False, True,
         True, False, False, True, proto.OFPPS_STP_FORWARD,
         _create_port_features(mode_1gb_fd=True, fiber=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True),
         _create_port_features(mode_1gb_fd=True, fiber=True, pause=True,
                               pause_asym=True),
         _create_port_features(mode_1gb_fd=True, fiber=True,
                               autoneg=True)),
      proto.PhyPort.deserialize(self.buf))


class TestSwitchFeatures(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()

  def test_create(self):
    pp1 = proto.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config_port_down=False, config_no_stp=True, config_no_recv=False,
      config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
      config_no_packet_in=False, state_link_down=True,
      state_stp=proto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    pp2 = proto.PhyPort(
      port_no=0x43, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
      config_port_down=False, config_no_stp=True, config_no_recv=False,
      config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
      config_no_packet_in=False, state_link_down=True,
      state_stp=proto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    sf = proto.SwitchFeatures(
        datapath_id=123456, n_buffers=42, n_tables=3, cap_flow_stats=True,
        cap_table_stats=False, cap_port_stats=True, cap_stp=False,
        cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
        actions=frozenset((0, 2, 3, 5)), ports=(pp1, pp2))

  def test_serialize_no_port(self):
    sf = proto.SwitchFeatures(
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
    pp1 = proto.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config_port_down=False, config_no_stp=True, config_no_recv=False,
      config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
      config_no_packet_in=False, state_link_down=True,
      state_stp=proto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    sf = proto.SwitchFeatures(
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
    pp1 = proto.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config_port_down=False, config_no_stp=True, config_no_recv=False,
      config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
      config_no_packet_in=False, state_link_down=True,
      state_stp=proto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    pp2 = proto.PhyPort(
      port_no=0x43, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
      config_port_down=False, config_no_stp=True, config_no_recv=False,
      config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
      config_no_packet_in=False, state_link_down=True,
      state_stp=proto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    sf = proto.SwitchFeatures(
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
      sf = proto.SwitchFeatures(*args)
      self.assertEqual('\x00\x00\x00\x00\x00\x12\x34\x56'
                       '\x00\x00\x00\x05'
                       '\x03\x00\x00\x00'
                       + struct.pack('!L', flag)
                       + '\x00\x00\x01\x2d', ''.join(sf.serialize()))

  def test_serialize_every_action(self):
    for i in xrange(0, 32):
      action_flag = 1 << i
      sf = proto.SwitchFeatures(
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
    pp1 = proto.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config_port_down=False, config_no_stp=True, config_no_recv=False,
      config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
      config_no_packet_in=False, state_link_down=True,
      state_stp=proto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    pp2 = proto.PhyPort(
      port_no=0x43, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
      config_port_down=False, config_no_stp=True, config_no_recv=False,
      config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
      config_no_packet_in=False, state_link_down=True,
      state_stp=proto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    sf = proto.SwitchFeatures(
        datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
        cap_table_stats=False, cap_port_stats=True, cap_stp=False,
        cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
        actions=frozenset((0, 2, 3, 5, 8)), ports=(pp1, pp2))
    self.buf.append(''.join(sf.serialize()))
    self.buf.set_message_boundaries(24 + 48 * 2)
    self.assertTupleEqual(sf, proto.SwitchFeatures.deserialize(self.buf))

  def test_deserialize_two_ports(self):
    pp1 = proto.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config_port_down=False, config_no_stp=True, config_no_recv=False,
      config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
      config_no_packet_in=False, state_link_down=True,
      state_stp=proto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    pp2 = proto.PhyPort(
      port_no=0x43, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
      config_port_down=False, config_no_stp=True, config_no_recv=False,
      config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
      config_no_packet_in=False, state_link_down=True,
      state_stp=proto.OFPPS_STP_FORWARD,
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
    self.assertTupleEqual((0x123456, 5, 3, True, False, True, False, True, False,
                          True, frozenset((0, 2, 3, 5, 8)), (pp1, pp2)),
                          proto.SwitchFeatures.deserialize(self.buf))

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
      self.assertTupleEqual(args, proto.SwitchFeatures.deserialize(self.buf))

  def test_deserialize_reserved_capability_flag_0x10(self):
    self.buf.append('\x00\x00\x00\x00\x00\x12\x34\x56'
                     '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                     '\x00\x00\x00\xb5' '\x00\x00\x01\x2d')
    self.buf.set_message_boundaries(24)
    # The reserved bit at 0x00000010 is ignored.
    self.assertTupleEqual((0x123456, 5, 3, True, False, True, False, True, False,
                          True, frozenset((0, 2, 3, 5, 8)), ()),
                          proto.SwitchFeatures.deserialize(self.buf))

  def test_deserialize_invalid_capability_flag_0x0100(self):
    self.buf.append('\x00\x00\x00\x00\x00\x12\x34\x56'
                    '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                    '\x00\x00\x01\xa5' '\x00\x00\x01\x2d')
    self.buf.set_message_boundaries(24)
    # The reserved bit at 0x00000100 is ignored.
    self.assertTupleEqual((0x123456, 5, 3, True, False, True, False, True, False,
                          True, frozenset((0, 2, 3, 5, 8)), ()),
                          proto.SwitchFeatures.deserialize(self.buf))

  def test_deserialize_every_action(self):
    for i in xrange(0, 32):
      action_flag = 1 << i
      self.buf.append('\x00\x00\x00\x00\x00\x12\x34\x56'
                      '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                      '\x00\x00\x00\xa5' + struct.pack('!L', action_flag))
      self.buf.set_message_boundaries(24)
      self.assertTupleEqual((0x123456, 5, 3, True, False, True, False, True,
                             False, True, frozenset((i,)), ()),
                            proto.SwitchFeatures.deserialize(self.buf))


class TestSwitchConfig(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()

  def test_create(self):
    sc = proto.SwitchConfig(config_frag=proto.OFPC_FRAG_DROP,
                            miss_send_len=128)

  def test_serialize(self):
    sc = proto.SwitchConfig(config_frag=proto.OFPC_FRAG_DROP,
                            miss_send_len=128)
    self.assertEqual('\x00\x01\x00\x80', sc.serialize())

  def test_serialize_every_config_frag(self):
    for config_frag in (proto.OFPC_FRAG_NORMAL, proto.OFPC_FRAG_DROP,
                        proto.OFPC_FRAG_REASM):
      sc = proto.SwitchConfig(config_frag=config_frag, miss_send_len=128)
      self.assertEqual(struct.pack('!H', config_frag) + '\x00\x80',
                       sc.serialize())

  def test_serialize_deserialize(self):
    sc = proto.SwitchConfig(config_frag=proto.OFPC_FRAG_DROP,
                            miss_send_len=128)
    self.buf.append(sc.serialize())
    self.buf.set_message_boundaries(4)
    self.assertTupleEqual(sc, proto.SwitchConfig.deserialize(self.buf))

  def test_deserialize(self):
    self.buf.append('\x00\x01\x00\x80')
    self.buf.set_message_boundaries(4)
    self.assertTupleEqual((proto.OFPC_FRAG_DROP, 128),
                          proto.SwitchConfig.deserialize(self.buf))

  def test_deserialize_every_config_frag(self):
    for config_frag in (proto.OFPC_FRAG_NORMAL, proto.OFPC_FRAG_DROP,
                        proto.OFPC_FRAG_REASM):
      self.buf.append(struct.pack('!H', config_frag) + '\x00\x80')
      self.buf.set_message_boundaries(4)
      self.assertTupleEqual((config_frag, 128),
                            proto.SwitchConfig.deserialize(self.buf))

  def test_deserialize_invalid_config_frag_0x0004(self):
    self.buf.append('\x00\x04\x00\x80')
    self.buf.set_message_boundaries(4)
    with self.assertRaises(ValueError):
      proto.SwitchConfig.deserialize(self.buf)


class TestMatch(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()

  def test_create(self):
    m = proto.Match(in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
                    dl_dst='\x12\x23\x34\x45\x56\x67',
                    dl_vlan=0x11, dl_vlan_pcp=0x22, dl_type=0x3344,
                    nw_tos=0x80, nw_proto=0xcc, nw_src=('\xaa\xbb\xcc\xdd', 32),
                    nw_dst=('\x21\x32\x43\x54', 32), tp_src=0x38, tp_dst=0x49)

  def test_create_wildcarded_no_attr(self):
    m = proto.Match.create_wildcarded()
    self.assertTupleEqual(tuple([None]*12), m)

  def test_create_wildcarded_every_attr(self):
    m_orig = proto.Match(in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
                         dl_dst='\x12\x23\x34\x45\x56\x67',
                         dl_vlan=0x11, dl_vlan_pcp=0x22, dl_type=0x3344,
                         nw_tos=0x80, nw_proto=0xcc,
                         nw_src=('\xaa\xbb\xcc\xdd', 32),
                         nw_dst=('\x21\x32\x43\x54', 32), tp_src=0x38,
                         tp_dst=0x49)
    for attr_name in proto.Match._fields:
      attr_value = m_orig._asdict()[attr_name]
      m = proto.Match.create_wildcarded(**{attr_name: attr_value})
      m_dict = {'in_port': None, 'dl_src': None, 'dl_dst': None,
                'dl_vlan': None, 'dl_vlan_pcp': None, 'dl_type': None,
                'nw_tos': None, 'nw_proto': None, 'nw_src': None,
                'nw_dst': None, 'tp_src': None, 'tp_dst': None}
      m_dict[attr_name] = attr_value
      self.assertDictEqual(m_dict, m._asdict())

  def test_wildcards_no_attrs_wildcarded(self):
    m = proto.Match(in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
                    dl_dst='\x12\x23\x34\x45\x56\x67',
                    dl_vlan=0x11, dl_vlan_pcp=0x22, dl_type=0x3344,
                    nw_tos=0x80, nw_proto=0xcc, nw_src=('\xaa\xbb\xcc\xdd', 32),
                    nw_dst=('\x21\x32\x43\x54', 32), tp_src=0x38, tp_dst=0x49)
    self.assertEqual(0, m.wildcards)

  def test_wildcards_all_attrs_wildcarded(self):
    m = proto.Match.create_wildcarded()
    self.assertEqual(0x3820ff, m.wildcards)

  def test_wildcards_every_lsb(self):
    m_orig = proto.Match(in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
                         dl_dst='\x12\x23\x34\x45\x56\x67',
                         dl_vlan=0x11, dl_vlan_pcp=0x22, dl_type=0x3344,
                         nw_tos=0x80, nw_proto=0xcc,
                         nw_src=('\xaa\xbb\xcc\xdd', 32),
                         nw_dst=('\x21\x32\x43\x54', 32), tp_src=0x38,
                         tp_dst=0x49)
    wildcard_bit = 1 << 0
    for attr_name in ('in_port', 'dl_vlan', 'dl_src', 'dl_dst', 'dl_type',
                      'nw_proto', 'tp_src', 'tp_dst'):
      attr_value = m_orig._asdict()[attr_name]
      m = proto.Match.create_wildcarded(**{attr_name: attr_value})
      self.assertEqual(0x3820ff & ~wildcard_bit, m.wildcards)
      wildcard_bit = wildcard_bit << 1

  def test_wildcards_every_nw_src_prefix_length(self):
    m_orig = proto.Match(in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
                         dl_dst='\x12\x23\x34\x45\x56\x67',
                         dl_vlan=0x11, dl_vlan_pcp=0x22, dl_type=0x3344,
                         nw_tos=0x80, nw_proto=0xcc,
                         nw_src=('\xaa\xbb\xcc\xdd', 32),
                         nw_dst=('\x21\x32\x43\x54', 32), tp_src=0x38,
                         tp_dst=0x49)
    for i in xrange(1, 33):
      m = m_orig._replace(nw_src=('\xaa\xbb\xcc\xdd', i))
      wildcards = (32 - i) << 8
      self.assertEqual(wildcards, m.wildcards)

  def test_wildcards_every_nw_dst_prefix_length(self):
    m_orig = proto.Match(in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
                         dl_dst='\x12\x23\x34\x45\x56\x67',
                         dl_vlan=0x11, dl_vlan_pcp=0x22, dl_type=0x3344,
                         nw_tos=0x80, nw_proto=0xcc,
                         nw_src=('\xaa\xbb\xcc\xdd', 32),
                         nw_dst=('\x21\x32\x43\x54', 32), tp_src=0x38,
                         tp_dst=0x49)
    for i in xrange(1, 33):
      m = m_orig._replace(nw_dst=('\x21\x32\x43\x54', i))
      wildcards = (32 - i) << 14
      self.assertEqual(wildcards, m.wildcards)

  def test_wildcards_every_msb(self):
    m_orig = proto.Match(in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
                         dl_dst='\x12\x23\x34\x45\x56\x67',
                         dl_vlan=0x11, dl_vlan_pcp=0x22, dl_type=0x3344,
                         nw_tos=0x80, nw_proto=0xcc,
                         nw_src=('\xaa\xbb\xcc\xdd', 32),
                         nw_dst=('\x21\x32\x43\x54', 32), tp_src=0x38,
                         tp_dst=0x49)
    wildcard_bit = 1 << 20
    for attr_name in ('dl_vlan_pcp', 'nw_tos'):
      attr_value = m_orig._asdict()[attr_name]
      m = proto.Match.create_wildcarded(**{attr_name: attr_value})
      self.assertEqual(0x3820ff & ~wildcard_bit, m.wildcards)
      wildcard_bit = wildcard_bit << 1

  def test_serialize_no_attrs_wildcarded(self):
    m = proto.Match(in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
                    dl_dst='\x12\x23\x34\x45\x56\x67',
                    dl_vlan=0x11, dl_vlan_pcp=0x22, dl_type=0x3344,
                    nw_tos=0x80, nw_proto=0xcc, nw_src=('\xaa\xbb\xcc\xdd', 32),
                    nw_dst=('\x21\x32\x43\x54', 32), tp_src=0x38, tp_dst=0x49)
    self.assertEqual('\x00\x00\x00\x00' '\x00\x13' '\x13\x24\x35\x46\x57\x68'
                     '\x12\x23\x34\x45\x56\x67' '\x00\x11' '\x22\x00' '\x33\x44'
                     '\x80\xcc\x00\x00' '\xaa\xbb\xcc\xdd' '\x21\x32\x43\x54'
                     '\x00\x38\x00\x49', m.serialize())

  def test_serialize_all_attrs_wildcarded(self):
    m = proto.Match.create_wildcarded()
    self.assertEqual('\x00\x38\x20\xff' + '\x00' * 36, m.serialize())

  def test_serialize_deserialize_no_attrs_wildcarded(self):
    m = proto.Match(in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
                    dl_dst='\x12\x23\x34\x45\x56\x67',
                    dl_vlan=0x11, dl_vlan_pcp=0x22, dl_type=0x3344,
                    nw_tos=0x80, nw_proto=0xcc, nw_src=('\xaa\xbb\xcc\xdd', 32),
                    nw_dst=('\x21\x32\x43\x54', 32), tp_src=0x38, tp_dst=0x49)
    self.buf.append(m.serialize())
    self.buf.set_message_boundaries(40)
    self.assertTupleEqual(m, proto.Match.deserialize(self.buf))

  def test_serialize_deserialize_no_attrs_wildcarded(self):
    m = proto.Match.create_wildcarded()
    self.buf.append(m.serialize())
    self.buf.set_message_boundaries(40)
    self.assertTupleEqual(m, proto.Match.deserialize(self.buf))

  def test_serialize_deserialize_wildcards_every_lsb(self):
    m_orig = proto.Match(in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
                         dl_dst='\x12\x23\x34\x45\x56\x67',
                         dl_vlan=0x11, dl_vlan_pcp=0x22, dl_type=0x3344,
                         nw_tos=0x80, nw_proto=0xcc,
                         nw_src=('\xaa\xbb\xcc\xdd', 32),
                         nw_dst=('\x21\x32\x43\x54', 32), tp_src=0x38,
                         tp_dst=0x49)
    for attr_name in ('in_port', 'dl_vlan', 'dl_src', 'dl_dst', 'dl_type',
                      'nw_proto', 'tp_src', 'tp_dst'):
      attr_value = m_orig._asdict()[attr_name]
      m = proto.Match.create_wildcarded(**{attr_name: attr_value})
      self.buf.append(m.serialize())
      self.buf.set_message_boundaries(40)
      self.assertTupleEqual(m, proto.Match.deserialize(self.buf))

  def test_serialize_deserialize_wildcards_every_nw_src_prefix_length(self):
    m_orig = proto.Match(in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
                         dl_dst='\x12\x23\x34\x45\x56\x67',
                         dl_vlan=0x11, dl_vlan_pcp=0x22, dl_type=0x3344,
                         nw_tos=0x80, nw_proto=0xcc,
                         nw_src=('\xaa\xbb\xcc\xdd', 32),
                         nw_dst=('\x21\x32\x43\x54', 32), tp_src=0x38,
                         tp_dst=0x49)
    for i in xrange(1, 33):
      m = m_orig._replace(nw_src=('\xaa\xbb\xcc\xdd', i))
      self.buf.append(m.serialize())
      self.buf.set_message_boundaries(40)
      self.assertTupleEqual(m, proto.Match.deserialize(self.buf))

  def test_serialize_deserialize_wildcards_every_nw_dst_prefix_length(self):
    m_orig = proto.Match(in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
                         dl_dst='\x12\x23\x34\x45\x56\x67',
                         dl_vlan=0x11, dl_vlan_pcp=0x22, dl_type=0x3344,
                         nw_tos=0x80, nw_proto=0xcc,
                         nw_src=('\xaa\xbb\xcc\xdd', 32),
                         nw_dst=('\x21\x32\x43\x54', 32), tp_src=0x38,
                         tp_dst=0x49)
    for i in xrange(1, 33):
      m = m_orig._replace(nw_dst=('\x21\x32\x43\x54', i))
      self.buf.append(m.serialize())
      self.buf.set_message_boundaries(40)
      self.assertTupleEqual(m, proto.Match.deserialize(self.buf))

  def test_serialize_deserialize_wildcards_every_msb(self):
    m_orig = proto.Match(in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
                         dl_dst='\x12\x23\x34\x45\x56\x67',
                         dl_vlan=0x11, dl_vlan_pcp=0x22, dl_type=0x3344,
                         nw_tos=0x80, nw_proto=0xcc,
                         nw_src=('\xaa\xbb\xcc\xdd', 32),
                         nw_dst=('\x21\x32\x43\x54', 32), tp_src=0x38,
                         tp_dst=0x49)
    for attr_name in ('dl_vlan_pcp', 'nw_tos'):
      attr_value = m_orig._asdict()[attr_name]
      m = proto.Match.create_wildcarded(**{attr_name: attr_value})
      self.buf.append(m.serialize())
      self.buf.set_message_boundaries(40)
      self.assertTupleEqual(m, proto.Match.deserialize(self.buf))


class MockTransport(object):
  """A basic mock of Twisted's ITransport interface.
  """

  __slots__ = ('buffer',)

  def __init__(self):
    self.buffer = buffer.ReceiveBuffer()

  def writeSequence(self, data):
    for buf in data:
      self.buffer.append(buf)


class MockOpenflowProtocolSubclass(proto.OpenflowProtocol):

  def __init__(self, *args, **kargs):
    proto.OpenflowProtocol.__init__(self, *args, **kargs)
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


MockVendorAction = action.vendor_action('MockVendorAction', 0x4242,
                                        '!L', ('dummy',))


class MockVendorHandler(object):
  """A mock vendor extension implementation.
  """

  def __init__(self):
    # A list of (ofproto, msg_length, xid, bytes) tuples.
    self.received_callbacks = []

  vendor_id = 0x4242

  def handle_vendor_message(self, ofproto, msg_length, xid, buffer):
    bytes = buffer.read_bytes(msg_length - 12)  # Consume the remaining bytes.
    self.received_callbacks.append(('handle_vendor_message', ofproto,
                                    msg_length, xid, bytes))

  def deserialize_vendor_action(self, length, buffer):
    a = MockVendorAction.deserialize(buffer)
    self.received_callbacks.append(('deserialize_vendor_action', type, length,
                                    buffer, a))
    return a


class TestOpenflowProtocol(unittest2.TestCase):

  def setUp(self):
    self.transport = MockTransport()
    self.vendor_handler = MockVendorHandler()
    self.proto = MockOpenflowProtocolSubclass(
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
    self.assertGreaterEqual(len(buf), proto.OFP_HEADER_LENGTH)
    buf.set_message_boundaries(proto.OFP_HEADER_LENGTH)
    _, _, msg_length, _ = buf.unpack_inplace(proto.OFP_HEADER_FORMAT)
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

    pp1 = proto.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config_port_down=False, config_no_stp=True, config_no_recv=False,
      config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
      config_no_packet_in=False, state_link_down=True,
      state_stp=proto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    sf = proto.SwitchFeatures(
        datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
        cap_table_stats=False, cap_port_stats=True, cap_stp=False,
        cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
        actions=frozenset((0, 2, 3, 5, 8)), ports=(pp1,))
    self.proto.send_features_reply(4, sf)
    self.assertEqual('\x01\x06\x00\x50\x00\x00\x00\x04'
                     + ''.join(sf.serialize()),
                     self._get_next_sent_message())

  def test_handle_features_reply(self):
    self.proto.connectionMade()

    pp1 = proto.PhyPort(
      port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
      config_port_down=False, config_no_stp=True, config_no_recv=False,
      config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
      config_no_packet_in=False, state_link_down=True,
      state_stp=proto.OFPPS_STP_FORWARD,
      curr=_create_port_features(mode_1gb_fd=True, fiber=True),
      advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       pause=True),
      supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                      pause=True, pause_asym=True),
      peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                 autoneg=True))
    sf = proto.SwitchFeatures(
        datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
        cap_table_stats=False, cap_port_stats=True, cap_stp=False,
        cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
        actions=frozenset((0, 2, 3, 5, 8)), ports=(pp1,))
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

    sc = proto.SwitchConfig(config_frag=proto.OFPC_FRAG_DROP,
                            miss_send_len=128)
    self.proto.send_get_config_reply(4, sc)
    self.assertEqual('\x01\x08\x00\x0c\x00\x00\x00\x04'
                     + ''.join(sc.serialize()),
                     self._get_next_sent_message())

  def test_handle_get_config_reply(self):
    self.proto.connectionMade()

    sc = proto.SwitchConfig(config_frag=proto.OFPC_FRAG_DROP,
                            miss_send_len=128)
    self.proto.dataReceived('\x01\x08\x00\x0c\x00\x00\x00\x04'
                            + ''.join(sc.serialize()))
    self.assertListEqual([('handle_get_config_reply', 4, sc)],
                         self.proto.calls_made)

  def test_send_set_config(self):
    self.proto.connectionMade()

    sc = proto.SwitchConfig(config_frag=proto.OFPC_FRAG_DROP,
                            miss_send_len=128)
    self.proto.send_set_config(sc)
    self.assertEqual('\x01\x09\x00\x0c\x00\x00\x00\x00'
                     + ''.join(sc.serialize()),
                     self._get_next_sent_message())

  def test_handle_set_config(self):
    self.proto.connectionMade()

    sc = proto.SwitchConfig(config_frag=proto.OFPC_FRAG_DROP,
                            miss_send_len=128)
    self.proto.dataReceived('\x01\x09\x00\x0c\x00\x00\x00\x00'
                            + ''.join(sc.serialize()))
    self.assertListEqual([('handle_set_config', sc)],
                         self.proto.calls_made)

  def test_send_packet_in(self):
    self.proto.connectionMade()

    self.proto.send_packet_in(0x1324, 0x100, 0x42, proto.OFPR_ACTION,
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
                           proto.OFPR_ACTION, 'abcdef')],
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

    match = proto.Match(
        in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
        dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
        dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
        nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
        tp_src=0x38, tp_dst=0x49)
    self.proto.send_flow_removed(match, 0x12345678, 0x1000, proto.OFPRR_DELETE,
                                 0x302010, 0x030201, 0x4231, 0x635241, 0x554433)
    self.assertEqual('\x01\x0b\x00\x58\x00\x00\x00\x00'
                     + match.serialize() + '\x00\x00\x00\x00\x12\x34\x56\x78'
                     '\x10\x00' '\x02\x00' '\x00\x30\x20\x10' '\x00\x03\x02\x01'
                     '\x42\x31\x00\x00' '\x00\x00\x00\x00\x00\x63\x52\x41'
                     '\x00\x00\x00\x00\x00\x55\x44\x33',
                     self._get_next_sent_message())

  def test_send_flow_removed_invalid_action_3(self):
    self.proto.connectionMade()

    match = proto.Match(
        in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
        dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
        dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
        nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
        tp_src=0x38, tp_dst=0x49)
    with self.assertRaises(ValueError):
      self.proto.send_flow_removed(match, 0x12345678, 0x1000, 3, 0x302010,
                                   0x030201, 0x4231, 0x635241, 0x554433)
    self.assertIsNone(self._get_next_sent_message())

  def test_handle_flow_removed(self):
    self.proto.connectionMade()

    match = proto.Match(
        in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
        dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
        dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
        nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
        tp_src=0x38, tp_dst=0x49)
    self.proto.dataReceived(
        '\x01\x0b\x00\x58\x00\x00\x00\x00'
        + match.serialize() + '\x00\x00\x00\x00\x12\x34\x56\x78'
        '\x10\x00' '\x02\x00' '\x00\x30\x20\x10' '\x00\x03\x02\x01'
        '\x42\x31\x00\x00' '\x00\x00\x00\x00\x00\x63\x52\x41'
        '\x00\x00\x00\x00\x00\x55\x44\x33')
    self.assertListEqual(
        [('handle_flow_removed', match, 0x12345678, 0x1000, proto.OFPRR_DELETE,
          0x302010, 0x030201, 0x4231, 0x635241, 0x554433)],
        self.proto.calls_made)

  def test_handle_flow_removed_invalid_action_3(self):
    self.proto.connectionMade()

    match = proto.Match(
        in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
        dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
        dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
        nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
        tp_src=0x38, tp_dst=0x49)
    with self.assertRaises(ValueError):
      self.proto.dataReceived(
          '\x01\x0b\x00\x58\x00\x00\x00\x00'
          + match.serialize() + '\x00\x00\x00\x00\x12\x34\x56\x78'
          '\x10\x00' '\x03\x00' '\x00\x30\x20\x10' '\x00\x03\x02\x01'
          '\x42\x31\x00\x00' '\x00\x00\x00\x00\x00\x63\x52\x41'
          '\x00\x00\x00\x00\x00\x55\x44\x33')
    self.assertListEqual([], self.proto.calls_made)

  def test_send_port_status(self):
    self.proto.connectionMade()

    pp = proto.PhyPort(
        port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
        config_port_down=False, config_no_stp=True, config_no_recv=False,
        config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
        config_no_packet_in=False, state_link_down=False,
        state_stp=proto.OFPPS_STP_FORWARD,
        curr=_create_port_features(mode_1gb_fd=True, fiber=True),
        advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
        supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                        pause=True, pause_asym=True),
        peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                   autoneg=True))
    self.proto.send_port_status(proto.OFPPR_MODIFY, pp)
    self.assertEqual('\x01\x0c\x00\x40\x00\x00\x00\x00'
                     '\x02\x00\x00\x00\x00\x00\x00\x00'
                     + pp.serialize(), self._get_next_sent_message())

  def test_send_port_status_invalid_action_3(self):
    self.proto.connectionMade()

    pp = proto.PhyPort(
        port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
        config_port_down=False, config_no_stp=True, config_no_recv=False,
        config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
        config_no_packet_in=False, state_link_down=False,
        state_stp=proto.OFPPS_STP_FORWARD,
        curr=_create_port_features(mode_1gb_fd=True, fiber=True),
        advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
        supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                        pause=True, pause_asym=True),
        peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                   autoneg=True))
    with self.assertRaises(ValueError):
      self.proto.send_port_status(3, pp)
    self.assertIsNone(self._get_next_sent_message())

  def test_handle_port_status(self):
    self.proto.connectionMade()

    pp = proto.PhyPort(
        port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
        config_port_down=False, config_no_stp=True, config_no_recv=False,
        config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
        config_no_packet_in=False, state_link_down=False,
        state_stp=proto.OFPPS_STP_FORWARD,
        curr=_create_port_features(mode_1gb_fd=True, fiber=True),
        advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
        supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                        pause=True, pause_asym=True),
        peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                   autoneg=True))
    self.proto.dataReceived('\x01\x0c\x00\x40\x00\x00\x00\x00'
                            '\x02\x00\x00\x00\x00\x00\x00\x00'
                            + pp.serialize())
    self.assertListEqual([('handle_port_status', proto.OFPPR_MODIFY, pp)],
                         self.proto.calls_made)

  def test_handle_port_status_invalid_action_3(self):
    self.proto.connectionMade()

    pp = proto.PhyPort(
        port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
        config_port_down=False, config_no_stp=True, config_no_recv=False,
        config_no_recv_stp=True, config_no_flood=True, config_no_fwd=False,
        config_no_packet_in=False, state_link_down=False,
        state_stp=proto.OFPPS_STP_FORWARD,
        curr=_create_port_features(mode_1gb_fd=True, fiber=True),
        advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
        supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                        pause=True, pause_asym=True),
        peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                   autoneg=True))
    with self.assertRaises(ValueError):
      self.proto.dataReceived('\x01\x0c\x00\x40\x00\x00\x00\x00'
                              '\x03\x00\x00\x00\x00\x00\x00\x00'
                              + pp.serialize())
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
            action.ActionOutput(port=0x1234, max_len=0x9abc),
            action.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')),
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
            action.ActionOutput(port=0x1234, max_len=0x9abc),
            action.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')),
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
    self.assertEqual('\x01\x0d\x00\x26\x00\x00\x00\x00'
                     '\xff\xff\xff\xff\xab\xcd\x00\x01'
                     '\x00\x0c\x00\x0c' '\x00\x00\x42\x42'
                         '\x15\x26\x37\x48'
                     'helloworld',
                     self._get_next_sent_message())
    # TODO(romain): Test that the vendor handler received the right callback.

  def test_send_packet_out_unbuffered_no_data(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.send_packet_out(
          0xffffffff, 0xabcd, (
              action.ActionOutput(port=0x1234, max_len=0x9abc),
              action.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')),
          ())
    self.assertIsNone(self._get_next_sent_message())

  def test_send_packet_out_buffered_with_data(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.send_packet_out(
          0x01010101, 0xabcd, (
              action.ActionOutput(port=0x1234, max_len=0x9abc),
              action.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')),
          ('helloworld',))
    self.assertIsNone(self._get_next_sent_message())

  def test_send_packet_out_invalid_port0xff01(self):
    self.proto.connectionMade()

    with self.assertRaises(ValueError):
      self.proto.send_packet_out(
          0x01010101, 0xff01, (
              action.ActionOutput(port=0x1234, max_len=0x9abc),
              action.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')),
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
            action.ActionOutput(port=0x1234, max_len=0x9abc),
            action.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')),
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
            action.ActionOutput(port=0x1234, max_len=0x9abc),
            action.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')),
        'helloworld')], self.proto.calls_made)

  def test_handle_packet_out_unbuffered_vendor_action(self):
    self.proto.connectionMade()

    self.proto.dataReceived('\x01\x0d\x00\x26\x00\x00\x00\x00'
                            '\xff\xff\xff\xff\xab\xcd\x00\x01'
                            '\x00\x0c\x00\x0c' '\x00\x00\x42\x42'
                                '\x15\x26\x37\x48'
                            'helloworld')
    self.assertListEqual([('handle_packet_out', 0xffffffff, 0xabcd,
                           (MockVendorAction(dummy=0x15263748),), 'helloworld')],
                          self.proto.calls_made)
    # TODO(romain): Test that the vendor handler received the right callback.

  def test_send_flow_mod(self):
    self.proto.connectionMade()

    match = proto.Match(
        in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
        dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
        dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
        nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
        tp_src=0x38, tp_dst=0x49)
    self.proto.send_flow_mod(
        match, 0x12345678, proto.OFPFC_MODIFY, 0x4231, 0, 0x1000, 0x01010101,
        0xabcd, True, False, False, (
            action.ActionOutput(port=0x1234, max_len=0x9abc),
            action.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')))
    self.assertEqual('\x01\x0e\x00\x60\x00\x00\x00\x00'
                     + match.serialize()
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

    match = proto.Match(
        in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
        dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
        dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
        nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
        tp_src=0x38, tp_dst=0x49)
    with self.assertRaises(ValueError):
      self.proto.send_flow_mod(
          match, 0xffffffffffffffff, proto.OFPFC_MODIFY, 0x4231, 0, 0x1000,
          0x01010101, 0xabcd, True, False, False, ())
    self.assertIsNone(self._get_next_sent_message())

  def test_send_flow_mod_invalid_command_5(self):
    self.proto.connectionMade()

    match = proto.Match(
        in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
        dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
        dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
        nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
        tp_src=0x38, tp_dst=0x49)
    with self.assertRaises(ValueError):
      self.proto.send_flow_mod(
          match, 0x12345678, 5, 0x4231, 0, 0x1000,
          0x01010101, 0xabcd, True, False, False, ())
    self.assertIsNone(self._get_next_sent_message())

  def test_handle_flow_mod_two_actions(self):
    self.proto.connectionMade()

    match = proto.Match(
        in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
        dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
        dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
        nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
        tp_src=0x38, tp_dst=0x49)
    self.proto.dataReceived(
        '\x01\x0e\x00\x60\x00\x00\x00\x00'
        + match.serialize()
        + '\x00\x00\x00\x00\x12\x34\x56\x78'
        '\x00\x01' '\x42\x31\x00\x00' '\x10\x00'
        '\x01\x01\x01\x01' '\xab\xcd' '\x00\x01'
        '\x00\x00\x00\x08'
            '\x12\x34\x9a\xbc'
        '\x00\x05\x00\x10'
            '\x12\x34\x56\x78\xab\xcd\x00\x00\x00\x00\x00\x00')
    self.assertListEqual(
        [('handle_flow_mod', match, 0x12345678, proto.OFPFC_MODIFY, 0x4231, 0,
          0x1000, 0x01010101, 0xabcd, True, False, False, (
              action.ActionOutput(port=0x1234, max_len=0x9abc),
              action.ActionSetDlDst(dl_addr='\x12\x34\x56\x78\xab\xcd')))],
        self.proto.calls_made)

  def test_handle_flow_mod_no_actions(self):
    self.proto.connectionMade()

    match = proto.Match(
        in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
        dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
        dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
        nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
        tp_src=0x38, tp_dst=0x49)
    self.proto.dataReceived(
        '\x01\x0e\x00\x48\x00\x00\x00\x00'
        + match.serialize()
        + '\x00\x00\x00\x00\x12\x34\x56\x78'
        '\x00\x01' '\x42\x31\x00\x00' '\x10\x00'
        '\x01\x01\x01\x01' '\xab\xcd' '\x00\x01')
    self.assertListEqual(
        [('handle_flow_mod', match, 0x12345678, proto.OFPFC_MODIFY, 0x4231, 0,
          0x1000, 0x01010101, 0xabcd, True, False, False, ())],
        self.proto.calls_made)

  def test_handle_flow_mod_invalid_cookie_minus1(self):
    self.proto.connectionMade()

    match = proto.Match(
        in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
        dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
        dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
        nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
        tp_src=0x38, tp_dst=0x49)
    with self.assertRaises(ValueError):
      self.proto.dataReceived(
          '\x01\x0e\x00\x48\x00\x00\x00\x00'
          + match.serialize()
          + '\xff\xff\xff\xff\xff\xff\xff\xff'
          '\x00\x01' '\x42\x31\x00\x00' '\x10\x00'
          '\x01\x01\x01\x01' '\xab\xcd' '\x00\x01')
    self.assertListEqual([], self.proto.calls_made)

  def test_handle_flow_mod_invalid_command_5(self):
    self.proto.connectionMade()

    match = proto.Match(
        in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
        dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
        dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
        nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
        tp_src=0x38, tp_dst=0x49)
    with self.assertRaises(ValueError):
      self.proto.dataReceived(
          '\x01\x0e\x00\x48\x00\x00\x00\x00'
          + match.serialize()
          + '\x00\x00\x00\x00\x12\x34\x56\x78'
          '\x00\x05' '\x42\x31\x00\x00' '\x10\x00'
          '\x01\x01\x01\x01' '\xab\xcd' '\x00\x01')
    self.assertListEqual([], self.proto.calls_made)

  # TODO(romain): Test handling of bogus messages, with wrong message lengths.

  # TODO(romain): Test proper handling of small chunks of data.


class TestOpenflowProtocolRequestTracker(unittest2.TestCase):

  def setUp(self):
    self.transport = MockTransport()
    self.vendor_handler = MockVendorHandler()
    self.proto = proto.OpenflowProtocolRequestTracker(
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
    self.assertGreaterEqual(len(buf), proto.OFP_HEADER_LENGTH)
    buf.set_message_boundaries(proto.OFP_HEADER_LENGTH)
    _, _, msg_length, _ = buf.unpack_inplace(proto.OFP_HEADER_FORMAT)
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
