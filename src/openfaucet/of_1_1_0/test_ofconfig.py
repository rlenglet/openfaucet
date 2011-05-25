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
from openfaucet.of_1_1_0 import ofconfig


def _create_port_config(
    port_down=False, no_recv=False, no_fwd=False, no_packet_in=False):
    return ofconfig.PortConfig(
        port_down=port_down, no_recv=no_recv, no_fwd=no_fwd,
        no_packet_in=no_packet_in)


def _create_port_features(
    mode_10mb_hd=False, mode_10mb_fd=False, mode_100mb_hd=False,
    mode_100mb_fd=False, mode_1gb_hd=False, mode_1gb_fd=False,
    mode_10gb_fd=False, mode_40gb_fd=False, mode_100gb_fd=False,
    mode_1tb_fd=False, mode_other=False, copper=False, fiber=False,
    autoneg=False, pause=False, pause_asym=False):
    return ofconfig.PortFeatures(
        mode_10mb_hd=mode_10mb_hd, mode_10mb_fd=mode_10mb_fd,
        mode_100mb_hd=mode_100mb_hd, mode_100mb_fd=mode_100mb_fd,
        mode_1gb_hd=mode_1gb_hd, mode_1gb_fd=mode_1gb_fd,
        mode_10gb_fd=mode_10gb_fd, mode_40gb_fd=mode_40gb_fd,
        mode_100gb_fd=mode_100gb_fd, mode_1tb_fd=mode_1tb_fd,
        mode_other=mode_other, copper=copper, fiber=fiber, autoneg=autoneg,
        pause=pause, pause_asym=pause_asym)


class TestPortConfig(unittest2.TestCase):

    def test_create(self):
        pc = ofconfig.PortConfig(port_down=False, no_recv=True, no_fwd=False,
                                 no_packet_in=True)

    def test_serialize(self):
        pc = ofconfig.PortConfig(port_down=False, no_recv=True, no_fwd=False,
                                 no_packet_in=True)
        self.assertEqual(0x44, pc.serialize())

    def test_serialize_every_flag(self):
        flag = 1 << 0
        args = (True, False, False, False)
        pc = ofconfig.PortConfig(*args)
        self.assertEqual(flag, pc.serialize())
        flag = 1 << 2
        args = (False, True, False, False)
        pc = ofconfig.PortConfig(*args)
        self.assertEqual(flag, pc.serialize())
        flag = 1 << 5
        args = (False, False, True, False)
        pc = ofconfig.PortConfig(*args)
        self.assertEqual(flag, pc.serialize())
        flag = 1 << 6
        args = (False, False, False, True)
        pc = ofconfig.PortConfig(*args)
        self.assertEqual(flag, pc.serialize())

    def test_serialize_deserialize(self):
        pc = ofconfig.PortConfig(port_down=False, no_recv=False,
                                 no_fwd=False, no_packet_in=False)
        self.assertTupleEqual(pc, ofconfig.PortConfig.deserialize(
            pc.serialize()))

    def test_deserialize(self):
        self.assertTupleEqual((False, True, False, True),
                              ofconfig.PortConfig.deserialize(0x44))

    def test_deserialize_every_invalid_bit(self):
        for i in [1, 3, 4] + range(7, 32):
            flags = (1 << i) | 0x00000044
            # The invalid bit is ignored.
            self.assertTupleEqual(
                (False, True, False, True),
                ofconfig.PortConfig.deserialize(flags))

    def test_get_diff_every_flag_true(self):
        all_false = ofconfig.PortConfig(*([False] * 4))
        for i in xrange(0, 4):
            args = [False] * 3
            args.insert(i, True)
            pc = ofconfig.PortConfig(*args)
            config, mask = pc.get_diff(all_false)
            args = tuple(args)
            self.assertEqual(True, config[i])
            self.assertTupleEqual(args, mask)

    def test_get_diff_every_flag_false(self):
        all_true = ofconfig.PortConfig(*([True] * 4))
        for i in xrange(0, 4):
            args = [True] * 3
            args.insert(i, False)
            pc = ofconfig.PortConfig(*args)
            config, mask = pc.get_diff(all_true)
            self.assertEqual(False, config[i])
            expected_mask = [False] * 3
            expected_mask.insert(i, True)
            expected_mask = tuple(expected_mask)
            self.assertTupleEqual(expected_mask, mask)

    def test_patch_every_flag_true(self):
        all_false = ofconfig.PortConfig(*([False] * 4))
        for i in xrange(0, 4):
            args = [False] * 3
            args.insert(i, True)
            config = ofconfig.PortConfig(*args)
            mask = ofconfig.PortConfig(*args)
            args = tuple(args)
            self.assertTupleEqual(args, all_false.patch(config, mask))

    def test_patch_every_flag_false(self):
        all_true = ofconfig.PortConfig(*([True] * 4))
        for i in xrange(0, 4):
            config_args = [False] * 4
            config = ofconfig.PortConfig(*config_args)
            mask_args = [False] * 3
            mask_args.insert(i, True)
            mask = ofconfig.PortConfig(*mask_args)
            expected_args = [True] * 3
            expected_args.insert(i, False)
            expected_args = tuple(expected_args)
            self.assertTupleEqual(expected_args, all_true.patch(config, mask))


class TestPortFeatures(unittest2.TestCase):

    def test_create(self):
        pf = ofconfig.PortFeatures(
            mode_10mb_hd=False, mode_10mb_fd=True, mode_100mb_hd=False,
            mode_100mb_fd=True, mode_1gb_hd=False, mode_1gb_fd=True,
            mode_10gb_fd=True, mode_40gb_fd=False, mode_100gb_fd=False,
            mode_1tb_fd=True, mode_other=False, copper=False, fiber=True,
            autoneg=True, pause=True, pause_asym=False)

    def test_serialize(self):
        pf = ofconfig.PortFeatures(
            mode_10mb_hd=False, mode_10mb_fd=True, mode_100mb_hd=False,
            mode_100mb_fd=True, mode_1gb_hd=False, mode_1gb_fd=True,
            mode_10gb_fd=True, mode_40gb_fd=False, mode_100gb_fd=False,
            mode_1tb_fd=True, mode_other=False, copper=False, fiber=True,
            autoneg=True, pause=True, pause_asym=False)
        self.assertEqual(0x0000726a, pf.serialize())

    def test_serialize_every_flag(self):
        for i in xrange(0, 16):
            flag = 1 << i
            args = [False] * 15
            args.insert(i, True)
            pf = ofconfig.PortFeatures(*args)
            self.assertEqual(flag, pf.serialize())

    def test_serialize_deserialize(self):
        pf = ofconfig.PortFeatures(
            mode_10mb_hd=False, mode_10mb_fd=True, mode_100mb_hd=False,
            mode_100mb_fd=True, mode_1gb_hd=False, mode_1gb_fd=True,
            mode_10gb_fd=True, mode_40gb_fd=False, mode_100gb_fd=False,
            mode_1tb_fd=True, mode_other=False, copper=False, fiber=True,
            autoneg=True, pause=True, pause_asym=False)
        self.assertTupleEqual(pf, ofconfig.PortFeatures.deserialize(
            pf.serialize()))

    def test_deserialize(self):
        self.assertTupleEqual((False, True, False, True, False, True, True,
                               False, False, True, False,
                               False, True, True, True, False),
                              ofconfig.PortFeatures.deserialize(0x0000726a))

    def test_deserialize_every_flag(self):
        for i in xrange(0, 16):
            flag = 1 << i
            args = [False] * 15
            args.insert(i, True)
            args = tuple(args)
            self.assertTupleEqual(args,
                                  ofconfig.PortFeatures.deserialize(flag))

    def test_deserialize_every_invalid_bit(self):
        for i in xrange(16, 32):
            flags = (1 << i) | 0x0000726a
            # The invalid bit is ignored.
            self.assertTupleEqual(
                (False, True, False, True, False, True, True,
                 False, False, True, False,
                 False, True, True, True, False),
                ofconfig.PortFeatures.deserialize(flags))


class TestPhyPort(unittest2.TestCase):

    def setUp(self):
        self.buf = buffer.ReceiveBuffer()

    def test_create(self):
        pp = ofconfig.PhyPort(
            port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
            config=_create_port_config(no_recv=True, no_packet_in=True),
            state_link_down=False, state_blocked=False, state_live=True,
            curr=_create_port_features(mode_1gb_fd=True, fiber=True),
            advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                             pause=True),
            supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                            pause=True, pause_asym=True),
            peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       autoneg=True),
            curr_speed=900000, max_speed=1000000)

    def test_serialize(self):
        pp = ofconfig.PhyPort(
            port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
            config=_create_port_config(no_recv=True, no_packet_in=True),
            state_link_down=True, state_blocked=False, state_live=True,
            curr=_create_port_features(mode_1gb_fd=True, fiber=True),
            advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                             pause=True),
            supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                            pause=True, pause_asym=True),
            peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       autoneg=True),
            curr_speed=900000, max_speed=1000000)
        self.assertEqual('\x00\x00\x00\x42' '\x00\x00\x00\x00'
                         '\xab\xcd\xef\xa0\xb1\xc2' '\x00\x00'
                         'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                         '\x00\x00\x00\x44'
                         '\x00\x00\x00\x05'
                         '\x00\x00\x10\x20'
                         '\x00\x00\x50\x20'
                         '\x00\x00\xd0\x20'
                         '\x00\x00\x30\x20'
                         '\x00\x0d\xbb\xa0'
                         '\x00\x0f\x42\x40',
                         pp.serialize())

    def test_serialize_every_state_flag(self):
        for i in xrange(0, 3):
            state_flag = 1 << i
            state_args = [False] * 2
            state_args.insert(i, True)
            args = (
                [0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport',
                 _create_port_config(no_recv=True, no_packet_in=True)]
                + state_args
                + [_create_port_features(mode_1gb_fd=True, fiber=True),
                   _create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
                   _create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True, pause_asym=True),
                   _create_port_features(mode_1gb_fd=True, fiber=True,
                                         autoneg=True),
                   900000, 1000000])
            pp = ofconfig.PhyPort(*args)
            self.assertEqual('\x00\x00\x00\x42' '\x00\x00\x00\x00'
                             '\xab\xcd\xef\xa0\xb1\xc2' '\x00\x00'
                             'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                             '\x00\x00\x00\x44'
                             + struct.pack('!L', state_flag)
                             + '\x00\x00\x10\x20'
                             '\x00\x00\x50\x20'
                             '\x00\x00\xd0\x20'
                             '\x00\x00\x30\x20'
                             '\x00\x0d\xbb\xa0'
                             '\x00\x0f\x42\x40',
                             pp.serialize())

    def test_serialize_deserialize(self):
        pp = ofconfig.PhyPort(
            port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport',
            config=_create_port_config(no_recv=True, no_packet_in=True),
            state_link_down=True, state_blocked=False, state_live=True,
            curr=_create_port_features(mode_1gb_fd=True, fiber=True),
            advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                             pause=True),
            supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                            pause=True, pause_asym=True),
            peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       autoneg=True),
            curr_speed=900000, max_speed=1000000)
        self.buf.append(pp.serialize())
        self.buf.set_message_boundaries(64)
        self.assertTupleEqual(pp, ofconfig.PhyPort.deserialize(self.buf))

    def test_deserialize(self):
        self.buf.append('\x00\x00\x00\x42' '\x00\x00\x00\x00'
                        '\xab\xcd\xef\xa0\xb1\xc2' '\x00\x00'
                        'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                        '\x00\x00\x00\x44'
                        '\x00\x00\x00\x05'
                        '\x00\x00\x10\x20'
                        '\x00\x00\x50\x20'
                        '\x00\x00\xd0\x20'
                        '\x00\x00\x30\x20'
                        '\x00\x0d\xbb\xa0'
                        '\x00\x0f\x42\x40')
        self.buf.set_message_boundaries(64)
        self.assertTupleEqual(
            (0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport',
             _create_port_config(no_recv=True, no_packet_in=True),
             True, False, True,
             _create_port_features(mode_1gb_fd=True, fiber=True),
             _create_port_features(mode_1gb_fd=True, fiber=True,
                                   pause=True),
             _create_port_features(mode_1gb_fd=True, fiber=True,
                                   pause=True, pause_asym=True),
             _create_port_features(mode_1gb_fd=True, fiber=True,
                                   autoneg=True),
             900000, 1000000),
            ofconfig.PhyPort.deserialize(self.buf))
        # Test that the deserialization consumed all 64 bytes.
        with self.assertRaises(IndexError):
            self.buf.skip_bytes(1)

    def test_deserialize_every_state_flag(self):
        for i in xrange(0, 3):  # (ofconfig.OFPPS_LINK_DOWN,
                                #  ofconfig.OFPPS_BLOCKED,
                                #  ofconfig.OFPPS_LIVE)
            state_ser = 1 << i
            self.buf.append('\x00\x00\x00\x42' '\x00\x00\x00\x00'
                            '\xab\xcd\xef\xa0\xb1\xc2' '\x00\x00'
                            'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                            '\x00\x00\x00\x44')
            self.buf.append(struct.pack('!L', state_ser))
            self.buf.append('\x00\x00\x10\x20'
                            '\x00\x00\x50\x20'
                            '\x00\x00\xd0\x20'
                            '\x00\x00\x30\x20'
                            '\x00\x0d\xbb\xa0'
                            '\x00\x0f\x42\x40')
            self.buf.set_message_boundaries(64)
            state_args = [False] * 2
            state_args.insert(i, True)
            args = (
                (0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport',
                 _create_port_config(no_recv=True, no_packet_in=True))
                + tuple(state_args)
                + (_create_port_features(mode_1gb_fd=True, fiber=True),
                   _create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True),
                   _create_port_features(mode_1gb_fd=True, fiber=True,
                                         pause=True, pause_asym=True),
                   _create_port_features(mode_1gb_fd=True, fiber=True,
                                         autoneg=True),
                   900000, 1000000))
            self.assertTupleEqual(args, ofconfig.PhyPort.deserialize(self.buf))

    def test_deserialize_invalid_state_0x040d(self):
        self.buf.append('\x00\x00\x00\x42' '\x00\x00\x00\x00'
                        '\xab\xcd\xef\xa0\xb1\xc2' '\x00\x00'
                        'testport\x00\x00\x00\x00\x00\x00\x00\x00'
                        '\x00\x00\x00\x44'
                        '\x00\x00\x04\x0d'
                        '\x00\x00\x10\x20'
                        '\x00\x00\x50\x20'
                        '\x00\x00\xd0\x20'
                        '\x00\x00\x30\x20'
                        '\x00\x0d\xbb\xa0'
                        '\x00\x0f\x42\x40')
        self.buf.set_message_boundaries(64)
        # The invalid bits at 0x0400 and 0x0006 in the state are ignored.
        self.assertTupleEqual(
            (0x42, '\xab\xcd\xef\xa0\xb1\xc2', 'testport',
             _create_port_config(no_recv=True, no_packet_in=True),
             True, False, True,
             _create_port_features(mode_1gb_fd=True, fiber=True),
             _create_port_features(mode_1gb_fd=True, fiber=True,
                                   pause=True),
             _create_port_features(mode_1gb_fd=True, fiber=True,
                                   pause=True, pause_asym=True),
             _create_port_features(mode_1gb_fd=True, fiber=True,
                                   autoneg=True),
             900000, 1000000),
            ofconfig.PhyPort.deserialize(self.buf))


class TestSwitchFeatures(unittest2.TestCase):

    def setUp(self):
        self.buf = buffer.ReceiveBuffer()

    def test_create(self):
        pp1 = ofconfig.PhyPort(
            port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
            config=_create_port_config(no_recv=True, no_packet_in=True),
            state_link_down=False, state_blocked=False, state_live=True,
            curr=_create_port_features(mode_1gb_fd=True, fiber=True),
            advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                             pause=True),
            supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                            pause=True, pause_asym=True),
            peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       autoneg=True),
            curr_speed=900000, max_speed=1000000)
        pp2 = ofconfig.PhyPort(
            port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
            config=_create_port_config(no_recv=True, no_packet_in=True),
            state_link_down=False, state_blocked=False, state_live=True,
            curr=_create_port_features(mode_1gb_fd=True, fiber=True),
            advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                             pause=True),
            supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                            pause=True, pause_asym=True),
            peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       autoneg=True),
            curr_speed=900000, max_speed=1000000)
        sf = ofconfig.SwitchFeatures(
            datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
            cap_table_stats=False, cap_port_stats=True, cap_group_stats=False,
            cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
            ports=(pp1, pp2))

    def test_serialize_no_port(self):
        sf = ofconfig.SwitchFeatures(
            datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
            cap_table_stats=False, cap_port_stats=True, cap_group_stats=False,
            cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
            ports=())
        self.assertEqual('\x00\x00\x00\x00\x00\x12\x34\x56'
                         '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                         '\x00\x00\x00\xa5' '\x00\x00\x00\x00',
                         ''.join(sf.serialize()))

    def test_serialize_one_port(self):
        pp1 = ofconfig.PhyPort(
            port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
            config=_create_port_config(no_recv=True, no_packet_in=True),
            state_link_down=False, state_blocked=False, state_live=True,
            curr=_create_port_features(mode_1gb_fd=True, fiber=True),
            advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                             pause=True),
            supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                            pause=True, pause_asym=True),
            peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       autoneg=True),
            curr_speed=900000, max_speed=1000000)
        sf = ofconfig.SwitchFeatures(
            datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
            cap_table_stats=False, cap_port_stats=True, cap_group_stats=False,
            cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
            ports=(pp1,))
        self.assertEqual('\x00\x00\x00\x00\x00\x12\x34\x56'
                         '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                         '\x00\x00\x00\xa5' '\x00\x00\x00\x00',
                         ''.join(sf.serialize()))

    def test_serialize_one_port(self):
        pp1 = ofconfig.PhyPort(
            port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
            config=_create_port_config(no_recv=True, no_packet_in=True),
            state_link_down=False, state_blocked=False, state_live=True,
            curr=_create_port_features(mode_1gb_fd=True, fiber=True),
            advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                             pause=True),
            supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                            pause=True, pause_asym=True),
            peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       autoneg=True),
            curr_speed=900000, max_speed=1000000)
        sf = ofconfig.SwitchFeatures(
            datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
            cap_table_stats=False, cap_port_stats=True, cap_group_stats=False,
            cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
            ports=(pp1,))
        self.assertEqual('\x00\x00\x00\x00\x00\x12\x34\x56'
                         '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                         '\x00\x00\x00\xa5' '\x00\x00\x00\x00'
                         + pp1.serialize(), ''.join(sf.serialize()))

    def test_serialize_two_ports(self):
        pp1 = ofconfig.PhyPort(
            port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
            config=_create_port_config(no_recv=True, no_packet_in=True),
            state_link_down=False, state_blocked=False, state_live=True,
            curr=_create_port_features(mode_1gb_fd=True, fiber=True),
            advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                             pause=True),
            supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                            pause=True, pause_asym=True),
            peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       autoneg=True),
            curr_speed=900000, max_speed=1000000)
        pp2 = ofconfig.PhyPort(
            port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
            config=_create_port_config(no_recv=True, no_packet_in=True),
            state_link_down=False, state_blocked=False, state_live=True,
            curr=_create_port_features(mode_1gb_fd=True, fiber=True),
            advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                             pause=True),
            supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                            pause=True, pause_asym=True),
            peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       autoneg=True),
            curr_speed=900000, max_speed=1000000)
        sf = ofconfig.SwitchFeatures(
            datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
            cap_table_stats=False, cap_port_stats=True, cap_group_stats=False,
            cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
            ports=(pp1, pp2))
        self.assertEqual('\x00\x00\x00\x00\x00\x12\x34\x56'
                         '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                         '\x00\x00\x00\xa5' '\x00\x00\x00\x00'
                         + pp1.serialize()
                         + pp2.serialize(), ''.join(sf.serialize()))

    def test_serialize_every_capability_flag(self):
        for i in xrange(0, 7):
            flag = 1 << i
            # Bit 4 is reserved and not exposed in the structure.
            # Shift all bits to the left from bit 4.
            if i > 3:
                flag = flag << 1
            args = [False] * 6
            args.insert(i, True)
            args[0:0] = [0x123456, 5, 3]
            args.append(())
            sf = ofconfig.SwitchFeatures(*args)
            self.assertEqual('\x00\x00\x00\x00\x00\x12\x34\x56'
                             '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                             + struct.pack('!L', flag)
                             + '\x00\x00\x00\x00', ''.join(sf.serialize()))

    def test_serialize_deserialize_two_ports(self):
        pp1 = ofconfig.PhyPort(
            port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
            config=_create_port_config(no_recv=True, no_packet_in=True),
            state_link_down=False, state_blocked=False, state_live=True,
            curr=_create_port_features(mode_1gb_fd=True, fiber=True),
            advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                             pause=True),
            supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                            pause=True, pause_asym=True),
            peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       autoneg=True),
            curr_speed=900000, max_speed=1000000)
        pp2 = ofconfig.PhyPort(
            port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
            config=_create_port_config(no_recv=True, no_packet_in=True),
            state_link_down=False, state_blocked=False, state_live=True,
            curr=_create_port_features(mode_1gb_fd=True, fiber=True),
            advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                             pause=True),
            supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                            pause=True, pause_asym=True),
            peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       autoneg=True),
            curr_speed=900000, max_speed=1000000)
        sf = ofconfig.SwitchFeatures(
            datapath_id=0x123456, n_buffers=5, n_tables=3, cap_flow_stats=True,
            cap_table_stats=False, cap_port_stats=True, cap_group_stats=False,
            cap_ip_reasm=True, cap_queue_stats=False, cap_arp_match_ip=True,
            ports=(pp1, pp2))
        self.buf.append(''.join(sf.serialize()))
        self.buf.set_message_boundaries(24 + 64 * 2)
        self.assertTupleEqual(sf,
                              ofconfig.SwitchFeatures.deserialize(self.buf))

    def test_deserialize_two_ports(self):
        pp1 = ofconfig.PhyPort(
            port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc2', name='testport1',
            config=_create_port_config(no_recv=True, no_packet_in=True),
            state_link_down=False, state_blocked=False, state_live=True,
            curr=_create_port_features(mode_1gb_fd=True, fiber=True),
            advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                             pause=True),
            supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                            pause=True, pause_asym=True),
            peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       autoneg=True),
            curr_speed=900000, max_speed=1000000)
        pp2 = ofconfig.PhyPort(
            port_no=0x42, hw_addr='\xab\xcd\xef\xa0\xb1\xc3', name='testport2',
            config=_create_port_config(no_recv=True, no_packet_in=True),
            state_link_down=False, state_blocked=False, state_live=True,
            curr=_create_port_features(mode_1gb_fd=True, fiber=True),
            advertised=_create_port_features(mode_1gb_fd=True, fiber=True,
                                             pause=True),
            supported=_create_port_features(mode_1gb_fd=True, fiber=True,
                                            pause=True, pause_asym=True),
            peer=_create_port_features(mode_1gb_fd=True, fiber=True,
                                       autoneg=True),
            curr_speed=900000, max_speed=1000000)
        self.buf.append('\x00\x00\x00\x00\x00\x12\x34\x56'
                         '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                         '\x00\x00\x00\xa5' '\x00\x00\x00\x00')
        self.buf.append(pp1.serialize())
        self.buf.append(pp2.serialize())
        self.buf.set_message_boundaries(24 + 64 * 2)
        self.assertTupleEqual(
            (0x123456, 5, 3, True, False, True, False, True,
             False, True, (pp1, pp2)),
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
                             + struct.pack('!L', flag)
                             + '\x00\x00\x00\x00')
            self.buf.set_message_boundaries(24)
            args = [False] * 6
            args.insert(i, True)
            args[0:0] = [0x123456, 5, 3]
            args.append(())
            args = tuple(args)
            self.assertTupleEqual(
                args, ofconfig.SwitchFeatures.deserialize(self.buf))

    def test_deserialize_reserved_capability_flag_0x10(self):
        self.buf.append('\x00\x00\x00\x00\x00\x12\x34\x56'
                        '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                        '\x00\x00\x00\xb5' '\x00\x00\x00\x00')
        self.buf.set_message_boundaries(24)
        # The reserved bit at 0x00000010 is ignored.
        self.assertTupleEqual((0x123456, 5, 3, True, False, True, False, True,
                               False, True, ()),
                              ofconfig.SwitchFeatures.deserialize(self.buf))

    def test_deserialize_invalid_capability_flag_0x0100(self):
        self.buf.append('\x00\x00\x00\x00\x00\x12\x34\x56'
                        '\x00\x00\x00\x05' '\x03\x00\x00\x00'
                        '\x00\x00\x01\xa5' '\x00\x00\x00\x00')
        self.buf.set_message_boundaries(24)
        # The reserved bit at 0x00000100 is ignored.
        self.assertTupleEqual((0x123456, 5, 3, True, False, True, False, True,
                               False, True, ()),
                              ofconfig.SwitchFeatures.deserialize(self.buf))


class TestSwitchConfig(unittest2.TestCase):

    def setUp(self):
        self.buf = buffer.ReceiveBuffer()

    def test_create(self):
        sc = ofconfig.SwitchConfig(
            config_frag=ofconfig.OFPC_FRAG_DROP,
            config_invalid_ttl_to_controller=True, miss_send_len=128)

    def test_serialize(self):
        sc = ofconfig.SwitchConfig(
            config_frag=ofconfig.OFPC_FRAG_DROP,
            config_invalid_ttl_to_controller=True, miss_send_len=128)
        self.assertEqual('\x00\x05\x00\x80', sc.serialize())

    def test_serialize_every_config_frag(self):
        for config_frag in (ofconfig.OFPC_FRAG_NORMAL, ofconfig.OFPC_FRAG_DROP,
                            ofconfig.OFPC_FRAG_REASM):
            sc = ofconfig.SwitchConfig(
                config_frag=config_frag, config_invalid_ttl_to_controller=True,
                miss_send_len=128)
            self.assertEqual(
                struct.pack('!H', config_frag | 0x04) + '\x00\x80',
                sc.serialize())

    def test_serialize_deserialize(self):
        sc = ofconfig.SwitchConfig(
            config_frag=ofconfig.OFPC_FRAG_DROP,
            config_invalid_ttl_to_controller=True, miss_send_len=128)
        self.buf.append(sc.serialize())
        self.buf.set_message_boundaries(4)
        self.assertTupleEqual(sc, ofconfig.SwitchConfig.deserialize(self.buf))

    def test_deserialize(self):
        self.buf.append('\x00\x05\x00\x80')
        self.buf.set_message_boundaries(4)
        self.assertTupleEqual((ofconfig.OFPC_FRAG_DROP, True, 128),
                              ofconfig.SwitchConfig.deserialize(self.buf))

    def test_deserialize_every_config_frag(self):
        for config_frag in (ofconfig.OFPC_FRAG_NORMAL, ofconfig.OFPC_FRAG_DROP,
                            ofconfig.OFPC_FRAG_REASM):
            self.buf.append(struct.pack('!H', config_frag | 0x04) + '\x00\x80')
            self.buf.set_message_boundaries(4)
            self.assertTupleEqual((config_frag, True, 128),
                                  ofconfig.SwitchConfig.deserialize(self.buf))

    def test_deserialize_invalid_config_frag_0x0008(self):
        self.buf.append('\x00\x08\x00\x80')
        self.buf.set_message_boundaries(4)
        with self.assertRaises(ValueError):
            ofconfig.SwitchConfig.deserialize(self.buf)


if __name__ == '__main__':
    unittest2.main()
