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

"""Unittests for ofmatch.py.
"""

import struct
import unittest2

from openfaucet import buffer
from openfaucet import ofmatch


class TestMatch(unittest2.TestCase):

    def setUp(self):
        self.buf = buffer.ReceiveBuffer()

    def test_create(self):
        m = ofmatch.Match(
            in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
            dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
            dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
            nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
            tp_src=0x38, tp_dst=0x49)

    def test_create_wildcarded_no_attr(self):
        m = ofmatch.Match.create_wildcarded()
        self.assertTupleEqual(tuple([None] * 12), m)

    def test_create_wildcarded_every_attr(self):
        m_orig = ofmatch.Match(
            in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
            dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
            dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
            nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
            tp_src=0x38, tp_dst=0x49)
        for attr_name in ofmatch.Match._fields:
            attr_value = m_orig._asdict()[attr_name]
            m = ofmatch.Match.create_wildcarded(**{attr_name: attr_value})
            m_dict = {'in_port': None, 'dl_src': None, 'dl_dst': None,
                      'dl_vlan': None, 'dl_vlan_pcp': None, 'dl_type': None,
                      'nw_tos': None, 'nw_proto': None, 'nw_src': None,
                      'nw_dst': None, 'tp_src': None, 'tp_dst': None}
            m_dict[attr_name] = attr_value
            self.assertDictEqual(m_dict, m._asdict())

    def test_wildcards_no_attrs_wildcarded(self):
        m = ofmatch.Match(
            in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
            dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
            dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
            nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
            tp_src=0x38, tp_dst=0x49)
        self.assertEqual(0, m.wildcards.serialize())

    def test_wildcards_all_attrs_wildcarded(self):
        m = ofmatch.Match.create_wildcarded()
        self.assertEqual(0x3820ff, m.wildcards.serialize())

    def test_wildcards_every_lsb(self):
        m_orig = ofmatch.Match(
            in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
            dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
            dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
            nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
            tp_src=0x38, tp_dst=0x49)
        wildcard_bit = 1 << 0
        for attr_name in ('in_port', 'dl_vlan', 'dl_src', 'dl_dst', 'dl_type',
                          'nw_proto', 'tp_src', 'tp_dst'):
            attr_value = m_orig._asdict()[attr_name]
            m = ofmatch.Match.create_wildcarded(**{attr_name: attr_value})
            self.assertEqual(0x3820ff & ~wildcard_bit, m.wildcards.serialize())
            wildcard_bit = wildcard_bit << 1

    def test_wildcards_every_nw_src_prefix_length(self):
        m_orig = ofmatch.Match(
            in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
            dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
            dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
            nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
            tp_src=0x38, tp_dst=0x49)
        for i in xrange(1, 33):
            m = m_orig._replace(nw_src=('\xaa\xbb\xcc\xdd', i))
            wildcards = (32 - i) << 8
            self.assertEqual(wildcards, m.wildcards.serialize())

    def test_wildcards_every_nw_dst_prefix_length(self):
        m_orig = ofmatch.Match(
            in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
            dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
            dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
            nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
            tp_src=0x38, tp_dst=0x49)
        for i in xrange(1, 33):
            m = m_orig._replace(nw_dst=('\x21\x32\x43\x54', i))
            wildcards = (32 - i) << 14
            self.assertEqual(wildcards, m.wildcards.serialize())

    def test_wildcards_every_msb(self):
        m_orig = ofmatch.Match(
            in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
            dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
            dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
            nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
            tp_src=0x38, tp_dst=0x49)
        wildcard_bit = 1 << 20
        for attr_name in ('dl_vlan_pcp', 'nw_tos'):
            attr_value = m_orig._asdict()[attr_name]
            m = ofmatch.Match.create_wildcarded(**{attr_name: attr_value})
            self.assertEqual(0x3820ff & ~wildcard_bit, m.wildcards.serialize())
            wildcard_bit = wildcard_bit << 1

    def test_serialize_no_attrs_wildcarded(self):
        m = ofmatch.Match(
            in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
            dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
            dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
            nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
            tp_src=0x38, tp_dst=0x49)
        self.assertEqual(
            '\x00\x00\x00\x00' '\x00\x13' '\x13\x24\x35\x46\x57\x68'
            '\x12\x23\x34\x45\x56\x67' '\x00\x11' '\x22\x00' '\x33\x44'
            '\x80\xcc\x00\x00' '\xaa\xbb\xcc\xdd' '\x21\x32\x43\x54'
            '\x00\x38\x00\x49', m.serialize())

    def test_serialize_all_attrs_wildcarded(self):
        m = ofmatch.Match.create_wildcarded()
        self.assertEqual('\x00\x38\x20\xff' + '\x00' * 36, m.serialize())

    def test_serialize_deserialize_no_attrs_wildcarded(self):
        m = ofmatch.Match(
            in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
            dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
            dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
            nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
            tp_src=0x38, tp_dst=0x49)
        self.buf.append(m.serialize())
        self.buf.set_message_boundaries(40)
        self.assertTupleEqual(m, ofmatch.Match.deserialize(self.buf))

    def test_serialize_deserialize_no_attrs_wildcarded(self):
        m = ofmatch.Match.create_wildcarded()
        self.buf.append(m.serialize())
        self.buf.set_message_boundaries(40)
        self.assertTupleEqual(m, ofmatch.Match.deserialize(self.buf))

    def test_serialize_deserialize_wildcards_every_lsb(self):
        m_orig = ofmatch.Match(
            in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
            dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
            dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
            nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
            tp_src=0x38, tp_dst=0x49)
        for attr_name in ('in_port', 'dl_vlan', 'dl_src', 'dl_dst', 'dl_type',
                          'nw_proto', 'tp_src', 'tp_dst'):
            attr_value = m_orig._asdict()[attr_name]
            m = ofmatch.Match.create_wildcarded(**{attr_name: attr_value})
            self.buf.append(m.serialize())
            self.buf.set_message_boundaries(40)
            self.assertTupleEqual(m, ofmatch.Match.deserialize(self.buf))

    def test_serialize_deserialize_wildcards_every_nw_src_prefix_length(self):
        m_orig = ofmatch.Match(
            in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
            dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
            dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
            nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
            tp_src=0x38, tp_dst=0x49)
        for i in xrange(1, 33):
            m = m_orig._replace(nw_src=('\xaa\xbb\xcc\xdd', i))
            self.buf.append(m.serialize())
            self.buf.set_message_boundaries(40)
            self.assertTupleEqual(m, ofmatch.Match.deserialize(self.buf))

    def test_serialize_deserialize_wildcards_every_nw_dst_prefix_length(self):
        m_orig = ofmatch.Match(
            in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
            dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
            dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
            nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
            tp_src=0x38, tp_dst=0x49)
        for i in xrange(1, 33):
            m = m_orig._replace(nw_dst=('\x21\x32\x43\x54', i))
            self.buf.append(m.serialize())
            self.buf.set_message_boundaries(40)
            self.assertTupleEqual(m, ofmatch.Match.deserialize(self.buf))

    def test_serialize_deserialize_wildcards_every_msb(self):
        m_orig = ofmatch.Match(
            in_port=0x13, dl_src='\x13\x24\x35\x46\x57\x68',
            dl_dst='\x12\x23\x34\x45\x56\x67', dl_vlan=0x11, dl_vlan_pcp=0x22,
            dl_type=0x3344, nw_tos=0x80, nw_proto=0xcc,
            nw_src=('\xaa\xbb\xcc\xdd', 32), nw_dst=('\x21\x32\x43\x54', 32),
            tp_src=0x38, tp_dst=0x49)
        for attr_name in ('dl_vlan_pcp', 'nw_tos'):
            attr_value = m_orig._asdict()[attr_name]
            m = ofmatch.Match.create_wildcarded(**{attr_name: attr_value})
            self.buf.append(m.serialize())
            self.buf.set_message_boundaries(40)
            self.assertTupleEqual(m, ofmatch.Match.deserialize(self.buf))


if __name__ == '__main__':
    unittest2.main()
