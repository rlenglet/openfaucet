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

"""Representations and encoding/decoding of OpenFlow 1.0.0 flow matches.
"""

import collections
import struct


# Flow match wildcard flags.
OFPFW_IN_PORT = 1 << 0
OFPFW_DL_VLAN = 1 << 1
OFPFW_DL_SRC = 1 << 2
OFPFW_DL_DST = 1 << 3
OFPFW_DL_TYPE = 1 << 4
OFPFW_NW_PROTO = 1 << 5
OFPFW_TP_SRC = 1 << 6
OFPFW_TP_DST = 1 << 7
OFPFW_NW_SRC_SHIFT = 8
OFPFW_NW_SRC_BITS = 6
OFPFW_NW_SRC_MASK = ((1 << OFPFW_NW_SRC_BITS) - 1) << OFPFW_NW_SRC_SHIFT
OFPFW_NW_SRC_ALL = 32 << OFPFW_NW_SRC_SHIFT
OFPFW_NW_DST_SHIFT = 14
OFPFW_NW_DST_BITS = 6
OFPFW_NW_DST_MASK = ((1 << OFPFW_NW_DST_BITS) - 1) << OFPFW_NW_DST_SHIFT
OFPFW_NW_DST_ALL = 32 << OFPFW_NW_DST_SHIFT
OFPFW_DL_VLAN_PCP = 1 << 20
OFPFW_NW_TOS = 1 << 21
OFPFW_ALL = ((1 << 22) - 1)


class Wildcards(collections.namedtuple('Wildcards', (
    'in_port', 'dl_src', 'dl_dst', 'dl_vlan', 'dl_vlan_pcp', 'dl_type',
    'nw_tos', 'nw_proto', 'nw_src', 'nw_dst', 'tp_src', 'tp_dst'))):
    """The description of wildcarded attributes in an OpenFlow flow entry.

    All attributes (except nw_src and nw_dst) are booleans, and have
    the same names and indexes as the attributes in class Match. If an
    attribute is True, the corresponding attribute in a Match is
    wildcarded, otherwise the Match attribute is exactly matched.

    nw_src and nw_dst are integers indicating how many bits are
    wildcarded from Match's nw_src and nw_dst attributes.
    """

    def serialize(self):
        """Serialize this object into a 32-bit unsigned integer.

        The returned integer can be passed to deserialize() to
        recreate a copy of this object.

        Returns:
            A 32-bit unsigned integer that is a serialized form of
            this object.
        """
        wildcard_bits = ((OFPFW_IN_PORT if self.in_port else 0)
                         | (OFPFW_DL_VLAN if self.dl_vlan else 0)
                         | (OFPFW_DL_SRC if self.dl_src else 0)
                         | (OFPFW_DL_DST if self.dl_dst else 0)
                         | (OFPFW_DL_TYPE if self.dl_type else 0)
                         | (OFPFW_NW_PROTO if self.nw_proto else 0)
                         | (OFPFW_TP_SRC if self.tp_src else 0)
                         | (OFPFW_TP_DST if self.tp_dst else 0)
                         | (OFPFW_DL_VLAN_PCP if self.dl_vlan_pcp else 0)
                         | (OFPFW_NW_TOS if self.nw_tos else 0))

        if self.nw_src < 0 or self.nw_src > 32:
            raise ValueError('invalid nw_src', self.nw_src)
        wildcard_bits |= self.nw_src << OFPFW_NW_SRC_SHIFT

        if self.nw_dst < 0 or self.nw_dst > 32:
            raise ValueError('invalid nw_dst', self.nw_dst)
        wildcard_bits |= self.nw_dst << OFPFW_NW_DST_SHIFT

        return wildcard_bits

    @classmethod
    def deserialize(cls, v):
        """Returns a Wildcards object deserialized from an integer.

        Args:
            v: A 32-bit unsigned integer that is a serialized form of
                a Wildcards object.

        Returns:
            A new Wildcards object deserialized from the integer.
        """
        # Be liberal. Ignore undefined wildcards bits that are set.
        nw_src = (v & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT
        nw_dst = (v & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT
        return Wildcards(bool(v & OFPFW_IN_PORT),
                         bool(v & OFPFW_DL_SRC),
                         bool(v & OFPFW_DL_DST),
                         bool(v & OFPFW_DL_VLAN),
                         bool(v & OFPFW_DL_VLAN_PCP),
                         bool(v & OFPFW_DL_TYPE),
                         bool(v & OFPFW_NW_TOS),
                         bool(v & OFPFW_NW_PROTO),
                         nw_src,
                         nw_dst,
                         bool(v & OFPFW_TP_SRC),
                         bool(v & OFPFW_TP_DST))


class Match(collections.namedtuple('Match', (
    'in_port', 'dl_src', 'dl_dst', 'dl_vlan', 'dl_vlan_pcp', 'dl_type',
    'nw_tos', 'nw_proto', 'nw_src', 'nw_dst', 'tp_src', 'tp_dst'))):
    """The description of an OpenFlow flow entry.

    Any attribute set to None is considered wildcarded.

    The attributes of a flow entry are:
        in_port: The input port, as a 16-bit unsigned integer.
        dl_src: The MAC source address, as a binary string.
        dl_dst: The MAC destination address, as a binary string.
        dl_vlan: The input VLAN ID, as a 16-bit unsigned integer.
        dl_vlan_pcp: The input VLAN priority, as a 8-bit unsigned integer.
        dl_type: The Ethernet frame type, as a 16-bit unsigned integer.
        nw_tos: The IP ToS (only the DSCP field's 6 bits), as an 8-bit
            unsigned integer.
        nw_proto: The IP protocol, or the lower 8 bits of the ARP opcode, as an
            8-bit unsigned integer.
        nw_src: The IP source address, as a tuple (address,
            prefix_length), where address is the address as a binary
            string, and prefix_length is the number of bits to match in
            the address. prefix_length must be > 0.
        nw_dst: The IP destination address, as a tuple (address,
            prefix_length), where address is the address as a binary
            string, and prefix_length is the number of bits to match in
            the address. prefix_length must be > 0.
        tp_src: The TCP/UDP source port, as a 16-bit unsigned integer.
        tp_dst: The TCP/UDP destination port, as a 16-bit unsigned integer.
    """

    FORMAT = '!LH6s6sHBxHBB2x4s4sHH'

    FORMAT_LENGTH = struct.calcsize(FORMAT)

    @classmethod
    def create_wildcarded(cls, in_port=None, dl_src=None, dl_dst=None,
                          dl_vlan=None, dl_vlan_pcp=None, dl_type=None,
                          nw_tos=None, nw_proto=None, nw_src=None, nw_dst=None,
                          tp_src=None, tp_dst=None):
        """Create a new Match with flow attributes wildcarded unless specified.

        Returns:
            A new Match object whose attributes are set to the given
            values, or None (i.e. wildcarded) if not specified.
        """
        return Match(in_port=in_port, dl_src=dl_src, dl_dst=dl_dst,
                     dl_vlan=dl_vlan, dl_vlan_pcp=dl_vlan_pcp, dl_type=dl_type,
                     nw_tos=nw_tos, nw_proto=nw_proto, nw_src=nw_src,
                     nw_dst=nw_dst, tp_src=tp_src, tp_dst=tp_dst)

    @property
    def wildcards(self):
        """Create a Wildcards object representing the wildcards of this flow.

        Any attribute set to None is considered to be wildcarded.

        Returns:
            A new Wildcards object.
        """
        if self.nw_src is None:
            wild_nw_src = 32
        else:
            _, prefix_length = self.nw_src
            if prefix_length < 1 or prefix_length > 32:
                raise ValueError('invalid nw_src prefix_length', prefix_length)
            wild_nw_src = 32 - prefix_length

        if self.nw_dst is None:
            wild_nw_dst = 32
        else:
            _, prefix_length = self.nw_dst
            if prefix_length < 1 or prefix_length > 32:
                raise ValueError('invalid nw_dst prefix_length', prefix_length)
            wild_nw_dst = 32 - prefix_length

        return Wildcards(in_port=self.in_port is None,
                         dl_src=self.dl_src is None,
                         dl_dst=self.dl_dst is None,
                         dl_vlan=self.dl_vlan is None,
                         dl_vlan_pcp=self.dl_vlan_pcp is None,
                         dl_type=self.dl_type is None,
                         nw_tos=self.nw_tos is None,
                         nw_proto=self.nw_proto is None,
                         nw_src=wild_nw_src,
                         nw_dst=wild_nw_dst,
                         tp_src=self.tp_src is None,
                         tp_dst=self.tp_dst is None)

    def serialize(self):
        """Serialize this object into an OpenFlow ofp_match.

        The returned string can be passed to deserialize() to recreate
        a copy of this object.

        Returns:
            A binary string that is a serialized form of this object
            into an OpenFlow ofp_match.
        """
        return struct.pack(
            self.FORMAT, self.wildcards.serialize(),
            self.in_port if self.in_port is not None else 0,
            self.dl_src if self.dl_src is not None else '',
            self.dl_dst if self.dl_dst is not None else '',
            self.dl_vlan if self.dl_vlan is not None else 0,
            self.dl_vlan_pcp if self.dl_vlan_pcp is not None else 0,
            self.dl_type if self.dl_type is not None else 0,
            self.nw_tos & 0xfc if self.nw_tos is not None else 0,
            self.nw_proto if self.nw_proto is not None else 0,
            self.nw_src[0] if self.nw_src is not None else '',
            self.nw_dst[0] if self.nw_dst is not None else '',
            self.tp_src if self.tp_src is not None else 0,
            self.tp_dst if self.tp_dst is not None else 0)

    @classmethod
    def deserialize(cls, buf):
        """Returns a Match object deserialized from a sequence of bytes.

        Args:
            buf: A ReceiveBuffer object that contains the bytes that
                are the serialized form of the Match object.

        Returns:
            A new Match object deserialized from the buffer.

        Raises:
            ValueError: The buffer has an invalid number of available
                bytes, or some elements cannot be deserialized.
        """
        (wildcards_ser, in_port, dl_src, dl_dst, dl_vlan, dl_vlan_pcp, dl_type,
         nw_tos, nw_proto, nw_src, nw_dst, tp_src, tp_dst) = buf.unpack(
            cls.FORMAT)

        wildcards = Wildcards.deserialize(wildcards_ser)

        # In OpenFlow 1.0.0, the "nw_tos" field doesn't contain the
        # whole IP TOS field, only the 6 bits of the DSCP field in
        # mask 0xfc. The 2 LSBs don't have any meaning and must be
        # ignored.
        if nw_tos & 0x03:
            # Be liberal. Zero out those bits instead of raising an
            # exception.
            # TODO(romain): Log this.
            # ('unused lower bits in nw_tos are set', nw_tos)
            nw_tos &= 0xfc

        nw_src_prefix_length = 32 - wildcards.nw_src
        nw_dst_prefix_length = 32 - wildcards.nw_dst
        return Match(
            None if wildcards.in_port else in_port,
            None if wildcards.dl_src else dl_src,
            None if wildcards.dl_dst else dl_dst,
            None if wildcards.dl_vlan else dl_vlan,
            None if wildcards.dl_vlan_pcp else dl_vlan_pcp,
            None if wildcards.dl_type else dl_type,
            None if wildcards.nw_tos else nw_tos,
            None if wildcards.nw_proto else nw_proto,
            (nw_src, nw_src_prefix_length) if nw_src_prefix_length > 0
                                           else None,
            (nw_dst, nw_dst_prefix_length) if nw_dst_prefix_length > 0
                                           else None,
            None if wildcards.tp_src else tp_src,
            None if wildcards.tp_dst else tp_dst)
