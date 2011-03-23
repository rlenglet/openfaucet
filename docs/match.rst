.. Copyright 2011 Midokura KK
..
.. Licensed under the Apache License, Version 2.0 (the "License");
.. you may not use this file except in compliance with the License.
.. You may obtain a copy of the License at
..
..     http://www.apache.org/licenses/LICENSE-2.0
..
.. Unless required by applicable law or agreed to in writing, software
.. distributed under the License is distributed on an "AS IS" BASIS,
.. WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
.. See the License for the specific language governing permissions and
.. limitations under the License.

OpenFlow flow matching
======================

.. currentmodule:: openfaucet.ofmatch

Each datapath flow entry is primarily defined by a
:class:`~openfaucet.ofmatch.Match` object which specifies which
packets are part of the flow, as a set of packet fields to match and
their expected values. The OpenFlow standard specifies the set of
packet fields that can be matched, at Layer-2 (Ethernet), Layer-3 (IP,
ARP), and Layer-4 (ICMP, TCP, UDP).

:class:`~openfaucet.ofmatch.Match` is a named tuple class
(cf. Python's :mod:`collections`), i.e. matches are also tuples whose
elements each correspond to an attribute. To create a match, its
attributes can be given in positional order, or using keywords, i.e.::

  from openfaucet import ofmatch
  match = ofmatch.Match(
      in_port=12, dl_src=None, dl_dst=None, dl_vlan=11423, dl_vlan_pcp=None,
      dl_type=0x800, nw_tos=0, nw_proto=None, nw_src=None, nw_dst=None,
      tp_src=None, tp_dst=None)

is equivalent to::

  from openfaucet import ofmatch
  match = ofmatch.Match(12, None, None, 11423, None, 0x800, 0, None, None,
                        None, None, None)

Likewise, attributes can be accessed by position or by name, i.e.::

  dl_src = match[1]

is equivalent to::

  dl_src = match.dl_src

Attribute access by name is recommended for readability. Every match,
just like any tuple, is immutable and hashable. A copy of an existing
match with some of its attributes modified can be created by calling
:meth:`_replace`, for instance::

  new_match = match._replace(in_port=None, tp_dst=80)

Any attribute can be wildcarded, to ignore that field in matching
packets. For instance, if all attributes are wildcarded, all packets
match the flow. All attributes can be wildcarded by setting their
value to ``None``. In addition,
:attr:`~openfaucet.ofmatch.Match.nw_src` and
:attr:`~openfaucet.ofmatch.Match.nw_dst` can be partly wildcarded, to
match only prefixes of IPv4 addresses instead of full
addresses. :meth:`~openfaucet.ofmatch.Match.create_wildcarded` is a
helper method to create wildcarded matches::

  from openfaucet import ofmatch
  match = ofmatch.Match.create_wildcarded(in_port=12, tp_dst=80)

is equivalent to::

  from openfaucet import ofmatch
  match = ofmatch.Match(12, None, None, None, None, None, None, None, None,
                        None, None, 80)

.. class:: Match

  Datapath input port:

  .. attribute:: in_port

    The input port, as a 16-bit unsigned integer. E.g. to match all
    packets coming into port 12::

      from openfaucet import ofmatch
      match = ofmatch.Match.create_wildcarded(in_port=12)

  Layer-2 header (Ethernet):

  .. attribute:: dl_src

    The MAC source address, as a binary string. E.g. to match all
    packets from MAC address ``02:12:34:56:78:90``::

      from openfaucet import ofmatch
      match = ofmatch.Match.create_wildcarded(
          dl_src='\x02\x12\x34\x56\x78\x90')

  .. attribute:: dl_dst

    The MAC destination address, as a binary string. E.g. to match all
    broadcast packets::

      from openfaucet import ofmatch
      match = ofmatch.Match.create_wildcarded(
          dl_src='\xff\xff\xff\xff\xff\xff')

  .. attribute:: dl_vlan

    The input VLAN ID, as a 16-bit unsigned integer. E.g. to match all
    packets in VLAN with ID 123::

      from openfaucet import ofmatch
      match = ofmatch.Match.create_wildcarded(dl_vlan=123)

  .. attribute:: dl_vlan_pcp

    The input VLAN priority, as a 8-bit unsigned integer.

  .. attribute:: dl_type

    The Ethernet frame type, as a 16-bit unsigned integer. E.g. to
    match all IPv6 packets::

      from openfaucet import ofmatch
      match = ofmatch.Match.create_wildcarded(dl_type=0x86dd)

  Layer-3 header (IPv4 and ARP):  

  .. attribute:: nw_tos

    The IP ToS (only the DSCP field's 6 bits), as an 8-bit unsigned
    integer. Bits 0 and 1 are reserved and must be set to 0. E.g. to
    match all IPv4 packets in the Expedited Forwarding class (DSCP
    field value ``0x2e``)::

      from openfaucet import ofmatch
      match = ofmatch.Match.create_wildcarded(
          dl_type=0x0800, nw_tos=(0x2e << 2))

  .. attribute:: nw_proto

    If the L3 protocol is IPv4, the IP protocol, or if the L3 protocol
    is ARP, the lower 8 bits of the ARP opcode, as an 8-bit unsigned
    integer. E.g. to match all TCPv4 packets::

      from openfaucet import ofmatch
      match = ofmatch.Match.create_wildcarded(
          dl_type=0x0800, nw_proto=6)

  .. attribute:: nw_src

    The IPv4 source address, as a tuple (address, prefix_length),
    where address is the address as a binary string, and prefix_length
    is the number of bits to match in the address. prefix_length must
    be > 0. E.g. to match all IPv4 packets with sources address in
    CIDR prefix ``192.168.1.0/24``::

      import socket
      from openfaucet import ofmatch
      ip_addr = socket.inet_pton(socket.AF_INET, '192.168.1.0')
      match = ofmatch.Match.create_wildcarded(
          dl_type=0x0800, nw_src=(ip_addr, 24))

  .. attribute:: nw_dst

    The IPv4 destination address, as a tuple (address, prefix_length),
    where address is the address as a binary string, and prefix_length
    is the number of bits to match in the address. prefix_length must
    be > 0.

  Layer-4 header (TCPv4 and UDPv4):  

  .. attribute:: tp_src

    The TCP/UDP source port, as a 16-bit unsigned integer.

  .. attribute:: tp_dst

    The TCP/UDP destination port, as a 16-bit unsigned
    integer. E.g. to match all TCPv4 packets to port 80 (WWW)::

      from openfaucet import ofmatch
      match = ofmatch.Match.create_wildcarded(
          dl_type=0x0800, nw_proto=6, tp_dst=80)

  Utility methods:

  .. classmethod:: create_wildcarded([in_port=None, dl_src=None, dl_dst=None, dl_vlan=None, dl_vlan_pcp=None, dl_type=None, nw_tos=None, nw_proto=None, nw_src=None, nw_dst=None, tp_src=None, tp_dst=None])

    Create a new :class:`Match` with flow attributes wildcarded unless
    specified.

    :returns: A new :class:`Match` object whose attributes are set to
      the given values, or ``None`` (i.e. wildcarded) if not
      specified.
