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

OpenFlow actions
================

.. currentmodule:: openfaucet.ofaction

Flows are defined by an OpenFlow controller by sending
``OFPT_FLOW_MOD`` messages to the datapath, by calling method
:meth:`~openfaucet.ofcontroller.IOpenflowControllerStub.send_flow_mod`
on the controller stub. A flow definition includes the actions to
perform on the packet in the flow. Every action is represented by an
object that is an instance of a class implementing the
:class:`~openfaucet.ofaction.IAction` interface:

.. class:: openfaucet.ofaction.IAction

  .. attribute:: type

    The type of the action, as one of ``OFPAT_`` integer constants.

  .. attribute:: format_length

    The length of the data in the encoded action. This length doesn't
    count the ``ofp_action_header`` information.

  .. method:: serialize()

    Serialize this action object into a binary string that is a
    serialized form of this action object into an OpenFlow action. The
    ``ofp_action_header`` structure is not included in the generated
    strings.

    The returned string can be passed to :meth:`deserialize` to
    recreate a copy of this action object.

  .. classmethod:: deserialize(buf)

    Returns an action object deserialized from a sequence of bytes.

    :param buf: A :class:`~openfaucet.buffer.ReceiveBuffer` object
      that contains the bytes that are the serialized form of the
      action, after the ``ofp_action_header`` structure.

    :raises: :class:`ValueError` if the buffer has an invalid number
      of available bytes, or if some elements cannot be deserialized.

The following action classes implement that interface and can be used
to encode and decode standard OpenFlow actions. All these classes are
named tuple classes (cf. Python's :mod:`collections`), i.e. action
objects are also tuples which elements each correspond to an
attribute. To create an action object, its attributes can be given in
positional order, or using keywords, i.e.::

  from openfaucet import ofaction
  action = ofaction.ActionOutput(12, 128)

is equivalent to::

  from openfaucet import ofaction
  action = ofaction.ActionOutput(port=12, max_len=128)

Likewise, attributes can be accessed by position or by name, i.e.::

  port = action[0]

is equivalent to::

  port = action.port

Attribute access by name is recommended for readability. Every action
object, just like any tuple, is immutable and hashable. A copy of an
existing action object with some of its attributes modified can be
created by calling :meth:`_replace`, for instance::

 new_action = action._replace(port=42)

.. rubric:: Output and QoS

Packets can be output to physical ports, which have port numbers 1 to
:const:`~openfaucet.ofproto.OFPP_MAX`:

.. data:: openfaucet.ofproto.OFPP_MAX

  The maximum number of physical ports in a datapath.

In addition to physical ports, several logical ports are defined:

.. data:: openfaucet.ofproto.OFPP_IN_PORT

  The input port, i.e. the packet was received on. This virtual port
  must be explicitly used in order to send back out of the input port.

.. data:: openfaucet.ofproto.OFPP_TABLE

  Perform actions in the flow table on the packet. This can be the
  destination port only for ``OFPT_PACKET_OUT`` messages, as sent
  using
  :meth:`~openfaucet.ofcontroller.IOpenflowControllerStub.send_packet_out`.

.. data:: openfaucet.ofproto.OFPP_NORMAL

  Process with normal L2/L3 switching performed by the datapath.

.. data:: openfaucet.ofproto.OFPP_FLOOD

  All physical ports, except the input port and those disabled by
  Spanning Tree Protocol.

.. data:: openfaucet.ofproto.OFPP_ALL

  All physical ports except the input port.

.. data:: openfaucet.ofproto.OFPP_CONTROLLER

  Send to the controller, in an ``OFPT_PACKET_IN``, as received by a
  controller in the
  :meth:`~openfaucet.ofcontroller.IOpenflowController.handle_packet_in`
  callback.

.. data:: openfaucet.ofproto.OFPP_LOCAL

  The local OpenFlow virtual port used for in-band control traffic.

.. data:: openfaucet.ofproto.OFPP_NONE

  Not associated with any port.

The following actions output packets to ports directly or to queues
associated with specific ports.

.. class:: ActionOutput

  An ``OFPAT_OUTPUT`` action, which sends packets out a given port.

  .. attribute:: port

    The output port number, either a physical port number or a logical
    port number (e.g. :const:`~openfaucet.ofproto.OFPP_CONTROLLER`,
    :const:`~openfaucet.ofproto.OFPP_FLOOD`, etc.).

  .. attribute:: max_len

    When the ``port`` is :const:`~openfaucet.ofproto.OFPP_CONTROLLER`,
    indicates the maximum number of bytes to send, otherwise it is
    ignored. A value of zero means no bytes of the packet should be
    sent.

For instance, to flood packets::

  from openfaucet import ofaction, ofproto
  action = ofaction.ActionOutput(ofproto.OFPP_FLOOD, 0)

.. class:: ActionEnqueue

  An ``OFPAT_ENQUEUE`` action, which sends packets out a given queue.

  .. attribute:: port

    The number of the output port the queue belongs to. Should be a
    valid physical port (number <
    :const:`~openfaucet.ofproto.OFPP_MAX`), or
    :const:`~openfaucet.ofproto.OFPP_IN_PORT` to send each packet out
    the port it came in.

  .. attribute:: queue_id

    The queue ID, as a 32-bit unsigned integer.

.. class:: ActionSetNwTos

  An ``OFPAT_SET_NW_TOS`` action, which sets the IPv4 ToS DSCP of
  packets. This action is applied only to IPv4 packets.

  .. attribute:: nw_tos

    The IPv4 ToS field to set in packets, as an 8-bit unsigned
    integer. Only the 6 most significant bits (bits 2-7) may be set to
    1, corresponding to the DSCP field. All other bits must be set to
    0.

.. rubric:: 802.1q VLAN

The following actions encapsulate / decapsulate packets into 802.1q
VLAN headers.

.. class:: ActionSetVlanVid

  An ``OFPAT_SET_VLAN_VID`` action, which sets the 802.1q VLAN ID of
  packets.

  .. attribute:: vlan_vid

    The 802.1q VLAN ID to set in packets.

.. class:: ActionSetVlanPcp

  An ``OFPAT_SET_VLAN_PCP`` action, which sets the 802.1q VLAN
  priority of packets.

  .. attribute:: vlan_pcp

    The VLAN 802.1q priority to set in packets, as an 8-bit unsigned
    integer. Only the 3 least significant bits may be set to 1. All
    other bits must be set to 0.

.. class:: ActionStripVlan

  An ``OFPAT_STRIP_VLAN`` action, which strips the 802.1q header from
  packets. This action has no attribute.

.. rubric:: Address rewriting

The following actions rewrite the packets' source and destination
addresses and ports, at the Ethernet, IPv4, and TCP/UDP levels.

.. class:: ActionSetDlSrc

  An ``OFPAT_SET_DL_SRC`` action, which sets the Ethernet source
  address of packets.

  .. attribute:: dl_addr

    The Ethernet source address, as a binary string.

.. class:: ActionSetDlDst

  An ``OFPAT_SET_DL_DST`` action, which sets the Ethernet destination
  address of packets.

  .. attribute:: dl_addr

    The Ethernet destination address, as a binary string.

For instance, to create an action that sets the Ethernet destination
address to ``ab:cd:ef:01:23:45``::

  from openfaucet import ofaction
  action = ofaction.ActionSetDlDst('\xab\xcd\xef\x01\x23\x45')

.. class:: ActionSetNwSrc

  An ``OFPAT_SET_NW_SRC`` action, which sets the IPv4 source address
  of packets. This action is applied only to IPv4 packets.

  .. attribute:: nw_addr

    The IPv4 source address, as a binary string.

.. class:: ActionSetNwDst

  An ``OFPAT_SET_NW_DST`` action, which sets the IPv4 destination
  address of packets. This action is applied only to IPv4 packets.

  .. attribute:: nw_addr

    The IPv4 destination address, as a binary string.

For instance, to redirect all packets to address ``192.168.0.1``::

  import socket
  from openfaucet import ofaction
  nw_addr = socket.inet_pton(socket.AF_INET, '192.168.0.1')
  action = ofaction.ActionSetNwDst(nw_addr)

.. class:: ActionSetTpSrc

  An ``OFPAT_SET_TP_SRC`` action, which sets the TCP or UDP source
  port of packets. This action is applied only to IPv4 TCP or UDP
  packets.

  .. attribute:: tp_port

    The TCP or UDP source port, as a 16-bit unsigned integer.

.. class:: ActionSetTpDst

  An ``OFPAT_SET_TP_DST`` action, which sets the TCP or UDP
  destination port of packets. This action is applied only to IPv4 TCP
  or UDP packets.

  .. attribute:: tp_port

    The TCP or UDP destination port, as a 16-bit unsigned integer.

For instance, to redirect all packets to port ``8080``::

  from openfaucet import ofaction
  action = ofaction.ActionSetTpDst(8080)

.. TODO(romain): Document how to use / develop vendor actions.
