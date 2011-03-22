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

OpenFlow switch configuration
=============================

.. currentmodule:: openfaucet.ofconfig

The status and configuration of an OpenFlow datapath and its parts
(ports, queues) is represented by instances of the classes below. All
these classes are named tuple classes (cf. Python's
:mod:`collections`), i.e. configuration objects are also tuples whose
elements each correspond to an attribute. To create a configuration
object, its attributes can be given in positional order, or using
keywords, i.e.::

  from openfaucet import ofconfig
  port_config = ofconfig.PortConfig(
      port_down=False, no_stp=True, no_recv=True, no_recv_stp=True,
      no_flood=False, no_fwd=False, no_packet_in=False)

is equivalent to::

  from openfaucet import ofconfig
  port_config = ofconfig.PortConfig(False, True, True, True, False,
                                    False, False)

Likewise, attributes can be accessed by position or by name, i.e.::

  no_stp = port_config[1]

is equivalent to::

  no_stp = port_config.no_stp

Attribute access by name is recommended for readability. Every
configuration object, just like any tuple, is immutable and
hashable. A copy of an existing configuration object with some of its
attributes modified can be created by calling :meth:`_replace`, for
instance::

  new_port_config = port_config._replace(port_down=True, no_packet_in=True)

.. rubric:: Datapath configuration

.. class:: SwitchFeatures

  Describes the features of a datapath.

  .. TODO(romain): Link to the method / attribute that allows
  .. retrieving that.

  .. attribute:: datapath_id

    The datapath's unique ID, as a binary string.

  .. attribute::  n_buffers

    The maximum number of buffers that can be used at once, each to
    buffer a packet.

  .. attribute:: n_tables

    The number of tables supported by the datapath.

  cap_*: Boolean flags indicating each the support of not of a capability:

  .. attribute:: cap_flow_stats

    A boolean flag which if True indicates that flow statistics are
    supported by the datapath.

    .. TODO(romain): Link to corresponding methods in
    .. IOpenflowControllerStub.

  .. attribute:: cap_table_stats

    A boolean flag which if True indicates that table statistics are
    supported by the datapath.

  .. attribute:: cap_port_stats

    A boolean flag which if True indicates that port statistics are
    supported by the datapath.

  .. attribute:: cap_stp

    A boolean flag which if True indicates that the 802.1d Spanning
    Tree Protocol is supported by the datapath.

  .. attribute:: cap_ip_reasm

    A boolean flag which if True indicates that the datapath can
    reassemble IP fragments.

  .. attribute:: cap_queue_stats

    A boolean flag which if True indicates that queue statistics are
    supported by the datapath.

  .. attribute:: cap_arp_match_ip

    A boolean flag which if True indicates that the datapath can match
    IP addresses in ARP packets.

  .. attribute:: actions

    The :class:`frozenset` of standard action type codes that is
    supported by the switch. See :mod:`~openfaucet.ofaction` for the
    list of standard action types.

  .. attribute:: ports

    A tuple of :class:`~openfaucet.ofconfig.PhyPort` objects defining
    the physical ports of the switch.

.. class:: SwitchConfig

  The configuration of an OpenFlow switch.

  .. TODO(romain): Document how to modify that configuration.

  .. attribute:: config_frag

    Indicates how IP fragments should be treated, either
    :const:`~openfaucet.ofconfig.OFPC_FRAG_NORMAL` (no special
    handling for fragments),
    :const:`~openfaucet.ofconfig.OFPC_FRAG_DROP` (drop fragments), or
    :const:`~openfaucet.ofconfig.OFPC_FRAG_REASM` (reassemble, only if
    supported,
    cf. :attr:`~openfaucet.ofconfig.SwitchFeatures.cap_ip_reasm`).

  .. attribute:: miss_send_len

    The maximum number of bytes of new flow packets that the datapath
    should send to the controller in ``OFPT_PACKET_IN`` messages.

.. rubric:: Port configuration

.. class:: PhyPort

  The description of a physical port of an OpenFlow switch.

  .. TODO(romain): Document which attributes can be modified.

  .. attribute:: port_no

    The port's unique number, as a 16-bit unsigned integer. Must be
    between 1 and :const:`~openfaucet.ofaction.OFPP_MAX`.

  .. attribute:: hw_addr

    The port's MAC address, as a binary string.

  .. attribute:: name

    The port's human-readable name, limited to 16 characters.

  .. attribute:: config

    A :class:`~openfaucet.ofconfig.PortConfig` object indicating the
    configuration of the port.

  .. attribute:: state_link_down

    A boolean value indicating that no physical link is present.

  .. attribute:: state_stp

    Indicates the Spanning Tree Protocol state, either
    :const:`~openfaucet.ofconfig.OFPPS_STP_LISTEN` (not learning or
    relaying frames), :const:`~openfaucet.ofconfig.OFPPS_STP_LEARN`
    (learning but not relaying frames),
    :const:`~openfaucet.ofconfig.OFPPS_STP_FORWARD` (learning and
    relaying frames), or :const:`~openfaucet.ofconfig.OFPPS_STP_BLOCK`
    (not part of spanning tree).

  .. attribute:: curr

    A :class:`~openfaucet.ofconfig.PortFeatures` object defining the
    current features of the port.

  .. attribute:: advertised

    A :class:`~openfaucet.ofconfig.PortFeatures` object defining the
    features being advertised by the port.

  .. attribute:: supported

    A :class:`~openfaucet.ofconfig.PortFeatures` object defining the
    features supported by the port.

  .. attribute:: peer

    A :class:`~openfaucet.ofconfig.PortFeatures` object defining the
    features advertised by the peer connected to the port.

.. class:: PortConfig

  The description of the configuration of a physical port.

  .. TODO(romain): Document how to modify that configuration.

  .. TODO(romain): Add documentation for get_diff() and patch().

  .. attribute:: port_down

    A boolean flag which if True indicates that the port is
    administratively down.

  .. attribute:: no_stp

    A boolean flag which if True indicates that 802.1D Spanning Tree
    Protocol is disabled on the port.

  .. attribute:: no_recv

    A boolean flag which if True indicates that all received packets
    are dropped except 802.1D Spanning Tree Protocol packets.

  .. attribute:: no_recv_stp

    A boolean flag which if True indicates that all received 802.1D
    STP packets are dropped.

  .. attribute:: no_flood

    A boolean flag which if True indicates that this port is not
    included when flooding.

  .. attribute:: no_fwd

    A boolean flag which if True indicates that packets forwarded to
    the port are dropped.

  .. attribute:: no_packet_in

    A boolean flag which if True indicates that no packet-in messages
    are sent by the datapath for packets received on the port.

.. class:: PortFeatures

  Boolean attributes describing the features of a physical port.

  .. attribute:: mode_10mb_hd

    If True, 10 Mbps half-duplex rate is supported.

  .. attribute:: mode_10mb_fd

    If True, 10 Mbps full-duplex rate is supported.

  .. attribute:: mode_100mb_hd

    If True, 100 Mbps half-duplex rate is supported.

  .. attribute:: mode_100mb_fd

    If True, 100 Mbps full-duplex rate is supported.

  .. attribute:: mode_1gb_hd

    If True, 1 Gbps half-duplex rate is supported.

  .. attribute:: mode_1gb_fd

    If True, 1 Gbps full-duplex rate is supported.

  .. attribute:: mode_10gb_fd

    If True, 10 Gbps full-duplex rate is supported.

  .. attribute:: copper

    If True, a copper medium is supported as the link type.

  .. attribute:: fiber

    If True, a fiber medium is supported as the link type.

  .. attribute:: autoneg

    If True, the auto-negotiation feature is supported.

  .. attribute:: pause

    If True, the pause feature is supported.

  .. attribute:: pause_asym

    If True, the asymmetric pause feature is supported.

.. rubric:: Queue configuration

.. class:: PacketQueue

  The description of a packet queue.

  .. attribute:: queue_id

    The queue's ID, as 32-bit unsigned integer.

  .. attribute:: min_rate

    If specified for this queue, the minimum data rate guaranteed, as
    a 16-bit unsigned integer. This value is given in 1/10 of a
    percent. If >1000, the queuing is disabled. If None, this property
    is not available for this queue.
