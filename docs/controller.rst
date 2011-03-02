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

OpenFlow controller developer's guide
=====================================

Controller instantiation
------------------------

OpenFaucet is based on the Twisted framework for managing transport
connections (e.g. TCP connections) between OpenFlow switches and
controllers. Once a transport connection is established, the
connection object is controlled by a controller stub object, which in
turn controls a controller object and zero of more vendor extension
handler objects. There is therefore a one-to-one binding between the
transport connection and controller stub, a one-to-one binding between
the controller stub and the controller, and one one-to-one binding
between the controller stub and every vendor handler::

       	       	       	   +---------+
		       	   |transport|
                           +---------+           1 +--------+
		       	      1	^  	   +------>|vendor_1|
		    	       	|    	   |  	   +--------+
		    	      1	v    	  1|
  +----------+ 1      1 +---------------+<-+ 1 	 1 +--------+
  |controller|<-------->|controller_stub|<-------->|vendor_2|
  +----------+	        +---------------+<-+  	   +--------+
		   			  1|
       	       	       	       	       	   |   	 1 +--------+
		   			   +------>|vendor_3|
		   				   +--------+

Every controller stub is an instance of class ControllerStub that is
created by a factory object which is an instance of class
OpenflowControllerStubFactory. This factory class implements Twisted's
:class:`~twisted.internet.interfaces.IProtocolFactory` interface, so
it can be used the standard way to manage Twisted transport
connections. It must be configured by passing arguments to the its
constructor:

.. currentmodule:: openfaucet.ofcontroller

.. class:: OpenflowControllerStubFactory

  .. method:: __init__(controller[, protocol, error_data_bytes, logger, vendor_handlers, reactor, default_op_timeout, echo_op_period])

    Create a factory of :class:`OpenflowControllerStub` objects and of
    controllers and vendor handlers bound to them. The only mandatory
    parameter is ``controller``, the class of controller objects to
    create.

    :param controller: The class of controller objects to create,
      which must implement interface :class:`IOpenflowController`.
    :type controller: class

    :param protocol: The class of protocol objects (controller stubs)
      to create. Defaults to class :class:`OpenflowControllerStub`.
    :type protocol: class

    :param error_data_bytes: The maximum number of bytes of erroneous
      requests to send back in an error message. Must be >= 64.
      Defaults to 64.
    :type error_data_bytes: integer

    :param logger: The Python logger object used for logging in every
      created protocol object. Defaults to the root logger, as
      obtained with ``logging.getLogger('')``.

    :param vendor_handlers: A sequence of vendor handler classes. One
      instance of every class is instantiated (with no arguments) and
      passed to every created protocol object. Defaults to an empty
      sequence.
    :type vendor_handlers: class list

    :param reactor: An object implementing Twisted's IReactorTime
      interface, used to do delayed calls. Defaults to Twisted's
      default reactor :mod:`twisted.internet.reactor`.
    :type reactor: reactor object

    :param default_op_timeout: The default period, in seconds, before
      an operation times out. This is also used as the timeout for
      echo operations. Defaults to 3.0 (seconds).
    :type default_op_timeout: float

    :param echo_op_period: The period, in seconds, between two echo
      operations. Defaults to 5.0 (seconds).
    :type echo_op_period: float

For example, to configure a factory to create controller objects that
are instance of class ``MyController``, and to connect to an OpenFlow
switch using a TCP connection::

  from twisted.internet import reactor
  from openfaucet import ofcontroller

  factory = ofcontroller.OpenflowControllerStubFactory(
      controller=MyController)
  reactor.connectTCP('switch1.example.com', 6633, factory)
  reactor.run()

Controller objects are created by the factory by calling the given
``controller`` class with no arguments, so every controller class must
implement an ``__init__()`` constructor with no arguments. If a
controller object requires attributes to be set, implement a factory
that is a subclass of :class:`OpenflowControllerStubFactory` which
sets the attributes after the controller stub, the controller and
vendor handlers are created, and override method
:meth:`~twisted.internet.interfaces.IProtocolFactory.buildProtocol`::

  from openfaucet import ofcontroller

  class MyController(object):

      def __init__():
          pass

      # ...

  class MyControllerStubFactory(ofcontroller.OpenflowControllerStubFactory):

      def buildProtocol(self, addr):
          p = ofcontroller.OpenflowControllerStubFactory.buildProtocol(self, addr)
          controller = p.controller
          # Complete controller initialization.
          controller.some_attribute = self._some_value
          return p
  
Asynchronous message callbacks
------------------------------

Every controller class must implement OpenFaucet's
:class:`IOpenflowController` interface, which defines the following 5
callback methods:

.. class:: IOpenflowController

  .. method:: connection_made()

    Initialize the resources to manage the newly opened OpenFlow
    connection. This callback is made once the handshake is completed
    with the switch, i.e. once the description of the switch's
    features have been received.

    .. TODO(romain): Link to the description of how to get those
    .. switch features.

  .. method:: connection_lost(reason)

    Release any resources used to manage the connection that was just
    lost.

    :param reason: The reason why the connection was lost, as a
      :class:`~twisted.python.failure.Failure` that wraps a
      :class:`~twisted.internet.error.ConnectionDone` or
      :class:`~twisted.internet.error.ConnectionLost` instance (or a
      subclass of one of those).

  .. method:: handle_packet_in(buffer_id, total_len, in_port, reason, data)

    Handle the reception of a ``OFPT_PACKET_IN`` message, i.e. an
    Ethernet frame forwarded by the datapath.

    :param buffer_id: The buffer ID assigned by datapath. If
      0xffffffff, the frame is not buffered, and the entire frame is
      passed in data.
    :type buffer_id: integer

    :param total_len: The full length of the frame, in bytes.
    :type total_len: integer

    :param in_port: The port on which the frame was received.
    :type in_port: integer

    :param reason: The reason why the frame is being sent, either
      :const:`~openfaucet.ofproto.OFPR_NO_MATCH` (no matching flow) or
      :const:`~openfaucet.ofproto.OFPR_ACTION` (action explicitly
      output to controller).
    :type reason: integer

    :param data: The Ethernet frame.
    :type data: binary string

  .. method:: handle_flow_removed(match, cookie, priority, reason, duration_sec, duration_nsec, idle_timeout, packet_count, byte_count)

    Handle the reception of a ``OFPT_FLOW_REMOVED`` message, i.e. the
    notification that a flow has been removed from the datapath.

    :param match: A :class:`~openfaucet.ofproto.Match` object
      describing the fields of the flow.

    :param cookie: An opaque value issued by the controller when the
      flow was added.
    :type cookie: 64-bit unsigned integer

    :param priority: The priority level of the expired flow entry.
    :type priority: 16-bit unsigned integer

    :param reason: The reason why the flow entry expired, either
      :const:`~openfaucet.ofproto.OFPRR_IDLE_TIMEOUT` (flow idle time
      exceeded idle_timeout),
      :const:`~openfaucet.ofproto.OFPRR_HARD_TIMEOUT` (time exceeded
      hard_timeout), or :const:`~openfaucet.ofproto.OFPRR_DELETE`
      (evicted by a ``DELETE`` flow mod message).
    :type reason: integer

    :param duration_sec: Time the flow was alive in seconds.
    :type duration_sec: 32-bit unsigned integer

    :param duration_nsec: Time flow was alive in nanoseconds beyond
      duration_sec.
    :type duration_nsec: 32-bit unsigned integer

    :param idle_timeout: The idle timeout in seconds from the original
      flow mod.
    :type idle_timeout: 16-bit unsigned integer

    :param packet_count: The number of packets in the flow.
    :type packet_count: 64-bit unsigned integer

    :param byte_count: The number of bytes in packets in the flow.
    :type byte_count: 64-bit unsigned integer

  .. method:: handle_port_status(reason, desc)

    Handle the reception of a ``OFPT_PORT_STATUS`` message, i.e. a
    notification that a datapath port's status has changed.

    :param reason: The reason for the port status change, either
      :const:`~openfaucet.ofproto.OFPPR_ADD` (the port was added),
      :const:`~openfaucet.ofproto.OFPPR_DELETE` (the port was
      removed), or :const:`~openfaucet.ofproto.OFPPR_MODIFY` (some
      attribute of the port has changed).
    :type reason: integer

    :param desc: A :class:`~openfaucet.ofconfig.PhyPort` object
      defining the physical port, including its new status.

Sending messages to datapaths
-----------------------------

Every controller object is bound to an
:class:`~openfaucet.ofcontroller.OpenflowControllerStub` object that
provides methods for sending requests and messages to the connected
OpenFlow datapath, as defined in interface
:class:`~openfaucet.ofcontroller.IOpenflowControllerStub`. The stub is
referenced by a weak reference set in the controller's ``protocol``
attribute, so it must be retrieved by calling ``self.protocol()``. For
instance, to print the datapath ID once the handshake with the
datapath is terminated::

  class MyController(object):

      def connection_made(self):
          dp_id = self.protocol().features.datapath_id
          print 'connected to datapath', dp_id

The controller stub provides several asynchronous methods for request
/ reply operations with the datapath. Those methods take callables as
arguments to specify callbacks to be made when the operation's reply
is received or the operation times out.

If a callable needs to get additional positional or keyword arguments
in addition to the arguments passed by the protocol object, the caller
must wrap the callable into a :class:`~openfaucet.ofprotoops.Callable`
object.

.. class:: openfaucet.ofprotoops.Callable

  A namedtuple object that decorates a callable to pass additional
  arguments to it when called. The additional arguments to the
  callable are passed in addition to the arguments given by the
  caller. The preferred way to create a
  :class:`~openfaucet.ofprotoops.Callable` is by calling
  :meth:`~openfaucet.ofprotoops.Callable.make_callable`:

  .. classmethod:: make_callable(callable[, *args, **kwargs])

    Create a :class:`~openfaucet.ofprotoops.Callable` with the given
    callable and args.

    :param callable: A callable.
    :param args: The (possibly empty) sequence of additional
      positional arguments to pass to the callable.
    :param kwargs: The (possibly empty) dict of additional keyword
      arguments to pass to the callable.

  A callable object can then be called directly, possibly with
  positional and keyword arguments. The positional arguments given to
  the call correspond to the signature of the method expected by the
  caller. The additional positional and keyword arguments given to
  :meth:`~openfaucet.ofprotoops.Callable.make_callable` can be used to
  pass context information to the callable, for example::

    from openfaucet import ofprotoops

    def my_callable(data, log_prefix=None):
        print '%s: %r' % (log_prefix, data)

    def call_me_back(callback):
        data = 'world'
        callback(data)

    callback= ofprotoops.Callable.make_callable(log_prefix='hello')
    call_me_back(callback)

.. class:: OpenflowControllerStub

.. class:: IOpenflowControllerStub

  .. rubric:: Configuration

  .. attribute:: features

    The :class:`~openfaucet.ofconfig.SwitchFeatures` object describing
    the switch features. None if the handshake with the datapath has
    not yet been completed, i.e. before
    :meth:`~openfaucet.ofcontroller.IOpenflowController.connection_made`
    has been called back. This
    :class:`~openfaucet.ofconfig.SwitchFeatures` object is
    automatically updated by this stub when any port status changes.

  .. method:: get_features(callback[, timeout_callback, timeout])

    Request the switch features.

    :param callback: The callable to be called with the replied data.

    :param timeout_callback: The callable to be called in case the
      operation times out.

    :param timeout: The period, in seconds, before the operation times
      out. If None, defaults to the default timeout.

    :type timeout: integer or None

    .. note::

      Using this object's :attr:`features` attribute is more efficient
      than calling this method, so this method should normally not be
      called by controllers.

    This operation is asynchronous: the switch features are passed
    back by calling the given ``callback`` as:

    .. function:: callback(switch_features)

      :param switch_features: A
        :class:`~openfaucet.ofconfig.SwitchFeatures` object containing
        the switch features.

    If the operation times out, i.e. if no reply is received before
    the ``timeout`` period, and if ``timeout_callback`` is not None,
    ``timeout_callback`` is called as:

    .. function:: timeout_callback()

    ``callback`` and / or ``timeout_callback`` must be None if no
    callback must be made when the reply is received and / or the
    operation times out. They may also be
    :class:`~openfaucet.ofprotoops.Callable` objects to pass
    additional arguments to the callables.

  .. method:: get_config(callback[, timeout_callback, timeout])

    Request the switch config.

    This operation is asynchronous. The ``callback``,
    ``timeout_callback``, and ``timeout`` are similar as in
    :meth:`get_features`, and ``callback`` is called as:

    .. function:: callback(switch_config)

      :param switch_config: A
        :class:`~openfaucet.ofconfig.SwitchConfig` object containing
        the switch configuration.

  .. method:: send_set_config(switch_config)

    Send a ``OFPT_SET_CONFIG`` message to modify the switch
    configuration.

    :param switch_config: A :class:`~openfaucet.ofconfig.SwitchConfig`
      object containing the switch configuration.

  .. method:: send_port_mod(port_no, hw_addr, config, mask, advertise)

    Send a ``OFPT_PORT_MOD`` message to modify the configuration of a
    port.

    :param port_no: The port's unique number. Must be between 1 and
      :const:`~openfaucet.ofproto.OFPP_MAX`.
    :type port_no: 16-bit unsigned integer

    :param hw_addr: The port's MAC address. The hardware address is
      not configurable. This is used only to sanity-check the request,
      so it must be the same as returned in
      :class:`~openfaucet.ofconfig.PhyPort` object.
    :type hw_addr: binary string

    :param config: The :class:`~openfaucet.ofconfig.PortConfig`
      containing the new values of fields to replace. Only the fields
      which are True in ``mask`` are replaced, the others are ignored.

    :param mask: The :class:`~openfaucet.ofconfig.PortConfig`
      indicating which fields are to be replaced with values from
      config.

    :param advertise: The :class:`~openfaucet.ofconfig.PortFeatures`
      indicating the features to be advertised by the port. If None or
      all fields are False, the advertised features are not replaced.

    The ``config`` and ``mask`` arguments can be obtained by calling
    :meth:`~openfaucet.ofconfig.PortConfig.get_diff` on a
    :class:`~openfaucet.ofconfig.PortConfig` object. For instance, to
    disable flooding on every port at connection time::

      from openfaucet import ofproto

      class MyController(object):

          def connection_made(self):
              for port in self.protocol().features.ports:
                  if not port.config.no_flood:
                      new_config = port.config._replace(no_flood=True)
                      config, mask = new_config.get_diff(port.config)
                      self.protocol().send_port_mod(port.port_no, port.hw_addr,
                                                    config, mask, None)

  .. method:: get_queue_config(port_no, callback[, timeout_callback, timeout])

    Request a port's queues configs.

    :param port_no: The port's unique number. Must be a valid physical
      port, i.e. < :const:`~openfaucet.ofproto.OFPP_MAX`.
    :type port_no: 16-bit unsigned integer

    This operation is asynchronous. The ``callback``,
    ``timeout_callback``, and ``timeout`` are similar as in
    :meth:`get_features`, and ``callback`` is called as:

    .. function:: callback(port_no, queues)

      :param port_no: The port's unique number. Must be a valid
        physical port, i.e. < :const:`~openfaucet.ofproto.OFPP_MAX`.
      :type port_no: 16-bit unsigned integer
      :param queues: A sequence of
        :class:`~openfaucet.ofconfig.PacketQueue` objects describing
        the port's queues.

  .. rubric:: Flows and packets

  .. method:: send_packet_out(buffer_id, in_port, actions, data)

    Send a ``OFPT_PACKET_OUT`` message to have a packet processed by
    the datapath.

    :param buffer_id: The buffer ID assigned by the datapath. If
      0xffffffff, the frame is not buffered, and the entire frame must
      be passed in ``data``.
    :type buffer_id: 32-bit unsigned integer

    :param in_port: The port from which the frame is to be
      sent. :const:`~openfaucet.ofproto.OFPP_NONE` if none.
      :const:`~openfaucet.ofproto.OFPP_TABLE` to perform the actions
      defined in the flow table.
    :type in_port: integer

    :param actions: The sequence of action objects (implementing
      :mod:`~openfaucet.ofaction.IAction`) specifying the actions to
      perform on the frame.

    :param data: The entire Ethernet frame, as a sequence of binary
      strings. Should be of length 0 if buffer_id is -1, and should be
      of length >0 otherwise.

  .. method:: send_flow_mod_add(match, cookie, idle_timeout, hard_timeout, priority, buffer_id, send_flow_rem, check_overlap, emerg, actions)

    Send a ``OFPT_FLOW_MOD`` message to add a flow into the datapath.

    :param match: A :class:`~openfaucet.ofmatch.Match` object
      describing the fields of the flow.

    :param cookie: An opaque value issued by the
      controller. 0xffffffffffffffff is reserved and must not be
      used.
    :type cookie: 64-bit unsigned integer

    :param idle_timeout: The idle time in seconds before
      discarding.
    :type idle_timeout: 16-bit unsigned integer

    :param hard_timeout: The maximum time before discarding in
      seconds.
    :type hard_timeout: 16-bit unsigned integer

    :param priority: The priority level of the flow entry.
    :type priority: 16-bit unsigned integer

    :param buffer_id: The buffer ID assigned by the datapath of a
      buffered packet to apply the flow to. If 0xffffffff, no buffered
      packet is to be applied the flow actions.
    :type buffer_id: 32-bit unsigned integer

    :param send_flow_rem: If True, send a ``OFPT_FLOW_REMOVED``
      message when the flow expires or is deleted.
    :type send_flow_rem: bool

    :param check_overlap: If True, check for overlapping entries
      first, i.e. if there are conflicting entries with the same
      priority, the flow is not added and the modification
      fails.
    :type check_overlap: bool

    :param emerg: if True, the switch must consider this flow entry as
      an emergency entry, and only use it for forwarding when
      disconnected from the controller.
    :type emerg: bool

    :param actions: The sequence of action objects (see
      :mod:`~openfaucet.ofaction`) specifying the actions to perform
      on the flow's packets.

  .. method:: send_flow_mod_modify(strict, match, cookie, idle_timeout, hard_timeout, priority, buffer_id, send_flow_rem, check_overlap, emerg, actions)

    Send a ``OFPT_FLOW_MOD`` message to modify a flow in the datapath.

    :param strict: If True, all args, including the wildcards and
      priority, are strictly matched against the entry, and only an
      identical flow is modified. If False, a match will occur when a
      flow entry exactly matches or is more specific than the given
      match and priority.
    :type strict: bool

    :param match: A :class:`~openfaucet.ofmatch.Match` object
      describing the fields of the flow.

    :param cookie: An opaque value issued by the
      controller. 0xffffffffffffffff is reserved and must not be
      used.
    :type cookie: 64-bit unsigned integer

    :param idle_timeout: The idle time in seconds before
      discarding.
    :type idle_timeout: 16-bit unsigned integer

    :param hard_timeout: The maximum time before discarding in
      seconds.
    :type hard_timeout: 16-bit unsigned integer

    :param priority: The priority level of the flow entry.
    :type priority: 16-bit unsigned integer

    :param buffer_id: The buffer ID assigned by the datapath of a
      buffered packet to apply the flow to. If 0xffffffff, no buffered
      packet is to be applied the flow actions.
    :type buffer_id: 32-bit unsigned integer

    :param send_flow_rem: If True, send a ``OFPT_FLOW_REMOVED``
      message when the flow expires or is deleted.
    :type send_flow_rem: bool

    :param check_overlap: If True, check for overlapping entries
      first, i.e. if there are conflicting entries with the same
      priority, the flow is not added and the modification
      fails.
    :type check_overlap: bool

    :param emerg: if True, the switch must consider this flow entry as
      an emergency entry, and only use it for forwarding when
      disconnected from the controller.
    :type emerg: bool

    :param actions: The sequence of action objects (see
      :mod:`~openfaucet.ofaction`) specifying the actions to perform
      on the flow's packets.

  .. method:: send_flow_mod_delete(strict, match, priority, out_port)

    Send a ``OFPT_FLOW_MOD`` message to delete a flow from the datapath.

    :param strict: If True, all args, including the wildcards and
      priority, are strictly matched against the entry, and only an
      identical flow is deleted. If False, a match will occur when a
      flow entry exactly matches or is more specific than the given
      match and priority.
    :type strict: bool

    :param match: A :class:`~openfaucet.ofmatch.Match` object
      describing the fields of the flow.

    :param priority: The priority level of the flow entry.
    :type priority: 16-bit unsigned integer

    :param out_port: An output port that is required to be included in
      matching flows' output actions. If
      :const:`~openfaucet.ofproto.OFPP_NONE`, no restriction applies
      in matching.
    :type out_port: integer

  .. method:: barrier(callback[, timeout_callback, timeout])

    Request a synchronization barrier.

    This operation is asynchronous. The ``callback``,
    ``timeout_callback``, and ``timeout`` are similar as in
    :meth:`get_features`, and ``callback`` is called as:

    .. function:: callback()

    The callback is called when the barrier has been reached, i.e. any
    message sent before the barrier has been completely processed by
    the datapath.

  .. rubric:: Statistics

  .. method:: get_stats_desc(callback[, timeout_callback, timeout])

    Request the switch stats.

    This operation is asynchronous. The ``callback``,
    ``timeout_callback``, and ``timeout`` are similar as in
    :meth:`get_features`, and ``callback`` is called as:

    .. function:: callback(desc_stats)

      :param desc_stats: A
        :class:`~openfaucet.ofconfig.DescriptionStats` that contains
        the switch description stats.

  .. method:: get_stats_flow(match, table_id, out_port, callback[, timeout_callback, timeout])

    Request individual flow stats.

    :param match: A :class:`~openfaucet.ofmatch.Match` object
      describing the fields of the flows to match.

    :param table_id: The ID of the table to read. 0xff for all tables
      or 0xfe for emergency.
    :type table_id: 8-bit unsigned integer

    :param out_port: Require matching flows to include this as an
      output port. A value of :const:`~openfaucet.ofproto.OFPP_NONE`
      indicates no restriction.
    :type out_port: integer

    The callback is called with the individual stats of every flow
    matching the given criteria.

    This operation is asynchronous. The ``callback``,
    ``timeout_callback``, and ``timeout`` are similar as in
    :meth:`get_features`, and ``callback`` is called as:

    .. function:: callback(flow_stats, reply_more)

      :param flow_stats: A tuple of
        :class:`~openfaucet.ofstats.FlowStats` objects each containing
        the stats for an individual flow.
      :param reply_more: If True, more callbacks will be made to the
        callable after this one to completely terminate this
        operation. If False, this is the last callback in this
        operation.
      :type reply_more: bool

    One or more calls to the ``callback`` may be made, to reply the
    stats for all matching flows: zero or more calls with
    ``reply_more`` set to True, followed by one call with
    ``reply_more`` set to False. The operation's timeout applies to
    the whole sequence of calls. So zero or more calls may be made to
    ``callback`` with ``reply_more`` set to True, before the operation
    times out and ``timeout_callback`` is called back.

  .. method:: get_stats_aggregate(match, table_id, out_port, callback[, timeout_callback, timeout])

    Request aggregate flow stats.

    The arguments are identical to those of :meth:`get_stats_flow`,
    except that the callback is called with the aggregate stats of all
    flows matching the given criteria.

    This operation is asynchronous. The ``callback``,
    ``timeout_callback``, and ``timeout`` are similar as in
    :meth:`get_features`, and ``callback`` is called as:

    .. function:: callback(packet_count, byte_count, flow_count)

      :param packet_count: The number of packets in aggregated flows.
      :type packet_count: 64-bit unsigned integer
      :param byte_count: The number of bytes in aggregated flows.
      :type byte_count: 64-bit unsigned integer
      :param flow_count: The number of aggregated flows.
      :type flow_count: 32-bit unsigned integer

  .. method:: get_stats_table(callback[, timeout_callback, timeout])

    Request table stats.

    This operation is asynchronous. The ``callback``,
    ``timeout_callback``, and ``timeout`` are similar as in
    :meth:`get_features`, and ``callback`` is called as:

    .. function:: callback(table_stats, reply_more)

      :param table_stats: A tuple of
        :class:`~openfaucet.ofstats.TableStats` objects containing
        each the stats for an individual table.
      :param reply_more: Indicates if this callback is not the last in
        this operation, cf. :meth:`get_stats_flow`.
      :type reply_more: bool

  .. method:: get_stats_port(port_no, callback[, timeout_callback, timeout])

    Request port stats.

    :param port_no: The port's unique number. If
      :const:`~openfaucet.ofproto.OFPP_NONE`, stats for all ports are
      replied.
    :type port_no: 16-bit unsigned integer

    This operation is asynchronous. The ``callback``,
    ``timeout_callback``, and ``timeout`` are similar as in
    :meth:`get_features`, and ``callback`` is called as:

    .. function:: callback(port_stats, reply_more)

      :param port_stats: A tuple of
        :class:`~openfaucet.ofstats.PortStats` objects containing
        each the stats for an individual port.
      :param reply_more: Indicates if this callback is not the last in
        this operation, cf. :meth:`get_stats_flow`.
      :type reply_more: bool

  .. method:: get_stats_queue(port_no, queue_id, callback[, timeout_callback, timeout])

    Request queue stats.

    :param port_no: The port's unique number. If
      :const:`~openfaucet.ofproto.OFPP_ALL`, stats for all ports are
      replied.
    :type port_no: 16-bit unsigned integer

    :param queue_id: The queue's ID. If
      :const:`~openfaucet.ofproto.OFPQ_ALL`, stats for all queues are
      replied.
    :type queue_id: 32-bit unsigned integer

    This operation is asynchronous. The ``callback``,
    ``timeout_callback``, and ``timeout`` are similar as in
    :meth:`get_features`, and ``callback`` is called as:

    .. function:: callback(queue_stats, reply_more)

      :param queue_stats: A tuple of
        :class:`~openfaucet.ofstats.QueueStats` objects containing
        each the stats for an individual queue.
      :param reply_more: Indicates if this callback is not the last in
        this operation, cf. :meth:`get_stats_flow`.
      :type reply_more: bool

  .. TODO(romain): Document how to get vendor stats.
