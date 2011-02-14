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

      Create a factory of :class:`OpenflowControllerStub` objects and
      of controllers and vendor handlers bound to them. The only
      mandatory parameter is ``controller``, the class of controller
      objects to create.

      :param controller: The class of controller objects to create,
        which must implement interface :class:`IOpenflowController`.
      :type controller: class

      :param protocol: The class of protocol objects (controller
        stubs) to create. Defaults to class
        :class:`OpenflowControllerStub`.
      :type protocol: class

      :param error_data_bytes: The maximum number of bytes of
        erroneous requests to send back in an error message. Must be
        >= 64.  Defaults to 64.
      :type error_data_bytes: integer

      :param logger: The Python logger used for logging in every
        created protocol object. Defaults to the root logger, as
        obtained with ``logging.getLogger('')``.
      :type logger: logger object

      :param vendor_handlers: A sequence of vendor handler
        classes. One instance of every class is instantiated (with no
        arguments) and passed to every created protocol
        object. Defaults to an empty sequence.
      :type vendor_handlers: class list

      :param reactor: An object implementing Twisted's IReactorTime
        interface, used to do delayed calls. Defaults to Twisted's
        default reactor :mod:`twisted.internet.reactor`.
      :type reactor: reactor object

      :param default_op_timeout: The default period, in seconds,
        before an operation times out. This is also used as the
        timeout for echo operations. Defaults to 3.0 (seconds).
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
      connection. This callback is made once the handshake is
      completed with the switch, i.e. once the description of the
      switch's features have been received.

      .. TODO(romain): Link to the description of how to get those
      .. switch features.

   .. method:: connection_lost(reason)

      Release any resources used to manage the connection that was
      just lost.

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
        :attr:`~openfaucet.ofproto.OFPR_NO_MATCH` (no matching flow)
        or :attr:`~openfaucet.ofproto.OFPR_ACTION` (action explicitly
        output to controller).
      :type reason: integer

      :param data: The Ethernet frame, as a byte buffer.
      :type data: byte buffer

   .. method:: handle_flow_removed(match, cookie, priority, reason, duration_sec, duration_nsec, idle_timeout, packet_count, byte_count)

      Handle the reception of a ``OFPT_FLOW_REMOVED`` message,
      i.e. the notification that a flow has been removed from the
      datapath.

      :param match: A :class:`~openfaucet.ofproto.Match` object
        describing the fields of the flow.

      :param cookie: An opaque value issued by the controller when the
        flow was added.
      :type cookie: 64-bit unsigned integer

      :param priority: The priority level of the expired flow entry.
      :type priority: 16-bit unsigned integer

      :param reason: The reason why the flow entry expired, either
        :attr:`~openfaucet.ofproto.OFPRR_IDLE_TIMEOUT` (flow idle time
        exceeded idle_timeout),
        :attr:`~openfaucet.ofproto.OFPRR_HARD_TIMEOUT` (time exceeded
        hard_timeout), or :attr:`~openfaucet.ofproto.OFPRR_DELETE`
        (evicted by a ``DELETE`` flow mod message).
      :type reason: integer

      :param duration_sec: Time the flow was alive in seconds.
      :type duration_sec: 32-bit unsigned integer.

      :param duration_nsec: Time flow was alive in nanoseconds beyond
        duration_sec.
      :type duration_nsec: 32-bit unsigned integer

      :param idle_timeout: The idle timeout in seconds from the
        original flow mod.
      :type idle_timeout: 16-bit unsigned integer

      :param packet_count: The number of packets in the flow.
      :type packet_count: 64-bit unsigned integer

      :param byte_count: The number of bytes in packets in the flow.
      :type byte_count: 64-bit unsigned integer

   .. method:: handle_port_status(reason, desc)

      Handle the reception of a ``OFPT_PORT_STATUS`` message, i.e. a
      notification that a datapath port's status has changed.

      :param reason: The reason for the port status change, either
        :attr:`~openfaucet.ofproto.OFPPR_ADD` (the port was added),
        :attr:`~openfaucet.ofproto.OFPPR_DELETE` (the port was
        removed), or :attr:`~openfaucet.ofproto.OFPPR_MODIFY` (some
        attribute of the port has changed).
      :type reason: integer

      :param desc: A :class:`~openfaucet.ofconfig.PhyPort` object
        defining the physical port, including its new status.

Asynchronous requests
---------------------

Asynchronous messages
---------------------
