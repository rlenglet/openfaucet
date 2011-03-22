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

OpenFlow errors
===============

.. currentmodule:: openfaucet.oferror

In OpenFaucet, OpenFlow ``OFPT_ERROR`` error messages are represented
as exceptions of type :class:`~openfaucet.oferror.OpenflowError`. In a
message handler, sending an error message to the peer is done by
raising an :class:`~openfaucet.oferror.OpenflowError` exception, with
the appropriate error type, error code, and data to describe the
error.  For instance, in an OpenFlow controller's
:meth:`~openflow.ofcontroller.IOpenflowController.handle_port_status`
callback::

  from openfaucet import oferror

  class MyController(object):

      def handle_port_status(self, reason, desc):
          # ...
	  raise oferror.OpenflowError(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_EPERM, ())

The exception object is transparently catched and serialized by an
OpenFaucet :class:`~openfaucet.ofcontroller.IOpenflowControllerStub`
protocol object into an ``OFPT_ERROR`` OpenFlow message.

.. class:: openfaucet.oferror.OpenflowError

  .. method:: __init__(error_type, error_code, data)

    Create an :class:`~openfaucet.oferror.OpenflowError`.

    :param error_type: The error type, as one of the ``OFPET_*``
      constants.

    :param error_code: The error code, as one of the ``OFP*`` error
      code constants.

    :param data: The data attached in the error message, as a sequence
      of binary strings.

A standard set of valid error types is defined in the OpenFlow
standard, as well as a set of valid error codes for every error
type. Most error types and codes can only be sent by a datapath to a
controller.

.. data:: openfaucet.oferror.OFPET_HELLO_FAILED

  The hello protocol failed. This error can be raised only when
  handling an ``OFPT_HELLO`` message during the initial handshake.

  .. data:: openfaucet.oferror.OFPHFC_INCOMPATIBLE

    The peers use incompatible versions of the protocol.

  .. data:: openfaucet.oferror.OFPHFC_EPERM

    Permissions error.

.. data:: openfaucet.oferror.OFPET_BAD_REQUEST

  The request was not understood.

  .. data:: openfaucet.oferror.OFPBRC_BAD_VERSION

    The protocol version in the received message is not supported.

  .. data:: openfaucet.oferror.OFPBRC_BAD_TYPE

    The message type is not supported.

  .. data:: openfaucet.oferror.OFPBRC_BAD_STAT

    The stats type is not supported.

  .. data:: openfaucet.oferror.OFPBRC_BAD_VENDOR

    The received vendor ID is not supported.

  .. data:: openfaucet.oferror.OFPBRC_BAD_SUBTYPE

    The received vendor-specific subtype is not supported.

  .. data:: openfaucet.oferror.OFPBRC_EPERM

    Permissions error.

  .. data:: openfaucet.oferror.OFPBRC_BAD_LEN

    The message has an invalid length.

  .. data:: openfaucet.oferror.OFPBRC_BUFFER_EMPTY

    The specified buffer has already been used.

  .. data:: openfaucet.oferror.OFPBRC_BUFFER_UNKNOWN

    The specified buffer does not exist.

.. data:: openfaucet.oferror.OFPET_BAD_ACTION

  Error in an action description.

  .. data:: openfaucet.oferror.OFPBAC_BAD_TYPE

    Unknown action type.

  .. data:: openfaucet.oferror.OFPBAC_BAD_LEN

    An action has an invalid length.

  .. data:: openfaucet.oferror.OFPBAC_BAD_VENDOR

    A vendor action has a vendor ID that is unsupported.

  .. data:: openfaucet.oferror.OFPBAC_BAD_VENDOR_TYPE

    A vendor action has a vendor-specific subtype that is not
    supported.

  .. data:: openfaucet.oferror.OFPBAC_BAD_OUT_PORT

    An output action has an invalid port number.

  .. data:: openfaucet.oferror.OFPBAC_BAD_ARGUMENT

    An action has an invalid argument.

  .. data:: openfaucet.oferror.OFPBAC_EPERM

    Permissions error.

  .. data:: openfaucet.oferror.OFPBAC_TOO_MANY

    Can't handle this many actions.

  .. data:: openfaucet.oferror.OFPBAC_BAD_QUEUE

    An action has an invalid queue number argument.

.. data:: openfaucet.oferror.OFPET_FLOW_MOD_FAILED

  Problem when modifying a flow entry.

  .. data:: openfaucet.oferror.OFPFMFC_ALL_TABLES_FULL

    The flow cannot be added because of full tables.

  .. data:: openfaucet.oferror.OFPFMFC_OVERLAP

    Attempted to add an overlapping flow with ``check_overlap`` set to
    ``True``.

  .. data:: openfaucet.oferror.OFPFMFC_EPERM

    Permissions error.

  .. data:: openfaucet.oferror.OFPFMFC_BAD_EMERG_TIMEOUT

    The flow cannot added because ``emerg`` was set to ``True`` and
    the idle and hard timeouts were set to non-zero.

  .. data:: openfaucet.oferror.OFPFMFC_BAD_COMMAND

    An ``OFPT_FLOW_MOD`` message was sent with an invalid command.

  .. data:: openfaucet.oferror.OFPFMFC_UNSUPPORTED

    The specified list of actions cannot be processed in this order.

.. data:: openfaucet.oferror.OFPET_PORT_MOD_FAILED

  A port modification request failed.

  .. data:: openfaucet.oferror.OFPPMFC_BAD_PORT

    The specified port number does not exist.

  .. data:: openfaucet.oferror.OFPPMFC_BAD_HW_ADDR

    The specified port hardware address is wrong.

.. data:: openfaucet.oferror.OFPET_QUEUE_OP_FAILED

  A queue operation failed.

  .. data:: openfaucet.oferror.OFPQOFC_BAD_PORT

    The specified port number does not exist or is invalid.

  .. data:: openfaucet.oferror.OFPQOFC_BAD_QUEUE

    The specified queue number does not exist.

  .. data:: openfaucet.oferror.OFPQOFC_EPERM

    Permissions error.

The semantics of ``data`` in an
:class:`~openfaucet.oferror.OpenflowError` depends on the error
type. For :const:`~openfaucet.oferror.OFPET_HELLO_FAILED` errors,
``data`` is an ASCII text string that adds detail on why the error
occurred::

  from openfaucet import oferror

  raise oferror.OpenflowError(oferror.OFPET_HELLO_FAILED,
                              oferror.OFPHFC_INCOMPATIBLE,
			      ('only v1.0.0 supported',))

For all other error types, ``data`` contains at least 64 bytes of the
failed
request. :meth:`~openfaucet.ofcontroller.IOpenflowControllerStub.raise_error_with_request`
is a helper method of protocol objects that can be used to raise
exceptions with such data, for instance in a controller callback::


  from openfaucet import oferror

  class MyController(object):

      def connection_made(self):
          # ...
          self.protocol().raise_error_with_request(oferror.OFPET_HELLO_FAILED,
	                                           oferror.OFPHFC_EPERM)
