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

# Unittests for ofprotoops.py.

import re
import struct
import unittest2
import weakref
import twisted.internet.address
import twisted.internet.error
import twisted.python.failure

from openfaucet import ofproto
from openfaucet import ofprotoops

from openfaucet import mock_twisted
from openfaucet import mock_vendor
# TODO(romain): Move mock types in test_ofproto into their own module.
from openfaucet import test_ofproto


class TestOpenflowProtocolOperations(unittest2.TestCase):

  def setUp(self):
    self.transport = mock_twisted.MockTransport()
    self.reactor = mock_twisted.MockReactorTime()
    self.vendor_handler = mock_vendor.MockVendorHandler()
    self.default_op_timeout = 3
    self.echo_op_period = 5

    self.proto = ofprotoops.OpenflowProtocolOperations()
    self.proto.vendor_handlers = (self.vendor_handler,)
    self.proto.reactor = self.reactor
    self.proto.default_op_timeout = self.default_op_timeout
    self.proto.echo_op_period = self.echo_op_period
    self.proto.transport = self.transport

    self.vendor_handler.protocol = weakref.ref(self.proto)

  def _get_next_sent_message(self):
    """Get the undecoded next message sent by the protocol.

    Returns:
      A byte array containing a single message, or None if no message
      was received.
    """
    buf = self.transport.buffer
    if len(buf) == 0:
      return None
    self.assertGreaterEqual(len(buf), ofproto.OFP_HEADER_LENGTH)
    buf.set_message_boundaries(ofproto.OFP_HEADER_LENGTH)
    _, _, msg_length, _ = buf.unpack_inplace(ofproto.OFP_HEADER_FORMAT)
    self.assertGreaterEqual(len(buf), msg_length)
    buf.set_message_boundaries(msg_length)
    return buf.read_bytes(msg_length)

  def test_connection_made_send_hello_echo_request(self):
    self.proto.connectionMade()
    # Sent initial OFPT_HELLO with XID 0.
    self.assertEqual('\x01\x00\x00\x08\x00\x00\x00\x00',
                     self._get_next_sent_message())
    # Sent initial OFPT_ECHO_REQUEST with XID 0.
    self.assertRegexpMatches(
        self._get_next_sent_message(),
        re.compile(r'\x01\x02\x00\x0c\x00\x00\x00\x00'
                   '....',  # 32-bit random data
                   re.DOTALL))

  def test_connection_lost_ops_timeout(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.
    # Send 2 more echo requests.
    self.proto._echo()
    self.proto._echo()
    self.assertItemsEqual(
        [mock_twisted.MockDelayedCall(
            reactor_time=self.reactor,
            time=self.default_op_timeout,
            already_cancelled=False,
            already_called=False,
            callable=self.proto._timeout_operation,
            args=(0,),
            kw={}),
         mock_twisted.MockDelayedCall(
            reactor_time=self.reactor,
            time=self.default_op_timeout,
            already_cancelled=False,
            already_called=False,
            callable=self.proto._timeout_operation,
            args=(1,),
            kw={}),
         mock_twisted.MockDelayedCall(
            reactor_time=self.reactor,
            time=self.default_op_timeout,
            already_cancelled=False,
            already_called=False,
            callable=self.proto._timeout_operation,
            args=(2,),
            kw={}),
         ], self.reactor.delayed_calls)
    
    self.proto.connectionLost(twisted.python.failure.Failure(
        twisted.internet.error.ConnectionLost()))
    self.assertItemsEqual([], self.reactor.delayed_calls)

  def test_echo_op_periodic(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.

    # Initial OFPT_ECHO_REQUEST with XID 0.
    next_msg = self._get_next_sent_message()
    self.assertEqual('\x01\x02\x00\x0c\x00\x00\x00\x00', next_msg[:8])
    data = next_msg[8:]  # 32-big random data
    self.assertItemsEqual(
        [mock_twisted.MockDelayedCall(
            reactor_time=self.reactor,
            time=self.default_op_timeout,
            already_cancelled=False,
            already_called=False,
            callable=self.proto._timeout_operation,
            args=(0,),
            kw={}),
         ], self.reactor.delayed_calls)

    # Receive the reply after 2s, before timeout.
    self.reactor.increment_time(2)
    self.assertItemsEqual(
        [mock_twisted.MockDelayedCall(
            reactor_time=self.reactor,
            time=self.default_op_timeout,
            already_cancelled=False,
            already_called=False,
            callable=self.proto._timeout_operation,
            args=(0,),
            kw={}),
         ], self.reactor.delayed_calls)
    self.proto.dataReceived('\x01\x03\x00\x0c\x00\x00\x00\x00' + data)
    self.assertItemsEqual(
        [mock_twisted.MockDelayedCall(
            reactor_time=self.reactor,
            time=self.reactor.seconds() + self.echo_op_period,
            already_cancelled=False,
            already_called=False,
            callable=self.proto._echo,
            args=(),
            kw={}),
         ], self.reactor.delayed_calls)

    # Next OFPT_ECHO_REQUEST with XID 1.
    self.reactor.increment_time(self.echo_op_period)
    next_msg = self._get_next_sent_message()
    self.assertEqual('\x01\x02\x00\x0c\x00\x00\x00\x01', next_msg[:8])
    data = next_msg[8:]  # 32-big random data
    self.assertItemsEqual(
        [mock_twisted.MockDelayedCall(
            reactor_time=self.reactor,
            time=self.reactor.seconds() + self.default_op_timeout,
            already_cancelled=False,
            already_called=False,
            callable=self.proto._timeout_operation,
            args=(1,),
            kw={}),
         ], self.reactor.delayed_calls)

  def test_echo_op_timeout(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.

    # Initial OFPT_ECHO_REQUEST with XID 0.
    next_msg = self._get_next_sent_message()
    self.assertEqual('\x01\x02\x00\x0c\x00\x00\x00\x00', next_msg[:8])
    data = next_msg[8:]  # 32-big random data
    self.assertItemsEqual(
        [mock_twisted.MockDelayedCall(
            reactor_time=self.reactor,
            time=self.default_op_timeout,
            already_cancelled=False,
            already_called=False,
            callable=self.proto._timeout_operation,
            args=(0,),
            kw={}),
         ], self.reactor.delayed_calls)
    self.assertTrue(self.transport.open)  # Connection open.

    # Let the echo operation time out.
    self.reactor.increment_time(self.default_op_timeout)
    self.assertFalse(self.transport.open)  # Connection closed.

  def test_echo_op_wrong_data(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.

    # Initial OFPT_ECHO_REQUEST with XID 0.
    next_msg = self._get_next_sent_message()
    self.assertEqual('\x01\x02\x00\x0c\x00\x00\x00\x00', next_msg[:8])
    data = next_msg[8:]  # 32-big random data
    self.assertItemsEqual(
        [mock_twisted.MockDelayedCall(
            reactor_time=self.reactor,
            time=self.default_op_timeout,
            already_cancelled=False,
            already_called=False,
            callable=self.proto._timeout_operation,
            args=(0,),
            kw={}),
         ], self.reactor.delayed_calls)

    # Receive the reply with wrong data, after 2s, before timeout.
    self.reactor.increment_time(2)
    self.assertItemsEqual(
        [mock_twisted.MockDelayedCall(
            reactor_time=self.reactor,
            time=self.default_op_timeout,
            already_cancelled=False,
            already_called=False,
            callable=self.proto._timeout_operation,
            args=(0,),
            kw={}),
         ], self.reactor.delayed_calls)
    self.proto.dataReceived('\x01\x03\x00\x13\x00\x00\x00\x00'
                            'garbage' + data)
    # No error message sent back, as this is not a standard error.
    self.assertIsNone(self._get_next_sent_message())

  def test_handle_echo_request(self):
    self.proto.connectionMade()
    self._get_next_sent_message()  # Initial OFPT_HELLO.
    self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.

    self.proto.dataReceived('\x01\x02\x00\x10\x00\x00\x00\x04abcdefgh')

    # Sent back an OFPT_ECHO_REPLY with same length 8+8, data, and XID 4.
    self.assertEqual('\x01\x03\x00\x10\x00\x00\x00\x04abcdefgh',
                     self._get_next_sent_message())


class TestOpenflowProtocolOperationsFactory(unittest2.TestCase):

  def setUp(self):
    self.vendor_handler_classes = (mock_vendor.MockVendorHandler,)
    self.reactor = mock_twisted.MockReactorTime()
    self.factory = ofprotoops.OpenflowProtocolOperationsFactory(
        protocol=ofprotoops.OpenflowProtocolOperations,
        error_data_bytes=64, vendor_handlers=self.vendor_handler_classes,
        reactor=self.reactor, default_op_timeout=4.0, echo_op_period=6.0)

    self.addr = twisted.internet.address.IPv4Address('TCP', '192.168.1.1',
                                                     '14123')

  def test_build_protocol_reactor(self):
    self.factory.doStart()
    proto = self.factory.buildProtocol(self.addr)
    self.assertEqual(self.reactor, proto.reactor)
    self.factory.doStop()

  def test_build_protocol_default_op_timeout(self):
    self.factory._default_op_timeout = 42.0
    self.factory.doStart()
    proto = self.factory.buildProtocol(self.addr)
    self.assertEqual(42.0, proto.default_op_timeout)
    self.factory.doStop()

  def test_build_protocol_echo_op_period(self):
    self.factory._echo_op_period = 42.0
    self.factory.doStart()
    proto = self.factory.buildProtocol(self.addr)
    self.assertEqual(42.0, proto.echo_op_period)
    self.factory.doStop()


if __name__ == '__main__':
  # Disable logging during unittests.
  import logging
  logging.basicConfig(level=logging.CRITICAL)
  #logging.basicConfig(level=logging.DEBUG,
  #                    format='%(asctime)s %(levelname)s %(message)s',
  #                    filename='unittest.log',
  #                    filemode='w')
  unittest2.main()
