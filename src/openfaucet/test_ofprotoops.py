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

"""Unittests for ofprotoops.py.
"""

import struct
import unittest2
import weakref
import twisted.internet.address
import twisted.internet.error
import twisted.python.failure

from openfaucet import ofproto
from openfaucet import ofprotoops

from openfaucet import mock_ofproto
from openfaucet import mock_twisted
from openfaucet import mock_vendor


class TestOpenflowProtocolOperations(unittest2.TestCase):

    def setUp(self):
        self.reactor = mock_twisted.MockReactorTime()
        self.default_op_timeout = 3
        self.echo_op_period = 5

        self.peerproto = mock_ofproto.MockOpenflowProtocolHandler()
        self.peer_vendor_handler = mock_vendor.MockVendorHandler()
        self.peerproto.vendor_handlers = (self.peer_vendor_handler,)
        self.peer_vendor_handler.protocol = weakref.ref(self.peerproto)

        self.proto = ofprotoops.OpenflowProtocolOperations()
        self.vendor_handler = mock_vendor.MockVendorHandler()
        self.proto.vendor_handlers = (self.vendor_handler,)
        self.vendor_handler.protocol = weakref.ref(self.proto)
        self.proto.reactor = self.reactor
        self.proto.default_op_timeout = self.default_op_timeout
        self.proto.echo_op_period = self.echo_op_period

        host_address = twisted.internet.address.IPv4Address(
            'TCP', '192.168.1.1', '14123')
        peer_address = twisted.internet.address.IPv4Address(
            'TCP', '192.168.1.2', '14567')
        self.proto.transport = mock_ofproto.LoopbackTransport(
            self.peerproto, host_address, peer_address)
        self.peerproto.transport = mock_ofproto.LoopbackTransport(
            self.proto, peer_address, host_address)

        self.peerproto.connectionMade()

    def _get_next_sent_message(self):
        """Get the decoded next message sent by the protocol.

        Returns:
            A tuple describing a single message, or None if no message
            was sent.
        """
        calls_made = self.peerproto.calls_made
        if not calls_made:
            return None
        m = calls_made[0]
        self.peerproto.calls_made = calls_made[1:]
        return m

    def test_connection_made_send_hello_echo_request(self):
        self.proto.connectionMade()
        # Sent initial OFPT_HELLO with XID 0.
        self.assertTupleEqual(('handle_hello',),
                              self._get_next_sent_message())
        # Sent initial OFPT_ECHO_REQUEST with XID 0.
        self.assertEqual('handle_echo_request',
                         self._get_next_sent_message()[0])

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
        self.assertEqual('handle_echo_request', next_msg[0])
        self.assertEqual(0, next_msg[1])
        data = next_msg[2]  # 32-big random data
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
        self.peerproto.send_echo_reply(0, (data,))
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
        self.assertEqual('handle_echo_request', next_msg[0])
        self.assertEqual(1, next_msg[1])
        data = next_msg[2]  # 32-big random data
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
        self.assertEqual('handle_echo_request', next_msg[0])
        self.assertEqual(0, next_msg[1])
        data = next_msg[2]  # 32-big random data
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
        self.assertTrue(self.proto.transport.open)  # Connection open.

        # Let the echo operation time out.
        self.reactor.increment_time(self.default_op_timeout)
        self.assertFalse(self.proto.transport.open)  # Connection closed.

    def test_echo_op_wrong_data(self):
        self.proto.connectionMade()
        self._get_next_sent_message()  # Initial OFPT_HELLO.

        # Initial OFPT_ECHO_REQUEST with XID 0.
        next_msg = self._get_next_sent_message()
        self.assertEqual('handle_echo_request', next_msg[0])
        self.assertEqual(0, next_msg[1])
        data = next_msg[2]  # 32-big random data
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
        self.peerproto.send_echo_reply(0, ('garbage' + data,))
        # No error message sent back, as this is not a standard error.
        self.assertIsNone(self._get_next_sent_message())

    def test_handle_echo_request(self):
        self.proto.connectionMade()
        self._get_next_sent_message()  # Initial OFPT_HELLO.
        self._get_next_sent_message()  # Initial OFPT_ECHO_REQUEST.

        self.peerproto.send_echo_request(4, ('abcdefgh',))

        # Sent back an OFPT_ECHO_REPLY with same length, data, and XID 4.
        self.assertEqual(('handle_echo_reply', 4, 'abcdefgh'),
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
