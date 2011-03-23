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

"""Mock implementation of the OpenFlow protocol.
"""


import struct
import twisted.python.failure
import twisted.internet.error

from openfaucet import ofproto


class MockOpenflowProtocolHandler(ofproto.OpenflowProtocol):
    """A mock implementation of the OpenFlow 1.0 protocol.

    All handle_* callbacks made to this object are appended as tuples
    into attribute calls_made.

    This is a subclass of OpenFaucet's OpenflowProtocol class, so that
    all calls to send_* methods result in messages being written into
    the transport connection. Only handle_* methods are mocked.
    """

    def __init__(self):
        ofproto.OpenflowProtocol.__init__(self)
        self.calls_made = []

    def handle_hello(self):
        self.calls_made.append(('handle_hello',))

    def handle_error(self, xid, error):
        self.calls_made.append(('handle_error', xid, error))

    def handle_echo_request(self, xid, data):
        self.calls_made.append(('handle_echo_request', xid, data))

    def handle_echo_reply(self, xid, data):
        self.calls_made.append(('handle_echo_reply', xid, data))

    def handle_features_request(self, xid):
        self.calls_made.append(('handle_features_request', xid))

    def handle_features_reply(self, xid, switch_features):
        self.calls_made.append(('handle_features_reply', xid, switch_features))

    def handle_get_config_request(self, xid):
        self.calls_made.append(('handle_get_config_request', xid))

    def handle_get_config_reply(self, xid, switch_config):
        self.calls_made.append(('handle_get_config_reply', xid, switch_config))

    def handle_set_config(self, switch_config):
        self.calls_made.append(('handle_set_config', switch_config))

    def handle_packet_in(self, buffer_id, total_len, in_port, reason, data):
        self.calls_made.append(('handle_packet_in', buffer_id, total_len,
                                in_port, reason, data))

    def handle_flow_removed(
        self, match, cookie, priority, reason, duration_sec, duration_nsec,
        idle_timeout, packet_count, byte_count):
        self.calls_made.append((
            'handle_flow_removed', match, cookie, priority, reason,
            duration_sec, duration_nsec, idle_timeout, packet_count,
            byte_count))

    def handle_port_status(self, reason, desc):
        self.calls_made.append(('handle_port_status', reason, desc))

    def handle_packet_out(self, buffer_id, in_port, actions, data):
        self.calls_made.append(('handle_packet_out', buffer_id, in_port,
                                actions, data))

    def handle_flow_mod_add(
        self, match, cookie, idle_timeout, hard_timeout, priority, buffer_id,
        send_flow_rem, check_overlap, emerg, actions):
        self.calls_made.append((
            'handle_flow_mod_add', match, cookie, idle_timeout, hard_timeout,
            priority, buffer_id, send_flow_rem, check_overlap, emerg, actions))

    def handle_flow_mod_modify(
        self, strict, match, cookie, idle_timeout, hard_timeout, priority,
        buffer_id, send_flow_rem, check_overlap, emerg, actions):
        self.calls_made.append((
            'handle_flow_mod_modify', strict, match, cookie, idle_timeout,
            hard_timeout, priority, buffer_id, send_flow_rem, check_overlap,
            emerg, actions))

    def handle_flow_mod_delete(self, strict, match, priority, out_port):
        self.calls_made.append(('handle_flow_mod_delete', strict, match,
                                priority, out_port))

    def handle_port_mod(self, port_no, hw_addr, config, mask, advertise):
        self.calls_made.append(('handle_port_mod', port_no, hw_addr, config,
                                mask, advertise))

    def handle_stats_request_desc(self, xid):
        self.calls_made.append(('handle_stats_request_desc', xid))

    def handle_stats_request_flow(self, xid, match, table_id, out_port):
        self.calls_made.append(('handle_stats_request_flow', xid, match,
                                table_id, out_port))

    def handle_stats_request_aggregate(self, xid, match, table_id, out_port):
        self.calls_made.append(('handle_stats_request_aggregate', xid, match,
                                table_id, out_port))

    def handle_stats_request_table(self, xid):
        self.calls_made.append(('handle_stats_request_table', xid))

    def handle_stats_request_port(self, xid, port_no):
        self.calls_made.append(('handle_stats_request_port', xid, port_no))

    def handle_stats_request_queue(self, xid, port_no, queue_id):
        self.calls_made.append(('handle_stats_request_queue', xid, port_no,
                                queue_id))

    def handle_stats_reply_desc(self, xid, desc_stats):
        self.calls_made.append(('handle_stats_reply_desc', xid, desc_stats))

    def handle_stats_reply_flow(self, xid, flow_stats, reply_more):
        self.calls_made.append(('handle_stats_reply_flow', xid, flow_stats,
                                reply_more))

    def handle_stats_reply_aggregate(self, xid, packet_count, byte_count,
                                     flow_count):
        self.calls_made.append(('handle_stats_reply_aggregate', xid,
                                packet_count, byte_count, flow_count))

    def handle_stats_reply_table(self, xid, table_stats, reply_more):
        self.calls_made.append(('handle_stats_reply_table', xid, table_stats,
                                reply_more))

    def handle_stats_reply_port(self, xid, port_stats, reply_more):
        self.calls_made.append(('handle_stats_reply_port', xid, port_stats,
                                reply_more))

    def handle_stats_reply_queue(self, xid, queue_stats, reply_more):
        self.calls_made.append(('handle_stats_reply_queue', xid, queue_stats,
                                reply_more))

    def handle_barrier_request(self, xid):
        self.calls_made.append(('handle_barrier_request', xid))

    def handle_barrier_reply(self, xid):
        self.calls_made.append(('handle_barrier_reply', xid))

    def handle_queue_get_config_request(self, xid, port_no):
        self.calls_made.append(('handle_queue_get_config_request', xid,
                                port_no))

    def handle_queue_get_config_reply(self, xid, port_no, queues):
        self.calls_made.append(('handle_queue_get_config_reply', xid, port_no,
                                queues))


class LoopbackTransport(object):
    """A twisted ITransport that directly writes data into an IProtocol.
    """

    def __init__(self, protocol, host, peer):
        """Initialize this transport to write all data into the given protocol.

        Args:
            protocol: An IProtocol object.
            peer: The remote address of this connection, as an
                IAddress object.
            host: The local address of this connection, as an IAddress
                object.
        """
        self._protocol = protocol
        self._host = host
        self._peer = peer
        self.open = True

    def write(self, data):
        self._protocol.dataReceived(data)

    def writeSequence(self, data):
        for d in data:
            self.write(d)

    def loseConnection(self):
        self._protocol.connectionLost(twisted.python.failure.Failure(
            twisted.internet.error.ConnectionDone()))
        self.open = False

    def getHost(self):
        return self._host

    def getPeer(self):
        return self._peer
