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

"""Implementation of an OpenFlow 1.0.0 controller stub.
"""

import collections
import logging
import threading
import weakref
import twisted.internet.reactor
from zope import interface

from openfaucet import oferror
from openfaucet import ofproto
from openfaucet import ofprotoops


class IOpenflowController(interface.Interface):
    """A handler of asynchronous messages received from a datapath.
    """

    def connection_made():
        """Initialize resources to manage the newly opened OpenFlow connection.

        This is called only after the handshake with the switch is
        completed, i.e. once the switch's features have been received.
        """

    def connection_lost(reason):
        """Release resources used to manage the connection that was just lost.

        All operations that are still pending when this method is
        called back are cancelled silently.

        Args:
            reason: A twisted.python.failure.Failure that wraps a
                twisted.internet.error.ConnectionDone or
                twisted.internet.error.ConnectionLost instance (or a
                subclass of one of those).
        """

    def handle_packet_in(buffer_id, total_len, in_port, reason, data):
        """Handle the reception of a OFPT_PACKET_IN message.

        Args:
            buffer_id: The buffer ID assigned by the datapath. If
                0xffffffff, the frame is not buffered, and the entire
                frame is passed in data.

            total_len: The full length of the frame.
            in_port: The port on which the frame was received.
            reason: The reason why the frame is being sent, either
                OFPR_NO_MATCH (no matching flow) or OFPR_ACTION
                (action explicitly output to controller).
            data: The Ethernet frame, as a binary string.
        """

    def handle_flow_removed(
        match, cookie, priority, reason, duration_sec, duration_nsec,
        idle_timeout, packet_count, byte_count):
        """Handle the reception of a OFPT_FLOW_REMOVED message.

        Args:
            match: A Match object describing the fields of the flow.
            cookie: An opaque 64-bit unsigned integer issued by the
                controller.
            priority: The priority level of the expired flow entry, as
                a 16-bit unsigned integer.
            reason: The reason why the flow entry expired, either
                OFPRR_IDLE_TIMEOUT (flow idle time exceeded idle_timeout),
                OFPRR_HARD_TIMEOUT (time exceeded hard_timeout), or
                OFPRR_DELETE (evicted by a DELETE flow mod message).
            duration_sec: Time the flow was alive in seconds, as a
                32-bit unsigned integer.
            duration_nsec: Time flow was alive in nanoseconds beyond
                duration_sec, as a 32-bit unsigned integer.
            idle_timeout: The idle timeout in seconds from the
                original flow mod, as a 16-bit unsigned integer.
            packet_count: The number of packets in the flow, as a
                64-bit unsigned integer.
            byte_count: The number of bytes in packets in the flow, as
                a 64-bit unsigned integer.
        """

    def handle_port_status(reason, desc):
        """Handle the reception of a OFPT_PORT_STATUS message.

        Args:
            reason: The reason for the port status change, either
                OFPPR_ADD (the port was added), OFPPR_DELETE (the port
                was removed), or OFPPR_MODIFY (some attribute of the
                port has changed).
            desc: A PhyPort object defining the physical port.
        """


class IOpenflowControllerStub(interface.Interface):
    """An encoder of messages to a datapath.
    """

    def get_features(callback, timeout_callback=None, timeout=None):
        """Request the switch features.

        This operation is asynchronous: the switch features are passed
        back by calling the given callback as:

        callback(switch_features)

        with arguments:
            switch_features: A SwitchFeatures object containing the
                switch features.

        Using this object's features attribute is more efficient than
        calling this method, so this method should normally not be
        called by controllers.

        Args:
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation
                times out. If None, defaults to the default timeout.
        """

    features = interface.Attribute(
        """The SwitchFeatures object describing the switch features.

        None if the handshake with the datapath has not yet been
        completed.

        This SwitchFeatures object is automatically updated by this
        stub when any port status changes.
        """)

    def get_config(callback, timeout_callback=None, timeout=None):
        """Request the switch config.

        This operation is asynchronous: the switch config is passed
        back by calling the given callback as:

        callback(switch_config)

        with arguments:
            switch_config: A SwitchConfig object containing the switch
                configuration.

        Args:
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation
                times out. If None, defaults to the default timeout.
        """

    def send_set_config(switch_config):
        """Send a OFPT_SET_CONFIG message.

        Args:
            switch_config: A SwitchConfig object containing the switch
                configuration.
        """

    def send_packet_out(buffer_id, in_port, actions, data):
        """Send a OFPT_PACKET_OUT message.

        Args:
            buffer_id: The buffer ID assigned by the datapath, as a
                32-bit unsigned integer. If 0xffffffff, the frame is
                not buffered, and the entire frame must be passed in
                data.
            in_port: The port from which the frame is to be
                sent. OFPP_NONE if none.
            actions: The sequence of Action* objects specifying the
                actions to perform on the frame.
            data: The entire Ethernet frame, as a sequence of byte
                buffers. Should be of length 0 if buffer_id is -1, and
                should be of length >0 otherwise.
        """

    def send_flow_mod_add(
        match, cookie, idle_timeout, hard_timeout, priority, buffer_id,
        send_flow_rem, check_overlap, emerg, actions):
        """Send a OFPT_FLOW_MOD message to add a flow.

        Args:
            match: A Match object describing the fields of the flow.
            cookie: An opaque 64-bit unsigned integer issued by the
                controller. 0xffffffffffffffff is reserved and must
                not be used.
            idle_timeout: The idle time in seconds before discarding,
                as a 16-bit unsigned integer.
            hard_timeout: The maximum time before discarding in
                seconds, as a 16-bit unsigned integer.
            priority: The priority level of the flow entry, as a
                16-bit unsigned integer.
            buffer_id: The buffer ID assigned by the datapath of a
                buffered packet to apply the flow to, as a 32-bit
                unsigned integer. If 0xffffffff, no buffered packet is
                to be applied the flow actions.
            send_flow_rem: If True, send a OFPT_FLOW_REMOVED message
                when the flow expires or is deleted.
            check_overlap: If True, check for overlapping entries
                first, i.e. if there are conflicting entries with the
                same priority, the flow is not added and the
                modification fails.
            emerg: if True, the switch must consider this flow entry
                as an emergency entry, and only use it for forwarding
                when disconnected from the controller.
            actions: The sequence of Action* objects specifying the
                actions to perform on the flow's packets.
        """

    def send_flow_mod_modify(
        strict, match, cookie, idle_timeout, hard_timeout, priority,
        buffer_id, send_flow_rem, check_overlap, emerg, actions):
        """Send a OFPT_FLOW_MOD message to modify a flow.

        Args:
            strict: If True, all args, including the wildcards and
                priority, are strictly matched against the entry, and
                only an identical flow is modified. If False, a match
                will occur when a flow entry exactly matches or is
                more specific than the given match and priority.
            match: A Match object describing the fields of the flow.
            cookie: An opaque 64-bit unsigned integer issued by the
                controller. 0xffffffffffffffff is reserved and must
                not be used.
            idle_timeout: The idle time in seconds before discarding,
                as a 16-bit unsigned integer.
            hard_timeout: The maximum time before discarding in
                seconds, as a 16-bit unsigned integer.
            priority: The priority level of the flow entry, as a
                16-bit unsigned integer.
            buffer_id: The buffer ID assigned by the datapath of a
                buffered packet to apply the flow to, as a 32-bit
                unsigned integer. If 0xffffffff, no buffered packet is
                to be applied the flow actions.
            send_flow_rem: If True, send a OFPT_FLOW_REMOVED message
                when the flow expires or is deleted.
            check_overlap: If True, check for overlapping entries
                first, i.e. if there are conflicting entries with the
                same priority, the flow is not modified and the
                modification fails.
            emerg: if True, the switch must consider this flow entry
                as an emergency entry, and only use it for forwarding
                when disconnected from the controller.
            actions: The sequence of Action* objects specifying the
                actions to perform on the flow's packets.
        """

    def send_flow_mod_delete(strict, match, priority, out_port):
        """Send a OFPT_FLOW_MOD message to delete a flow.

        Args:
            strict: If True, all args, including the wildcards and
                priority, are strictly matched against the entry, and
                only an identical flow is deleted. If False, a match
                will occur when a flow entry exactly matches or is
                more specific than the given match and priority.
            match: A Match object describing the fields of the flow.
            priority: The priority level of the flow entry, as a
                16-bit unsigned integer.
            out_port: An output port that is required to be included
                in matching flows' output actions. If OFPP_NONE, no
                restriction applies in matching.
        """

    def send_port_mod(port_no, hw_addr, config, mask, advertise):
        """Send a OFPT_PORT_MOD message.

        The config and mask arguments can be obtained by calling
        get_diff() on a PortConfig object.

        Args:
            port_no: The port's unique number, as a 16-bit unsigned
                integer. Must be between 1 and OFPP_MAX.
            hw_addr: The port's MAC address, as a binary string. The
                hardware address is not configurable. This is used
                only to sanity-check the request, so it must be the
                same as returned in PhyPort object.
            config: The PortConfig containing the new values of fields
                to replace. Only the fields which are True in mask are
                replaced, the others are ignored.
            mask: The PortConfig indicating which fields are to be
                replaced with values from config.
            advertise: The PortFeatures indicating the features to be
                advertised by the port. If None or all fields are
                False, the advertised features are not replaced.
        """

    def get_stats_desc(callback, timeout_callback=None, timeout=None):
        """Request the switch stats.

        This operation is asynchronous: the switch stats are passed
        back by calling the given callback as:

        callback(desc_stats)

        with arguments:
            desc_stats: A DescriptionStats that contains the switch
                description stats.

        Args:
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation
                times out. If None, defaults to the default timeout.
        """

    def get_stats_flow(match, table_id, out_port, callback,
                       timeout_callback=None, timeout=None):
        """Request individual flow stats.

        This operation is asynchronous: the flow stats are passed back
        by calling the given callback as:

        callback(flow_stats, reply_more)

        with arguments:
            flow_stats: A tuple of FlowStats objects containing each
                the stats for an individual flow.
            reply_more: If True, more callbacks will be made to the
                callable after this one to completely terminate this
                operation. If False, this is the last callback in this
                operation.

        Args:
            match: A Match object describing the fields of the flows
                to match.
            table_id: The ID of the table to read, as an 8-bit
                unsigned integer. 0xff for all tables or 0xfe for
                emergency.
            out_port: Require matching flows to include this as an
                output port. A value of OFPP_NONE indicates no
                restriction.
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation times
                out. If None, defaults to the default timeout.
        """

    def get_stats_aggregate(match, table_id, out_port, callback,
                            timeout_callback=None, timeout=None):
        """Request aggregate flow stats.

        This operation is asynchronous: the aggregate flow stats are
        passed back by calling the given callback as:

        callback(packet_count, byte_count, flow_count)

        with arguments:
            packet_count: The number of packets in aggregated flows,
                as a 64-bit unsigned integer.
            byte_count: The number of bytes in aggregated flows, as a
                64-bit unsigned integer.
            flow_count: The number of aggregated flows, as a 32-bit
                unsigned integer.

        Args:
            match: A Match object describing the fields of the flows
                to match.
            table_id: The ID of the table to read, as an 8-bit
                unsigned integer. 0xff for all tables or 0xfe for
                emergency.
            out_port: Require matching flows to include this as an
                output port. A value of OFPP_NONE indicates no
                restriction.
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation
                times out. If None, defaults to the default timeout.
        """

    def get_stats_table(callback, timeout_callback=None, timeout=None):
        """Request table stats.

        This operation is asynchronous: the table stats are passed
        back by calling the given callback as:

        callback(table_stats, reply_more)

        with arguments:
            table_stats: A tuple of TableStats objects containing each
                the stats for an individual table.
            reply_more: If True, more callbacks will be made to the
                callable after this one to completely terminate this
                operation. If False, this is the last callback in this
                operation.

        Args:
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation times
                out. If None, defaults to the default timeout.
        """

    def get_stats_port(port_no, callback, timeout_callback=None,
                       timeout=None):
        """Request port stats.

        This operation is asynchronous: the port stats are passed back
        by calling the given callback as:

        callback(port_stats, reply_more)

        with arguments:
            port_stats: A tuple of PortStats objects containing each
                the stats for an individual port.
            reply_more: If True, more callbacks will be made to the
                callable after this one to completely terminate this
                operation. If False, this is the last callback in this
                operation.

        Args:
            port_no: The port's unique number, as a 16-bit unsigned
                integer. If OFPP_NONE, stats for all ports are
                replied.
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation times
                out. If None, defaults to the default timeout.
        """

    def get_stats_queue(port_no, queue_id, callback, timeout_callback=None,
                        timeout=None):
        """Request queue stats.

        This operation is asynchronous: the queue stats are passed
        back by calling the given callback as:

        callback(queue_stats, reply_more)

        with arguments:
            queue_stats: A tuple of QueueStats objects containing each
                the stats for an individual queue.
            reply_more: If True, more callbacks will be made to the
                callable after this one to completely terminate this
                operation. If False, this is the last callback in this
                operation.

        Args:
            port_no: The port's unique number, as a 16-bit unsigned
                integer. If OFPP_ALL, stats for all ports are replied.
            queue_id: The queue's ID. If OFPQ_ALL, stats for all
                queues are replied.
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation times
                out. If None, defaults to the default timeout.
        """

    def barrier(callback, timeout_callback=None, timeout=None):
        """Request a synchronization barrier.

        This operation is asynchronous: the given callback is called
        when the barrier is reached as:

        callback()

        Args:
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation times
                out. If None, defaults to the default timeout.
        """

    def get_queue_config(port_no, callback, timeout_callback=None,
                         timeout=None):
        """Request a port's queues configs.

        This operation is asynchronous: the port's queues configs are
        passed back by calling the given callback as:

        callback(port_no, queues)

        with arguments:
            port_no: The port's unique number, as a 16-bit unsigned
                integer. Must be a valid physical port, i.e. <
                OFPP_MAX.
            queues: A sequence of PacketQueue objects describing the
                port's queues.

        Args:
            port_no: The port's unique number, as a 16-bit unsigned
                integer. Must be a valid physical port, i.e. <
                OFPP_MAX.
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation times
                out. If None, defaults to the default timeout.
        """

    def raise_error_with_request(error_type, error_code):
        """Raise an OpenFlow error with the failed request.

        The raised exception's data contains at least 64 bytes of the
        currently handled message. This method must be called from a
        message handling callback.

        Args:
            error_type: The error type, as one of the OFPET_*
                constants.
            error_code: The error code, as one of the OFP* error code
                constants.

        Raises:
            OpenflowError: Always.
        """


class OpenflowControllerStub(ofprotoops.OpenflowProtocolOperations):
    """A basic implementation of the OpenFlow 1.0 protocol controller side.

    This is a stub for an actual controller, which is an object
    implementing the IOpenflowController interface. The controller
    must be set in the 'controller' attribute of this object.

    The switch features description is kept in attribute 'features',
    and is kept up-to-date transparently when port mod messages are
    received.
    """

    interface.implements(IOpenflowControllerStub)

    def __init__(self):
        ofprotoops.OpenflowProtocolOperations.__init__(self)
        self._features = None
        self._features_lock = threading.Lock()

    def connectionMade(self):
        """Initialize resources to manage the newly opened OpenFlow connection.

        Send a request for the switch features as the
        controller-to-switch handshake.
        """
        ofprotoops.OpenflowProtocolOperations.connectionMade(self)
        self._features = None
        self.logger.info('controller stub configuration: controller=%r',
                         self.controller, extra=self.log_extra)

        # At handshake completion, call back the controller's
        # connection_made() callback, which is done in
        # handle_features_reply(). In case the handshake times out,
        # close the connection.
        self.get_features(None, timeout_callback=self.transport.loseConnection)

    def connectionLost(self, reason):
        """Release resources used to manage the connection that was just lost.

        Call connection_lost() on the controller.

        Args:
            reason: A twisted.python.failure.Failure that wraps a
                twisted.internet.error.ConnectionDone or
                twisted.internet.error.ConnectionLost instance (or a
                subclass of one of those).
        """
        ofprotoops.OpenflowProtocolOperations.connectionLost(self, reason)
        self.controller.connection_lost(reason)

    @property
    def features(self):
        """Get the switch features.

        The returned SwitchFeatures object is automatically updated by
        this stub when the status of ports is modified.

        Returns:

            The SwitchFeatures object describing the switch features,
            or None if the handshake with the datapath has not yet
            been completed.
        """
        with self._features_lock:
            return self._features

    # ----------------------------------------------------------------------
    # Controller operations API.
    # ----------------------------------------------------------------------

    def get_features(self, callback, timeout_callback=None, timeout=None):
        """Request the switch features.

        This operation is asynchronous: the switch features are passed
        back by calling the given callback as:

        callback(switch_features)

        with arguments:
            switch_features: A SwitchFeatures object containing the
                switch features.

        Using this object's features attribute is more efficient than
        calling this method, so this method should normally not be
        called by controllers.

        Args:
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation
                times out. If None, defaults to the default timeout.
        """
        xid = self.initiate_operation(
            callback, timeout_callback, timeout=timeout,
            cookie=ofproto.OFPT_FEATURES_REQUEST)
        self.send_features_request(xid)

    def get_config(self, callback, timeout_callback=None, timeout=None):
        """Request the switch config.

        This operation is asynchronous: the switch config is passed
        back by calling the given callback as:

        callback(switch_config)

        with arguments:
            switch_config: A SwitchConfig object containing the switch
                configuration.

        Args:
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation
                times out. If None, defaults to the default timeout.
        """
        xid = self.initiate_operation(
            callback, timeout_callback, timeout=timeout,
            cookie=ofproto.OFPT_GET_CONFIG_REQUEST)
        self.send_get_config_request(xid)

    def get_stats_desc(self, callback, timeout_callback=None, timeout=None):
        """Request the switch stats.

        This operation is asynchronous: the switch stats are passed
        back by calling the given callback as:

        callback(desc_stats)

        with arguments:
            desc_stats: A DescriptionStats that contains the switch
                description stats.

        Args:
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation
                times out. If None, defaults to the default timeout.
        """
        xid = self.initiate_operation(
            callback, timeout_callback, timeout=timeout,
            cookie=(ofproto.OFPT_STATS_REQUEST, ofproto.OFPST_DESC))
        self.send_stats_request_desc(xid)

    def get_stats_flow(self, match, table_id, out_port, callback,
                       timeout_callback=None, timeout=None):
        """Request individual flow stats.

        This operation is asynchronous: the flow stats are passed back
        by calling the given callback as:

        callback(flow_stats, reply_more)

        with arguments:
            flow_stats: A tuple of FlowStats objects containing each
                the stats for an individual flow.
            reply_more: If True, more callbacks will be made to the
                callable after this one to completely terminate this
                operation. If False, this is the last callback in this
                operation.

        Args:
            match: A Match object describing the fields of the flows
                to match.
            table_id: The ID of the table to read, as an 8-bit
                unsigned integer. 0xff for all tables or 0xfe for
                emergency.
            out_port: Require matching flows to include this as an
                output port. A value of OFPP_NONE indicates no
                restriction.
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation times
                out. If None, defaults to the default timeout.
        """
        xid = self.initiate_operation(
            callback, timeout_callback, timeout=timeout,
            cookie=(ofproto.OFPT_STATS_REQUEST, ofproto.OFPST_FLOW))
        self.send_stats_request_flow(xid, match, table_id, out_port)

    def get_stats_aggregate(self, match, table_id, out_port, callback,
                            timeout_callback=None, timeout=None):
        """Request aggregate flow stats.

        This operation is asynchronous: the aggregate flow stats are
        passed back by calling the given callback as:

        callback(packet_count, byte_count, flow_count)

        with arguments:
            packet_count: The number of packets in aggregated flows,
                as a 64-bit unsigned integer.
            byte_count: The number of bytes in aggregated flows, as a
                64-bit unsigned integer.
            flow_count: The number of aggregated flows, as a 32-bit
                unsigned integer.

        Args:
            match: A Match object describing the fields of the flows
                to match.
            table_id: The ID of the table to read, as an 8-bit
                unsigned integer. 0xff for all tables or 0xfe for
                emergency.
            out_port: Require matching flows to include this as an
                output port. A value of OFPP_NONE indicates no
                restriction.
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation
                times out. If None, defaults to the default timeout.
        """
        xid = self.initiate_operation(
            callback, timeout_callback, timeout=timeout,
            cookie=(ofproto.OFPT_STATS_REQUEST, ofproto.OFPST_AGGREGATE))
        self.send_stats_request_aggregate(xid, match, table_id, out_port)

    def get_stats_table(self, callback, timeout_callback=None, timeout=None):
        """Request table stats.

        This operation is asynchronous: the table stats are passed
        back by calling the given callback as:

        callback(table_stats, reply_more)

        with arguments:
            table_stats: A tuple of TableStats objects containing each
                the stats for an individual table.
            reply_more: If True, more callbacks will be made to the
                callable after this one to completely terminate this
                operation. If False, this is the last callback in this
                operation.

        Args:
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation times
                out. If None, defaults to the default timeout.
        """
        xid = self.initiate_operation(
            callback, timeout_callback, timeout=timeout,
            cookie=(ofproto.OFPT_STATS_REQUEST, ofproto.OFPST_TABLE))
        self.send_stats_request_table(xid)

    def get_stats_port(self, port_no, callback, timeout_callback=None,
                       timeout=None):
        """Request port stats.

        This operation is asynchronous: the port stats are passed back
        by calling the given callback as:

        callback(port_stats, reply_more)

        with arguments:
            port_stats: A tuple of PortStats objects containing each
                the stats for an individual port.
            reply_more: If True, more callbacks will be made to the
                callable after this one to completely terminate this
                operation. If False, this is the last callback in this
                operation.

        Args:
            port_no: The port's unique number, as a 16-bit unsigned
                integer. If OFPP_NONE, stats for all ports are
                replied.
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation times
                out. If None, defaults to the default timeout.
        """
        xid = self.initiate_operation(
            callback, timeout_callback, timeout=timeout,
            cookie=(ofproto.OFPT_STATS_REQUEST, ofproto.OFPST_PORT))
        self.send_stats_request_port(xid, port_no)

    def get_stats_queue(self, port_no, queue_id, callback,
                        timeout_callback=None, timeout=None):
        """Request queue stats.

        This operation is asynchronous: the queue stats are passed
        back by calling the given callback as:

        callback(queue_stats, reply_more)

        with arguments:
            queue_stats: A tuple of QueueStats objects containing each
                the stats for an individual queue.
            reply_more: If True, more callbacks will be made to the
                callable after this one to completely terminate this
                operation. If False, this is the last callback in this
                operation.

        Args:
            port_no: The port's unique number, as a 16-bit unsigned
                integer. If OFPP_ALL, stats for all ports are replied.
            queue_id: The queue's ID. If OFPQ_ALL, stats for all
                queues are replied.
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation times
                out. If None, defaults to the default timeout.
        """
        xid = self.initiate_operation(
            callback, timeout_callback, timeout=timeout,
            cookie=(ofproto.OFPT_STATS_REQUEST, ofproto.OFPST_QUEUE))
        self.send_stats_request_queue(xid, port_no, queue_id)

    def barrier(self, callback, timeout_callback=None, timeout=None):
        """Request a synchronization barrier.

        This operation is asynchronous: the given callback is called
        when the barrier is reached as:

        callback()

        Args:
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation times
                out. If None, defaults to the default timeout.
        """
        xid = self.initiate_operation(
            callback, timeout_callback, timeout=timeout,
            cookie=ofproto.OFPT_BARRIER_REQUEST)
        self.send_barrier_request(xid)

    def get_queue_config(self, port_no, callback, timeout_callback=None,
                         timeout=None):
        """Request a port's queues configs.

        This operation is asynchronous: the port's queues configs are
        passed back by calling the given callback as:

        callback(port_no, queues)

        with arguments:
            port_no: The port's unique number, as a 16-bit unsigned
                integer. Must be a valid physical port, i.e. <
                OFPP_MAX.
            queues: A sequence of PacketQueue objects describing the
                port's queues.

        Args:
            port_no: The port's unique number, as a 16-bit unsigned
                integer. Must be a valid physical port, i.e. <
                OFPP_MAX.
            callback: The callable to be called with the replied data.
            timeout_callback: The callable to be called in case the
                operation times out.
            timeout: The period, in seconds, before the operation times
                out. If None, defaults to the default timeout.
        """
        xid = self.initiate_operation(
            callback, timeout_callback, timeout=timeout,
            cookie=ofproto.OFPT_QUEUE_GET_CONFIG_REQUEST)
        self.send_queue_get_config_request(xid, port_no)

    # ----------------------------------------------------------------------
    # Internal handling of incoming messages, incl. operation replies.
    # ----------------------------------------------------------------------

    def handle_features_reply(self, xid, switch_features):
        success_callable = self.terminate_operation(
            xid, cookie=ofproto.OFPT_FEATURES_REQUEST)
        first_time = False

        # Update the local copy of the switch features, accessible in
        # property 'features'.
        with self._features_lock:

            if self._features is None:
                first_time = True

            self._features = switch_features

        # This is the first time we receive an
        # OFPT_FEATURES_REPLY, which means that this
        # terminates the handshake with the datapath. Callback
        # the controller.
        if first_time:
            self.controller.connection_made()

        if success_callable is not None:
            success_callable(switch_features)

    def handle_get_config_reply(self, xid, switch_config):
        success_callable = self.terminate_operation(
            xid, cookie=ofproto.OFPT_GET_CONFIG_REQUEST)
        if success_callable is not None:
            success_callable(switch_config)

    def handle_stats_reply_desc(self, xid, desc_stats):
        success_callable = self.terminate_operation(
            xid, cookie=(ofproto.OFPT_STATS_REQUEST, ofproto.OFPST_DESC))
        if success_callable is not None:
            success_callable(desc_stats)

    def handle_stats_reply_flow(self, xid, flow_stats, reply_more):
        success_callable = self.terminate_operation(
            xid, reply_more=reply_more,
            cookie=(ofproto.OFPT_STATS_REQUEST, ofproto.OFPST_FLOW))
        if success_callable is not None:
            success_callable(flow_stats, reply_more)

    def handle_stats_reply_aggregate(self, xid, packet_count, byte_count,
                                     flow_count):
        success_callable = self.terminate_operation(
            xid, cookie=(ofproto.OFPT_STATS_REQUEST, ofproto.OFPST_AGGREGATE))
        if success_callable is not None:
            success_callable(packet_count, byte_count, flow_count)

    def handle_stats_reply_table(self, xid, table_stats, reply_more):
        success_callable = self.terminate_operation(
            xid, reply_more=reply_more,
            cookie=(ofproto.OFPT_STATS_REQUEST, ofproto.OFPST_TABLE))
        if success_callable is not None:
            success_callable(table_stats, reply_more)

    def handle_stats_reply_port(self, xid, port_stats, reply_more):
        success_callable = self.terminate_operation(
            xid, reply_more=reply_more,
            cookie=(ofproto.OFPT_STATS_REQUEST, ofproto.OFPST_PORT))
        if success_callable is not None:
            success_callable(port_stats, reply_more)

    def handle_stats_reply_queue(self, xid, queue_stats, reply_more):
        success_callable = self.terminate_operation(
            xid, reply_more=reply_more,
            cookie=(ofproto.OFPT_STATS_REQUEST, ofproto.OFPST_QUEUE))
        if success_callable is not None:
            success_callable(queue_stats, reply_more)

    def handle_barrier_reply(self, xid):
        success_callable = self.terminate_operation(
            xid, cookie=ofproto.OFPT_BARRIER_REQUEST)
        if success_callable is not None:
            success_callable()

    def handle_queue_get_config_reply(self, xid, port_no, queues):
        success_callable = self.terminate_operation(
            xid, cookie=ofproto.OFPT_QUEUE_GET_CONFIG_REQUEST)
        if success_callable is not None:
            success_callable(port_no, queues)

    # ----------------------------------------------------------------------
    # Internal handling of asynchronous operations by calling back the
    # controller.
    # ----------------------------------------------------------------------

    def handle_error(self, xid, error):
        # TODO(romain): Decide what to do with the error: pass it to the
        # controller?
        pass

    def handle_packet_in(self, buffer_id, total_len, in_port, reason, data):
        self.controller.handle_packet_in(buffer_id, total_len, in_port, reason,
                                         data)

    def handle_flow_removed(
        self, match, cookie, priority, reason, duration_sec, duration_nsec,
        idle_timeout, packet_count, byte_count):
        self.controller.handle_flow_removed(
            match, cookie, priority, reason, duration_sec, duration_nsec,
            idle_timeout, packet_count, byte_count)

    def handle_port_status(self, reason, desc):
        # Update the local copy of the switch features, accessible in
        # property 'features'.
        with self._features_lock:
            ports = self._features.ports
            if reason == ofproto.OFPPR_ADD:
                ports = ports + (desc,)
            elif reason == ofproto.OFPPR_DELETE:
                ports = tuple([p for p in ports if p.port_no != desc.port_no])
            else:  # reason == ofproto.OFPPR_MODIFY:
                ports = tuple([(desc if desc.port_no == p.port_no else p)
                               for p in ports])
            self._features = self._features._replace(ports=ports)

        self.controller.handle_port_status(reason, desc)

    # ----------------------------------------------------------------------
    # Internal handling of incoming messages that are not supported on
    # this controller side of the connection.
    # ----------------------------------------------------------------------

    def handle_features_request(self, xid):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_get_config_request(self, xid):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_set_config(self, switch_config):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_packet_out(self, buffer_id, in_port, actions, data):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_flow_mod_add(
        self, match, cookie, idle_timeout, hard_timeout, priority, buffer_id,
        send_flow_rem, check_overlap, emerg, actions):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_flow_mod_modify(
        self, strict, match, cookie, idle_timeout, hard_timeout, priority,
        buffer_id, send_flow_rem, check_overlap, emerg, actions):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_flow_mod_delete(self, strict, match, priority, out_port):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_port_mod(self, port_no, hw_addr, config, mask, advertise):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_stats_request_desc(self, xid):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_stats_request_flow(self, xid, match, table_id, out_port):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_stats_request_aggregate(self, xid, match, table_id, out_port):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_stats_request_table(self, xid):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_stats_request_port(self, xid, port_no):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_stats_request_queue(self, xid, port_no, queue_id):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_barrier_request(self, xid):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)

    def handle_queue_get_config_request(self, xid, port_no):
        self.raise_error_with_request(oferror.OFPET_BAD_REQUEST,
                                      oferror.OFPBRC_BAD_TYPE)


class OpenflowControllerStubFactory(
    ofprotoops.OpenflowProtocolOperationsFactory):
    """A Twisted factory of OpenflowControllerStub objects.
    """

    def __init__(self, controller, protocol=OpenflowControllerStub,
                 error_data_bytes=64, logger=logging.getLogger(''),
                 vendor_handlers=(), reactor=twisted.internet.reactor,
                 default_op_timeout=3.0, echo_op_period=5.0):
        """Initialize this OpenFlow protocol factory.

        Args:
            controller: The class of controller objects to create,
                which must implement interface IOpenflowController.
            protocol: The class of protocol objects to
                create. Defaults to class OpenflowControllerStub.
            error_data_bytes: The maximum number of bytes of erroneous
                requests to send back in an error message. Must be >=
                64. Defaults to 64.
            logger: The Python logger used for logging in every
                created protocol object. Defaults to the root logger.
            vendor_handlers: A sequence of vendor handler classes. One
                instance of every class is instantiated (with no
                arguments) and passed to every created protocol
                object. Defaults to an empty sequence.
            reactor: An object implementing Twisted's IReactorTime
                interface, used to do delayed calls. Defaults to
                Twisted's default reactor.
            default_op_timeout: The default period, in seconds, before
                an operation times out. This is also used as the
                timeout for echo operations. Defaults to 3.0
                (seconds).
            echo_op_period: The period, in seconds, between two echo
                operations. Defaults to 5.0 (seconds).
        """
        ofprotoops.OpenflowProtocolOperationsFactory.__init__(
            self, protocol=protocol, error_data_bytes=error_data_bytes,
            logger=logger, vendor_handlers=vendor_handlers, reactor=reactor,
            default_op_timeout=default_op_timeout,
            echo_op_period=echo_op_period)
        self._controller = controller
        self._logger.info(
            'controller stub factory configuration: controller=%r',
            self._controller)

    def buildProtocol(self, addr):
        """Create a protocol to handle an established connection.

        Create a new controller object and bind it with the created
        protocol object: the protocol object is set as a weak
        reference in attribute 'protocol' of the created controller
        object.

        Args:
            addr: The address of the newly-established connection, as
                a twisted.internet.interfaces.IAddress object.

        Returns:
            An OpenflowControllerStub object.
        """
        p = ofprotoops.OpenflowProtocolOperationsFactory.buildProtocol(
            self, addr)
        c = self._controller()
        p.controller = c
        c.protocol = weakref.ref(p)
        return p
