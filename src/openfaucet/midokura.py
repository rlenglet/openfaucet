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

"""Implementation of Midokura's OpenFlow vendor extensions.
"""


import struct
from zope import interface

from openfaucet import ofaction
from openfaucet import oferror
from openfaucet import ofproto


MIDOKURA_VENDOR_ID = 0x00ACCABA


MIDO_ACTION_CHECK_TCP_FLAGS = 0
MIDO_ACTION_CHECK_ACK_SEQ_NUM = 1


class MidoActionCheckTCPFlags(
    ofaction.vendor_action('MidoActionCheckTCPFlags', MIDOKURA_VENDOR_ID,
                           '!B5x', ('tcp_flags',))):
    """Send any packets which have any of the TCP flags set in 'tcp_flags' to
    the controller.
    """

    subtype = MIDO_ACTION_CHECK_TCP_FLAGS


class MidoActionCheckAckSeqNum(
    ofaction.vendor_action('MidoActionCheckAckSeqNum', MIDOKURA_VENDOR_ID,
                           '!2xI', ('ack_seq_num',))):
    """Send any packets which have an acknowledged sequence number of
    'ack_seq_num' to the controller.
    """

    subtype = MIDO_ACTION_CHECK_ACK_SEQ_NUM


class MidokuraVendorHandler(object):
    """Extension handler for Midokura's vendor extensions."""

    interface.implements(ofproto.IOpenflowVendorHandler)

    vendor_id = MIDOKURA_VENDOR_ID

    @staticmethod
    def serialize_vendor_action(action):
        header = struct.pack('!H', action.subtype)
        return (header, action.serialize())

    def deserialize_vendor_action(self, length, buffer):
        subtype = buffer.unpack('!H')[0]
        if subtype == MIDO_ACTION_CHECK_TCP_FLAGS:
            return MidoActionCheckTCPFlags.deserialize(buffer)
        if subtype == MIDO_ACTION_CHECK_ACK_SEQ_NUM:
            return MidoActionCheckAckSeqNum.deserialize(buffer)
        # TODO(romain): Handle error reporting in an excetpion
        # handler, then make this into a @staticmethod which raises an
        # exception.
        self.protocol().logger.error(
            'unknown Midokura extension action subtype', subtype)
        self.protocol().raise_error_with_request(
            oferror.OFPET_BAD_ACTION, oferror.OFPBAC_BAD_VENDOR_TYPE)

    # protocol() method injected into instances by OpenflowProtocolFactory.
    # def protocol(self):
    #     """Returns the protocol object passed to the
    #     OpenflowProtocolFactory which was passed this VendorHandler.
    #     """

    # Required methods.

    def connection_made(self):
        pass

    def connection_lost(self, reason):
        pass

    # Unsupported handler methods.

    def handle_vendor_message(self, msg_length, xid, buffer):
        self.protocol().raise_error_with_request(
            oferror.OFPET_BAD_REQUEST, oferror.OFPBRC_BAD_SUBTYPE)

    def handle_vendor_stats_request(self, msg_length, xid, buffer):
        self.protocol().raise_error_with_request(
            oferror.OFPET_BAD_REQUEST, oferror.OFPBRC_BAD_SUBTYPE)

    def handle_vendor_stats_reply(self, msg_length, xid, buffer,
                                  reply_more):
        self.protocol().raise_error_with_request(
            oferror.OFPET_BAD_REQUEST, oferror.OFPBRC_BAD_SUBTYPE)
