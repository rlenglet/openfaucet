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

"""Mock implementations of OpenFlow vendor extension interfaces.
"""


import struct
from zope import interface

from openfaucet import ofaction
from openfaucet import ofproto


MOCK_VENDOR_ID = 0x4242


class MockVendorAction(ofaction.vendor_action(
    'MockVendorAction', MOCK_VENDOR_ID, '!2xL', ('dummy',))):

    subtype = 0x1664


class MockVendorHandler(object):
    """A mock vendor extension implementation.

    All callbacks made to this object are appended as tuples into
    attribute calls_made.
    """

    interface.implements(ofproto.IOpenflowVendorHandler)

    vendor_id = MOCK_VENDOR_ID

    def __init__(self):
        # A list of tuples representing calls.
        self.calls_made = []

    def connection_made(self):
        pass

    def connection_lost(self, reason):
        pass

    def handle_vendor_message(self, msg_length, xid, buf):
        bytes = buf.read_bytes(msg_length - 12)  # Consume the remaining bytes.
        self.calls_made.append(('handle_vendor_message', msg_length, xid,
                                bytes))

    def serialize_vendor_action(self, action):
        self.calls_made.append(('serialize_vendor_action', action))
        subtype = action.subtype
        if subtype != MockVendorAction.subtype:
            raise ValueError('wrong vendor action subtype', subtype)
        header = struct.pack('!H', subtype)
        return (header, action.serialize())

    def deserialize_vendor_action(self, action_length, buf):
        subtype = buf.unpack('!H')[0]
        if subtype != MockVendorAction.subtype:
            raise ValueError('wrong vendor action subtype', subtype)
        a = MockVendorAction.deserialize(buf)
        self.calls_made.append(('deserialize_vendor_action', action_length, a))
        return a

    def handle_vendor_stats_request(self, msg_length, xid, buf):
        bytes = buf.read_bytes(msg_length - 16)  # Consume the remaining bytes.
        self.calls_made.append(('handle_vendor_stats_request', msg_length,
                                xid, bytes))

    def handle_vendor_stats_reply(self, msg_length, xid, buf, reply_more):
        bytes = buf.read_bytes(msg_length - 16)  # Consume the remaining bytes.
        self.calls_made.append(('handle_vendor_stats_reply', msg_length,
                                xid, bytes, reply_more))
