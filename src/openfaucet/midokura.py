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

# Implementation of Midokura's OpenFlow vendor extensions.

import struct

from openfaucet import ofaction

MIDOKURA_VENDOR_ID = 0x00ACCABA
MIDO_ACTION_CHECK_TCP_FLAGS = 0
MIDO_ACTION_CHECK_ACK_SEQ_NUM = 1


class MidoActionCheckTCPFlags(ofaction.vendor_action('MidoActionCheckTCPFlags',
                                                     MIDOKURA_VENDOR_ID, '!B5x',
                                                     ('tcp_flags',))):
  subtype = MIDO_ACTION_CHECK_TCP_FLAGS


class MidoActionCheckAckSeqNum(ofaction.vendor_action('MidoActionCheckAckSeqNum',
                                                      MIDOKURA_VENDOR_ID, '!2xI',
                                                      ('ack_seq_num',))):
  subtype = MIDO_ACTION_CHECK_ACK_SEQ_NUM


class MidokuraVendorHandler(object):
  """Extension handler for Midokura's vendor extensions."""

  vendor_id = MIDOKURA_VENDOR_ID

  @staticmethod
  def serialize_vendor_action(action):
    header = struct.pack('!H', action.subtype)
    return (header, action.serialize())

  
