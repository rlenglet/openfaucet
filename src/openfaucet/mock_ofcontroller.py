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

# Mock implementation of an OpenFlow controller stub.

import zope.interface

from openfaucet import ofcontroller


class MockOpenflowController(object):
  """A mock implementation of the IOpenflowController interface.

  All callbacks made to this object are appended as tuples into
  attribute calls_made.
  """

  zope.interface.implements(ofcontroller.IOpenflowController)

  def __init__(self):
    self.calls_made = []

  def connection_made(self):
    pass

  def connection_lost(self, reason):
    pass

  def handle_packet_in(self, buffer_id, total_len, in_port, reason, data):
    self.calls_made.append(
        ('handle_packet_in', buffer_id, total_len, in_port, reason, data))

  def handle_flow_removed(
      self, match, cookie, priority, reason, duration_sec, duration_nsec,
      idle_timeout, packet_count, byte_count):
    self.calls_made.append(
        ('handle_flow_removed', match, cookie, priority, reason, duration_sec,
         duration_nsec, idle_timeout, packet_count, byte_count))

  def handle_port_status(self, reason, desc):
    self.calls_made.append(
        ('handle_port_status', reason, desc))
