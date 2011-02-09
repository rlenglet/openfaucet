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

# Unittests for oferror.py.

import struct
import unittest2

from openfaucet import buffer
from openfaucet import oferror


class TestOpenflowError(unittest2.TestCase):

  def setUp(self):
    self.buf = buffer.ReceiveBuffer()
    self.hello_failed_error = oferror.OpenflowError(
        oferror.OFPET_HELLO_FAILED, oferror.OFPHFC_INCOMPATIBLE,
        ('incompatible version',))
    self.action_bad_len_error = oferror.OpenflowError(
        oferror.OFPET_BAD_ACTION, oferror.OFPBAC_BAD_LEN,
        ('blahblahblah',))

  def test_serialize_hello_failed(self):
    self.assertEqual('\x00\x00' '\x00\x00'
                     'incompatible version',
                     ''.join(self.hello_failed_error.serialize()))

  def test_serialize_action_bad_len(self):
    self.assertEqual('\x00\x02' '\x00\x01'
                     'blahblahblah',
                     ''.join(self.action_bad_len_error.serialize()))

  def test_deserialize_hello_failed(self):
    self.buf.append('\x00\x00' '\x00\x00'
                    'incompatible version')
    self.buf.set_message_boundaries(24)
    self.assertEqual(self.hello_failed_error,
                     oferror.OpenflowError.deserialize(self.buf))

  def test_deserialize_action_bad_len(self):
    self.buf.append('\x00\x02' '\x00\x01'
                    'blahblahblah')
    self.buf.set_message_boundaries(16)
    self.assertEqual(self.action_bad_len_error,
                     oferror.OpenflowError.deserialize(self.buf))


if __name__ == '__main__':
  unittest2.main()
