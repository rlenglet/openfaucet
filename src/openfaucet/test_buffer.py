# Copyright 2011 Midokura KK

import unittest2

from openfaucet import buffer


class TestReceiveBuffer(unittest2.TestCase):

  def setUp(self):
    self.buffer = buffer.ReceiveBuffer()

  def test_length_empty_zero_offset(self):
    self.assertEqual(0, len(self.buffer))

  def test_append_length_zero_offset(self):
    self.buffer.append('1234')
    self.assertEqual(4, len(self.buffer))
    self.buffer.append('567')
    self.assertEqual(7, len(self.buffer))

  def test_length_empty_nonzero_offset(self):
    self.buffer.append('1234')
    self.buffer.set_message_boundaries(4)
    self.buffer.skip_bytes(4)
    self.assertEqual(0, len(self.buffer))

  def test_append_length_nonzero_offset(self):
    self.buffer.append('1234')
    self.buffer.set_message_boundaries(4)
    self.buffer.skip_bytes(2)
    self.buffer.append('567')
    self.assertEqual(5, len(self.buffer))

  def test_set_message_boundaries_zero_offset(self):
    self.buffer.append('1234')
    self.buffer.set_message_boundaries(3)
    self.buffer.set_message_boundaries(4)
    with self.assertRaises(AssertionError):
      self.buffer.set_message_boundaries(5)

  def test_set_message_boundaries_nonzero_offset(self):
    self.buffer.append('123456')
    self.buffer.set_message_boundaries(6)
    self.buffer.skip_bytes(2)
    self.assertEqual(4, len(self.buffer))
    self.buffer.set_message_boundaries(3)
    self.buffer.set_message_boundaries(4)
    with self.assertRaises(AssertionError):
      self.buffer.set_message_boundaries(5)

  def test_get_first_message_bytes(self):
    self.buffer.append('12345')
    self.buffer.set_message_boundaries(5)
    self.assertEqual('12345', self.buffer.get_first_message_bytes(64))
    self.assertEqual('12', self.buffer.get_first_message_bytes(2))

    self.buffer.append('6')
    self.assertEqual('12345', self.buffer.get_first_message_bytes(64))
    self.assertEqual('12', self.buffer.get_first_message_bytes(2))

    self.buffer.set_message_boundaries(6)
    self.assertEqual('123456', self.buffer.get_first_message_bytes(64))
    self.assertEqual('12', self.buffer.get_first_message_bytes(2))

    self.buffer.skip_bytes(3)
    self.assertEqual('123456', self.buffer.get_first_message_bytes(64))
    self.assertEqual('12', self.buffer.get_first_message_bytes(2))

    self.buffer.set_message_boundaries(3)
    self.assertEqual('456', self.buffer.get_first_message_bytes(64))
    self.assertEqual('45', self.buffer.get_first_message_bytes(2))

    self.buffer.append('789')
    self.assertEqual('456', self.buffer.get_first_message_bytes(64))
    self.assertEqual('45', self.buffer.get_first_message_bytes(2))

    self.buffer.set_message_boundaries(6)
    self.assertEqual('456789', self.buffer.get_first_message_bytes(64))
    self.assertEqual('45', self.buffer.get_first_message_bytes(2))

    self.buffer.compact()
    self.assertEqual('456789', self.buffer.get_first_message_bytes(64))
    self.assertEqual('45', self.buffer.get_first_message_bytes(2))

    self.buffer.skip_bytes(1)
    self.assertEqual('456789', self.buffer.get_first_message_bytes(64))
    self.assertEqual('45', self.buffer.get_first_message_bytes(2))

    self.buffer.compact()
    with self.assertRaises(AssertionError):
      self.buffer.get_first_message_bytes(64)

    self.buffer.set_message_boundaries(5)
    self.assertEqual('56789', self.buffer.get_first_message_bytes(64))
    self.assertEqual('56', self.buffer.get_first_message_bytes(2))

  def test_compact(self):
    self.assertEqual(0, len(self.buffer._buffer))
    self.buffer.compact()
    self.assertEqual(0, len(self.buffer))
    self.assertEqual(0, len(self.buffer._buffer))

    self.buffer.append('1234')
    self.buffer.set_message_boundaries(4)
    self.buffer.skip_bytes(2)
    self.buffer.skip_bytes(1)
    self.assertEqual(1, len(self.buffer))
    self.assertEqual(4, len(self.buffer._buffer))
    self.buffer.compact()
    self.assertEqual(1, len(self.buffer))
    self.assertEqual(1, len(self.buffer._buffer))

  def test_unpack(self):
    self.buffer.append('\x01\x00\x02')
    self.buffer.set_message_boundaries(3)
    self.assertTupleEqual((1, 2), self.buffer.unpack('!BH'))
    self.assertEqual(0, len(self.buffer))

    self.buffer.append('\x01\x00\x02')
    self.buffer.set_message_boundaries(3)
    self.assertTupleEqual((1,), self.buffer.unpack('!B'))
    self.assertEqual(2, len(self.buffer))
    self.assertTupleEqual((2,), self.buffer.unpack('!H'))
    self.assertEqual(0, len(self.buffer))

  def test_unpack_boundaries(self):
    self.buffer.append('\x01\x00\x02')
    self.buffer.set_message_boundaries(3)
    with self.assertRaises(AssertionError):
      self.buffer.unpack('!HH')

    self.buffer.set_message_boundaries(2)
    with self.assertRaises(AssertionError):
      self.buffer.unpack('!BH')

    self.assertTupleEqual((1,), self.buffer.unpack('!B'))
    with self.assertRaises(AssertionError):
      self.buffer.unpack('!H')

    self.assertTupleEqual((0,), self.buffer.unpack('!B'))

  def test_unpack_inplace(self):
    self.buffer.append('\x01\x00\x02')
    self.buffer.set_message_boundaries(3)
    self.assertTupleEqual((1, 2), self.buffer.unpack_inplace('!BH'))
    self.assertEqual(3, len(self.buffer))

    self.buffer.append('\x03\x00\x04')
    self.buffer.set_message_boundaries(6)
    self.assertTupleEqual((1, 2, 3, 4), self.buffer.unpack_inplace('!BHBH'))
    self.assertEqual(6, len(self.buffer))

    self.buffer.skip_bytes(3)
    self.assertTupleEqual((3, 4), self.buffer.unpack_inplace('!BH'))
    self.assertEqual(3, len(self.buffer))

  def test_unpack_inplace_boundaries(self):
    self.buffer.append('\x01\x00\x02')
    self.buffer.set_message_boundaries(3)
    with self.assertRaises(AssertionError):
      self.buffer.unpack_inplace('!HH')

    self.buffer.set_message_boundaries(2)
    with self.assertRaises(AssertionError):
      self.buffer.unpack_inplace('!BH')

    self.assertTupleEqual((1,), self.buffer.unpack('!B'))
    with self.assertRaises(AssertionError):
      self.buffer.unpack_inplace('!H')

    self.assertTupleEqual((0,), self.buffer.unpack_inplace('!B'))

  def test_read_bytes(self):
    self.buffer.append('1234')
    self.buffer.set_message_boundaries(4)
    self.assertEqual('123', self.buffer.read_bytes(3))

    self.buffer.append('567')
    self.buffer.set_message_boundaries(4)
    self.assertEqual('4567', self.buffer.read_bytes(4))

  def test_read_bytes_boundaries(self):
    self.buffer.append('123')
    self.buffer.set_message_boundaries(3)
    with self.assertRaises(AssertionError):
      self.buffer.read_bytes(4)

    self.buffer.set_message_boundaries(2)
    with self.assertRaises(AssertionError):
      self.buffer.read_bytes(3)

    self.assertEqual('1', self.buffer.read_bytes(1))
    with self.assertRaises(AssertionError):
      self.buffer.read_bytes(2)

    self.assertEqual('2', self.buffer.read_bytes(1))

  def test_skip_bytes(self):
    self.buffer.append('1234')
    self.buffer.set_message_boundaries(4)
    self.buffer.skip_bytes(3)
    self.assertEqual(1, len(self.buffer))

    self.buffer.append('567')
    self.buffer.set_message_boundaries(4)
    self.buffer.skip_bytes(4)
    self.assertEqual(0, len(self.buffer))

  def test_skip_bytes_boundaries(self):
    self.buffer.append('123')
    self.buffer.set_message_boundaries(3)
    with self.assertRaises(AssertionError):
      self.buffer.skip_bytes(4)

    self.buffer.set_message_boundaries(2)
    with self.assertRaises(AssertionError):
      self.buffer.skip_bytes(3)

    self.buffer.skip_bytes(1)
    with self.assertRaises(AssertionError):
      self.buffer.skip_bytes(2)

    self.buffer.skip_bytes(1)


if __name__ == '__main__':
  unittest2.main()
