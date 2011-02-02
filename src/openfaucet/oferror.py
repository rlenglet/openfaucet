# Copyright (C) 2011 Midokura KK

# Representations and encoding/decoding of OpenFlow 1.0.0 errors.

import binascii
import struct

from openfaucet import buffer


# OpenFlow error types.
OFPET_HELLO_FAILED = 0        # Hello protocol failed.
OFPET_BAD_REQUEST = 1         # Request was not understood.
OFPET_BAD_ACTION = 2          # Error in action description.
OFPET_FLOW_MOD_FAILED = 3     # Problem modifying flow entry.
OFPET_PORT_MOD_FAILED = 4     # Port mod request failed.
OFPET_QUEUE_OP_FAILED = 5     # Queue operation failed.
# OpenFlow error codes for type OFPET_HELLO_FAILED.
OFPHFC_INCOMPATIBLE = 0
OFPHFC_EPERM = 1
# OpenFlow error codes for type OFPET_BAD_REQUEST.
OFPBRC_BAD_VERSION = 0
OFPBRC_BAD_TYPE = 1
OFPBRC_BAD_STAT = 2
OFPBRC_BAD_VENDOR = 3
OFPBRC_BAD_SUBTYPE = 4
OFPBRC_EPERM = 5
OFPBRC_BAD_LEN = 6
OFPBRC_BUFFER_EMPTY = 7
OFPBRC_BUFFER_UNKNOWN = 8
# OpenFlow error codes for type OFPET_BAD_ACTION.
OFPBAC_BAD_TYPE = 0
OFPBAC_BAD_LEN = 1
OFPBAC_BAD_VENDOR = 2
OFPBAC_BAD_VENDOR_TYPE = 3
OFPBAC_BAD_OUT_PORT = 4
OFPBAC_BAD_ARGUMENT = 5
OFPBAC_EPERM = 6
OFPBAC_TOO_MANY = 7
OFPBAC_BAD_QUEUE = 8
# OpenFlow error codes for type OFPET_FLOW_MOD_FAILED.
OFPFMFC_ALL_TABLES_FULL = 0
OFPFMFC_OVERLAP = 1
OFPFMFC_EPERM = 2
OFPFMFC_BAD_EMERG_TIMEOUT = 3
OFPFMFC_BAD_COMMAND = 4
OFPFMFC_UNSUPPORTED = 5
# OpenFlow error codes for type OFPET_PORT_MOD_FAILED.
OFPPMFC_BAD_PORT = 0
OFPPMFC_BAD_HW_ADDR = 1
# OpenFlow error codes for type OFPET_QUEUE_OP_FAILED.
OFPQOFC_BAD_PORT = 0
OFPQOFC_BAD_QUEUE = 1
OFPQOFC_EPERM = 2

OFP_ERROR_MESSAGES = {
  OFPET_HELLO_FAILED: ('hello protocol failed', {
    OFPHFC_INCOMPATIBLE: 'no compatible version',
    OFPHFC_EPERM: 'permissions error',
    }),
  OFPET_BAD_REQUEST: ('request was not understood', {
    OFPBRC_BAD_VERSION: 'ofp_header.version not supported',
    OFPBRC_BAD_TYPE: 'ofp_header.type not supported',
    OFPBRC_BAD_STAT: 'ofp_stats_request.type not supported',
    OFPBRC_BAD_VENDOR: 'vendor not supported',
    OFPBRC_BAD_SUBTYPE: 'vendor subtype not supported',
    OFPBRC_EPERM: 'permissions error',
    OFPBRC_BAD_LEN: 'wrong request length for type',
    OFPBRC_BUFFER_EMPTY: 'specified buffer has already been used',
    OFPBRC_BUFFER_UNKNOWN: 'specified buffer does not exist',
    }),
  OFPET_BAD_ACTION: ('error in action description', {
    OFPBAC_BAD_TYPE: 'unknown action type',
    OFPBAC_BAD_LEN: 'length problem in actions',
    OFPBAC_BAD_VENDOR: 'unknown vendor id specified',
    OFPBAC_BAD_VENDOR_TYPE: 'unknown action type for vendor id',
    OFPBAC_BAD_OUT_PORT: 'problem validating output action',
    OFPBAC_BAD_ARGUMENT: 'bad action argument',
    OFPBAC_EPERM: 'permissions error',
    OFPBAC_TOO_MANY: 'can\'t handle this many actions',
    OFPBAC_BAD_QUEUE: 'problem validating output queue',
    }),
  OFPET_FLOW_MOD_FAILED: ('problem modifying flow entry', {
    OFPFMFC_ALL_TABLES_FULL: 'flow not added because of full tables',
    OFPFMFC_OVERLAP:
        'attempted to add overlapping flow with CHECK_OVERLAP flag set',
    OFPFMFC_EPERM: 'permissions error',
    OFPFMFC_BAD_EMERG_TIMEOUT:
        'flow not added because of non-zero idle/hard timeout',
    OFPFMFC_BAD_COMMAND: 'unknown command',
    OFPFMFC_UNSUPPORTED:
        'unsupported action list - cannot process in the order specified',
    }),
  OFPET_PORT_MOD_FAILED: ('port mod request failed', {
    OFPPMFC_BAD_PORT: 'specified port does not exist',
    OFPPMFC_BAD_HW_ADDR: 'specified hardware address is wrong',
    }),
  OFPET_QUEUE_OP_FAILED: ('queue operation failed', {
    OFPQOFC_BAD_PORT: 'invalid port (or port does not exist)',
    OFPQOFC_BAD_QUEUE: 'queue does not exist',
    OFPQOFC_EPERM: 'permissions error',
    }),
  }


class OpenflowError(Exception):
  """The base class of OpenFlow errors.
  """

  def __init__(self, error_type, error_code, data):
    """Create an OpenflowError.

    Args:
      error_type: The error type, as one of the OFPET_* constants.
      error_code: The error code, as one of the OFP* error code constants.
      data: The data attached in the error message, as a sequence of
          byte buffers.
    """
    Exception.__init__(self, error_type, error_code, data)
    error_type_data = OFP_ERROR_MESSAGES.get(error_type)
    if error_type_data is None:
      raise ValueError('unknown error type', error_type)
    error_type_txt, error_code_txts = error_type_data
    error_code_txt = error_code_txts.get(error_code)
    if error_code_txt is None:
      raise ValueError('unknown error code', error_code)

    self.error_type = error_type
    self.error_code = error_code
    self.error_type_txt = error_type_txt
    self.error_code_txt = error_code_txt
    self.data = data

  def __str__(self):
    return 'error type %i (%s) code %i (%s) with data %s' % (
        self.error_type, self.error_type_txt, self.error_code,
        self.error_code_txt, binascii.b2a_hex(self.data))

  def __cmp__(self, other):
    return cmp(self.args, other.args)

  def serialize(self):
    """Serialize this exception into an OpenFlow ofp_error_msg.

    The returned string can be passed to deserialize() to recreate a
    copy of this object.

    Returns:
      A sequence of binary strings that is a serialized form of this
      object into an OpenFlow ofp_error_msg. The ofp_header structure
      is not included in the generated strings.
    """
    all_data = [struct.pack('!HH', self.error_type, self.error_code)]
    all_data.extend(self.data)
    return all_data

  @classmethod
  def deserialize(self, buf):
    """Returns an OpenflowError object deserialized from a sequence of bytes.

    Args:
      buf: A ReceiveBuffer object that contains the bytes that are the
          serialized form of the OpenflowError object.

    Returns:
      A new OpenflowError object deserialized from the buffer.

    Raises:
      ValueError if the buffer has an invalid number of available
      bytes, or if the error type or code is invalid.
      OpenflowError if the error data length is invalid for the
      deserialized error type and code.
    """
    error_type, error_code = buf.unpack('!HH')
    data = ()

    if error_type == OFPET_HELLO_FAILED:
      if buf.message_bytes_left > 0:
        data = (buf.read_bytes(buf.message_bytes_left),)
    elif error_type in (OFPET_BAD_REQUEST, OFPET_BAD_ACTION,
                        OFPET_FLOW_MOD_FAILED, OFPET_PORT_MOD_FAILED,
                        OFPET_QUEUE_OP_FAILED):
      data = (buf.read_bytes(buf.message_bytes_left),)
    elif buf.message_bytes_left > 0:
      # Be liberal. Ignore data if none should have been sent.
      buf.skip_bytes(buf.message_bytes_left)

    return OpenflowError(error_type, error_code, data)
