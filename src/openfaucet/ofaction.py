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

# Representations and encoding/decoding of OpenFlow 1.0.0 actions.
#
# Vendor actions are handled specially by the OpenflowProtocol implementation,
# and are not handled in this module.

import collections
import struct
from zope import interface

from openfaucet import buffer


# Action types.
OFPAT_OUTPUT = 0
OFPAT_SET_VLAN_VID = 1
OFPAT_SET_VLAN_PCP = 2
OFPAT_STRIP_VLAN = 3
OFPAT_SET_DL_SRC = 4
OFPAT_SET_DL_DST = 5
OFPAT_SET_NW_SRC = 6
OFPAT_SET_NW_DST = 7
OFPAT_SET_NW_TOS = 8
OFPAT_SET_TP_SRC = 9
OFPAT_SET_TP_DST = 10
OFPAT_ENQUEUE = 11
OFPAT_VENDOR = 0xffff


class IAction(interface.Interface):
  """An OpenFlow action."""

  type = interface.Attribute(
    """The type of the action, as one of OFPAT_* constants.
    """)

  format_length = interface.Attribute(
    """The length of the data in the encoded action.

    This length doesn't count the ofp_action_header information.
    """)

  def serialize():
    """Serialize this action object into an OpenFlow action.

    The returned string can be passed to deserialize() to recreate a
    copy of this action object.

    Returns:
      A binary string that is a serialized form of this action object
      into an OpenFlow action. The ofp_action_header structure is not
      included in the generated strings.
    """

  def deserialize(buf):
    """Returns an action object deserialized from a sequence of bytes.

    Args:
      buf: A ReceiveBuffer object that contains the bytes that are the
          serialized form of the action, after the ofp_action_header
          structure.

    Returns:
      A new action object deserialized from the buffer.

    Raises:
      ValueError if the buffer has an invalid number of available
      bytes, or if some elements cannot be deserialized.
    """


def __action(type_name, action_type, format, field_names, verbose=False):
  """Generates a class for an OpenFlow action.

  The returned class creates objects that serialize / deserialize the
  data for an action, which is sent / received after the
  ofp_action_header. The ofp_action_header information for an action
  (the type and length fields) must be serialized / deserialized by
  users of the generated class.

  Args:
    type_name: The name of the type to generate.
    action_type: The OFPAT_* type of the action.
    format: The struct format of the action-specific representation
        which is sent / received after the ofp_action_header.
    field_names: The tuple of name strings of fields in the
        action. Must not contain 'type' or 'format_length'.
    verbose: If True, the code for the generated type is printed.
  """
  # Use generic programming, using dynamic generation of code and
  # execution, as is done in function namedtuple() in standard module
  # collections.
  format_length = struct.calcsize(format)
  template = '''class %(type_name)s(_collections.namedtuple(
      '%(type_name)s', %(field_names)s)):\n
      _interface.implements(_iaction)
      type = %(action_type)d\n
      format_length = %(format_length)d\n
      def serialize(self):
        return _struct.pack('%(format)s', *self)\n
      @classmethod
      def deserialize(cls, buf):
        return %(type_name)s(*buf.unpack('%(format)s'))\n\n''' % locals()

  if verbose:
    print template

  namespace = dict(__name__='action_%s' % type_name, _property=property,
                   _collections=collections, _struct=struct,
                   _interface=interface, _iaction=IAction)
  try:
    exec template in namespace
  except SyntaxError, e:
    raise SyntaxError(e.message + ':\n' + template)
  result = namespace[type_name]

  # TODO(romain): Add __module__ attribute to result to enable
  # pickling in some environments, as done in
  # collections.namedtuple()?

  return result


def vendor_action(type_name, vendor_id, format, field_names, verbose=False):
  """Generates a class for an OpenFlow OFPAT_VENDOR action.

  The returned class creates objects that serialize / deserialize the
  data for a vendor action, which is sent / received after the
  ofp_action_vendor_header. The ofp_action_vendor_header information
  for an action (the type, length, and vendor fields) must be
  serialized / deserialized by users of the generated class.

  Args:
    type_name: The name of the type to generate.
    vendor_id: The OpenFlow vendor ID, as a 32-bit unsigned integer.
    format: The struct format of the action-specific representation
        which is sent / received after the ofp_action_vendor_header.
    field_names: The tuple of name strings of fields in the
        action. Must not contain 'type', 'format_length', or 'vendor_id'.
    verbose: If True, the code for the generated type is printed.
  """
  result = __action(type_name, OFPAT_VENDOR, format, field_names,
                    verbose=verbose)
  result.vendor_id = vendor_id
  return result


ActionOutput = __action('ActionOutput', OFPAT_OUTPUT,
                        '!HH', ('port', 'max_len'))


ActionSetVlanVid = __action('ActionSetVlanVid', OFPAT_SET_VLAN_VID,
                            '!H2x', ('vlan_vid',))


class ActionSetVlanPcp(__action('ActionSetVlanPcp', OFPAT_SET_VLAN_PCP,
                                '!B3x', ('vlan_pcp',))):

  def serialize(self):
    # The PCP field has only its 3 LSBs meaningful. Check that the 5
    # MSBs are zeroed.
    if self.vlan_pcp & 0xf8:
      raise ValueError('vlan_pcp has non-zero MSB bits set', self.vlan_pcp)
    return super(ActionSetVlanPcp, self).serialize()

  @classmethod
  def deserialize(cls, buf):
    a = super(ActionSetVlanPcp, cls).deserialize(buf)
    # The PCP field has only its 3 LSBs meaningful. Check that the 5
    # MSBs are zeroed.
    if a.vlan_pcp & 0xf8:
      # Be liberal. Zero out those bits instead of raising an exception.
      # TODO(romain): Log this.
      # ('vlan_pcp has non-zero MSB bits set', a.vlan_pcp)
      a = a._replace(vlan_pcp=a.vlan_pcp & 0x07)
    return a


ActionStripVlan = __action('ActionStripVlan', OFPAT_STRIP_VLAN, '', ())


ActionSetDlSrc = __action('ActionSetDlSrc', OFPAT_SET_DL_SRC,
                          '!6s6x', ('dl_addr',))


ActionSetDlDst = __action('ActionSetDlDst', OFPAT_SET_DL_DST,
                          '!6s6x', ('dl_addr',))


ActionSetNwSrc = __action('ActionSetNwSrc', OFPAT_SET_NW_SRC,
                          '!4s', ('nw_addr',))


ActionSetNwDst = __action('ActionSetNwDst', OFPAT_SET_NW_DST,
                          '!4s', ('nw_addr',))


class ActionSetNwTos(__action('ActionSetNwTos', OFPAT_SET_NW_TOS,
                              '!B3x', ('nw_tos',))):

  def serialize(self):
    # In OpenFlow 1.0.0, the "nw_tos" field doesn't contain the whole
    # IP TOS field, only the 6 bits of the DSCP field in mask
    # 0xfc. The 2 LSBs don't have any meaning and must be ignored. Be
    # strict and enforce users to set those bits to zero.
    if self.nw_tos & 0x3:
      raise ValueError('unused lower bits in nw_tos are set', self.nw_tos)
    return super(ActionSetNwTos, self).serialize()

  @classmethod
  def deserialize(cls, buf):
    a = super(ActionSetNwTos, cls).deserialize(buf)

    # In OpenFlow 1.0.0, the "nw_tos" field doesn't contain the whole
    # IP TOS field, only the 6 bits of the DSCP field in mask
    # 0xfc. The 2 LSBs don't have any meaning and must be ignored.
    if a.nw_tos & 0x3:
      # Be liberal. Zero out those bits instead of raising an exception.
      # TODO(romain): Log this.
      # ('unused lower bits in nw_tos are set', a.nw_tos)
      a = a._replace(nw_tos=a.nw_tos & 0xfc)
    return a


ActionSetTpSrc = __action('ActionSetTpSrc', OFPAT_SET_TP_SRC,
                          '!H2x', ('tp_port',))


ActionSetTpDst = __action('ActionSetTpDst', OFPAT_SET_TP_DST,
                          '!H2x', ('tp_port',))


ActionEnqueue = __action('ActionEnqueue', OFPAT_ENQUEUE,
                         '!H2xL', ('port', 'queue_id'))

# Mapping of all OFPAT_* action types (except OFPAT_VENDOR) to Action* types.
ACTION_CLASSES = dict((action_type.type, action_type) for action_type in (
    ActionOutput, ActionSetVlanVid, ActionSetVlanPcp, ActionStripVlan,
    ActionSetDlSrc, ActionSetDlDst, ActionSetNwSrc, ActionSetNwDst,
    ActionSetNwTos, ActionSetTpSrc, ActionSetTpDst, ActionEnqueue))

# Midokura vendor actions
MIDOKURA_VENDOR_ID = 0x00ACCABA
MIDO_ACTION_CHECK_TCP_FLAGS = 0
MIDO_ACTION_CHECK_ACK_SEQ_NUM = 1

MidoActionCheckTCPFlags = vendor_action('MidoActionCheckTCPFlags',
                                         MIDOKURA_VENDOR_ID, '!HB',
                                         ('subtype', 'tcp_flags'))

MidoActionCheckAckSeqNum = vendor_action('MidoActionCheckAckSeqNum',
                                         MIDOKURA_VENDOR_ID, '!H2xI',
                                         ('subtype', 'ack_seq_num'))
