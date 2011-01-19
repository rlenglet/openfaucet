# Copyright (C) 2011 Midokura KK

# Representations and encoding/decoding of OpenFlow 1.0.0 actions.
#
# Vendor actions are handled specially by the OpenflowProtocol implementation,
# and are not handled in this module.

import collections
import struct

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
OFPAT_VENDOR = 12


def __action(type_name, action_type, format, field_names, verbose=False):
  """Generates a type for an OpenFlow action.

  Args:
    type_name: The name of the type to generate.
    action_type: The OFPAT_* type of the action.
    format: The struct format of the action-specific representation.
    field_names: The sequence of names of fields in the action. Must not
        contain 'type'.
    verbose: If True, the code for the generated type is printed.
  """
  # Use generic programming, using dynamic generation of code and
  # execution, as is done in standard module collections, in
  # namedtuple().
  
  # Make sure that field_names is a tuple of strings.
  field_names = tuple(str(n) for n in field_names)

  template = '''class %(type_name)s(_collections.namedtuple(
      '%(type_name)s', %(field_names)s)):\n
      def _get_type(self):
        return %(action_type)d\n
      type = _property(_get_type)\n
      def serialize(self):
        return _struct.pack('%(format)s', *self)\n
      @classmethod
      def deserialize(cls, buf):
        return %(type_name)s(*buf.unpack('%(format)s'))\n\n''' % locals()

  if verbose:
    print template

  namespace = dict(__name__='action_%s' % type_name, _property=property,
                   _collections=collections, _struct=struct)
  try:
    exec template in namespace
  except SyntaxError, e:
    raise SyntaxError(e.message + ':\n' + template)
  result = namespace[type_name]

  # TODO(romain): Add __module__ attribute to result to enable
  # pickling in some environments, like it's done in
  # collections.namedtuple()?

  return result


ActionOutput = __action('ActionOutput', OFPAT_OUTPUT,
                        '!HH', ('port', 'max_len'))
ActionSetVlanVid = __action('ActionSetVlanVid', OFPAT_SET_VLAN_VID,
                            '!H2x', ('vlan_vid',))
# TODO(romain): The PCP field has only its 3 LSBs meaningful. Check
# that the 5 MSBs are zeroed.
ActionSetVlanPcp = __action('ActionSetVlanPcp', OFPAT_SET_VLAN_PCP,
                            '!B3x', ('vlan_pcp',))
ActionStripVlan = __action('ActionStripVlan', OFPAT_STRIP_VLAN, '', ())
ActionSetDlSrc = __action('ActionSetDlSrc', OFPAT_SET_DL_SRC,
                          '!6s6x', ('dl_addr',))
ActionSetDlDst = __action('ActionSetDlDst', OFPAT_SET_DL_DST,
                          '!6s6x', ('dl_addr',))
ActionSetNwSrc = __action('ActionSetNwSrc', OFPAT_SET_NW_SRC,
                          '!4s', ('nw_addr',))
ActionSetNwDst = __action('ActionSetNwDst', OFPAT_SET_NW_DST,
                          '!4s', ('nw_addr',))
# TODO(romain): The DSCP field has only its 6 MSBs meaningful. Check
# that the 3 LSBs are zeroed.
ActionSetNwTos = __action('ActionSetNwTos', OFPAT_SET_NW_TOS,
                          '!B3x', ('nw_tos',))
ActionSetTpSrc = __action('ActionSetTpSrc', OFPAT_SET_TP_SRC,
                          '!H2x', ('tp_port',))
ActionSetTpDst = __action('ActionSetTpDst', OFPAT_SET_TP_DST,
                          '!H2x', ('tp_port',))
ActionEnqueue = __action('ActionEnqueue', OFPAT_ENQUEUE,
                         '!H2xL', ('port', 'queue_id'))


# Mapping of all OFPAT_* action types (except OFPAT_VENDOR) to Action* types.
ACTION_TYPES = dict((action_type.type, action_type) for action_type in (
    ActionOutput, ActionSetVlanVid, ActionSetVlanPcp, ActionStripVlan,
    ActionSetDlSrc, ActionSetDlDst, ActionSetNwSrc, ActionSetNwDst,
    ActionSetNwTos, ActionSetTpSrc, ActionSetTpDst, ActionEnqueue))
