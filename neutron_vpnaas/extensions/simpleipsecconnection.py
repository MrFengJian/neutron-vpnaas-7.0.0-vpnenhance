#    Copyright 2015 OpenStack Foundation.
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import abc

import six

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper
from neutron.plugins.common import constants
from neutron.services import service_base

vpn_supported_initiators = ['bi-directional', 'response-only']
vpn_supported_encryption_algorithms = ['3des', 'aes-128',
                                       'aes-192', 'aes-256']
vpn_dpd_supported_actions = [
    'hold', 'clear', 'restart', 'restart-by-peer', 'disabled'
]
vpn_supported_transform_protocols = ['esp', 'ah', 'ah-esp']
vpn_supported_encapsulation_mode = ['tunnel', 'transport']
# TODO(nati) add kilobytes when we support it
vpn_supported_lifetime_units = ['seconds']
vpn_supported_pfs = ['group2', 'group5', 'group14']
vpn_supported_ike_versions = ['v1', 'v2']
vpn_supported_auth_mode = ['psk']
vpn_supported_auth_algorithms = ['sha1']
vpn_supported_phase1_negotiation_mode = ['main']

vpn_lifetime_limits = (60, attr.UNLIMITED)
positive_int = (0, attr.UNLIMITED)

RESOURCE_ATTRIBUTE_MAP = {

    'simpleipsecconnections': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'peer_address': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:string': None},
                         'is_visible': True},
        'peer_id': {'allow_post': False, 'allow_put': False,
                    'validate': {'type:string': None},
                    'is_visible': True},
        'peer_cidrs': {'allow_post': True, 'allow_put': True,
                       'convert_to': attr.convert_to_list,
                       'validate': {'type:subnet_list': None},
                       'is_visible': True},
        'route_mode': {'allow_post': False, 'allow_put': False,
                       'default': 'static',
                       'is_visible': True},
        'router_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:uuid': None},
                      'is_visible': False},
        'subnet_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:uuid': None},
                      'is_visible': False},
        'mtu': {'allow_post': True, 'allow_put': True,
                'default': '1500',
                'validate': {'type:range': positive_int},
                'convert_to': attr.convert_to_int,
                'is_visible': True},
        'initiator': {'allow_post': True, 'allow_put': True,
                      'default': 'bi-directional',
                      'validate': {'type:values': vpn_supported_initiators},
                      'is_visible': True},
        'auth_mode': {'allow_post': False, 'allow_put': False,
                      'default': 'psk',
                      'validate': {'type:values': vpn_supported_auth_mode},
                      'is_visible': True},
        'psk': {'allow_post': True, 'allow_put': True,
                'validate': {'type:string': None},
                'is_visible': True},
        'dpd': {'allow_post': True, 'allow_put': True,
                'convert_to': attr.convert_none_to_empty_dict,
                'is_visible': True,
                'default': {},
                'validate': {
                    'type:dict_or_empty': {
                        'actions': {
                            'type:values': vpn_dpd_supported_actions,
                        },
                        'interval': {
                            'type:range': positive_int
                        },
                        'timeout': {
                            'type:range': positive_int
                        }}}},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'vpnservice_id': {'allow_post': False, 'allow_put': False,
                          'validate': {'type:uuid': None},
                          'is_visible': True},
        'ikepolicy_id': {'allow_post': False, 'allow_put': False,
                         'validate': {'type:uuid': None},
                         'is_visible': True},
        'ipsecpolicy_id': {'allow_post': False, 'allow_put': False,
                           'validate': {'type:uuid': None},
                           'is_visible': True}
    },
}


class Simpleipsecconnection(extensions.ExtensionDescriptor):
    @classmethod
    def get_name(cls):
        return "Simple IPSec Connection extension"

    @classmethod
    def get_alias(cls):
        return "simpleipsecconnection"

    @classmethod
    def get_description(cls):
        return "Extension for Simple IPSec Connection"

    @classmethod
    def get_namespace(cls):
        return "https://wiki.openstack.org/Neutron/simpleipsecconnection/API_1.0"

    @classmethod
    def get_updated(cls):
        return "2015-12-11T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        resources = resource_helper.build_resource_info(plural_mappings,
                                                        RESOURCE_ATTRIBUTE_MAP,
                                                        constants.VPN,
                                                        register_quota=True,
                                                        translate_name=True)
        return resources

    @classmethod
    def get_plugin_interface(cls):
        return SimpleIPsecConnection

    def update_attributes_map(self, attributes):
        super(Simpleipsecconnection, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class SimpleIPsecConnection(service_base.ServicePluginBase):
    def get_plugin_name(self):
        return constants.VPN

    def get_plugin_type(self):
        return constants.VPN

    def get_plugin_description(self):
        return 'Simple IPsec Connection plugin'

    @abc.abstractmethod
    def create_simpleipsecconnection(self, context, simpleipsecconnection):
        pass

    @abc.abstractmethod
    def delete_simpleipsecconnection(self, context, id):
        pass

    @abc.abstractmethod
    def get_simpleipsecconnection(self, context, id):
        pass