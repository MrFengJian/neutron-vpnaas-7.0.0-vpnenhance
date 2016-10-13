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
from neutron.common import exceptions as q_exc
from neutron.plugins.common import constants
from neutron.services import service_base


class OpenvpnConnectionNotFound(q_exc.NotFound):
    message = _("OpenvpnConnection %(id)s could not be found")


class OpenVpnServiceExisted(q_exc.Conflict):
    message = _("OpenVPNConnection already exists on router %(router_id)s")


class OpenvpnConnectionExisted(q_exc.Conflict):
    message = _("vpn serivce %(vpnservice_id)s has already configured openvpn connections ")


RESOURCE_ATTRIBUTE_MAP = {

    'openvpnconnections': {
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
        'protocol': {'allow_post': True, 'allow_put': True,
                     'validate': {'type:values': ['TCP', 'UDP']},
                     'is_visible': True, 'default': 'UDP'},
        'port': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:range': [1, 65535]},
                 'convert_to': attr.convert_to_int,
                 'is_visible': True, 'default': 1194},
        'client_cidr': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:subnet': None},
                        'is_visible': True, 'default': ''},
        'router_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:uuid': None},
                      'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True}
    },
}


class Openvpn(extensions.ExtensionDescriptor):
    @classmethod
    def get_name(cls):
        return "Openvpn extension"

    @classmethod
    def get_alias(cls):
        return "openvpn"

    @classmethod
    def get_description(cls):
        return "Extension for Openvpn service"

    @classmethod
    def get_namespace(cls):
        return "https://wiki.openstack.org/Neutron/openvpn/API_1.0"

    @classmethod
    def get_updated(cls):
        return "2015-12-09T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        action_map = {"openvpnconnection": {"get_client_cert": "GET"}}
        resources = resource_helper.build_resource_info(plural_mappings,
                                                        RESOURCE_ATTRIBUTE_MAP,
                                                        constants.VPN,
                                                        register_quota=True,
                                                        translate_name=True,
                                                        action_map=action_map)
        return resources

    @classmethod
    def get_plugin_interface(cls):
        return OpenvpnPluginBase

    def update_attributes_map(self, attributes):
        super(Openvpn, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class OpenvpnPluginBase(service_base.ServicePluginBase):
    def get_plugin_name(self):
        return constants.VPN

    def get_plugin_type(self):
        return constants.VPN

    def get_plugin_description(self):
        return 'OPENVPN service plugin'

    @abc.abstractmethod
    def create_openvpnconnection(self, context, openvpnconnection):
        pass

    @abc.abstractmethod
    def get_openvpnconnections(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_openvpnconnection(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def update_openvpnconnection(self, context, id, openvpnconnection):
        pass

    @abc.abstractmethod
    def delete_openvpnconnection(self, context, id):
        pass
