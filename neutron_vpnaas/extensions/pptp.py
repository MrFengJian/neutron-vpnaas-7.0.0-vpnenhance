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


class PPTPConnectionNotFound(q_exc.NotFound):
    message = _("PPTPConnection %(conn_id)s could not be found")


class PPTPServiceExisted(q_exc.Conflict):
    message = _("PPTPConnection on %{router_id}s already existes")


class ConnCredAssociationExists(q_exc.Conflict):
    message = _("PPTP credential %(credential_id)s is already associated "
                "with connection %(connection_id)s")


class ConnCredNotFound(q_exc.NotFound):
    message = _("PPTP credential %(credential_id)s is not associated "
                "with connection %(connection_id)s")


class PPTPCredentialNotFound(q_exc.NotFound):
    message = _("PPTPCredential %(cred_id)s could not be found")


class PPTPCredentialExisted(q_exc.BadRequest):
    message = _("PPTPCredential with username %(username)s already exists in pptp connection %s(connection_id)s")


class PPTPCredententailQueryNotAllowed(q_exc.BadRequest):
    message = _("PPTPCredential is not allowed to query without pptpconnection_id")


RESOURCE_ATTRIBUTE_MAP = {

    'pptpconnections': {
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
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'client_cidr': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:subnet': None},
                        'is_visible': True},
        'router_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:uuid': None},
                      'is_visible': True},
        'credentials': {'allow_post': True, 'allow_put': True,
                        'default': None,
                        'validate': {'type:uuid_list': None},
                        'convert_to': attr.convert_to_list,
                        'is_visible': True},
    },
    'pptpcredentials': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:uuid': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'pptpconnection_id': {'allow_post': True, 'allow_put': False,
                              'validate': {'type:uuid': None},
                              'required_by_policy': True,
                              'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': False, 'default': ''},
        'username': {'allow_post': True, 'allow_put': False,
                     'validate': {'type:string': None},
                     'is_visible': True},
        'password': {'allow_post': True, 'allow_put': True,
                     'validate': {'type:string': None},
                     'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
    },
}


class Pptp(extensions.ExtensionDescriptor):
    @classmethod
    def get_name(cls):
        return "PPTP VPN extension"

    @classmethod
    def get_alias(cls):
        return "pptp"

    @classmethod
    def get_description(cls):
        return "Extension for PPTP VPN service"

    @classmethod
    def get_namespace(cls):
        return "https://wiki.openstack.org/Neutron/pptp/API_1.0"

    @classmethod
    def get_updated(cls):
        return "2015-12-09T10:00:00-00:00"

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
        return PPTPPluginBase

    def update_attributes_map(self, attributes):
        super(Pptp, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class PPTPPluginBase(service_base.ServicePluginBase):
    def get_plugin_name(self):
        return constants.VPN

    def get_plugin_type(self):
        return constants.VPN

    def get_plugin_description(self):
        return 'PPTP service plugin'

    @abc.abstractmethod
    def create_pptpconnection(self, context, pptpconnection):
        pass

    @abc.abstractmethod
    def get_pptpconnections(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_pptpconnection(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def update_pptpconnection(self, context, id, pptpconnection):
        pass

    @abc.abstractmethod
    def delete_pptpconnection(self, context, id):
        pass

    @abc.abstractmethod
    def create_pptpcredential(self, context, pptpcredential):
        pass

    @abc.abstractmethod
    def get_pptpcredentials(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_pptpcredential(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def update_pptpcredential(self, context, id, pptpcredential):
        pass

    @abc.abstractmethod
    def delete_pptpcredential(self, context, id):
        pass
