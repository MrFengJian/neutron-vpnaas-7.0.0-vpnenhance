#    (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
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

from neutron.db import servicetype_db as st_db
from neutron.i18n import _LI
from neutron.plugins.common import constants
from neutron.services import provider_configuration as pconf
from neutron.services import service_base
from oslo_log import log as logging
from neutron_vpnaas.db.vpn import openvpn_db
from neutron_vpnaas.db.vpn import pptp_db
from neutron_vpnaas.services.vpn.common import constants as vpn_consts
from neutron_vpnaas.db.vpn import vpn_db
from eventlet import greenthread

LOG = logging.getLogger(__name__)


def add_provider_configuration(type_manager, service_type):
    type_manager.add_provider_configuration(
        service_type,
        pconf.ProviderConfiguration('neutron_vpnaas'))


class PPTPDriverMixin(pptp_db.PPTP_db_mixin):
    """VpnPlugin which supports PPTP Service Drivers."""

    def _get_driver_for_pptpconnection(self, context):
        vpnservice = vpn_consts.PPTP
        return self._get_driver_for_vpnservice(vpnservice)

    def create_pptpconnection(self, context, pptpconnection):
        vpnservice = {"vpnservice": {
            "name": pptpconnection["pptpconnection"]["name"],
            "description": pptpconnection["pptpconnection"]["name"],
            "router_id": pptpconnection["pptpconnection"]["router_id"],
            "admin_state_up": pptpconnection["pptpconnection"]["admin_state_up"],
            "service_type": vpn_consts.SERVICE_TYPE_PPTP
        }}
        vpnservice_db = self.create_vpnservice(context, vpnservice)
        pptpconnection["pptpconnection"]["vpnservice_id"] = vpnservice_db["id"]
        pptpconnection = super(
            PPTPDriverMixin, self).create_pptpconnection(
            context, pptpconnection)
        driver = self._get_driver_for_pptpconnection(context)
        driver.create_pptpconnection(context, pptpconnection)
        return pptpconnection

    def delete_pptpconnection(self, context, pptp_conn_id):
        pptpconnection = self.get_pptpconnection(context, pptp_conn_id)
        super(PPTPDriverMixin, self).delete_pptpconnection(
            context, pptp_conn_id)
        driver = self._get_driver_for_pptpconnection(context)
        driver.delete_pptpconnection(context, pptpconnection)
        vpnservice_id = pptpconnection["vpnservice_id"]
        self.delete_vpnservice(context, vpnservice_id)

    def update_pptpconnection(
            self, context,
            pptp_conn_id, pptpconnection):
        old_pptpconnection = self.get_pptpconnection(context, pptp_conn_id)
        pptpconnection = super(
            PPTPDriverMixin, self).update_pptpconnection(
            context,
            pptp_conn_id,
            pptpconnection)
        driver = self._get_driver_for_pptpconnection(context)
        driver.update_pptpconnection(
            context, old_pptpconnection, pptpconnection)
        return pptpconnection

    def create_pptpcredential(self, context, pptpcredential):
        pptpcredential = super(PPTPDriverMixin, self).create_pptpcredential(context, pptpcredential)
        pptpconnection = self._get_pptpconnection(context, pptpcredential["pptpconnection_id"])
        driver = self._get_driver_for_pptpconnection(context)
        driver.create_pptpcredential(
            context, pptpcredential, pptpconnection)
        return pptpcredential

    def delete_pptpcredential(self, context, pptp_cred_id):
        pptpcredential = self.get_pptpcredential(context, pptp_cred_id)
        pptpconnection = self._get_pptpconnection(context, pptpcredential["pptpconnection_id"])
        super(PPTPDriverMixin, self).delete_pptpcredential(context, pptp_cred_id)
        driver = self._get_driver_for_pptpconnection(context)
        driver.delete_pptpcredential(
            context, pptpcredential, pptpconnection)

    def update_pptpcredential(self, context, id, pptpcredential):
        pptpcredential = self._get_pptpcredential(context, id)
        pptpcredential = super(PPTPDriverMixin, self).update_pptpcredential(context, id, pptpcredential)
        pptpconnection = self._get_pptpconnection(context, pptpcredential["pptpconnection_id"])
        driver = self._get_driver_for_pptpconnection(context)
        driver.update_pptpcredential(
            context, pptpcredential, pptpconnection)
        return pptpcredential


class OpenvpnDriverMixin(openvpn_db.Openvpn_db_mixin):
    def create_openvpnconnection(self, context, openvpnconnection):
        vpnservice = {"vpnservice": {
            "name": openvpnconnection["openvpnconnection"]["name"],
            "description": openvpnconnection["openvpnconnection"]["name"],
            "router_id": openvpnconnection["openvpnconnection"]["router_id"],
            "admin_state_up": openvpnconnection["openvpnconnection"]["admin_state_up"],
            "service_type": vpn_consts.SERVICE_TYPE_OPENVPN
        }}
        vpnservice_db = self.create_vpnservice(context, vpnservice)
        openvpnconnection["openvpnconnection"]["vpnservice_id"] = vpnservice_db["id"]
        openvpnconnection = super(
            OpenvpnDriverMixin, self).create_openvpnconnection(
            context, openvpnconnection)
        # fengjj:to test cert generate,build cert here
        # self._inform_openvpndriver(context, openvpnconnection)
        # fengjj:build server in another thread
        greenthread.spawn_n(self._inform_openvpndriver, context, openvpnconnection)
        return openvpnconnection

    def _inform_openvpndriver(self, context, openvpnconnection):
        # build server cert
        self.update_openvpn_server_config(context, openvpnconnection["id"])
        driver = self._get_driver_for_openvpn(context)
        # inform openvpn agent
        driver.create_openvpnconnection(context, openvpnconnection)

    def update_openvpnconnection(self, context, openvpnconnection_id, openvpnconnection):
        openvpnconnection = super(OpenvpnDriverMixin, self).update_openvpnconnection(context, openvpnconnection_id,
                                                                                     openvpnconnection)
        driver = self._get_driver_for_openvpn(context)
        driver.delete_openvpnconnection(context, openvpnconnection)
        return openvpnconnection

    def delete_openvpnconnection(self, context, openvpnconnection_id):
        openvpnconnection = self.get_openvpnconnection(context, openvpnconnection_id)
        super(OpenvpnDriverMixin, self).delete_openvpnconnection(
            context, openvpnconnection_id)
        driver = self._get_driver_for_openvpn(context)
        driver.delete_openvpnconnection(context, openvpnconnection)
        # fengjj:vpn service will be delete automotically
        vpnservice_id = openvpnconnection["vpnservice_id"]
        self.delete_vpnservice(context, vpnservice_id)

    def _get_driver_for_openvpn(self, context):
        vpnservice = vpn_consts.OPENVPN
        return self._get_driver_for_vpnservice(vpnservice)


class SimpleIPsecConnectionDriverMixin(object):
    def create_simpleipsecconnection(self, context, simpleipsecconnection):
        name = simpleipsecconnection["simpleipsecconnection"]["name"]
        vpnservice = {"vpnservice": {
            "name": name,
            "description": name,
            "subnet_id": simpleipsecconnection["simpleipsecconnection"]["subnet_id"],
            "router_id": simpleipsecconnection["simpleipsecconnection"]["router_id"],
            "admin_state_up": simpleipsecconnection["simpleipsecconnection"]["admin_state_up"],
            "service_type": vpn_consts.SERVICE_TYPE_IPSEC
        }}
        vpnservice_db = self.create_vpnservice(context, vpnservice)
        ikepolicy = {"ikepolicy": {
            "name": name,
            "description": name,
            "auth_algorithm": "sha1",
            "encryption_algorithm": "aes-128",
            "phase1_negotiation_mode": "main",
            "lifetime": {},
            "ike_version": "v1",
            "pfs": "group5"
        }}
        ipsecpolicy = {"ipsecpolicy": {
            "name": name,
            "description": name,
            "transform_protocol": "esp",
            "auth_algorithm": "sha1",
            "encryption_algorithm": "aes-128",
            "encapsulation_mode": "tunnel",
            "lifetime": {},
            "pfs": "group5"
        }}
        ikepolicy_db = self.create_ikepolicy(context, ikepolicy)
        ipsecpolicy_db = self.create_ipsecpolicy(context, ipsecpolicy)
        ipsec_site_connection = {"ipsec_site_connection": {
            "name": name,
            "description": name,
            "peer_address": simpleipsecconnection["simpleipsecconnection"]["peer_address"],
            "peer_id": simpleipsecconnection["simpleipsecconnection"]["peer_address"],
            "peer_cidrs": simpleipsecconnection["simpleipsecconnection"]["peer_cidrs"],
            "psk": simpleipsecconnection["simpleipsecconnection"]["psk"],
            "route_mode": "static",
            "mtu": "1500",
            "initiator": "bi-directional",
            "auth_mode": "psk",
            "dpd": {},
            "admin_state_up": simpleipsecconnection["simpleipsecconnection"]["admin_state_up"],
            "vpnservice_id": vpnservice_db["id"],
            "ikepolicy_id": ikepolicy_db["id"],
            "ipsecpolicy_id": ipsecpolicy_db["id"]
        }
        }
        return self.create_ipsec_site_connection(context, ipsec_site_connection)

    def delete_simpleipsecconnection(self, context, connection_id):
        ipsec_connection_db = self.get_ipsec_site_connection(context, connection_id)
        self.delete_ipsec_site_connection(context, connection_id)
        self.delete_ikepolicy(context, ipsec_connection_db["ikepolicy_id"])
        self.delete_ipsecpolicy(context, ipsec_connection_db["ipsecpolicy_id"])
        self.delete_vpnservice(context, ipsec_connection_db["vpnservice_id"])

    def get_simpleipsecconnection(self, context, connection_id, fields=None):
        return self.get_ipsec_site_connection(context, connection_id, fields)


class VPNPlugin(vpn_db.VPNPluginDb):
    """Implementation of the VPN Service Plugin.

    This class manages the workflow of VPNaaS request/response.
    Most DB related works are implemented in class
    vpn_db.VPNPluginDb.
    """
    supported_extension_aliases = ["vpnaas", "service-type", "pptp", "openvpn", "simpleipsecconnection"]
    path_prefix = "/vpn"


class VPNDriverPlugin(VPNPlugin, vpn_db.VPNPluginRpcDbMixin,
                      PPTPDriverMixin,
                      OpenvpnDriverMixin,
                      SimpleIPsecConnectionDriverMixin,
                      pptp_db.PPTPPluginRpcDbMixin,
                      openvpn_db.OpenvpnPluginRpcDbMixin):
    """VpnPlugin which supports VPN Service Drivers."""
    # TODO(nati) handle ikepolicy and ipsecpolicy update usecase
    def __init__(self):
        super(VPNDriverPlugin, self).__init__()
        self.service_type_manager = st_db.ServiceTypeManager.get_instance()
        add_provider_configuration(self.service_type_manager, constants.VPN)
        # Load the service driver from neutron.conf.
        drivers, default_provider = service_base.load_drivers(
            constants.VPN, self)
        LOG.info(_LI("VPN plugin using service driver: %s"), default_provider)
        self.vpn_driver = drivers[default_provider]
        vpn_db.subscribe()

    def get_agent_hosting_vpn_services(self, context, host, vpntype):
        if vpntype == vpn_consts.PPTP:
            return self._get_agent_hosting_pptp_services(context, host)
        elif vpntype == vpn_consts.OPENVPN:
            return self._get_agent_hosting_openvpn_services(context, host)
        else:
            return self._get_agent_hosting_vpn_services(context, host)

    def update_status_by_agent(
            self, context, service_status_info_list, vpntype):
        if vpntype == vpn_consts.PPTP:
            return self.update_pptp_status_by_agent(
                context, service_status_info_list)
        elif vpntype == vpn_consts.OPENVPN:
            return self.update_openvpn_status_by_agent(context, service_status_info_list)
        else:
            return self.update_ipsec_status_by_agent(
                context, service_status_info_list)

    def _get_driver_for_vpnservice(self, vpnservice):
        return self.vpn_driver

    def _get_driver_for_ipsec_site_connection(self, context,
                                              ipsec_site_connection):
        # TODO(nati) get vpnservice when we support service type framework
        vpnservice = None
        return self._get_driver_for_vpnservice(vpnservice)

    def _get_validator(self):
        return self.vpn_driver.validator

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        ipsec_site_connection = super(
            VPNDriverPlugin, self).create_ipsec_site_connection(
            context, ipsec_site_connection)
        driver = self._get_driver_for_ipsec_site_connection(
            context, ipsec_site_connection)
        driver.create_ipsec_site_connection(context, ipsec_site_connection)
        return ipsec_site_connection

    def delete_ipsec_site_connection(self, context, ipsec_conn_id):
        ipsec_site_connection = self.get_ipsec_site_connection(
            context, ipsec_conn_id)
        super(VPNDriverPlugin, self).delete_ipsec_site_connection(
            context, ipsec_conn_id)
        driver = self._get_driver_for_ipsec_site_connection(
            context, ipsec_site_connection)
        driver.delete_ipsec_site_connection(context, ipsec_site_connection)

    def update_ipsec_site_connection(
            self, context,
            ipsec_conn_id, ipsec_site_connection):
        old_ipsec_site_connection = self.get_ipsec_site_connection(
            context, ipsec_conn_id)
        ipsec_site_connection = super(
            VPNDriverPlugin, self).update_ipsec_site_connection(
            context,
            ipsec_conn_id,
            ipsec_site_connection)
        driver = self._get_driver_for_ipsec_site_connection(
            context, ipsec_site_connection)
        driver.update_ipsec_site_connection(
            context, old_ipsec_site_connection, ipsec_site_connection)
        return ipsec_site_connection

    def create_vpnservice(self, context, vpnservice):
        vpnservice = super(
            VPNDriverPlugin, self).create_vpnservice(context, vpnservice)
        driver = self._get_driver_for_vpnservice(vpnservice)
        driver.create_vpnservice(context, vpnservice)
        return vpnservice

    def update_vpnservice(self, context, vpnservice_id, vpnservice):
        old_vpn_service = self.get_vpnservice(context, vpnservice_id)
        new_vpn_service = super(
            VPNDriverPlugin, self).update_vpnservice(context, vpnservice_id,
                                                     vpnservice)
        driver = self._get_driver_for_vpnservice(old_vpn_service)
        driver.update_vpnservice(context, old_vpn_service, new_vpn_service)
        return new_vpn_service

    def delete_vpnservice(self, context, vpnservice_id):
        vpnservice = self._get_vpnservice(context, vpnservice_id)
        super(VPNDriverPlugin, self).delete_vpnservice(context, vpnservice_id)
        driver = self._get_driver_for_vpnservice(vpnservice)
        driver.delete_vpnservice(context, vpnservice)
