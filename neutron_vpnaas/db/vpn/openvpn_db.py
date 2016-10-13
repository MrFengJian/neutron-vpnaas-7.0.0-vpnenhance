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
from neutron.db import models_v2
from neutron.common import constants as n_constants
from neutron.db import common_db_mixin as base_db
from neutron.db import l3_agentschedulers_db as l3_agent_db
from neutron.db import l3_db
from neutron.i18n import _LW
from neutron import manager
from oslo_log import log as logging
from oslo_utils import uuidutils
from neutron.plugins.common import constants
from neutron.plugins.common import utils

from neutron_vpnaas.extensions import openvpn
from neutron_vpnaas.extensions import vpnaas
from neutron_vpnaas.services.vpn.common import cert_util
from sqlalchemy.orm import exc
from neutron_vpnaas.db.vpn import vpn_models

LOG = logging.getLogger(__name__)

import os


class Openvpn_db_mixin(openvpn.OpenvpnPluginBase, base_db.CommonDbMixin):
    def update_status(self, context, model, p_id, status):
        with context.session.begin(subtransactions=True):
            p_db = self._get_resource(context, model, p_id)
            p_db.update({'status': status})

    def _make_openvpnconnection_dict(self, openvpnconnection, fields=None):
        res = {'id': openvpnconnection['id'],
               'tenant_id': openvpnconnection['tenant_id'],
               'name': openvpnconnection['name'],
               'admin_state_up': openvpnconnection['admin_state_up'],
               'vpnservice_id': openvpnconnection['vpnservice_id'],
               'router_id': openvpnconnection['router_id'],
               'protocol': openvpnconnection["protocol"],
               "port": openvpnconnection["port"],
               'client_cidr': openvpnconnection["client_cidr"],
               'status': openvpnconnection['status']
               }
        return self._fields(res, fields)

    def create_openvpnconnection(self, context, openvpnconnection):
        service = openvpnconnection['openvpnconnection']
        tenant_id = self._get_tenant_id_for_create(context, service)
        # Make sure vpnservice exists
        self._get_resource(context, vpn_models.VPNService, service['vpnservice_id'])
        query = self._model_query(context,
                                  vpn_models.OpenvpnConnection).filter(
            vpn_models.OpenvpnConnection.router_id == service['router_id'])
        items = [self._make_openvpnconnection_dict(i) for i in query]
        if items:
            raise openvpn.OpenvpnConnectionExisted(vpnservice_id=service['vpnservice_id'])
        with context.session.begin(subtransactions=True):
            uuid = uuidutils.generate_uuid()
            openvpnconnection_db = vpn_models.OpenvpnConnection(
                id=uuid,
                tenant_id=tenant_id,
                name=service['name'] or uuid,
                admin_state_up=service["admin_state_up"],
                vpnservice_id=service['vpnservice_id'],
                client_cidr=service['client_cidr'],
                protocol=service['protocol'],
                port=service['port'],
                router_id=service["router_id"],
                status=constants.PENDING_CREATE
            )
            context.session.add(openvpnconnection_db)

        openvpnconnection_db = self._get_resource(
            context, vpn_models.OpenvpnConnection, openvpnconnection_db['id'])
        return self._make_openvpnconnection_dict(openvpnconnection_db)

    def get_client_cert(self, context, openvpnconnection_id):
        openvpn_service = self._get_openvpnconnection(context, openvpnconnection_id)
        vpnservice = self._get_by_id(context, vpn_models.VPNService, openvpn_service["vpnservice_id"])
        router_gw_ip = vpnservice.external_v4_ip
        ca_content = openvpn_service.ca
        client_cert_content = openvpn_service.client_certificate
        client_key_content = openvpn_service.client_key
        ta_key_content=openvpn_service.ta_key
        cilent_config = cert_util.CLIENT_CONFIG_TEMPLATE % ({"router_gw_ip": router_gw_ip,
                                                             "protocol": openvpn_service["protocol"].lower(),
                                                             "port": openvpn_service["port"],
                                                             "ta_key": openvpn_service["ta_key"],
                                                             "client_id": openvpnconnection_id[:11]})
        # client_path=os.path.join(NEUTRON_PATH,"openvpn_client")
        # if not os.path.exists(client_path):
        #     os.mkdir(client_path)
        # config_dir=os.path.join(client_path,client_id[:11])
        # os.mkdir(config_dir)
        # with open(os.path.join(config_dir,"client.ovpn")) as config:
        #     config.write(cilent_config)
        # clientZip=zipfile.ZipFile(os.path.join(config_dir,"client.zip"), 'w' ,zipfile.ZIP_DEFLATED)
        # clientZip.write(client_cert_path)
        # clientZip.write(client_key_path)
        # clientZip.write(ca_path)
        # clientZip.write(os.path.join(config_dir,"client.ovpn")) 
        # clientZip.close()

        return {"client_id": openvpnconnection_id[:11],
                "client_cert": client_cert_content,
                "client_key": client_key_content,
                "ta_key":ta_key_content,
                "ca_cert": ca_content,
                "client_config": cilent_config}

    def update_openvpn_server_config(self, context, service_id):
        LOG.debug("begin to prepare server config for openvpn service %s " % (service_id))
        # generate all certs at the same time
        keys_path = cert_util.ensure_server_config(service_id)
        ca_path = os.path.join(keys_path, "ca.crt")
        server_cert_path = os.path.join(keys_path, "server-%s.crt" % (service_id[:11]))
        server_key_path = os.path.join(keys_path, "server-%s.key" % (service_id[:11]))
        dh_path = os.path.join(keys_path, "dh1024.pem")
        client_cert_path = os.path.join(keys_path, "client-%s.crt" % (service_id[:11]))
        client_key_path = os.path.join(keys_path, "client-%s.key" % (service_id[:11]))
        ta_key_path = os.path.join(keys_path, "ta.key")
        ca_content = self.read_content(ca_path)
        server_cert_content = self.read_content(server_cert_path)
        server_key_content = self.read_content(server_key_path)
        dh_content = self.read_content(dh_path)
        client_cert_content = self.read_content(client_cert_path)
        client_key_content = self.read_content(client_key_path)
        ta_key_content = self.read_content(ta_key_path)
        with context.session.begin(subtransactions=True):
            openvpnconnection_db = self._get_resource(context, vpn_models.OpenvpnConnection,
                                                      service_id)
            if openvpnconnection_db:
                conn = {"ca": ca_content,
                        "server_certificate": server_cert_content,
                        "server_key": server_key_content,
                        "dh": dh_content,
                        "client_certificate": client_cert_content,
                        "client_key": client_key_content,
                        "ta_key": ta_key_content}
                openvpnconnection_db.update(conn)

    def read_content(self, path):
        with open(path) as f:
            return f.read()

    def _get_openvpnconnection(self, context, openvpnconnection_id):
        return self._get_resource(context, vpn_models.OpenvpnConnection, openvpnconnection_id)

    def get_openvpnconnection(self, context, openvpnconnection_id, fields=None):
        openvpnconnection_db = self._get_openvpnconnection(context, openvpnconnection_id)
        return self._make_openvpnconnection_dict(openvpnconnection_db, fields)

    def get_openvpnconnections(self, context, filters=None, fields=None):
        return self._get_collection(context, vpn_models.OpenvpnConnection,
                                    self._make_openvpnconnection_dict,
                                    filters=filters, fields=fields)

    def update_openvpnconnection(self, context, openvpnconnection_id, openvpnconnection):
        conn = openvpnconnection['openvpnconnection']
        with context.session.begin(subtransactions=True):
            openvpnconnection_db = self._get_resource(context, vpn_models.OpenvpnConnection,
                                                      openvpnconnection_id)
            if openvpnconnection_db:
                openvpnconnection_db.update(conn)
        return self._make_openvpnconnection_dict(openvpnconnection_db)

    def delete_openvpnconnection(self, context, openvpnconnection_id):
        with context.session.begin(subtransactions=True):
            openvpnconnection_db = self._get_resource(context, vpn_models.OpenvpnConnection,
                                                      openvpnconnection_id)
            context.session.delete(openvpnconnection_db)
        cert_util.delete_server_config(openvpnconnection_id)


class OpenvpnPluginRpcDbMixin(object):
    def _get_agent_hosting_openvpn_services(self, context, host):
        plugin = manager.NeutronManager.get_plugin()
        agent = plugin._get_agent_by_type_and_host(
            context, n_constants.AGENT_TYPE_L3, host)
        agent_conf = plugin.get_configuration_dict(agent)
        agent_mode = agent_conf.get('agent_mode', 'legacy')
        if not agent.admin_state_up or agent_mode == 'dvr':
            return []
        query = context.session.query(vpn_models.VPNService)
        query = query.join(vpn_models.OpenvpnConnection)
        query = query.join(l3_agent_db.RouterL3AgentBinding,
                           l3_agent_db.RouterL3AgentBinding.router_id ==
                           vpn_models.VPNService.router_id)
        vpnservices = query.filter(
            l3_agent_db.RouterL3AgentBinding.l3_agent_id == agent.id).filter(
            vpn_models.OpenvpnConnection.dh != None)
        vpnservices_dict = [self._make_rpcvpnservice_dict(context, vpnservice) for vpnservice in vpnservices]
        return vpnservices_dict

    def _make_rpcvpnservice_dict(self, context, vpnservice):
        vpnservice_dict = dict(vpnservice)
        router = context.session.query(l3_db.Router).filter(l3_db.Router.id == vpnservice.router_id).one()
        router_attached_ports = router.attached_ports
        port_ids = [port.port_id for port in router_attached_ports if port.port_type == "network:router_interface"]
        subnet_query = context.session.query(models_v2.Subnet)
        subnet_query = subnet_query.join(models_v2.IPAllocation, models_v2.Subnet.id
                                         == models_v2.IPAllocation.subnet_id)
        subnets = subnet_query.filter(models_v2.IPAllocation.port_id.in_(port_ids))
        vpnservice_dict["cidrs"] = [subnet.cidr for subnet in subnets]
        vpnservice_dict['openvpnconnections'] = []
        for openvpnconnection in vpnservice.openvpnconnections:
            openvpnconnection_dict = dict(openvpnconnection)
            vpnservice_dict['openvpnconnections'].append(openvpnconnection_dict)
        return vpnservice_dict

    def update_openvpn_status_by_agent(self, context, service_status_info_list):
        with context.session.begin(subtransactions=True):
            for vpnservice in service_status_info_list:
                try:
                    vpnservice_db = self._get_vpnservice(
                        context, vpnservice['id'])
                except vpnaas.VPNServiceNotFound:
                    LOG.warn(_LW('vpnservice %s in db is already deleted'),
                             vpnservice['id'])
                    continue

                if (not utils.in_pending_status(vpnservice_db.status)
                    or vpnservice['updated_pending_status']):
                    vpnservice_db.status = vpnservice['status']
                for openvpnconnection_id, conn in vpnservice['openvpn_connections'].items():
                    try:
                        conn_db = self._get_resource(
                            context, vpn_models.OpenvpnConnection, openvpnconnection_id)
                    except openvpn.OpenvpnConnectionNotFound:
                        continue
                    if (not utils.in_pending_status(conn_db.status)
                        or conn['updated_pending_status']):
                        conn_db.status = conn['status']
