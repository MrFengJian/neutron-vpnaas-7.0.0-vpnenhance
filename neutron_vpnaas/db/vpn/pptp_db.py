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

from neutron.common import constants as n_constants
from neutron.db import common_db_mixin as base_db
from neutron.db import l3_agentschedulers_db as l3_agent_db
from neutron.i18n import _LW
from neutron import manager
from oslo_log import log as logging
from oslo_utils import uuidutils
from neutron.plugins.common import constants
from neutron.plugins.common import utils

from neutron_vpnaas.extensions import pptp
from neutron_vpnaas.extensions import vpnaas
from neutron_vpnaas.db.vpn import vpn_models
from sqlalchemy.orm import exc

LOG = logging.getLogger(__name__)


class PPTP_db_mixin(pptp.PPTPPluginBase, base_db.CommonDbMixin):
    def update_status(self, context, model, p_id, status):
        with context.session.begin(subtransactions=True):
            p_db = self._get_resource(context, model, p_id)
            p_db.update({'status': status})

    def _make_pptpconnection_dict(self, pptpconnection, fields=None):
        res = {'id': pptpconnection['id'],
               'tenant_id': pptpconnection['tenant_id'],
               'name': pptpconnection['name'],
               'admin_state_up': pptpconnection['admin_state_up'],
               'vpnservice_id': pptpconnection['vpnservice_id'],
               'router_id': pptpconnection['router_id'],
               'client_cidr':
                   pptpconnection['client_cidr'],
               'status': pptpconnection['status']
               }
        res['credentials'] = [
            dict(cred) for cred in pptpconnection.credentials]
        return self._fields(res, fields)

    def create_pptpconnection(self, context, pptpconnection):
        conn = pptpconnection['pptpconnection']
        tenant_id = self._get_tenant_id_for_create(context, conn)
        # Make sure vpnservice exists
        self._get_resource(context, vpn_models.VPNService, conn['vpnservice_id'])
        with context.session.begin(subtransactions=True):
            uuid = uuidutils.generate_uuid()
            pptp_conn_db = vpn_models.PPTPConnection(
                id=uuid,
                tenant_id=tenant_id,
                name=conn['name'] or uuid,
                admin_state_up=conn['admin_state_up'],
                vpnservice_id=conn['vpnservice_id'],
                client_cidr=conn['client_cidr'],
                router_id=conn["router_id"],
                status=constants.PENDING_CREATE
            )
            context.session.add(pptp_conn_db)

        pptp_conn_db = self._get_resource(
            context, vpn_models.PPTPConnection, pptp_conn_db['id'])
        return self._make_pptpconnection_dict(pptp_conn_db)

    def _get_pptpconnection(self, context, pptp_conn_id):
        return self._get_resource(context, vpn_models.PPTPConnection, pptp_conn_id)

    def get_pptpconnection(self, context, pptp_conn_id, fields=None):
        pptp_conn_db = self._get_pptpconnection(context, pptp_conn_id)
        return self._make_pptpconnection_dict(pptp_conn_db, fields)

    def get_pptpconnections(self, context, filters=None, fields=None):
        return self._get_collection(context, vpn_models.PPTPConnection,
                                    self._make_pptpconnection_dict,
                                    filters=filters, fields=fields)

    def update_pptpconnection(self, context, pptp_conn_id, pptpconnection):
        conn = pptpconnection['pptpconnection']
        with context.session.begin(subtransactions=True):
            pptp_conn_db = self._get_resource(context, vpn_models.PPTPConnection,
                                              pptp_conn_id)
            if pptp_conn_db:
                pptp_conn_db.update(conn)
        return self._make_pptpconnection_dict(pptp_conn_db)

    def delete_pptpconnection(self, context, pptp_conn_id):
        with context.session.begin(subtransactions=True):
            pptp_conn_db = self._get_resource(context, vpn_models.PPTPConnection,
                                              pptp_conn_id)
            context.session.delete(pptp_conn_db)

    def _make_pptpcredential_dict(self, pptpcredential, fields=None):
        res = {'id': pptpcredential['id'],
               'tenant_id': pptpcredential['tenant_id'],
               'name': pptpcredential['name'],
               'username': pptpcredential['username'],
               'password': pptpcredential['password'],
               "admin_state_up": pptpcredential["admin_state_up"],
               "pptpconnection_id": pptpcredential["pptpconnection_id"]
               }
        return self._fields(res, fields)

    def create_pptpcredential(self, context, pptpcredential):
        credential = pptpcredential['pptpcredential']
        pptpconnection_id = credential["pptpconnection_id"]
        cred_username = credential["username"]
        count = self._get_collection_count(context, vpn_models.PPTPCredential,
                                           filters={"pptpconnection_id": pptpconnection_id, "username": cred_username})
        if count:
            raise pptp.PPTPCredentialExisted(username=cred_username, connection_id=pptpconnection_id)
        tenant_id = self._get_tenant_id_for_create(context, credential)
        with context.session.begin(subtransactions=True):
            uuid = uuidutils.generate_uuid()
            pptp_cred_db = vpn_models.PPTPCredential(
                id=uuid,
                tenant_id=tenant_id,
                name=credential['name'] or uuid,
                admin_state_up=credential["admin_state_up"],
                pptpconnection_id=pptpconnection_id,
                username=cred_username,
                password=credential['password'],
            )
            context.session.add(pptp_cred_db)

        pptp_cred_db = self._get_resource(
            context, vpn_models.PPTPCredential, pptp_cred_db['id'])
        return self._make_pptpcredential_dict(pptp_cred_db)

    def _get_pptpcredential(self, context, pptp_cred_id):
        return self._get_resource(context, vpn_models.PPTPCredential, pptp_cred_id)

    def get_pptpcredential(self, context, pptp_cred_id, fields=None):
        pptp_cred_db = self._get_pptpcredential(context, pptp_cred_id)
        return self._make_pptpcredential_dict(pptp_cred_db, fields)

    def get_pptpcredentials(self, context, filters=None, fields=None):
        if "pptpconnection_id" not in filters:
            raise pptp.PPTPCredententailQueryNotAllowed()
        return self._get_collection(context, vpn_models.PPTPCredential,
                                    self._make_pptpcredential_dict,
                                    filters=filters, fields=fields)

    def update_pptpcredential(self, context, pptp_cred_id, pptpcredential):
        conn = pptpcredential['pptpcredential']
        with context.session.begin(subtransactions=True):
            pptp_cred_db = self._get_resource(context, vpn_models.PPTPCredential,
                                              pptp_cred_id)
            if pptp_cred_db:
                pptp_cred_db.update(conn)
        return self._make_pptpcredential_dict(pptp_cred_db)

    def delete_pptpcredential(self, context, pptp_cred_id):
        with context.session.begin(subtransactions=True):
            pptp_cred_db = self._get_resource(context, vpn_models.PPTPCredential,
                                              pptp_cred_id)
            context.session.delete(pptp_cred_db)


class PPTPPluginRpcDbMixin(object):
    def _get_agent_hosting_pptp_services(self, context, host):
        plugin = manager.NeutronManager.get_plugin()
        agent = plugin._get_agent_by_type_and_host(
            context, n_constants.AGENT_TYPE_L3, host)
        agent_conf = plugin.get_configuration_dict(agent)
        agent_mode = agent_conf.get('agent_mode', 'legacy')
        if not agent.admin_state_up or agent_mode == 'dvr':
            return []
        query = context.session.query(vpn_models.VPNService)
        query = query.join(vpn_models.PPTPConnection)
        query = query.join(l3_agent_db.RouterL3AgentBinding,
                           l3_agent_db.RouterL3AgentBinding.router_id ==
                           vpn_models.VPNService.router_id)
        query = query.filter(
            l3_agent_db.RouterL3AgentBinding.l3_agent_id == agent.id)
        return query

    def update_pptp_status_by_agent(self, context, service_status_info_list):
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
                for conn_id, conn in vpnservice['pptpconnections'].items():
                    try:
                        conn_db = self._get_resource(
                            context, vpn_models.PPTPConnection, conn_id)
                    except pptp.PPTPConnectionNotFound:
                        continue
                    if (not utils.in_pending_status(conn_db.status)
                        or conn['updated_pending_status']):
                        conn_db.status = conn['status']
