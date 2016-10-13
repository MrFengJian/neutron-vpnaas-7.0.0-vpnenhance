# Copyright 2013, Nachi Ueno, NTT I3, Inc.
# All Rights Reserved.
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
#    License for the specific language governing file_modes and limitations
#    under the License.
import abc
import copy
import shutil
import os
import netaddr
from oslo_concurrency import lockutils
from oslo_config import cfg
import oslo_messaging
import six

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import rpc as n_rpc
from neutron import context
from oslo_log import log as logging
from oslo_service import loopingcall
from neutron.plugins.common import constants
from neutron.plugins.common import utils as plugin_utils
from neutron_vpnaas.services.vpn.common import topics
from neutron_vpnaas.services.vpn.common import constants as vpn_consts
from neutron_vpnaas.services.vpn import device_drivers
from neutron_vpnaas.services.vpn.device_drivers import linux as linux_driver

LOG = logging.getLogger(__name__)
TEMPLATE_PATH = os.path.dirname(__file__)

openvpn_opts = [
    cfg.StrOpt(
        'config_base_dir',
        default='$state_path/openvpn',
        help=_('Location to store accel ppp server config files')),
    cfg.IntOpt(
        'status_check_interval',
        default=60,
        help=_("Interval for checking accel ppp status")),
    cfg.StrOpt(
        'config_template',
        default=os.path.join(
            TEMPLATE_PATH,
            'template/openvpn/openvpn.conf.template'),
        help=_('Template file for openvpn configuration')),
    cfg.ListOpt(
        'dns',
        default=['8.8.8.8', '4.4.4.4'],
        help=_('DNS for openvpn server.')),
]

cfg.CONF.register_opts(openvpn_opts, 'openvpn')
OPENVPN_CONNS = "openvpn_connections"


@six.add_metaclass(abc.ABCMeta)
class BaseSSLVpnProcess(linux_driver.BaseLinuxProcess):
    def __init__(self, conf, process_id, vpnservice, namespace):
        self.binary = "openvpn"
        self.CONFIG_DIRS = [
            "var/run",
            "log",
            "etc"]
        self.config_dir = os.path.join(
            cfg.CONF.openvpn.config_base_dir, process_id)
        super(BaseSSLVpnProcess, self).__init__(conf, process_id,
                                                vpnservice, namespace, self.config_dir)

    def translate_dialect(self):
        pass

    def _get_config_filename(self, kind):
        config_dir = self.etc_dir
        return os.path.join(config_dir, kind)

    def _ensure_dir(self, dir_path):
        if not os.path.isdir(dir_path):
            os.makedirs(dir_path, 0o755)

    def ensure_config_dir(self, vpnservice):
        """Create config directory if it does not exist."""
        self._ensure_dir(self.config_dir)
        for subdir in self.CONFIG_DIRS:
            dir_path = os.path.join(self.config_dir, subdir)
            self._ensure_dir(dir_path)

    def _gen_config_content(self, template_file, openvpnconnection):
        template = linux_driver._get_template(template_file)
        openvpn_path = self.etc_dir
        pool_cidr = openvpnconnection["client_cidr"]
        address = netaddr.IPNetwork(pool_cidr)
        network = str(address.network)
        netmask = str(address.netmask)
        cidrs = self.vpnservice["cidrs"]
        router_cidr_list = []
        for cidr in cidrs:
            address = netaddr.IPNetwork(cidr)
            m = {"network": str(address.network),
                 "netmask": str(address.netmask)}
            router_cidr_list.append(m)
        protocol = openvpnconnection["protocol"].lower()
        port = openvpnconnection["port"]
        return template.render(
            {'openvpnconnection': openvpnconnection,
             'openvpn_path': openvpn_path,
             'protocol': protocol,
             'port': port,
             'network': network,
             'netmask': netmask,
             'router_cidr_list': router_cidr_list})

    @property
    def active(self):
        """Check if the process is active or not."""
        if not self.namespace:
            return False
        try:
            status = self.get_status()
            if status == constants.ACTIVE:
                return True
        except RuntimeError:
            return False
        return False

    def _update_connection_status(self, status):
        for conn_id in self.connection_status:
            self.connection_status[conn_id] = {'status': status}

    def get_connection_status(self, conn_id):
        if conn_id not in self.connection_status:
            self.connection_status[conn_id] = {'status': None}
        return self.connection_status[conn_id]

    def update(self):
        """Update Status based on vpnservice configuration."""
        super(BaseSSLVpnProcess, self).update()

        self.vpnservice['status'] = self.get_status()
        for openvpnconnection in self.vpnservice['openvpnconnections']:
            if plugin_utils.in_pending_status(openvpnconnection['status']):
                conn_id = openvpnconnection['id']
                conn_status = self.get_connection_status(conn_id)
                if not conn_status:
                    continue
                conn_status['updated_pending_status'] = True
                conn_status['status'] = self.vpnservice['status']
                openvpnconnection['status'] = conn_status['status']


@six.add_metaclass(abc.ABCMeta)
class OpenVpnProcess(BaseSSLVpnProcess):
    """
    openvpn process manager class
    """

    def __init__(self, conf, process_id, vpnservice, namespace):
        super(OpenVpnProcess, self).__init__(conf, process_id,
                                             vpnservice, namespace)
        self.binary = "openvpn"
        self.tunnel_interface = "tun0"
        self.pid_file = os.path.join(
            self.config_dir, 'var', 'run', 'openvpn.pid')

    def _execute(self, cmd, check_exit_code=True):
        """Execute command on namespace."""
        ip_wrapper = ip_lib.IPWrapper(namespace=self.namespace)
        return ip_wrapper.netns.execute(
            cmd,
            check_exit_code=check_exit_code)

    def remove_config(self):
        """Remove whole config file and delete related user."""
        shutil.rmtree(self.config_dir, ignore_errors=True)

    def ensure_configs(self):
        """Generate config files which are needed for openvpn.

        If there is no directory, this function will create
        dirs.
        """
        self.ensure_config_dir(self.vpnservice)
        # ensure config for openvpn process
        openvpnconnection = self.vpnservice['openvpnconnections'][0]
        config_file_name = self._get_config_filename('ca.crt')
        utils.replace_file(config_file_name, openvpnconnection['ca'])

        config_file_name = self._get_config_filename('server.crt')
        utils.replace_file(
            config_file_name, openvpnconnection['server_certificate'])

        config_file_name = self._get_config_filename('server.key')
        utils.replace_file(config_file_name, openvpnconnection['server_key'])

        config_file_name = self._get_config_filename('dh1024.pem')
        utils.replace_file(config_file_name, openvpnconnection['dh'])

        config_file_name = self._get_config_filename('ta.key')
        utils.replace_file(config_file_name, openvpnconnection['ta_key'])

        self.ensure_config_file("openvpn.conf", self.conf.openvpn.config_template, openvpnconnection)

    def ensure_config_file(self, kind, template, openvpnconnection):
        """Update config file, based on current settings for service."""
        config_str = self._gen_config_content(template, openvpnconnection)
        config_file_name = self._get_config_filename(kind)
        utils.replace_file(config_file_name, config_str)

    def get_status(self):
        pid = self.pid
        if pid is None:
            return False
        cmdline = '/proc/%s/cmdline' % pid
        try:
            with open(cmdline, "r"):
                return constants.ACTIVE
        except IOError:
            return constants.DOWN

    def restart(self):
        """Restart the process."""
        self.stop()
        self.start()
        return

    def start(self):
        """Start the process.

        Note: if there is not namespace yet,
        just do nothing, and wait next event.
        """
        if not self.namespace:
            return
        config_file_name = self._get_config_filename('openvpn.conf')
        log_file = os.path.join(self.log_dir, 'openvpn.log')
        # openvpn will create tap interfaces automotically
        # if not ip_lib.device_exists(self.tunnel_interface,
        #                             namespace=self.namespace):
        #     #setup tun device
        #     self._execute([self.binary,
        #                    '--mktun',
        #                    '--dev', self.tunnel_interface,
        #                    ])

        # device = ip_lib.IPDevice(self.tunnel_interface, 
        #                          namespace=self.namespace)
        # device.link.set_up()

        self._execute([self.binary,
                       '--tls-server',
                       '--daemon',
                       '--writepid', self.pid_file,
                       '--log-append', log_file,
                       '--config', config_file_name,
                       ])
        openvpnconnections = self.vpnservice['openvpnconnections']
        for openvpnconnection in openvpnconnections:
            self.connection_status[openvpnconnection["id"]] = {"status": constants.ACTIVE}

    @property
    def pid(self):
        try:
            with open(self.pid_file, 'r') as f:
                return int(f.read())
        except IOError:
            LOG.warn('Unable to access %s', self.pid_file)
        return None

    def stop(self):
        pid = self.pid
        if pid:
            utils.execute(['kill', '-9', pid], run_as_root=True)
            os.remove(self.pid_file)
        if ip_lib.device_exists(self.tunnel_interface,
                                namespace=self.namespace):
            device = ip_lib.IPDevice(
                self.tunnel_interface, namespace=self.namespace)
            device.link.delete()
        # clean connection_status info
        self.connection_status = {}


@six.add_metaclass(abc.ABCMeta)
class SslVpnDriver(device_drivers.DeviceDriver):
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, agent, host):
        self.agent = agent
        self.conf = self.agent.conf
        self.host = host
        self.conn = n_rpc.create_connection(new=True)
        self.context = context.get_admin_context_without_session()
        # Different consumer topic from IPSEC
        self.topic = topics.OPENVPN_AGENT_TOPIC
        node_topic = '%s.%s' % (self.topic, self.host)

        self.processes = {}
        self.routers = {}
        self.process_status_cache = {}

        self.endpoints = [self]
        self.conn.create_consumer(node_topic, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        # Currently, the service driver is shared with IPSEC, so the rpc agent
        # topic should be IPSEC.
        self.agent_rpc = linux_driver.VpnDriverApi(topics.IPSEC_DRIVER_TOPIC)
        self.process_status_cache_check = loopingcall.FixedIntervalLoopingCall(
            self.report_status, self.context)
        self.process_status_cache_check.start(
            interval=self.conf.openvpn.status_check_interval)

    def get_namespace(self, router_id):
        """Get namespace of router.

        :router_id: router_id
        :returns: namespace string.
            Note: If the router is a DVR, then the SNAT namespace will be
                  provided. If the router does not exist, return None.
        """
        router = self.routers.get(router_id)
        if not router:
            return
        # For DVR, use SNAT namespace
        # TODO(pcm): Use router object method to tell if DVR, when available
        if router.router['distributed']:
            return router.snat_namespace.name
        else:
            return router.ns_name

    def vpnservice_updated(self, context, **kwargs):
        """Vpnservice updated rpc handler

        VPN Service Driver will call this method
        when openvpn updated.
        Then this method start sync with server.
        """
        router = kwargs.get('router', None)
        openvpnconnection = kwargs.get('openvpnconnection', None)
        self.sync(context, [router] if router else [], openvpnconnection=openvpnconnection)

    @abc.abstractmethod
    def create_process(self, process_id, vpnservice, namespace):
        pass

    def ensure_process(self, process_id, vpnservice=None):
        """Ensuring process.

        If the process doesn't exist, it will create process
        and store it in self.processs
        """
        process = self.processes.get(process_id)
        if not process or not process.namespace:
            namespace = self.get_namespace(process_id)
            # TODO:in some cases,this namespace will be None
            if not namespace:
                namespace = "qrouter-%s" % (process_id)
                LOG.warn("router id do not have namespace ,treat to be " + namespace)
            process = self.create_process(
                process_id,
                vpnservice,
                namespace)
            self.processes[process_id] = process
        elif vpnservice:
            process.update_vpnservice(vpnservice)
        return process

    def create_router(self, router):
        """Handling create router event.

        Agent calls this method, when the process namespace
        is ready.
        """
        process_id = router.router_id
        self.routers[process_id] = router
        if process_id in self.processes:
            # In case of vpnservice is created
            # before router's namespace
            process = self.processes[process_id]
            process.enable()

    def destroy_router(self, process_id):
        """Handling destroy_router event.

        Agent calls this method, when the process namespace
        is deleted.
        """
        if process_id in self.processes:
            process = self.processes[process_id]
            process.disable()
            del self.processes[process_id]
        if process_id in self.routers:
            del self.routers[process_id]

    def get_process_status_cache(self, process):
        if not self.process_status_cache.get(process.id):
            self.process_status_cache[process.id] = {
                'status': None,
                'id': process.vpnservice['id'],
                'updated_pending_status': False,
                OPENVPN_CONNS: {}}
        return self.process_status_cache[process.id]

    def is_status_updated(self, process, previous_status):
        if process.updated_pending_status:
            return True
        if process.status != previous_status['status']:
            return True
        if process.active and (process.connection_status !=
                                   previous_status[OPENVPN_CONNS]):
            return True

    def unset_updated_pending_status(self, process):
        process.updated_pending_status = False
        for connection_status in process.connection_status.values():
            connection_status['updated_pending_status'] = False

    def copy_process_status(self, process):
        return {
            'id': process.vpnservice['id'],
            'status': process.status,
            'updated_pending_status': process.updated_pending_status,
            OPENVPN_CONNS: copy.deepcopy(process.connection_status)
        }

    def update_downed_connections(self, process_id, new_status):
        """Update info to be reported, if connections just went down.

        If there is no longer any information for a connection, because it
        has been removed (e.g. due to an admin down of VPN service or openvpn
        connection), but there was previous status information for the
        connection, mark the connection as down for reporting purposes.
        """
        if process_id in self.process_status_cache:
            for conn in self.process_status_cache[process_id][OPENVPN_CONNS]:
                if conn not in new_status[OPENVPN_CONNS]:
                    new_status[OPENVPN_CONNS][conn] = {
                        'status': constants.DOWN,
                        'updated_pending_status': True
                    }

    def report_status(self, context):
        status_changed_vpn_services = []
        for process in self.processes.values():
            previous_status = self.get_process_status_cache(process)
            if self.is_status_updated(process, previous_status):
                new_status = self.copy_process_status(process)
                self.update_downed_connections(process.id, new_status)
                status_changed_vpn_services.append(new_status)
                self.process_status_cache[process.id] = (
                    self.copy_process_status(process))
                # We need unset updated_pending status after it
                # is reported to the server side
                self.unset_updated_pending_status(process)

        if status_changed_vpn_services:
            self.agent_rpc.update_status(
                context,
                status_changed_vpn_services,
                vpn_consts.OPENVPN)

    @lockutils.synchronized('vpn-agent', 'neutron-')
    def sync(self, context, routers, openvpnconnection=None):
        """Sync status with server side.

        :param context: context object for RPC call
        :param routers: Router objects which is created in this sync event

        There could be many failure cases should be
        considered including the followings.
        1) Agent class restarted
        2) Failure on process creation
        3) VpnService is deleted during agent down
        4) RPC failure

        In order to handle, these failure cases,
        This driver takes simple sync strategies.
        """
        vpnservices = self.agent_rpc.get_vpn_services_on_host(
            context, self.host, vpn_consts.OPENVPN)
        router_ids = [vpnservice['router_id'] for vpnservice in vpnservices]
        sync_router_ids = [router['id'] for router in routers]
        self._sync_vpn_processes(vpnservices, sync_router_ids,
                                 openvpnconnection=openvpnconnection)
        self._delete_vpn_processes(sync_router_ids, router_ids)
        self._cleanup_stale_vpn_processes(router_ids)

        self.report_status(context)

    def _sync_vpn_processes(self, vpnservices, sync_router_ids,
                            openvpnconnection=None):
        # Ensure the ipsec process is enabled only for
        # - the vpn services which are not yet in self.processes
        # - vpn services whose router id is in 'sync_router_ids'
        for vpnservice in vpnservices:
            if vpnservice['router_id'] not in self.processes or (
                        vpnservice['router_id'] in sync_router_ids):
                process = self.ensure_process(vpnservice['router_id'],
                                              vpnservice=vpnservice)
                # router = self.routers.get(vpnservice['router_id'])
                # if not router:
                #     continue
                # # For HA router, spawn vpn process on master router
                # # and terminate vpn process on backup router
                # if router.router['ha'] and router.ha_state == 'backup':
                #     process.disable()
                # else:
                process.update()

    def _delete_vpn_processes(self, sync_router_ids, vpn_router_ids):
        # Delete any accel ppp processes that are
        # associated with routers, but are not running the VPN service.
        for process_id in sync_router_ids:
            if process_id not in vpn_router_ids:
                self.ensure_process(process_id)
                self.destroy_router(process_id)

    def _cleanup_stale_vpn_processes(self, vpn_router_ids):
        # Delete any accel ppp processes running
        # VPN that do not have an associated router.
        process_ids = [pid for pid in self.processes
                       if pid not in vpn_router_ids]
        for process_id in process_ids:
            self.destroy_router(process_id)


class OpenVpnDriver(SslVpnDriver):
    def create_process(self, process_id, vpnservice, namespace):
        return OpenVpnProcess(self.conf, process_id, vpnservice, namespace)
