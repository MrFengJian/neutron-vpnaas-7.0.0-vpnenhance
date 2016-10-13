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
#    License for the specific language governing permissions and limitations
#    under the License.
import abc
import os
import shutil

import jinja2
import oslo_messaging
from oslo_log import log as logging

from neutron.common import rpc as n_rpc
from neutron.plugins.common import constants
from neutron.plugins.common import utils as plugin_utils
from neutron_vpnaas.services.vpn import device_drivers

LOG = logging.getLogger(__name__)
TEMPLATE_PATH = os.path.dirname(__file__)

JINJA_ENV = None


def _get_template(template_file):
    global JINJA_ENV
    if not JINJA_ENV:
        templateLoader = jinja2.FileSystemLoader(searchpath="/")
        JINJA_ENV = jinja2.Environment(loader=templateLoader)
    return JINJA_ENV.get_template(template_file)


class BaseLinuxProcess(device_drivers.BaseProcess):
    """Linux Process Manager

    This class manages start/restart/stop ipsec process.
    This class create/delete config template
    """

    CONFIG_DIRS = []

    DIALECT_MAP = {}

    def __init__(self, conf, process_id, vpnservice, namespace, config_dir):
        self.conf = conf
        self.id = process_id
        self.updated_pending_status = False
        self.namespace = namespace
        self.connection_status = {}
        self.config_dir = config_dir
        self.etc_dir = os.path.join(self.config_dir, 'etc')
        self.log_dir = os.path.join(self.config_dir, 'log')
        self.update_vpnservice(vpnservice)

    @abc.abstractmethod
    def translate_dialect(self):
        pass

    def update_vpnservice(self, vpnservice):
        self.vpnservice = vpnservice
        self.translate_dialect()

    def _dialect(self, obj, key):
        obj[key] = self.DIALECT_MAP.get(obj[key], obj[key])

    @abc.abstractmethod
    def ensure_config_file(self, kind, template, vpnservice):
        """Update config file,  based on current settings for service."""
        pass

    def remove_config(self):
        """Remove whole config file."""
        shutil.rmtree(self.config_dir, ignore_errors=True)

    @abc.abstractmethod
    def ensure_config_dir(self, vpnservice):
        """Create config directory if it does not exist."""
        pass

    @property
    def status(self):
        if self.active:
            return constants.ACTIVE
        return constants.DOWN

    @property
    def active(self):
        """Check if the process is active or not."""
        if not self.namespace:
            return False
        try:
            self.get_status()
        except RuntimeError:
            return False
        return True

    def update(self):
        """Update Status based on vpnservice configuration."""
        if self.vpnservice and not self.vpnservice['admin_state_up']:
            self.disable()
        else:
            self.enable()

        if plugin_utils.in_pending_status(self.vpnservice['status']):
            self.updated_pending_status = True

    def enable(self):
        """Enabling the process."""
        try:
            self.ensure_configs()
            if self.active:
                self.restart()
            else:
                self.start()
        except RuntimeError:
            LOG.exception(
                _("Failed to enable vpn process on router %s"),
                self.id)

    def disable(self):
        """Disabling the process."""
        try:
            if self.active:
                self.stop()
            self.remove_config()
        except RuntimeError:
            LOG.exception(
                _("Failed to disable vpn process on router %s"),
                self.id)


class VpnDriverApi(object):
    """IPSecVpnDriver RPC api."""

    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_vpn_services_on_host(self, context, host, vpntype):
        """Get list of openvpn.
        """
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_vpn_services_on_host', host=host,
                          vpntype=vpntype)

    def update_status(self, context, status, vpntype):
        """Update local status.

        This method call updates status attribute of
        VPNServices.
        """
        cctxt = self.client.prepare()
        return cctxt.call(context, 'update_status', status=status,
                          vpntype=vpntype)
