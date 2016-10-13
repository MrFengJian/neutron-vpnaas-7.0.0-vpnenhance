#author:fengjj@chinaskycloud.com
#use for openvpn extension to generate sertificates
import pexpect
import os,shutil
from oslo_log import log as logging
from oslo_config import cfg

cert_opts = [
    cfg.StrOpt('easy_rsa_path', default='/usr/share/easy-rsa',
               help=_("path to easy-rsa tools"))]
LOG = logging.getLogger(__name__)

cfg.CONF.register_opts(cert_opts)

CLIENT_CONFIG_TEMPLATE="""
client
dev tap
proto %(protocol)s
remote %(router_gw_ip)s %(port)s
resolv-retry infinite
nobind
persist-key
persist-tun
tls-auth ta.key 1
ca ca.crt
cert client-%(client_id)s.crt
key client-%(client_id)s.key
remote-cert-tls server
link-mtu 1573
verb 3
"""

"""
fengjj:delete local certificates for open vpn service
"""
def delete_server_config(service_id):
    server_data_dir=os.path.join(cfg.CONF.state_path,"tmp",service_id[:11])
    if os.path.exists(server_data_dir):
        shutil.rmtree(server_data_dir)
"""
fengjj:create ca.crt,server.crt,dh1024.pem,files used for openvpn server
"""
def ensure_server_config(service_id):
    server_data_dir=build_keys_path(service_id)
    if os.path.exists(os.path.join(server_data_dir,"keys","dh1024.pem")):
        return os.path.join(server_data_dir,"keys")
    shutil.copytree(cfg.CONF.easy_rsa_path,server_data_dir)
    os.chdir(server_data_dir)
    cleanall=pexpect.run("bash skycloud-clean-all")
    buildca=pexpect.spawn("bash skycloud-ca")
    buildca.expect("CN]:")
    buildca.sendline()
    buildca.expect("ShaanXi]:")
    buildca.sendline()
    buildca.expect("Xi'an]:")
    buildca.sendline()
    buildca.expect("SkycloudSoftware]:")
    buildca.sendline()
    buildca.expect("SkycloudSoftwareUnit]:")
    buildca.sendline()
    buildca.expect("CA]:")
    buildca.sendline()
    buildca.expect("SkyCloud]:")
    buildca.sendline()
    buildca.expect("com]:")
    buildca.sendline()
    server="server-"+service_id[:11]
    buildserver=pexpect.spawn("bash skycloud-server %s"%(server))
    buildserver.expect("CN]:")
    buildserver.sendline()
    buildserver.expect("ShaanXi]:")
    buildserver.sendline()
    buildserver.expect("Xi'an]:")
    buildserver.sendline()
    buildserver.expect("SkycloudSoftware]:")
    buildserver.sendline()
    buildserver.expect("SkycloudSoftwareUnit]:")
    buildserver.sendline()
    buildserver.expect("%s]:"%(server))
    buildserver.sendline()
    buildserver.expect("SkyCloud]:")
    buildserver.sendline()
    buildserver.expect("com]:")
    buildserver.sendline()
    buildserver.expect_exact("A challenge password []:")
    buildserver.sendline()
    buildserver.expect_exact("An optional company name []:")
    buildserver.sendline()
    buildserver.expect_exact("Sign the certificate? [y/n]:")
    buildserver.sendline("y")
    buildserver.expect_exact("n]")
    buildserver.sendline("y")
    buildserver.sendline()
    ensure_client(service_id,service_id)
    build_takey=pexpect.spawn("openvpn --genkey --secret ./keys/ta.key")
    builddh=pexpect.run("bash skycloud-build-dh")
    return os.path.join(server_data_dir,"keys")

def build_keys_path(service_id):
    return os.path.join(cfg.CONF.state_path,"tmp",service_id[:11])

"""
fengjj:create client.crt,use for openvpn client to connect
"""
def ensure_client(service_id,client_id):
    server_data_dir=build_keys_path(service_id)
    os.chdir(server_data_dir)
    client="client-"+client_id[:11]
    buildclient=pexpect.spawn("bash skycloud-build-key %s"%(client))
    buildclient.expect("CN]:")
    buildclient.sendline()
    buildclient.expect("ShaanXi]:")
    buildclient.sendline()
    buildclient.expect("Xi'an]:")
    buildclient.sendline()
    buildclient.expect("SkycloudSoftware]:")
    buildclient.sendline()
    buildclient.expect("SkycloudSoftwareUnit]:")
    buildclient.sendline()
    buildclient.expect("%s]:"%(client))
    buildclient.sendline()
    buildclient.expect("SkyCloud]:")
    buildclient.sendline()
    buildclient.expect("com]:")
    buildclient.sendline()
    buildclient.expect_exact("A challenge password []:")
    buildclient.sendline()
    buildclient.expect_exact("An optional company name []:")
    buildclient.sendline()
    buildclient.expect_exact("Sign the certificate? [y/n]:")
    buildclient.sendline("y")
    buildclient.expect_exact("n]")
    buildclient.sendline("y")
    buildclient.sendline()
    return os.path.join(server_data_dir,"keys")