基于OpenStack Liberty vpnaas 7.0.0版本，通过其原生的扩展机制扩展SSLVPN、PPTP VPN功能，并通过包装其原生的IPSec VPN接口，简化IPSec VPN的调用过程。

# SSLVPN

基于openvpn的的SSLVPN实现，提供基于证书访问被隔离的内网

# PPTP VPN

提供基于accel-ppp或者pptpd两种驱动的PPTP VPN实现，能够通过用户、密码来登陆VPN，从而访问被隔离的内网。

# IPSec VPN

原生VPNaaS支持的基于OpenSwan或者StrongSwan的Site-to-Site VPN实现，使隔离的两个网络之间能够通信。