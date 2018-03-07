# Copyright 2016 VMware, Inc.
# All Rights Reserved
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

import netaddr
import six

from vmware_nsxlib.v3 import constants
from vmware_nsxlib.v3 import utils


class NsxLibNativeDhcp(utils.NsxLibApiBase):

    def build_static_routes(self, gateway_ip, cidr, host_routes):
        # The following code is based on _generate_opts_per_subnet() in
        # neutron/agent/linux/dhcp.py. It prepares DHCP options for a subnet.

        # Add route for directly connected network.
        static_routes = [{'network': cidr, 'next_hop': '0.0.0.0'}]
        # Copy routes from subnet host_routes attribute.
        for hr in host_routes:
            if hr['destination'] == constants.IPv4_ANY:
                if not gateway_ip:
                    gateway_ip = hr['nexthop']
            else:
                static_routes.append({'network': hr['destination'],
                                      'next_hop': hr['nexthop']})
        # If gateway_ip is defined, add default route via this gateway.
        if gateway_ip:
            static_routes.append({'network': constants.IPv4_ANY,
                                  'next_hop': gateway_ip})
        return static_routes, gateway_ip

    def build_server_name(self, net_name, net_id):
        return utils.get_name_and_uuid(net_name or 'dhcpserver', net_id)

    def build_server_domain_name(self, net_dns_domain, default_dns_domain):
        if net_dns_domain:
            if isinstance(net_dns_domain, six.string_types):
                domain_name = net_dns_domain
            else:
                domain_name = net_dns_domain['dns_domain']
        else:
            # use the default one, or the globally configured one
            if default_dns_domain is not None:
                domain_name = default_dns_domain
            else:
                domain_name = self.nsxlib_config.dns_domain
        return domain_name

    def build_server_config(self, network, subnet, port, tags,
                            default_dns_nameservers=None,
                            default_dns_domain=None):
        # Prepare the configuration for a new logical DHCP server.
        server_ip = "%s/%u" % (port['fixed_ips'][0]['ip_address'],
                               netaddr.IPNetwork(subnet['cidr']).prefixlen)
        dns_nameservers = subnet['dns_nameservers']
        if not dns_nameservers or not utils.is_attr_set(dns_nameservers):
            # use the default one , or the globally configured one
            if default_dns_nameservers is not None:
                dns_nameservers = default_dns_nameservers
            else:
                dns_nameservers = self.nsxlib_config.dns_nameservers
        gateway_ip = subnet['gateway_ip']
        if not utils.is_attr_set(gateway_ip):
            gateway_ip = None
        static_routes, gateway_ip = self.build_static_routes(
            gateway_ip, subnet['cidr'], subnet['host_routes'])
        options = {'option121': {'static_routes': static_routes}}
        name = self.build_server_name(network['name'], network['id'])
        domain_name = self.build_server_domain_name(network.get('dns_domain'),
                                                    default_dns_domain)
        return {'name': name,
                'server_ip': server_ip,
                'dns_nameservers': dns_nameservers,
                'domain_name': domain_name,
                'gateway_ip': gateway_ip,
                'options': options,
                'tags': tags}
