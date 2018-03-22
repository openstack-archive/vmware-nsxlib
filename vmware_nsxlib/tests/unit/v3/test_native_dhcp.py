# Copyright (c) 2017 VMware, Inc.
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

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.v3 import native_dhcp


class TestNativeDhcp(nsxlib_testcase.NsxLibTestCase):
    """Tests for vmware_nsxlib.v3.native_dhcp.NsxLibNativeDhcp."""

    def setUp(self, *args, **kwargs):
        super(TestNativeDhcp, self).setUp()
        self.handler = native_dhcp.NsxLibNativeDhcp(
            self.nsxlib.client,
            nsxlib_testcase.get_default_nsxlib_config())
        self.net_dns_domain = 'a.com'
        self.subnet_dns_nameserver = '1.1.1.1'
        self.default_dns_domain = 'b.com'
        self.default_dns_nameserver = '2.2.2.2'

    def _get_server_config(self, with_net_dns=True, with_default_dns=True,
                           tags=None, gateway_ip='2.2.2.2', cidr='5.5.0.0/24',
                           port_ip='5.5.0.1', net_name='dummy',
                           net_id='dummy_uuid'):
        net = {'name': net_name, 'id': net_id}
        subnet = {'dns_nameservers': None,
                  'gateway_ip': gateway_ip,
                  'cidr': cidr,
                  'host_routes': []}
        port = {'fixed_ips': [{'ip_address': port_ip}]}
        if not tags:
            tags = []
        if with_net_dns:
            net['dns_domain'] = {'dns_domain': self.net_dns_domain}
            subnet['dns_nameservers'] = [self.subnet_dns_nameserver]
        if with_default_dns:
            result = self.handler.build_server_config(
                net, subnet, port, tags,
                default_dns_nameservers=[self.default_dns_nameserver],
                default_dns_domain=self.default_dns_domain)
        else:
            result = self.handler.build_server_config(net, subnet, port, tags)
        return result

    def test_build_server_config_dns_from_net_no_defaults(self):
        # Verify that net/subnet dns params are used if exist
        result = self._get_server_config(with_net_dns=True,
                                         with_default_dns=False)
        self.assertEqual(self.net_dns_domain, result['domain_name'])
        self.assertEqual([self.subnet_dns_nameserver],
                         result['dns_nameservers'])

    def test_build_server_config_dns_from_net_with_defaults(self):
        # Verify that net/subnet dns params are used if exist, even if there
        # are defaults
        result = self._get_server_config(with_net_dns=True,
                                         with_default_dns=True)
        self.assertEqual(self.net_dns_domain, result['domain_name'])
        self.assertEqual([self.subnet_dns_nameserver],
                         result['dns_nameservers'])

    def test_build_server_config_dns_from_defaults(self):
        # Verify that default dns params are used if net/subnet dns params
        # are missing
        result = self._get_server_config(with_net_dns=False,
                                         with_default_dns=True)
        self.assertEqual(self.default_dns_domain, result['domain_name'])
        self.assertEqual([self.default_dns_nameserver],
                         result['dns_nameservers'])

    def test_build_server_config_dns_from_config(self):
        # Verify that config dns params are used if net/subnet and default
        # dns params are missing
        result = self._get_server_config(with_net_dns=False,
                                         with_default_dns=False)
        self.assertEqual(nsxlib_testcase.DNS_DOMAIN, result['domain_name'])
        self.assertEqual(nsxlib_testcase.DNS_NAMESERVERS,
                         result['dns_nameservers'])

    def test_build_server_config_with_tags(self):
        tags = [{'scope': 'a', 'value': 'a'}]
        result = self._get_server_config(tags=tags)
        self.assertEqual(tags, result['tags'])

    def test_build_server_config_with_gateway(self):
        gw_ip = '10.10.10.10'
        result = self._get_server_config(gateway_ip=gw_ip)
        self.assertEqual(gw_ip, result['gateway_ip'])

    def test_build_server_config_with_server_ip(self):
        result = self._get_server_config(cidr='7.7.7.0/24', port_ip='7.7.7.14')
        self.assertEqual('7.7.7.14/24', result['server_ip'])

    def test_build_server_config_with_name(self):
        net_name = 'net1'
        net_id = 'uuid1uuid2'
        result = self._get_server_config(net_name=net_name, net_id=net_id)
        self.assertEqual('%s_%s...%s' % (net_name, net_id[:5], net_id[-5:]),
                         result['name'])

    def test_build_server_config_no_name(self):
        net_id = 'uuid1uuid2'
        result = self._get_server_config(net_name=None, net_id=net_id)
        self.assertEqual('dhcpserver_%s...%s' % (net_id[:5], net_id[-5:]),
                         result['name'])

    def test_build_static_routes(self):
        gateway_ip = '2.2.2.2'
        cidr = '5.5.0.0/24'
        host_routes = [{'nexthop': '81.0.200.254',
                        'destination': '91.255.255.0/24'}]
        static_routes, gateway_ip = self.handler.build_static_routes(
            gateway_ip, cidr, host_routes)
        expected = [{'network': '5.5.0.0/24', 'next_hop': '0.0.0.0'},
                    {'network': '91.255.255.0/24', 'next_hop': '81.0.200.254'},
                    {'network': '0.0.0.0/0', 'next_hop': '2.2.2.2'}]
        self.assertEqual(expected, static_routes)
        self.assertEqual('2.2.2.2', gateway_ip)

    def test_build_static_routes_gw_none(self):
        gateway_ip = None
        cidr = '5.5.0.0/24'
        host_routes = [{'nexthop': '81.0.200.254',
                        'destination': '91.255.255.0/24'}]
        static_routes, gateway_ip = self.handler.build_static_routes(
            gateway_ip, cidr, host_routes)
        expected = [{'network': '5.5.0.0/24', 'next_hop': '0.0.0.0'},
                    {'network': '91.255.255.0/24', 'next_hop': '81.0.200.254'}]
        self.assertEqual(expected, static_routes)
        self.assertIsNone(gateway_ip)

    def test_build_static_routes_no_host_routes(self):
        gateway_ip = '2.2.2.2'
        cidr = '5.5.0.0/24'
        host_routes = []
        static_routes, gateway_ip = self.handler.build_static_routes(
            gateway_ip, cidr, host_routes)
        expected = [{'network': '5.5.0.0/24', 'next_hop': '0.0.0.0'},
                    {'network': '0.0.0.0/0', 'next_hop': '2.2.2.2'}]
        self.assertEqual(expected, static_routes)
        self.assertEqual('2.2.2.2', gateway_ip)

    def test_build_static_routes_gw_none_host_route_any(self):
        gateway_ip = None
        cidr = '5.5.0.0/24'
        host_routes = [{'nexthop': '81.0.200.254',
                        'destination': '0.0.0.0/0'}]
        static_routes, gateway_ip = self.handler.build_static_routes(
            gateway_ip, cidr, host_routes)
        expected = [{'network': '5.5.0.0/24', 'next_hop': '0.0.0.0'},
                    {'network': '0.0.0.0/0', 'next_hop': '81.0.200.254'}]
        self.assertEqual(expected, static_routes)
        self.assertEqual('81.0.200.254', gateway_ip)
