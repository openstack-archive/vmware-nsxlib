# Copyright 2018 VMware, Inc.
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
#

import copy

import mock

from oslo_utils import uuidutils

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.tests.unit.v3 import test_constants
from vmware_nsxlib.v3 import exceptions as nsxlib_exc


class TestRouter(nsxlib_testcase.NsxClientTestCase):

    def test_get_connected_t0_transit_net(self):
        t1_uuid = uuidutils.generate_uuid()
        link_port_uuid = uuidutils.generate_uuid()
        link_port = {
            'linked_logical_router_port_id': {
                'target_id': link_port_uuid}}
        transit_net = '1.1.1.0'
        transit_prefix = '31'
        t0_port = {'subnets': [{'ip_addresses': [transit_net],
                                'prefix_length': transit_prefix}]}
        with mock.patch.object(self.nsxlib.router._router_port_client,
                               'get_tier1_link_port',
                               return_value=link_port) as get_link,\
            mock.patch.object(self.nsxlib.router._router_port_client,
                              'get', return_value=t0_port) as get_port:
            cidr = self.nsxlib.router.get_connected_t0_transit_net(t1_uuid)
            get_link.assert_called_with(t1_uuid)
            get_port.assert_called_with(link_port_uuid)
            self.assertEqual('%s/%s' % (transit_net, transit_prefix), cidr)

    def test_validate_tier0(self):
        tier0_groups_dict = {}
        tier0_uuid = uuidutils.generate_uuid()
        rtr = {'edge_cluster_id': test_constants.FAKE_EDGE_CLUSTER_ID}
        with mock.patch.object(self.nsxlib.router._router_client, 'get',
                               return_value=rtr),\
            mock.patch.object(
                self.nsxlib.edge_cluster, 'get',
                return_value=test_constants.FAKE_EDGE_CLUSTER):
            self.nsxlib.router.validate_tier0(tier0_groups_dict, tier0_uuid)
            self.assertEqual(
                tier0_groups_dict[tier0_uuid]['edge_cluster_uuid'],
                test_constants.FAKE_EDGE_CLUSTER_ID)
            self.assertEqual(
                tier0_groups_dict[tier0_uuid]['member_index_list'], [0])

    def test_validate_tier0_fail(self):
        tier0_groups_dict = {}
        tier0_uuid = uuidutils.generate_uuid()
        edge_cluster = copy.copy(test_constants.FAKE_EDGE_CLUSTER)
        edge_cluster['members'] = []
        with mock.patch.object(self.nsxlib.router._router_client, 'get'),\
            mock.patch.object(self.nsxlib.edge_cluster, 'get',
                              return_value=edge_cluster):
            self.assertRaises(
                nsxlib_exc.NsxLibInvalidInput,
                self.nsxlib.router.validate_tier0,
                tier0_groups_dict, tier0_uuid)

    def test_add_router_link_port(self):
        tags = [{'scope': 'a', 'tag': 'b'}]
        tier0_uuid = uuidutils.generate_uuid()
        tier1_uuid = uuidutils.generate_uuid()
        with mock.patch.object(self.nsxlib.router._router_port_client,
                               'create') as port_create:
            self.nsxlib.router.add_router_link_port(
                tier1_uuid, tier0_uuid, tags)
            self.assertEqual(port_create.call_count, 2)

    def test_remove_router_link_port(self):
        tier1_uuid = uuidutils.generate_uuid()
        with mock.patch.object(
            self.nsxlib.router._router_port_client, 'get_tier1_link_port',
            return_value=test_constants.FAKE_ROUTER_LINKT1_PORT) as port_get,\
            mock.patch.object(self.nsxlib.router._router_port_client,
                              'delete') as port_delete:
            self.nsxlib.router.remove_router_link_port(tier1_uuid)
            self.assertEqual(port_get.call_count, 1)
            self.assertEqual(port_delete.call_count, 2)

    def test_create_logical_router_intf_port_by_ls_id(self):
        pass

    def test_add_fip_nat_rules(self):
        pass

    def test_delete_fip_nat_rules_by_internal_ip(self):
        pass

    def test_get_tier0_router_tz(self):
        pass

    def test_get_tier0_router_overlay_tz(self):
        pass
