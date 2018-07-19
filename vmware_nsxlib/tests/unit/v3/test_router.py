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

import mock

from oslo_utils import uuidutils

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase


class TestRouter(nsxlib_testcase.NsxClientTestCase):
    # TODO(asarfaty): add unit tests of other RouterLib APIs
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
