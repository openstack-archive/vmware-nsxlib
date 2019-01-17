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

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.tests.unit.v3.policy import policy_testcase
from vmware_nsxlib.v3 import policy
from vmware_nsxlib.v3.policy import transaction as trans


class TestPolicyTransaction(policy_testcase.TestPolicyApi):

    def setUp(self):

        super(TestPolicyTransaction, self).setUp()

        nsxlib_config = nsxlib_testcase.get_default_nsxlib_config()
        # Mock the nsx-lib for the passthrough api
        with mock.patch('vmware_nsxlib.v3.NsxLib'):
            self.policy_lib = policy.NsxPolicyLib(nsxlib_config)
        self.policy_api = self.policy_lib.policy_api
        self.policy_api.client = self.client

    def assert_infra_patch_call(self, body):
        self.assert_json_call('PATCH', self.client, 'infra',
                              data=body)

    def test_domains_only(self):

        tags = [{'scope': 'color', 'tag': 'green'}]
        d1 = {'resource_type': 'Domain', 'id': 'domain1',
              'display_name': 'd1', 'description': 'first domain',
              'tags': tags}

        d2 = {'resource_type': 'Domain', 'id': 'domain2',
              'display_name': 'd2', 'description': 'no tags',
              'tags': None}
        with trans.NsxPolicyTransaction():

            for d in (d1, d2):
                self.policy_lib.domain.create_or_overwrite(
                    d['display_name'],
                    d['id'],
                    d['description'],
                    tags=d['tags'] if 'tags' in d else None)

        expected_body = {'resource_type': 'Infra',
                         'children': [{'resource_type': 'ChildDomain',
                                       'Domain': d1},
                                      {'resource_type': 'ChildDomain',
                                       'Domain': d2}]}

        self.assert_infra_patch_call(expected_body)

    def test_domains_and_groups(self):

        tags = [{'scope': 'color', 'tag': 'green'}]
        g1 = {'resource_type': 'Group', 'id': 'group1',
              'display_name': 'g1',
              'description': 'first group',
              'tags': None}
        g2 = {'resource_type': 'Group', 'id': 'group2',
              'description': 'second group',
              'display_name': 'g2',
              'tags': tags}
        g3 = {'resource_type': 'Group', 'id': 'group3',
              'display_name': 'g3',
              'description': 'third group',
              'tags': None}
        d1 = {'resource_type': 'Domain', 'id': 'domain1',
              'display_name': 'd1', 'description': 'first domain',
              'tags': tags}

        d2 = {'resource_type': 'Domain', 'id': 'domain2',
              'display_name': 'd2', 'description': 'no tags',
              'tags': None}

        with trans.NsxPolicyTransaction():

            for d in (d1, d2):
                self.policy_lib.domain.create_or_overwrite(
                    d['display_name'],
                    d['id'],
                    d['description'],
                    tags=d['tags'] if 'tags' in d else None)

                d['children'] = []

                for g in (g1, g2, g3):
                    self.policy_lib.group.create_or_overwrite(
                        g['display_name'],
                        d['id'],
                        g['id'],
                        g['description'],
                        tags=g['tags'] if 'tags' in g else None)

                    d['children'].append({'resource_type': 'ChildGroup',
                                          'Group': g})

        expected_body = {'resource_type': 'Infra',
                         'children': [{'resource_type': 'ChildDomain',
                                       'Domain': d1},
                                      {'resource_type': 'ChildDomain',
                                       'Domain': d2}]}

        self.assert_infra_patch_call(expected_body)

    def test_ip_address_pool_and_block_subnets(self):

        pool = {'id': 'pool1',
                'resource_type': 'IpAddressPool',
                'display_name': 'pool1',
                'children': []}

        ip_block_id = 'block1'
        subnet1 = {'id': 'subnet1',
                   'resource_type': 'IpAddressPoolBlockSubnet',
                   'ip_block_path': '/infra/ip-blocks/%s' % ip_block_id,
                   'size': 8}

        subnet2 = {'id': 'subnet2',
                   'resource_type': 'IpAddressPoolBlockSubnet',
                   'ip_block_path': '/infra/ip-blocks/%s' % ip_block_id,
                   'size': 4}

        with trans.NsxPolicyTransaction():
            self.policy_lib.ip_pool.create_or_overwrite(
                pool['display_name'],
                ip_pool_id=pool['id'])

            for s in (subnet1, subnet2):
                self.policy_lib.ip_pool.allocate_block_subnet(
                    ip_pool_id=pool['id'],
                    ip_block_id=ip_block_id,
                    ip_subnet_id=s['id'],
                    size=s['size'])

                pool['children'].append(
                    {'resource_type': 'ChildIpAddressPoolSubnet',
                     'IpAddressPoolSubnet': s})

        expected_body = {'resource_type': 'Infra',
                         'children': [{'resource_type': 'ChildIpAddressPool',
                                       'IpAddressPool': pool}]}

        self.assert_infra_patch_call(expected_body)

    def test_groups_only(self):

        g1 = {'resource_type': 'Group', 'id': 'group1',
              'display_name': 'g1',
              'description': 'first group'}
        g2 = {'resource_type': 'Group', 'id': 'group2',
              'description': 'second group',
              'display_name': 'g2'}
        d1 = {'resource_type': 'Domain', 'id': 'domain1'}

        d2 = {'resource_type': 'Domain', 'id': 'domain2'}

        with trans.NsxPolicyTransaction():

            for d in (d1, d2):
                d['children'] = []

                for g in (g1, g2):
                    self.policy_lib.group.create_or_overwrite(
                        g['display_name'],
                        d['id'],
                        g['id'],
                        g['description'])

                    d['children'].append({'resource_type': 'ChildGroup',
                                          'Group': g})

        expected_body = {'resource_type': 'Infra',
                         'children': [{'resource_type': 'ChildDomain',
                                       'Domain': d1},
                                      {'resource_type': 'ChildDomain',
                                       'Domain': d2}]}

        self.assert_infra_patch_call(expected_body)

    def test_segment_ports(self):

        port1 = {'id': 'port_on_seg1',
                 'resource_type': 'SegmentPort',
                 'display_name': 'port_on_seg1',
                 'attachment': {'type': 'VIF',
                                'app_id': 'app1',
                                'traffic_tag': 5}
                 }

        port2 = {'id': 'port1_on_seg2',
                 'resource_type': 'SegmentPort',
                 'display_name': 'port_on_seg2',
                 'attachment': {'type': 'CHILD',
                                'app_id': 'app2',
                                'traffic_tag': None}
                 }

        seg1 = {'id': 'seg1',
                'resource_type': 'Segment',
                'children': [{'resource_type': 'ChildSegmentPort',
                              'SegmentPort': port1}]}
        seg2 = {'id': 'seg2',
                'resource_type': 'Segment',
                'children': [{'resource_type': 'ChildSegmentPort',
                              'SegmentPort': port2}]}

        with trans.NsxPolicyTransaction():

            self.policy_lib.segment_port.create_or_overwrite(
                port1['display_name'],
                seg1['id'],
                port1['id'],
                attachment_type=port1['attachment']['type'],
                app_id=port1['attachment']['app_id'],
                traffic_tag=port1['attachment']['traffic_tag'])

            self.policy_lib.segment_port.create_or_overwrite(
                port2['display_name'],
                seg2['id'],
                port2['id'],
                attachment_type=port2['attachment']['type'],
                app_id=port2['attachment']['app_id'],
                traffic_tag=port2['attachment']['traffic_tag'])

        expected_body = {'resource_type': 'Infra',
                         'children': [{'resource_type': 'ChildSegment',
                                       'Segment': seg1},
                                      {'resource_type': 'ChildSegment',
                                       'Segment': seg2}]}

        self.assert_infra_patch_call(expected_body)
