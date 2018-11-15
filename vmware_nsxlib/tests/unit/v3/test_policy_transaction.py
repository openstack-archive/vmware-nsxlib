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

from vmware_nsxlib import v3

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.tests.unit.v3 import policy_testcase

from vmware_nsxlib.v3 import policy_transaction as trans


class TestPolicyTransaction(policy_testcase.TestPolicyApi):

    def setUp(self):

        super(TestPolicyTransaction, self).setUp()

        nsxlib_config = nsxlib_testcase.get_default_nsxlib_config()
        self.policy_lib = v3.NsxPolicyLib(nsxlib_config)
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
