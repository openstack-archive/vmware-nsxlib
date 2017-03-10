# Copyright 2015 VMware, Inc.
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
from oslo_serialization import jsonutils

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.v3 import client
from vmware_nsxlib.v3 import policy

BASE_POLICY_URI = "https://1.2.3.4/api/v1/"


# TODO(annak) - move to shared place
def assert_json_call(method, client, url,
                     headers=client.JSONRESTClient._DEFAULT_HEADERS,
                     timeout=(nsxlib_testcase.NSX_HTTP_TIMEOUT,
                              nsxlib_testcase.NSX_HTTP_READ_TIMEOUT),
                     data=None):
    cluster = client._conn
    url = BASE_POLICY_URI + url
    if data:
        data = jsonutils.dumps(data, sort_keys=True)
    cluster.assert_called_once(
        method,
        **{'url': url, 'verify': nsxlib_testcase.NSX_CERT, 'body': data,
           'headers': headers, 'cert': None, 'timeout': timeout})


class TestPolicyApi(nsxlib_testcase.NsxClientTestCase):

    def setUp(self):
        self.client = self.new_mocked_client(client.NSX3Client,
                                             url_prefix='api/v1/')
        self.policy_api = policy.NsxPolicyApi(self.client)

        super(TestPolicyApi, self).setUp()


class TestPolicyDomain(TestPolicyApi):

    def test_create(self):
        domain_def = policy.DomainDef(
            'archaea',
            'prokaryotic cells',
            'typically characterized by membrane lipids')
        self.policy_api.create(domain_def)
        assert_json_call('PUT', self.client,
                         'tenants/infra/domains/archaea',
                         data=domain_def.get_body())

    def test_delete(self):
        domain_def = policy.DomainDef('bacteria')
        self.policy_api.delete(domain_def)
        assert_json_call('DELETE', self.client,
                         'tenants/infra/domains/bacteria')

    def test_get(self):
        domain_def = policy.DomainDef('eukarya')
        self.policy_api.get(domain_def)
        assert_json_call('GET', self.client,
                         'tenants/infra/domains/eukarya')

    def test_list(self):
        domain_def = policy.DomainDef()
        self.policy_api.list(domain_def)
        assert_json_call('GET', self.client, 'tenants/infra/domains')


class TestPolicyGroup(TestPolicyApi):

    def test_create(self):
        group_def = policy.GroupDef(
            'eukarya',
            'cat',
            'felis catus')
        self.policy_api.create(group_def)
        assert_json_call('PUT', self.client,
                         'tenants/infra/domains/eukarya/groups/cat',
                         data=group_def.get_body())

    def test_create_with_parent(self):
        domain_def = policy.DomainDef('eukarya',
                                      'eukarya',
                                      'stuff with membranes')
        group_def = policy.GroupDef('eukarya',
                                    'panda',
                                    'Ailuropoda melanoleuca')

        self.policy_api.create_with_parent(domain_def, group_def)
        data = domain_def.get_body()
        data['groups'] = [group_def.get_body()]
        assert_json_call('PUT', self.client,
                         'tenants/infra/domains/eukarya',
                         data=data)
