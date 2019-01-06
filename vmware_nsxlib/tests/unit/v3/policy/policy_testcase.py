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
from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.v3 import client
from vmware_nsxlib.v3.policy import core_defs as policy

BASE_POLICY_URI = "https://1.2.3.4/policy/api/v1/"


class TestPolicyApi(nsxlib_testcase.NsxClientTestCase):

    def setUp(self):
        self.client = self.new_mocked_client(client.NSX3Client,
                                             url_prefix='policy/api/v1/')
        self.policy_api = policy.NsxPolicyApi(self.client)

        super(TestPolicyApi, self).setUp()

    def assert_json_call(self, method, client, url, data=None):
        url = BASE_POLICY_URI + url
        return super(TestPolicyApi, self).assert_json_call(
            method, client, url, data=data)
