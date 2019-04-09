# Copyright 2019 VMware, Inc.
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
from vmware_nsxlib.tests.unit.v3 import test_constants as consts


class TestNsxLibTrustManagement(nsxlib_testcase.NsxClientTestCase):

    def test_create_cert_list(self):
        fake_cert_list = consts.FAKE_CERT_LIST
        fake_pem = (fake_cert_list[0]['pem_encoded'] +
                    fake_cert_list[1]['pem_encoded'])
        fake_private_key = 'fake_key'
        cert_api = self.nsxlib.trust_management
        body = {
            'pem_encoded': fake_pem,
            'private_key': fake_private_key,
            'tags': consts.FAKE_TAGS
        }
        with mock.patch.object(self.nsxlib.client, 'create') as create:
            cert_api.create_cert_list(
                cert_pem=fake_pem,
                private_key=fake_private_key,
                tags=consts.FAKE_TAGS)
            create.assert_called_with(
                'trust-management/certificates?action=import',
                body)
