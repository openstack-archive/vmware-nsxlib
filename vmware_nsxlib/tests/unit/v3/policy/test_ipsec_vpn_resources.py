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

from vmware_nsxlib.tests.unit.v3.policy import test_resources
from vmware_nsxlib.v3 import vpn_ipsec

TEST_TENANT = 'test'


class TestPolicyIkeProfileApi(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyIkeProfileApi, self).setUp()
        self.resourceApi = self.policy_lib.ipsec_vpn.ike_profile

    def test_create(self):
        name = 'd1'
        obj_id = 'D1'
        description = 'desc'
        ike_version = vpn_ipsec.IkeVersionTypes.IKE_VERSION_V1
        encryption_algorithms = (
            vpn_ipsec.EncryptionAlgorithmTypes.ENCRYPTION_ALGORITHM_128)
        digest_algorithms = (
            vpn_ipsec.DigestAlgorithmTypes.DIGEST_ALGORITHM_SHA256)
        dh_groups = [vpn_ipsec.DHGroupTypes.DH_GROUP_15]
        sa_life_time = vpn_ipsec.IkeSALifetimeLimits.SA_LIFETIME_MIN + 1
        tags = []
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                profile_id=obj_id,
                description=description,
                ike_version=ike_version,
                encryption_algorithms=encryption_algorithms,
                digest_algorithms=digest_algorithms,
                dh_groups=dh_groups,
                sa_life_time=sa_life_time,
                tags=tags,
                tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                profile_id=obj_id,
                name=name,
                description=description,
                ike_version=ike_version,
                encryption_algorithms=encryption_algorithms,
                digest_algorithms=digest_algorithms,
                dh_groups=dh_groups,
                sa_life_time=sa_life_time,
                tags=tags,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                profile_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                profile_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = self.resourceApi.entry_def(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                profile_id=obj_id,
                name=name,
                description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyTunnelProfileApi(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTunnelProfileApi, self).setUp()
        self.resourceApi = self.policy_lib.ipsec_vpn.tunnel_profile

    def test_create(self):
        name = 'd1'
        obj_id = 'D1'
        description = 'desc'
        enable_perfect_forward_secrecy = True
        encryption_algorithms = (
            vpn_ipsec.EncryptionAlgorithmTypes.ENCRYPTION_ALGORITHM_128)
        digest_algorithms = (
            vpn_ipsec.DigestAlgorithmTypes.DIGEST_ALGORITHM_SHA256)
        dh_groups = [vpn_ipsec.DHGroupTypes.DH_GROUP_15]
        sa_life_time = vpn_ipsec.IkeSALifetimeLimits.SA_LIFETIME_MIN + 1
        tags = []
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                profile_id=obj_id,
                description=description,
                enable_perfect_forward_secrecy=enable_perfect_forward_secrecy,
                encryption_algorithms=encryption_algorithms,
                digest_algorithms=digest_algorithms,
                dh_groups=dh_groups,
                sa_life_time=sa_life_time,
                tags=tags,
                tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                profile_id=obj_id,
                name=name,
                description=description,
                enable_perfect_forward_secrecy=enable_perfect_forward_secrecy,
                encryption_algorithms=encryption_algorithms,
                digest_algorithms=digest_algorithms,
                dh_groups=dh_groups,
                sa_life_time=sa_life_time,
                tags=tags,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                profile_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                profile_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = self.resourceApi.entry_def(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                profile_id=obj_id,
                name=name,
                description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyDpdProfileApi(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyDpdProfileApi, self).setUp()
        self.resourceApi = self.policy_lib.ipsec_vpn.dpd_profile

    def test_create(self):
        name = 'd1'
        obj_id = 'D1'
        description = 'desc'
        dpd_probe_interval = 7
        enabled = True
        tags = []
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                profile_id=obj_id,
                description=description,
                dpd_probe_interval=dpd_probe_interval,
                enabled=enabled,
                tags=tags,
                tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                profile_id=obj_id,
                name=name,
                description=description,
                dpd_probe_interval=dpd_probe_interval,
                enabled=enabled,
                tags=tags,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                profile_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                profile_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = self.resourceApi.entry_def(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                profile_id=obj_id,
                name=name,
                description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyVpnServiceApi(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyVpnServiceApi, self).setUp()
        self.resourceApi = self.policy_lib.ipsec_vpn.service

    def test_create(self):
        name = 'd1'
        tier1_id = 'tier1'
        obj_id = 'D1'
        description = 'desc'
        ike_log_level = vpn_ipsec.IkeLogLevelTypes.LOG_LEVEL_ERROR
        enabled = True
        tags = []
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                tier1_id=tier1_id,
                vpn_service_id=obj_id,
                description=description,
                ike_log_level=ike_log_level,
                enabled=enabled,
                tags=tags,
                tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                tier1_id=tier1_id,
                vpn_service_id=obj_id,
                name=name,
                description=description,
                ike_log_level=ike_log_level,
                enabled=enabled,
                tags=tags,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_delete(self):
        obj_id = '111'
        tier1_id = 'tier1'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(tier1_id, obj_id, tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                tier1_id=tier1_id,
                vpn_service_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        tier1_id = 'tier1'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(tier1_id, obj_id, tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                tier1_id=tier1_id,
                vpn_service_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        tier1_id = 'tier1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(tier1_id, name,
                                               tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = self.resourceApi.entry_def(
                tier1_id=tier1_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        tier1_id = 'tier1'
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tier1_id, tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                tier1_id=tier1_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        tier1_id = 'tier1'
        name = 'new name'
        description = 'new desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(tier1_id, obj_id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = self.resourceApi.entry_def(
                tier1_id=tier1_id,
                vpn_service_id=obj_id,
                name=name,
                description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)

# DEBUG ADIT add tests for endpoint & session
