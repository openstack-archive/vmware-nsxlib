# Copyright 2017 VMware, Inc.
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
from vmware_nsxlib.v3.policy import lb_defs

TEST_TENANT = 'test'


class TestPolicyLBClientSSLProfileApi(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBClientSSLProfileApi, self).setUp()
        self.resourceApi = self.policy_lib.load_balancer.client_ssl_profile

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        protocols = ['TLS_V1_1']
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                client_ssl_profile_id=obj_id,
                description=description,
                protocols=protocols,
                tenant=TEST_TENANT)
            expected_def = lb_defs.LBClientSslProfileDef(
                client_ssl_profile_id=obj_id,
                name=name,
                description=description,
                protocols=protocols,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT)
            expected_def = lb_defs.LBClientSslProfileDef(
                client_ssl_profile_id=mock.ANY,
                name=name,
                description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBClientSslProfileDef(
                client_ssl_profile_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBClientSslProfileDef(
                client_ssl_profile_id=obj_id,
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
            expected_def = lb_defs.LBClientSslProfileDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = lb_defs.LBClientSslProfileDef(
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
            expected_def = lb_defs.LBClientSslProfileDef(
                client_ssl_profile_id=obj_id,
                name=name,
                description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyLBCookiePersistenceProfile(
    test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBCookiePersistenceProfile, self).setUp()
        self.resourceApi = (
            self.policy_lib.load_balancer.lb_cookie_persistence_profile)

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        cookie_garble = 'test_garble'
        cookie_name = 'test_name'
        cookie_mode = 'INSERT'
        cookie_path = 'path'
        cookie_time = 'time'
        persistence_shared = False
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                persistence_profile_id=obj_id,
                description=description,
                cookie_name=cookie_name,
                cookie_garble=cookie_garble,
                cookie_mode=cookie_mode,
                cookie_path=cookie_path,
                cookie_time=cookie_time,
                persistence_shared=persistence_shared,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBCookiePersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    name=name,
                    description=description,
                    cookie_name=cookie_name,
                    cookie_garble=cookie_garble,
                    cookie_mode=cookie_mode,
                    cookie_path=cookie_path,
                    cookie_time=cookie_time,
                    persistence_shared=persistence_shared,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBCookiePersistenceProfileDef(
                    persistence_profile_id=mock.ANY,
                    name=name,
                    description=description,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBCookiePersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBCookiePersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = (
                lb_defs.LBCookiePersistenceProfileDef(
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBCookiePersistenceProfileDef(
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        cookie_garble = 'test_garble'
        cookie_name = 'test_name'
        cookie_mode = 'INSERT'
        cookie_path = 'path'
        cookie_time = 'time'
        persistence_shared = False
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    cookie_name=cookie_name,
                                    cookie_garble=cookie_garble,
                                    cookie_mode=cookie_mode,
                                    cookie_path=cookie_path,
                                    cookie_time=cookie_time,
                                    persistence_shared=persistence_shared,
                                    tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBCookiePersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    name=name,
                    description=description,
                    cookie_name=cookie_name,
                    cookie_garble=cookie_garble,
                    cookie_mode=cookie_mode,
                    cookie_path=cookie_path,
                    cookie_time=cookie_time,
                    persistence_shared=persistence_shared,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyLBSourceIpProfileApi(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBSourceIpProfileApi, self).setUp()
        self.resourceApi = (
            self.policy_lib.load_balancer.lb_source_ip_persistence_profile)

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        ha = 'ha'
        persistence_shared = True
        purge = 'purge'
        timeout = 100
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                persistence_profile_id=obj_id,
                description=description,
                ha_persistence_mirroring_enabled=ha,
                persistence_shared=persistence_shared,
                purge=purge,
                timeout=timeout,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBSourceIpPersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    name=name,
                    description=description,
                    ha_persistence_mirroring_enabled=ha,
                    persistence_shared=persistence_shared,
                    purge=purge,
                    timeout=timeout,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBSourceIpPersistenceProfileDef(
                    persistence_profile_id=mock.ANY,
                    name=name,
                    description=description,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBSourceIpPersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBSourceIpPersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = (
                lb_defs.LBSourceIpPersistenceProfileDef(
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBSourceIpPersistenceProfileDef(
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        ha = False
        persistence_shared = False
        purge = 'no purge'
        timeout = 101
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    ha_persistence_mirroring_enabled=ha,
                                    persistence_shared=persistence_shared,
                                    purge=purge,
                                    timeout=timeout,
                                    tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBSourceIpPersistenceProfileDef(
                    persistence_profile_id=obj_id,
                    name=name,
                    description=description,
                    ha_persistence_mirroring_enabled=ha,
                    persistence_shared=persistence_shared,
                    purge=purge,
                    timeout=timeout,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyLBApplicationProfile(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBApplicationProfile, self).setUp()
        self.resourceApi = self.policy_lib.load_balancer.lb_http_profile

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        http_redirect_to_https = False
        http_redirect_to = "sample-url"
        idle_timeout = 100
        ntlm = False
        request_body_size = 1025
        request_header_size = 10
        response_header_size = 10
        response_timeout = 10
        x_forwarded_for = 'INSERT'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                lb_app_profile_id=obj_id,
                description=description,
                http_redirect_to_https=http_redirect_to_https,
                http_redirect_to=http_redirect_to,
                idle_timeout=idle_timeout,
                ntlm=ntlm,
                request_body_size=request_body_size,
                request_header_size=request_header_size,
                response_header_size=response_header_size,
                response_timeout=response_timeout,
                x_forwarded_for=x_forwarded_for,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBHttpProfileDef(
                    lb_app_profile_id=obj_id,
                    name=name,
                    description=description,
                    http_redirect_to_https=http_redirect_to_https,
                    http_redirect_to=http_redirect_to,
                    idle_timeout=idle_timeout,
                    ntlm=ntlm,
                    request_body_size=request_body_size,
                    request_header_size=request_header_size,
                    response_header_size=response_header_size,
                    response_timeout=response_timeout,
                    x_forwarded_for=x_forwarded_for,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBHttpProfileDef(
                    lb_app_profile_id=mock.ANY,
                    name=name,
                    description=description,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBHttpProfileDef(
                    lb_app_profile_id=obj_id,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBHttpProfileDef(
                    lb_app_profile_id=obj_id,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = (
                lb_defs.LBHttpProfileDef(tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBHttpProfileDef(tenant=TEST_TENANT))
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
            expected_def = (
                lb_defs.LBHttpProfileDef(
                    lb_app_profile_id=obj_id,
                    name=name,
                    description=description,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyLBService(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBService, self).setUp()
        self.resourceApi = self.policy_lib.load_balancer.lb_service

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        size = 'SMALL'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                lb_service_id=obj_id,
                description=description,
                size=size,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBServiceDef(
                    lb_service_id=obj_id,
                    name=name,
                    description=description,
                    size=size,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT)
            expected_def = (
                lb_defs.LBServiceDef(lb_service_id=mock.ANY,
                                     name=name,
                                     description=description,
                                     tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBServiceDef(
                lb_service_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBServiceDef(
                lb_service_id=obj_id,
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
            expected_def = lb_defs.LBServiceDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = lb_defs.LBServiceDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        size = 'SMALL'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT,
                                    size=size)
            expected_def = lb_defs.LBServiceDef(
                lb_service_id=obj_id,
                name=name,
                description=description,
                tenant=TEST_TENANT,
                size=size)
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyLBVirtualServer(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBVirtualServer, self).setUp()
        self.resourceApi = self.policy_lib.load_balancer.virtual_server

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                virtual_server_id=obj_id,
                description=description,
                tenant=TEST_TENANT)
            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=obj_id, name=name, description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT)
            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=mock.ANY, name=name, description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=obj_id,
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
            expected_def = lb_defs.LBVirtualServerDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = lb_defs.LBVirtualServerDef(
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
            expected_def = lb_defs.LBVirtualServerDef(
                virtual_server_id=obj_id, name=name, description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyLBPoolApi(test_resources.NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyLBPoolApi, self).setUp()
        self.resourceApi = self.policy_lib.load_balancer.lb_pool

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        members = [
            lb_defs.LBPoolMemberDef(ip_address='10.0.0.1')]
        algorithm = 'algo'
        active_monitor_paths = 'path1'
        member_group = 'group1'
        snat_translation = False
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                lb_pool_id=obj_id,
                description=description,
                members=members,
                active_monitor_paths=active_monitor_paths,
                algorithm=algorithm,
                member_group=member_group,
                snat_translation=snat_translation,
                tenant=TEST_TENANT)
            expected_def = lb_defs.LBPoolDef(
                lb_pool_id=obj_id,
                name=name,
                description=description,
                members=members,
                active_monitor_paths=active_monitor_paths,
                algorithm=algorithm,
                member_group=member_group,
                snat_translation=snat_translation,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT)
            expected_def = lb_defs.LBPoolDef(
                lb_pool_id=mock.ANY,
                name=name,
                description=description,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBPoolDef(
                lb_pool_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = lb_defs.LBPoolDef(
                lb_pool_id=obj_id,
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
            expected_def = lb_defs.LBPoolDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = lb_defs.LBPoolDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        members = [{'ip_address': '10.0.0.1'}]
        algorithm = 'algo'
        active_monitor_paths = 'path1'
        member_group = 'group1'
        snat_translation = False
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    members=members,
                                    active_monitor_paths=active_monitor_paths,
                                    algorithm=algorithm,
                                    member_group=member_group,
                                    snat_translation=snat_translation,
                                    tenant=TEST_TENANT)
            expected_def = lb_defs.LBPoolDef(
                lb_pool_id=obj_id,
                name=name,
                description=description,
                members=members,
                active_monitor_paths=active_monitor_paths,
                algorithm=algorithm,
                member_group=member_group,
                snat_translation=snat_translation,
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)
