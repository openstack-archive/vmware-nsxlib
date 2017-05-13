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

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.tests.unit.v3 import test_constants as consts
from vmware_nsxlib.v3 import load_balancer


app_profile_types = load_balancer.ApplicationProfileTypes
app_profiles = [app_profile_types.HTTP,
                app_profile_types.FAST_TCP,
                app_profile_types.FAST_UDP]
per_profile_types = load_balancer.PersistenceProfileTypes
per_profiles = [per_profile_types.COOKIE, per_profile_types.SOURCE_IP]
monitor_types = load_balancer.MonitorTypes
monitors = [monitor_types.HTTP, monitor_types.HTTPS, monitor_types.ICMP,
            monitor_types.PASSIVE, monitor_types.TCP, monitor_types.UDP]


class TestApplicationProfile(nsxlib_testcase.NsxClientTestCase):

    def test_create_application_profiles(self):
        fake_profile = consts.FAKE_APPLICATION_PROFILE.copy()
        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]
        for profile_type in app_profiles:
            body = {
                'display_name': fake_profile['display_name'],
                'description': fake_profile['description'],
                'resource_type': profile_type,
                'tags': tags
            }
            with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.lb_application_profile.create(
                    display_name=body['display_name'],
                    description=body['description'],
                    resource_type=body['resource_type'],
                    tags=tags)
                create.assert_called_with('loadbalancer/application-profiles',
                                          body)

    def test_list_application_profiles(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            self.nsxlib.lb_application_profile.list()
            get.assert_called_with('loadbalancer/application-profiles')

    def test_get_application_profile(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_profile = consts.FAKE_APPLICATION_PROFILE.copy()
            self.nsxlib.lb_application_profile.get(fake_profile['id'])
            get.assert_called_with(
                'loadbalancer/application-profiles/%s' % fake_profile['id'])

    def test_delete_application_profile(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_profile = consts.FAKE_APPLICATION_PROFILE.copy()
            self.nsxlib.lb_application_profile.delete(fake_profile['id'])
            delete.assert_called_with(
                'loadbalancer/application-profiles/%s' % fake_profile['id'])


class TestPersistenceProfile(nsxlib_testcase.NsxClientTestCase):

    def test_create_persistence_profiles(self):
        fake_profile = consts.FAKE_PERSISTENCE_PROFILE.copy()
        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]
        for profile_type in per_profiles:
            body = {
                'display_name': fake_profile['display_name'],
                'description': fake_profile['description'],
                'resource_type': profile_type,
                'tags': tags
            }
            with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.lb_persistence_profile.create(
                    body['display_name'], body['description'],
                    body['resource_type'], tags)
                create.assert_called_with('loadbalancer/persistence-profiles',
                                          body)

    def test_list_persistence_profiles(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            self.nsxlib.lb_persistence_profile.list()
            get.assert_called_with('loadbalancer/persistence-profiles')

    def test_get_persistence_profile(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_profile = consts.FAKE_APPLICATION_PROFILE.copy()
            self.nsxlib.lb_persistence_profile.get(fake_profile['id'])
            get.assert_called_with(
                'loadbalancer/persistence-profiles/%s' % fake_profile['id'])

    def test_delete_persistence_profile(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_profile = consts.FAKE_PERSISTENCE_PROFILE.copy()
            self.nsxlib.lb_persistence_profile.delete(fake_profile['id'])
            delete.assert_called_with(
                'loadbalancer/persistence-profiles/%s' % fake_profile['id'])


class TestClientSslProfile(nsxlib_testcase.NsxClientTestCase):

    def test_create_client_ssl_profiles(self):
        fake_profile = consts.FAKE_CLIENT_SSL_PROFILE.copy()
        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]
        body = {
            'display_name': fake_profile['display_name'],
            'description': fake_profile['description'],
            'tags': tags
        }
        with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.lb_client_ssl_profile.create(
                    body['display_name'], body['description'], tags)
                create.assert_called_with('loadbalancer/client-ssl-profiles',
                                          body)

    def test_list_client_ssl_profiles(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            self.nsxlib.lb_client_ssl_profile.list()
            get.assert_called_with('loadbalancer/client-ssl-profiles')

    def test_get_client_ssl_profile(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_profile = consts.FAKE_CLIENT_SSL_PROFILE.copy()
            self.nsxlib.lb_client_ssl_profile.get(fake_profile['id'])
            get.assert_called_with(
                'loadbalancer/client-ssl-profiles/%s' % fake_profile['id'])

    def test_delete_client_ssl_profile(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_profile = consts.FAKE_CLIENT_SSL_PROFILE.copy()
            self.nsxlib.lb_client_ssl_profile.delete(fake_profile['id'])
            delete.assert_called_with(
                'loadbalancer/client-ssl-profiles/%s' % fake_profile['id'])


class TestServerSslProfile(nsxlib_testcase.NsxClientTestCase):

    def test_create_server_client_ssl_profiles(self):
        fake_profile = consts.FAKE_SERVER_SSL_PROFILE.copy()
        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]
        body = {
            'display_name': fake_profile['display_name'],
            'description': fake_profile['description'],
            'tags': tags
        }
        with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.lb_server_ssl_profile.create(
                    body['display_name'], body['description'], tags)
                create.assert_called_with('loadbalancer/server-ssl-profiles',
                                          body)

    def test_list_server_ssl_profiles(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            self.nsxlib.lb_server_ssl_profile.list()
            get.assert_called_with('loadbalancer/server-ssl-profiles')

    def test_get_server_ssl_profile(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_profile = consts.FAKE_SERVER_SSL_PROFILE.copy()
            self.nsxlib.lb_server_ssl_profile.get(fake_profile['id'])
            get.assert_called_with(
                'loadbalancer/server-ssl-profiles/%s' % fake_profile['id'])

    def test_delete_server_ssl_profile(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_profile = consts.FAKE_SERVER_SSL_PROFILE.copy()
            self.nsxlib.lb_server_ssl_profile.delete(fake_profile['id'])
            delete.assert_called_with(
                'loadbalancer/server-ssl-profiles/%s' % fake_profile['id'])


class TestMonitor(nsxlib_testcase.NsxClientTestCase):

    def test_create_monitors(self):
        fake_monitor = consts.FAKE_MONITOR.copy()
        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]
        for monitor_type in monitors:
            body = {
                'display_name': fake_monitor['display_name'],
                'description': fake_monitor['description'],
                'resource_type': monitor_type,
                'tags': tags
            }
            with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.lb_monitor.create(
                    body['display_name'], body['description'],
                    body['resource_type'], tags)
                create.assert_called_with('loadbalancer/monitors',
                                          body)

    def test_list_monitors(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            self.nsxlib.lb_monitor.list()
            get.assert_called_with('loadbalancer/monitors')

    def test_get_monitor(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_monitor = consts.FAKE_MONITOR.copy()
            self.nsxlib.lb_monitor.get(fake_monitor['id'])
            get.assert_called_with(
                'loadbalancer/monitors/%s' % fake_monitor['id'])

    def test_delete_monitor(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_monitor = consts.FAKE_MONITOR.copy()
            self.nsxlib.lb_monitor.delete(fake_monitor['id'])
            delete.assert_called_with(
                'loadbalancer/monitors/%s' % fake_monitor['id'])


class TestPool(nsxlib_testcase.NsxClientTestCase):

    def test_create_pool(self):
        fake_pool = consts.FAKE_POOL.copy()
        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]
        body = {
            'display_name': fake_pool['display_name'],
            'description': fake_pool['description'],
            'algorithm': fake_pool['algorithm'],
            'tags': tags
        }
        with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.lb_pool.create(
                    body['display_name'], body['description'], tags,
                    algorithm=body['algorithm'])
                create.assert_called_with('loadbalancer/pools',
                                          body)

    def test_list_pools(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            self.nsxlib.lb_pool.list()
            get.assert_called_with('loadbalancer/pools')

    def test_get_pool(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_profile = consts.FAKE_POOL.copy()
            self.nsxlib.lb_pool.get(fake_profile['id'])
            get.assert_called_with(
                'loadbalancer/pools/%s' % fake_profile['id'])

    def test_delete_pool(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_profile = consts.FAKE_POOL.copy()
            self.nsxlib.lb_pool.delete(fake_profile['id'])
            delete.assert_called_with(
                'loadbalancer/pools/%s' % fake_profile['id'])


class TestVirtualServer(nsxlib_testcase.NsxClientTestCase):

    def test_create_virtual_server(self):
        fake_virtual_server = consts.FAKE_VIRTUAL_SERVER.copy()
        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]
        body = {
            'display_name': fake_virtual_server['display_name'],
            'description': fake_virtual_server['description'],
            'ip_protocol': fake_virtual_server['ip_protocol'],
            'port': fake_virtual_server['port'],
            'enabled': fake_virtual_server['enabled'],
            'tags': tags
        }
        with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.lb_virtual_server.create(
                    body['display_name'], body['description'], tags,
                    ip_protocol=body['ip_protocol'], port=body['port'],
                    enabled=body['enabled'])
                create.assert_called_with('loadbalancer/virtual-servers',
                                          body)

    def test_list_virtual_servers(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            self.nsxlib.lb_virtual_server.list()
            get.assert_called_with('loadbalancer/virtual-servers')

    def test_get_virtual_server(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_virtual_server = consts.FAKE_VIRTUAL_SERVER.copy()
            self.nsxlib.lb_virtual_server.get(fake_virtual_server['id'])
            get.assert_called_with(
                'loadbalancer/virtual-servers/%s' % fake_virtual_server['id'])

    def test_delete_virtual_server(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_virtual_server = consts.FAKE_VIRTUAL_SERVER.copy()
            self.nsxlib.lb_virtual_server.delete(fake_virtual_server['id'])
            delete.assert_called_with(
                'loadbalancer/virtual-servers/%s' % fake_virtual_server['id'])


class TestService(nsxlib_testcase.NsxClientTestCase):

    def test_create_service(self):
        fake_service = consts.FAKE_SERVICE.copy()
        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]
        body = {
            'display_name': fake_service['display_name'],
            'description': fake_service['description'],
            'enabled': fake_service['enabled'],
            'attachment': fake_service['attachment'],
            'tags': tags
        }
        with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.lb_service.create(
                    body['display_name'], body['description'], tags,
                    enabled=body['enabled'], attachment=body['attachment'])
                create.assert_called_with('loadbalancer/services',
                                          body)

    def test_list_services(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            self.nsxlib.lb_service.list()
            get.assert_called_with('loadbalancer/services')

    def test_get_service(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_service = consts.FAKE_SERVICE.copy()
            self.nsxlib.lb_service.get(fake_service['id'])
            get.assert_called_with(
                'loadbalancer/services/%s' % fake_service['id'])

    def test_delete_service(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_service = consts.FAKE_SERVICE.copy()
            self.nsxlib.lb_service.delete(fake_service['id'])
            delete.assert_called_with(
                'loadbalancer/services/%s' % fake_service['id'])