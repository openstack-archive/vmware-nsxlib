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
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
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


class TestApplicationProfile(nsxlib_testcase.NsxClientTestCase):

    def test_create_application_profiles(self):
        fake_profile = consts.FAKE_APPLICATION_PROFILE.copy()
        for profile_type in app_profiles:
            body = {
                'display_name': fake_profile['display_name'],
                'description': fake_profile['description'],
                'resource_type': profile_type,
                'tags': tags
            }
            with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.load_balancer.application_profile.create(
                    display_name=body['display_name'],
                    description=body['description'],
                    resource_type=body['resource_type'],
                    tags=tags)
                create.assert_called_with('loadbalancer/application-profiles',
                                          body)

    def test_list_application_profiles(self):
        with mock.patch.object(self.nsxlib.client, 'list') as list_call:
            self.nsxlib.load_balancer.application_profile.list()
            list_call.assert_called_with(
                resource='loadbalancer/application-profiles')

    def test_get_application_profile(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_profile = consts.FAKE_APPLICATION_PROFILE.copy()
            self.nsxlib.load_balancer.application_profile.get(
                fake_profile['id'])
            get.assert_called_with(
                'loadbalancer/application-profiles/%s' % fake_profile['id'])

    def test_delete_application_profile(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_profile = consts.FAKE_APPLICATION_PROFILE.copy()
            self.nsxlib.load_balancer.application_profile.delete(
                fake_profile['id'])
            delete.assert_called_with(
                'loadbalancer/application-profiles/%s' % fake_profile['id'])


class TestPersistenceProfile(nsxlib_testcase.NsxClientTestCase):

    def test_create_persistence_profiles(self):
        fake_profile = consts.FAKE_PERSISTENCE_PROFILE.copy()
        for profile_type in per_profiles:
            body = {
                'display_name': fake_profile['display_name'],
                'description': fake_profile['description'],
                'resource_type': profile_type,
                'tags': tags
            }
            with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.load_balancer.persistence_profile.create(
                    body['display_name'], body['description'], tags,
                    body['resource_type'])
                create.assert_called_with('loadbalancer/persistence-profiles',
                                          body)

    def test_list_persistence_profiles(self):
        with mock.patch.object(self.nsxlib.client, 'list') as list_call:
            self.nsxlib.load_balancer.persistence_profile.list()
            list_call.assert_called_with(
                resource='loadbalancer/persistence-profiles')

    def test_get_persistence_profile(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_profile = consts.FAKE_APPLICATION_PROFILE.copy()
            self.nsxlib.load_balancer.persistence_profile.get(
                fake_profile['id'])
            get.assert_called_with(
                'loadbalancer/persistence-profiles/%s' % fake_profile['id'])

    def test_delete_persistence_profile(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_profile = consts.FAKE_PERSISTENCE_PROFILE.copy()
            self.nsxlib.load_balancer.persistence_profile.delete(
                fake_profile['id'])
            delete.assert_called_with(
                'loadbalancer/persistence-profiles/%s' % fake_profile['id'])


class TestRule(nsxlib_testcase.NsxClientTestCase):
    def test_create_rule(self):
        fake_rule = consts.FAKE_RULE.copy()
        body = {
            'display_name': fake_rule['display_name'],
            'description': fake_rule['description'],
            'resource_type': fake_rule['resource_type'],
            'phase': fake_rule['phase'],
            'match_strategy': fake_rule['match_strategy'],
            'tags': tags
        }
        with mock.patch.object(self.nsxlib.client, 'create') as create:
            self.nsxlib.load_balancer.rule.create(**body)
            create.assert_called_with('loadbalancer/rules', body)

    def test_list_rules(self):
        with mock.patch.object(self.nsxlib.client, 'list') as list_call:
            self.nsxlib.load_balancer.rule.list()
            list_call.assert_called_with(resource='loadbalancer/rules')

    def test_get_rule(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_rule = consts.FAKE_RULE.copy()
            self.nsxlib.load_balancer.rule.get(fake_rule['id'])
            get.assert_called_with('loadbalancer/rules/%s' % fake_rule['id'])

    def test_delete_rule(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_rule = consts.FAKE_RULE.copy()
            self.nsxlib.load_balancer.rule.delete(fake_rule['id'])
            delete.assert_called_with(
                'loadbalancer/rules/%s' % fake_rule['id'])


class TestClientSslProfile(nsxlib_testcase.NsxClientTestCase):

    def test_create_client_ssl_profiles(self):
        fake_profile = consts.FAKE_CLIENT_SSL_PROFILE.copy()
        body = {
            'display_name': fake_profile['display_name'],
            'description': fake_profile['description'],
            'tags': tags
        }
        with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.load_balancer.client_ssl_profile.create(
                    body['display_name'], body['description'], tags)
                create.assert_called_with('loadbalancer/client-ssl-profiles',
                                          body)

    def test_list_client_ssl_profiles(self):
        with mock.patch.object(self.nsxlib.client, 'list') as list_call:
            self.nsxlib.load_balancer.client_ssl_profile.list()
            list_call.assert_called_with(
                resource='loadbalancer/client-ssl-profiles')

    def test_get_client_ssl_profile(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_profile = consts.FAKE_CLIENT_SSL_PROFILE.copy()
            self.nsxlib.load_balancer.client_ssl_profile.get(
                fake_profile['id'])
            get.assert_called_with(
                'loadbalancer/client-ssl-profiles/%s' % fake_profile['id'])

    def test_delete_client_ssl_profile(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_profile = consts.FAKE_CLIENT_SSL_PROFILE.copy()
            self.nsxlib.load_balancer.client_ssl_profile.delete(
                fake_profile['id'])
            delete.assert_called_with(
                'loadbalancer/client-ssl-profiles/%s' % fake_profile['id'])


class TestServerSslProfile(nsxlib_testcase.NsxClientTestCase):

    def test_create_server_client_ssl_profiles(self):
        fake_profile = consts.FAKE_SERVER_SSL_PROFILE.copy()
        body = {
            'display_name': fake_profile['display_name'],
            'description': fake_profile['description'],
            'tags': tags
        }
        with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.load_balancer.server_ssl_profile.create(
                    body['display_name'], body['description'], tags)
                create.assert_called_with('loadbalancer/server-ssl-profiles',
                                          body)

    def test_list_server_ssl_profiles(self):
        with mock.patch.object(self.nsxlib.client, 'list') as list_call:
            self.nsxlib.load_balancer.server_ssl_profile.list()
            list_call.assert_called_with(
                resource='loadbalancer/server-ssl-profiles')

    def test_get_server_ssl_profile(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_profile = consts.FAKE_SERVER_SSL_PROFILE.copy()
            self.nsxlib.load_balancer.server_ssl_profile.get(
                fake_profile['id'])
            get.assert_called_with(
                'loadbalancer/server-ssl-profiles/%s' % fake_profile['id'])

    def test_delete_server_ssl_profile(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_profile = consts.FAKE_SERVER_SSL_PROFILE.copy()
            self.nsxlib.load_balancer.server_ssl_profile.delete(
                fake_profile['id'])
            delete.assert_called_with(
                'loadbalancer/server-ssl-profiles/%s' % fake_profile['id'])


class TestMonitor(nsxlib_testcase.NsxClientTestCase):

    def test_create_monitors(self):
        fake_monitor = consts.FAKE_MONITOR.copy()
        for monitor_type in monitors:
            body = {
                'display_name': fake_monitor['display_name'],
                'description': fake_monitor['description'],
                'resource_type': monitor_type,
                'tags': tags
            }
            with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.load_balancer.monitor.create(
                    body['display_name'], body['description'], tags,
                    body['resource_type'])
                create.assert_called_with('loadbalancer/monitors',
                                          body)

    def test_list_monitors(self):
        with mock.patch.object(self.nsxlib.client, 'list') as list_call:
            self.nsxlib.load_balancer.monitor.list()
            list_call.assert_called_with(resource='loadbalancer/monitors')

    def test_get_monitor(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_monitor = consts.FAKE_MONITOR.copy()
            self.nsxlib.load_balancer.monitor.get(fake_monitor['id'])
            get.assert_called_with(
                'loadbalancer/monitors/%s' % fake_monitor['id'])

    def test_delete_monitor(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_monitor = consts.FAKE_MONITOR.copy()
            self.nsxlib.load_balancer.monitor.delete(fake_monitor['id'])
            delete.assert_called_with(
                'loadbalancer/monitors/%s' % fake_monitor['id'])


class TestPool(nsxlib_testcase.NsxClientTestCase):

    def test_create_pool(self):
        fake_pool = consts.FAKE_POOL.copy()
        body = {
            'display_name': fake_pool['display_name'],
            'description': fake_pool['description'],
            'algorithm': fake_pool['algorithm'],
            'tags': tags
        }
        with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.load_balancer.pool.create(
                    body['display_name'], body['description'], tags,
                    algorithm=body['algorithm'])
                create.assert_called_with('loadbalancer/pools',
                                          body)

    def test_list_pools(self):
        with mock.patch.object(self.nsxlib.client, 'list') as list_call:
            self.nsxlib.load_balancer.pool.list()
            list_call.assert_called_with(resource='loadbalancer/pools')

    def test_get_pool(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_profile = consts.FAKE_POOL.copy()
            self.nsxlib.load_balancer.pool.get(fake_profile['id'])
            get.assert_called_with(
                'loadbalancer/pools/%s' % fake_profile['id'])

    def test_delete_pool(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_profile = consts.FAKE_POOL.copy()
            self.nsxlib.load_balancer.pool.delete(fake_profile['id'])
            delete.assert_called_with(
                'loadbalancer/pools/%s' % fake_profile['id'])

    def test_remove_monitor_from_pool(self):
        fake_pool = consts.FAKE_POOL.copy()
        fake_pool['active_monitor_ids'] = [consts.FAKE_MONITOR_UUID]
        body = {'display_name': fake_pool['display_name'],
                'description': fake_pool['description'],
                'id': fake_pool['id'],
                'algorithm': fake_pool['algorithm'],
                'active_monitor_ids': []}
        with mock.patch.object(self.nsxlib.client, 'get',
                               return_value=fake_pool):
            with mock.patch.object(self.nsxlib.client, 'update') as update:
                self.nsxlib.load_balancer.pool.remove_monitor_from_pool(
                    fake_pool['id'], consts.FAKE_MONITOR_UUID)
                resource = 'loadbalancer/pools/%s' % fake_pool['id']
                update.assert_called_with(resource, body)

    def test_remove_non_exist_monitor_from_pool(self):
        fake_pool = consts.FAKE_POOL.copy()
        fake_pool['active_monitor_ids'] = [consts.FAKE_MONITOR_UUID]
        with mock.patch.object(self.nsxlib.client, 'get',
                               return_value=fake_pool):
            self.assertRaises(
                nsxlib_exc.ResourceNotFound,
                self.nsxlib.load_balancer.pool.remove_monitor_from_pool,
                fake_pool['id'],
                'xxx-yyy')

    def test_add_monitor_to_pool(self):
        fake_pool = consts.FAKE_POOL.copy()
        body = {'display_name': fake_pool['display_name'],
                'description': fake_pool['description'],
                'id': fake_pool['id'],
                'algorithm': fake_pool['algorithm'],
                'active_monitor_ids': [consts.FAKE_MONITOR_UUID]}
        with mock.patch.object(self.nsxlib.client, 'get',
                               return_value=fake_pool):
            with mock.patch.object(self.nsxlib.client, 'update') as update:
                self.nsxlib.load_balancer.pool.add_monitor_to_pool(
                    fake_pool['id'], consts.FAKE_MONITOR_UUID)
                resource = 'loadbalancer/pools/%s' % fake_pool['id']
                update.assert_called_with(resource, body)


class TestVirtualServer(nsxlib_testcase.NsxClientTestCase):

    def test_create_virtual_server(self):
        fake_virtual_server = consts.FAKE_VIRTUAL_SERVER.copy()
        body = {
            'display_name': fake_virtual_server['display_name'],
            'description': fake_virtual_server['description'],
            'ip_protocol': fake_virtual_server['ip_protocol'],
            'port': fake_virtual_server['port'],
            'enabled': fake_virtual_server['enabled'],
            'tags': tags
        }
        with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.load_balancer.virtual_server.create(
                    body['display_name'], body['description'], tags,
                    ip_protocol=body['ip_protocol'], port=body['port'],
                    enabled=body['enabled'])
                create.assert_called_with('loadbalancer/virtual-servers',
                                          body)

    def test_list_virtual_servers(self):
        with mock.patch.object(self.nsxlib.client, 'list') as list_call:
            self.nsxlib.load_balancer.virtual_server.list()
            list_call.assert_called_with(
                resource='loadbalancer/virtual-servers')

    def test_get_virtual_server(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_virtual_server = consts.FAKE_VIRTUAL_SERVER.copy()
            self.nsxlib.load_balancer.virtual_server.get(
                fake_virtual_server['id'])
            get.assert_called_with(
                'loadbalancer/virtual-servers/%s' % fake_virtual_server['id'])

    def test_delete_virtual_server(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_virtual_server = consts.FAKE_VIRTUAL_SERVER.copy()
            self.nsxlib.load_balancer.virtual_server.delete(
                fake_virtual_server['id'])
            delete.assert_called_with(
                'loadbalancer/virtual-servers/%s' % fake_virtual_server['id'])

    def test_add_rule(self):
        fake_virtual_server = consts.FAKE_VIRTUAL_SERVER.copy()
        body = {
            'display_name': fake_virtual_server['display_name'],
            'description': fake_virtual_server['description'],
            'id': fake_virtual_server['id'],
            'enabled': fake_virtual_server['enabled'],
            'port': fake_virtual_server['port'],
            'ip_protocol': fake_virtual_server['ip_protocol'],
            'rule_ids': [consts.FAKE_RULE_UUID]
        }
        with mock.patch.object(self.nsxlib.client, 'get') as mock_get, \
            mock.patch.object(self.nsxlib.client, 'update') as mock_update:
            mock_get.return_value = fake_virtual_server
            self.nsxlib.load_balancer.virtual_server.add_rule(
                fake_virtual_server['id'], consts.FAKE_RULE_UUID)
            mock_update.assert_called_with(
                'loadbalancer/virtual-servers/%s' % fake_virtual_server['id'],
                body)

    def test_remove_rule(self):
        fake_virtual_server = consts.FAKE_VIRTUAL_SERVER.copy()
        fake_virtual_server['rule_ids'] = [consts.FAKE_RULE_UUID]
        body = {
            'display_name': fake_virtual_server['display_name'],
            'description': fake_virtual_server['description'],
            'id': fake_virtual_server['id'],
            'enabled': fake_virtual_server['enabled'],
            'port': fake_virtual_server['port'],
            'ip_protocol': fake_virtual_server['ip_protocol'],
            'rule_ids': []
        }
        with mock.patch.object(self.nsxlib.client, 'get') as mock_get, \
            mock.patch.object(self.nsxlib.client, 'update') as mock_update:
            mock_get.return_value = fake_virtual_server
            self.nsxlib.load_balancer.virtual_server.remove_rule(
                fake_virtual_server['id'], consts.FAKE_RULE_UUID)
            mock_update.assert_called_with(
                'loadbalancer/virtual-servers/%s' % fake_virtual_server['id'],
                body)

    def test_add_client_ssl_profile_binding(self):
        fake_virtual_server = consts.FAKE_VIRTUAL_SERVER.copy()
        body = {
            'display_name': fake_virtual_server['display_name'],
            'description': fake_virtual_server['description'],
            'id': fake_virtual_server['id'],
            'enabled': fake_virtual_server['enabled'],
            'port': fake_virtual_server['port'],
            'ip_protocol': fake_virtual_server['ip_protocol'],
            'client_ssl_profile_binding': {
                'ssl_profile_id': consts.FAKE_CLIENT_SSL_PROFILE_UUID,
                'default_certificate_id': consts.FAKE_DEFAULT_CERTIFICATE_ID,
                'client_auth': 'IGNORE',
                'certificate_chain_depth': 3
            }
        }
        with mock.patch.object(self.nsxlib.client, 'get') as mock_get, \
            mock.patch.object(self.nsxlib.client, 'update') as mock_update:
            mock_get.return_value = fake_virtual_server
            vs_client = self.nsxlib.load_balancer.virtual_server
            vs_client.add_client_ssl_profile_binding(
                fake_virtual_server['id'],
                consts.FAKE_CLIENT_SSL_PROFILE_UUID,
                consts.FAKE_DEFAULT_CERTIFICATE_ID,
                client_auth='IGNORE',
                certificate_chain_depth=3,
                xyz='xyz'
            )
            mock_update.assert_called_with(
                'loadbalancer/virtual-servers/%s' % fake_virtual_server['id'],
                body)

    def test_add_server_ssl_profile_binding(self):
        fake_virtual_server = consts.FAKE_VIRTUAL_SERVER.copy()
        body = {
            'display_name': fake_virtual_server['display_name'],
            'description': fake_virtual_server['description'],
            'id': fake_virtual_server['id'],
            'enabled': fake_virtual_server['enabled'],
            'port': fake_virtual_server['port'],
            'ip_protocol': fake_virtual_server['ip_protocol'],
            'server_ssl_profile_binding': {
                'ssl_profile_id': consts.FAKE_SERVER_SSL_PROFILE_UUID,
                'server_auth': 'IGNORE',
                'certificate_chain_depth': 3
            }
        }
        with mock.patch.object(self.nsxlib.client, 'get') as mock_get, \
            mock.patch.object(self.nsxlib.client, 'update') as mock_update:
            mock_get.return_value = fake_virtual_server
            vs_client = self.nsxlib.load_balancer.virtual_server
            vs_client.add_server_ssl_profile_binding(
                fake_virtual_server['id'],
                consts.FAKE_SERVER_SSL_PROFILE_UUID,
                server_auth='IGNORE',
                certificate_chain_depth=3,
                xyz='xyz')
            mock_update.assert_called_with(
                'loadbalancer/virtual-servers/%s' % fake_virtual_server['id'],
                body)


class TestService(nsxlib_testcase.NsxClientTestCase):

    def test_create_service(self):
        fake_service = consts.FAKE_SERVICE.copy()
        body = {
            'display_name': fake_service['display_name'],
            'description': fake_service['description'],
            'enabled': fake_service['enabled'],
            'attachment': fake_service['attachment'],
            'tags': tags
        }
        with mock.patch.object(self.nsxlib.client, 'create') as create:
                self.nsxlib.load_balancer.service.create(
                    body['display_name'], body['description'], tags,
                    enabled=body['enabled'], attachment=body['attachment'])
                create.assert_called_with('loadbalancer/services',
                                          body)

    def test_list_services(self):
        with mock.patch.object(self.nsxlib.client, 'list') as list_call:
            self.nsxlib.load_balancer.service.list()
            list_call.assert_called_with(resource='loadbalancer/services')

    def test_get_service(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_service = consts.FAKE_SERVICE.copy()
            self.nsxlib.load_balancer.service.get(fake_service['id'])
            get.assert_called_with(
                'loadbalancer/services/%s' % fake_service['id'])

    def test_get_stats(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_service = consts.FAKE_SERVICE.copy()
            self.nsxlib.load_balancer.service.get_stats(fake_service['id'])
            get.assert_called_with(
                'loadbalancer/services/%s/statistics?source=realtime' %
                fake_service['id'])

    def test_get_status(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_service = consts.FAKE_SERVICE.copy()
            self.nsxlib.load_balancer.service.get_status(fake_service['id'])
            get.assert_called_with(
                'loadbalancer/services/%s/status' % fake_service['id'])

    def test_get_virtual_servers_status(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_service = consts.FAKE_SERVICE.copy()
            self.nsxlib.load_balancer.service.get_virtual_servers_status(
                fake_service['id'])
            get.assert_called_with(
                'loadbalancer/services/%s/virtual-servers/status' %
                fake_service['id'])

    def test_delete_service(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_service = consts.FAKE_SERVICE.copy()
            self.nsxlib.load_balancer.service.delete(fake_service['id'])
            delete.assert_called_with(
                'loadbalancer/services/%s' % fake_service['id'])

    def test_get_usage(self):
        with mock.patch.object(self.nsxlib.client, 'get') as get:
            fake_service = consts.FAKE_SERVICE.copy()
            self.nsxlib.load_balancer.service.get_usage(fake_service['id'])
            get.assert_called_with(
                'loadbalancer/services/%s/usage' % fake_service['id'])
