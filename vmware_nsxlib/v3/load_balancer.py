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

from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils


class ApplicationProfileTypes(object):
    """LoadBalancer Application Profile types"""

    HTTP = "LoadBalancerHttpProfile"
    FAST_TCP = "LoadBalancerFastTcpProfile"
    FAST_UDP = "LoadBalancerFastUdpProfile"


class PersistenceProfileTypes(object):
    """LoadBalancer Persistence Profile types"""

    COOKIE = "LoadBalancerCookiePersistenceProfile"
    SOURCE_IP = "LoadBalancerSourceIpPersistenceProfile"


class MonitorTypes(object):
    """LoadBalancer Monitor types"""

    HTTP = "LoadBalancerHttpMonitor"
    HTTPS = "LoadBalancerHttpsMonitor"
    ICMP = "LoadBalancerIcmpMonitor"
    PASSIVE = "LoadBalancerPassiveMonitor"
    TCP = "LoadBalancerTcpMonitor"
    UDP = "LoadBalancerUdpMonitor"


class LoadBalancerBase(utils.NsxLibApiBase):
    resource = ''

    @staticmethod
    def _build_args(body, display_name=None, description=None, tags=None,
                    resource_type=None, **kwargs):
        if display_name:
            body['display_name'] = display_name
        if description:
            body['description'] = description
        if tags:
            body['tags'] = tags
        if resource_type:
            body['resource_type'] = resource_type
        body.update(kwargs)
        return body

    def create(self, display_name=None, description=None, tags=None,
               resource_type=None, **kwargs):
        orig_body = {}
        body = self._build_args(orig_body, display_name, description, tags,
                                resource_type, **kwargs)
        return self.client.create(self.resource, body)

    def list(self):
        return self.client.get(self.resource)

    def get(self, object_id):
        object_url = self.resource + '/' + object_id
        return self.client.get(object_url)

    def update(self, object_id, display_name=None, description=None,
               tags=None, resource_type=None, **kwargs):
        object_url = self.resource + '/' + object_id
        orig_body = self.client.get(object_url)
        body = self._build_args(orig_body, display_name, description, tags,
                                resource_type, **kwargs)
        return self.client.update(object_url, body)

    def delete(self, object_id):
        object_url = self.resource + '/' + object_id
        return self.client.delete(object_url)


class ApplicationProfile(LoadBalancerBase):
    resource = 'loadbalancer/application-profiles'

    @staticmethod
    def _build_args(body, display_name=None, description=None, tags=None,
                    resource_type=None, **kwargs):
        if display_name:
            body['display_name'] = display_name
        if description:
            body['description'] = description
        if tags:
            body['tags'] = tags
        if resource_type == ApplicationProfileTypes.HTTP:
            body['resource_type'] = resource_type
            extra_args = ['http_redirect_to', 'http_redirect_to_https',
                          'ntlm', 'request_header_size', 'x_forwarded_for',
                          'idle_timeout']
            return utils.build_extra_args(body, extra_args, **kwargs)
        elif (resource_type == ApplicationProfileTypes.FAST_TCP or
              resource_type == ApplicationProfileTypes.FAST_UDP):
            body['resource_type'] = resource_type
            extra_args = ['flow_mirroring_enabled', 'idle_timeout']
            return utils.build_extra_args(body, extra_args, **kwargs)
        else:
            raise nsxlib_exc.InvalidInput(
                operation='create_application_profile',
                arg_val=resource_type,
                arg_name='resource_type')


class PersistenceProfile(LoadBalancerBase):
    resource = 'loadbalancer/persistence-profiles'

    @staticmethod
    def _build_args(body, display_name=None, description=None, tags=None,
                    resource_type=None, **kwargs):
        if display_name:
            body['display_name'] = display_name
        if description:
            body['description'] = description
        if tags:
            body['tags'] = tags
        if resource_type == PersistenceProfileTypes.COOKIE:
            body['resource_type'] = resource_type
            extra_args = ['cookie_domain', 'cookie_fallback', 'cookie_garble',
                          'cookie_mode', 'cookie_name', 'cookie_path',
                          'cookie_time']
            return utils.build_extra_args(body, extra_args, **kwargs)
        elif resource_type == PersistenceProfileTypes.SOURCE_IP:
            body['resource_type'] = resource_type
            extra_args = ['persistence_mirroring_enabled', 'purge', 'timeout']
            return utils.build_extra_args(body, extra_args, **kwargs)
        else:
            raise nsxlib_exc.InvalidInput(
                operation='create_persistence_profile',
                arg_val=resource_type,
                arg_name='resource_type')


class ClientSslProfile(LoadBalancerBase):
    resource = 'loadbalancer/client-ssl-profiles'


class ServerSslProfile(LoadBalancerBase):
    resource = 'loadbalancer/server-ssl-profiles'


class Monitor(LoadBalancerBase):
    resource = 'loadbalancer/monitors'

    @staticmethod
    def _build_args(body, display_name=None, description=None, tags=None,
                    resource_type=None, **kwargs):
        if display_name:
            body['display_name'] = display_name
        if description:
            body['description'] = description
        if tags:
            body['tags'] = tags
        if resource_type == MonitorTypes.HTTP:
            body['resource_type'] = resource_type
            extra_args = ['fall_count', 'interval', 'monitor_port',
                          'request_body', 'request_method', 'request_url',
                          'request_version', 'response_body',
                          'response_status', 'rise_count', 'timeout']
            return utils.build_extra_args(body, extra_args, **kwargs)
        elif resource_type == MonitorTypes.HTTPS:
            body['resource_type'] = resource_type
            extra_args = ['authentication_depth', 'ciphers',
                          'client_certificate_id', 'fall_count', 'interval',
                          'monitor_port', 'protocols', 'request_body',
                          'request_method', 'request_url', 'request_version',
                          'response_body', 'response_status', 'rise_count',
                          'server_auth', 'server_auth_ca_ids',
                          'server_auth_crl_ids', 'timeout']
            return utils.build_extra_args(body, extra_args, **kwargs)
        elif resource_type == MonitorTypes.ICMP:
            body['resource_type'] = resource_type
            extra_args = ['data_length', 'fall_count', 'interval',
                          'monitor_port', 'rise_count', 'timeout']
            return utils.build_extra_args(body, extra_args, **kwargs)
        elif resource_type == MonitorTypes.PASSIVE:
            body['resource_type'] = resource_type
            extra_args = ['max_fails', 'timeout']
            return utils.build_extra_args(body, extra_args, **kwargs)
        elif (resource_type == MonitorTypes.TCP or
              resource_type == MonitorTypes.UDP):
            body['resource_type'] = resource_type
            extra_args = ['fall_count', 'interval', 'monitor_port', 'receive',
                          'rise_count', 'send', 'timeout']
            return utils.build_extra_args(body, extra_args, **kwargs)
        else:
            raise nsxlib_exc.InvalidInput(
                operation='create_monitor',
                arg_val=resource_type,
                arg_name='resource_type')


class Pool(LoadBalancerBase):
    resource = 'loadbalancer/pools'

    def update_pool_with_members(self, pool_id, members):
        object_url = self.resource + '/' + pool_id
        body = self.client.get(object_url)
        body['members'] = members
        return self.client.update(object_url, body)


class VirtualServer(LoadBalancerBase):
    resource = 'loadbalancer/virtual-servers'

    def update_virtual_server_with_pool(self, virtual_server_id, pool_id):
        object_url = self.resource + '/' + virtual_server_id
        body = self.client.get(object_url)
        body['pool_id'] = pool_id
        return self.client.update(object_url, body)

    def update_virtual_server_with_profiles(self, virtual_server_id,
                                            application_profile_id,
                                            persistence_profile_id):
        object_url = self.resource + '/' + virtual_server_id
        body = self.client.get(object_url)
        body['application_profile_id'] = application_profile_id
        body['persistence_profile_id'] = persistence_profile_id
        return self.client.update(object_url, body)

    def update_virtual_server_with_vip(self, virtual_server_id, vip):
        object_url = self.resource + '/' + virtual_server_id
        body = self.client.get(object_url)
        body['ip_address'] = vip
        return self.client.update(object_url, body)


class Service(LoadBalancerBase):
    resource = 'loadbalancer/services'

    def update_service_with_virtual_servers(self, service_id,
                                            virtual_server_ids):
        object_url = self.resource + '/' + service_id
        body = self.client.get(object_url)
        body['virtual_server_ids'] = virtual_server_ids
        return self.client.update(object_url, body)

    def update_service_with_attachment(self, service_id, logical_router_id):
        object_url = self.resource + '/' + service_id
        body = self.client.get(object_url)
        body['attachment'] = {'target_id': logical_router_id,
                              'target_type': 'LogicalRouter'}
        return self.client.update(object_url, body)

    def get_status(self, service_id):
        object_url = '%s/%s/%s' % (self.resource, service_id, 'status')
        return self.client.get(object_url)

    def get_stats(self, service_id):
        object_url = '%s/%s/%s' % (self.resource, service_id, 'statistics')
        return self.client.get(object_url)


class LoadBalancer(object):
    """This is the class that have all load balancer resource clients"""

    def __init__(self, client, nsxlib_config=None):
        self.service = Service(client, nsxlib_config)
        self.virtual_server = VirtualServer(client, nsxlib_config)
        self.pool = Pool(client, nsxlib_config)
        self.monitor = Monitor(client, nsxlib_config)
        self.application_profile = ApplicationProfile(client, nsxlib_config)
        self.persistence_profile = PersistenceProfile(client, nsxlib_config)
        self.client_ssl_profile = ClientSslProfile(client, nsxlib_config)
        self.server_ssh_profile = ServerSslProfile(client, nsxlib_config)
