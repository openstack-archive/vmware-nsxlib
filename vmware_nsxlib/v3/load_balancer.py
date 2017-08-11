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

from oslo_log import log as logging

from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class ApplicationProfileTypes(object):
    """LoadBalancer Application Profile types"""

    HTTP = "LbHttpProfile"
    FAST_TCP = "LbFastTcpProfile"
    FAST_UDP = "LbFastUdpProfile"


class PersistenceProfileTypes(object):
    """LoadBalancer Persistence Profile types"""

    COOKIE = "LbCookiePersistenceProfile"
    SOURCE_IP = "LbSourceIpPersistenceProfile"


class MonitorTypes(object):
    """LoadBalancer Monitor types"""

    HTTP = "LbHttpMonitor"
    HTTPS = "LbHttpsMonitor"
    ICMP = "LbIcmpMonitor"
    PASSIVE = "LbPassiveMonitor"
    TCP = "LbTcpMonitor"
    UDP = "LbUdpMonitor"


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

    def add_to_list(self, resource_id, item_id, item_key):
        """Add item_id to resource item_key list

        :param resource_id: resource id, e.g. pool_id, virtual_server_id
        :param item_id: item to be added to the list
        :param item_key: item list in the resource, e.g. rule_ids in
                         virtual server
        :return: client update response
        """
        object_url = self.resource + '/' + resource_id
        body = self.client.get(object_url)
        if item_key in body:
            item_list = body[item_key]
            if item_id not in item_list:
                item_list.append(item_id)
            else:
                LOG.error('Item %s is already in resource %s',
                          item_id, item_key)
                return body
        else:
            item_list = [item_id]
        body[item_key] = item_list
        return self.client.update(object_url, body)

    def remove_from_list(self, resource_id, item_id, item_key):
        """Remove item_id from resource item_key list

        :param resource_id: resource id, e.g. pool_id, virtual_server_id
        :param item_id: item to be removed from the list
        :param item_key: item list in the resource, e.g. rule_ids in
                         virtual server
        :return: client update response
        """
        object_url = self.resource + '/' + resource_id
        body = self.client.get(object_url)
        item_list = body.get(item_key)
        if item_list and item_id in item_list:
            item_list.remove(item_id)
            body[item_key] = item_list
            return self.client.update(object_url, body)
        else:
            ops = ('removing item %s from resource %s %s as it is not in '
                   'the list', item_id, item_key, item_list)
            raise nsxlib_exc.ResourceNotFound(
                manager=self.client.nsx_api_managers, operation=ops)

    def create(self, display_name=None, description=None, tags=None,
               resource_type=None, **kwargs):
        orig_body = {}
        body = self._build_args(orig_body, display_name, description, tags,
                                resource_type, **kwargs)
        return self.client.create(self.resource, body)

    def list(self):
        return self.client.list(resource=self.resource)

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
            extra_args = ['ha_flow_mirroring_enabled', 'idle_timeout']
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
            extra_args = ['ha_persistence_mirroring_enabled', 'purge',
                          'timeout']
            return utils.build_extra_args(body, extra_args, **kwargs)
        else:
            raise nsxlib_exc.InvalidInput(
                operation='create_persistence_profile',
                arg_val=resource_type,
                arg_name='resource_type')


class Rule(LoadBalancerBase):
    resource = 'loadbalancer/rules'


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
            extra_args = ['certificate_chain_depth', 'ciphers',
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

    def add_monitor_to_pool(self, pool_id, monitor_id):
        self.add_to_list(pool_id, monitor_id, 'active_monitor_ids')

    def remove_monitor_from_pool(self, pool_id, monitor_id):
        self.remove_from_list(pool_id, monitor_id, 'active_monitor_ids')


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

    def add_rule(self, vs_id, rule_id):
        self.add_to_list(vs_id, rule_id, 'rule_ids')

    def remove_rule(self, vs_id, rule_id):
        self.remove_from_list(vs_id, rule_id, 'rule_ids')


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

    def add_virtual_server(self, service_id, vs_id):
        self.add_to_list(service_id, vs_id, 'virtual_server_ids')

    def remove_virtual_server(self, service_id, vs_id):
        self.remove_from_list(service_id, vs_id, 'virtual_server_ids')

    def get_router_lb_service(self, nsx_router_id):
        lb_services = self.list()['results']
        for service in lb_services:
            if service.get('attachment'):
                if service['attachment']['target_id'] == nsx_router_id:
                    return service

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
        self.rule = Rule(client, nsxlib_config)
