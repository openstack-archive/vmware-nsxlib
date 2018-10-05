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
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            nsxlib_exc.StaleRevision,
            max_attempts=self.client.max_attempts)
        def do_update():
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
        return do_update()

    def remove_from_list(self, resource_id, item_id, item_key):
        """Remove item_id from resource item_key list

        :param resource_id: resource id, e.g. pool_id, virtual_server_id
        :param item_id: item to be removed from the list
        :param item_key: item list in the resource, e.g. rule_ids in
                         virtual server
        :return: client update response
        """
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            nsxlib_exc.StaleRevision,
            max_attempts=self.client.max_attempts)
        def do_update():
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
        return do_update()

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
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            nsxlib_exc.StaleRevision,
            max_attempts=self.client.max_attempts)
        def do_update():
            object_url = self.resource + '/' + object_id
            orig_body = self.client.get(object_url)
            body = self._build_args(orig_body, display_name, description, tags,
                                    resource_type, **kwargs)
            return self.client.update(object_url, body)
        return do_update()

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
        if resource_type is None:
            return body
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
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            nsxlib_exc.StaleRevision,
            max_attempts=self.client.max_attempts)
        def do_update():
            object_url = self.resource + '/' + pool_id
            body = self.client.get(object_url)
            body['members'] = members
            return self.client.update(object_url, body)
        return do_update()

    def add_monitor_to_pool(self, pool_id, monitor_id):
        self.add_to_list(pool_id, monitor_id, 'active_monitor_ids')

    def remove_monitor_from_pool(self, pool_id, monitor_id):
        self.remove_from_list(pool_id, monitor_id, 'active_monitor_ids')


class VirtualServer(LoadBalancerBase):
    resource = 'loadbalancer/virtual-servers'

    def update_virtual_server_with_pool(self, virtual_server_id, pool_id):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            nsxlib_exc.StaleRevision,
            max_attempts=self.client.max_attempts)
        def do_update():
            object_url = self.resource + '/' + virtual_server_id
            body = self.client.get(object_url)
            body['pool_id'] = pool_id
            return self.client.update(object_url, body)
        return do_update()

    def update_virtual_server_with_profiles(self, virtual_server_id,
                                            application_profile_id=None,
                                            persistence_profile_id=None,
                                            ip_protocol=None):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            nsxlib_exc.StaleRevision,
            max_attempts=self.client.max_attempts)
        def do_update():
            object_url = self.resource + '/' + virtual_server_id
            body = self.client.get(object_url)
            if application_profile_id:
                body['application_profile_id'] = application_profile_id
            if persistence_profile_id:
                body['persistence_profile_id'] = persistence_profile_id
            # In case the application profile is updated and its protocol
            # is updated as well, backend requires us to pass the new
            # protocol in the virtual server body.
            if ip_protocol:
                body['ip_protocol'] = ip_protocol
            return self.client.update(object_url, body)
        return do_update()

    def update_virtual_server_with_vip(self, virtual_server_id, vip):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            nsxlib_exc.StaleRevision,
            max_attempts=self.client.max_attempts)
        def do_update():
            object_url = self.resource + '/' + virtual_server_id
            body = self.client.get(object_url)
            body['ip_address'] = vip
            return self.client.update(object_url, body)
        return do_update()

    def add_rule(self, vs_id, rule_id):
        self.add_to_list(vs_id, rule_id, 'rule_ids')

    def remove_rule(self, vs_id, rule_id):
        self.remove_from_list(vs_id, rule_id, 'rule_ids')

    def add_client_ssl_profile_binding(self, virtual_server_id,
                                       ssl_profile_id, default_certificate_id,
                                       sni_certificate_ids=None, **kwargs):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            nsxlib_exc.StaleRevision,
            max_attempts=self.client.max_attempts)
        def do_update():
            binding = {'ssl_profile_id': ssl_profile_id,
                       'default_certificate_id': default_certificate_id}
            if sni_certificate_ids:
                binding.update({'sni_certificate_ids': sni_certificate_ids})

            valid_args = ['client_auth_ca_ids', 'client_auth_crl_ids',
                          'certificate_chain_depth', 'client_auth']
            # Remove the args that is not in the valid_args list or the
            # keyword argument doesn't have value.
            for arg in kwargs:
                if arg in valid_args and kwargs.get(arg):
                    binding[arg] = kwargs.get(arg)
            object_url = self.resource + '/' + virtual_server_id
            body = self.client.get(object_url)
            body['client_ssl_profile_binding'] = binding
            return self.client.update(object_url, body)
        return do_update()

    def add_server_ssl_profile_binding(self, virtual_server_id,
                                       ssl_profile_id, **kwargs):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            nsxlib_exc.StaleRevision,
            max_attempts=self.client.max_attempts)
        def do_update():
            binding = {'ssl_profile_id': ssl_profile_id}

            valid_args = ['server_auth_ca_ids', 'server_auth_crl_ids',
                          'certificate_chain_depth', 'server_auth',
                          'client_certificate_id']
            # Remove the args that is not in the valid_args list or the
            # keyword argument doesn't have value.
            for arg in kwargs:
                if arg in valid_args and kwargs.get(arg):
                    binding[arg] = kwargs[arg]
            object_url = self.resource + '/' + virtual_server_id
            body = self.client.get(object_url)
            body['server_ssl_profile_binding'] = binding
            return self.client.update(object_url, body)
        return do_update()


class Service(LoadBalancerBase):
    resource = 'loadbalancer/services'

    def update_service_with_virtual_servers(self, service_id,
                                            virtual_server_ids):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            nsxlib_exc.StaleRevision,
            max_attempts=self.client.max_attempts)
        def do_update():
            object_url = self.resource + '/' + service_id
            body = self.client.get(object_url)
            body['virtual_server_ids'] = virtual_server_ids
            return self.client.update(object_url, body)
        return do_update()

    def update_service_with_attachment(self, service_id, logical_router_id):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            nsxlib_exc.StaleRevision,
            max_attempts=self.client.max_attempts)
        def do_update():
            object_url = self.resource + '/' + service_id
            body = self.client.get(object_url)
            body['attachment'] = {'target_id': logical_router_id,
                                  'target_type': 'LogicalRouter'}
            return self.client.update(object_url, body)
        return do_update()

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

    def get_virtual_servers_status(self, service_id):
        object_url = '%s/%s/%s/%s' % (self.resource, service_id,
                                      'virtual-servers', 'status')
        return self.client.get(object_url)

    def get_stats(self, service_id, source='realtime'):
        object_url = '%s/%s/%s?source=%s' % (self.resource, service_id,
                                             'statistics', source)
        return self.client.get(object_url)

    def get_usage(self, service_id):
        object_url = '%s/%s/%s' % (self.resource, service_id, 'usage')
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
        self.server_ssl_profile = ServerSslProfile(client, nsxlib_config)
        self.rule = Rule(client, nsxlib_config)
