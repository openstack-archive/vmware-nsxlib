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

from vmware_nsxlib.v3.policy_defs import ResourceDef

TENANTS_PATH_PATTERN = "%s/"
LB_VIRTUAL_SERVERS_PATH_PATTERN = TENANTS_PATH_PATTERN + "lb-virtual-servers/"
LB_SERVICES_PATH_PATTERN = TENANTS_PATH_PATTERN + "lb-services/"
LB_POOL_PATH_PATTERN = TENANTS_PATH_PATTERN + "lb-pools/"
LB_APP_PROFILE_PATTERN = TENANTS_PATH_PATTERN + "lb-app-profiles/"
LB_CLIENT_SSL_PROFILE_PATTERN = (TENANTS_PATH_PATTERN +
                                 "lb-client-ssl-profiles/")
LB_PERSISTENCE_PROFILE_PATTERN = (TENANTS_PATH_PATTERN +
                                  "lb-persistence-profiles/")

class LBRuleDef(object):
    def __init__(self, actions, match_conditions=None, name=None,
                 match_strategy=None, phase=None):
        self.actions = actions
        self.name = name
        self.match_conditions = match_conditions
        self.match_strategy = match_strategy
        self.phase = phase

    def get_obj_dict(self):
        lb_rule = {
            'actions': self.actions
        }
        if self.match_conditions:
            lb_rule['match_conditions'] = self.match_conditions
        if self.name:
            lb_rule['name'] = self.name
        if self.match_strategy:
            lb_rule['match_strategy'] = self.match_strategy
        if self.phase:
            lb_rule['phase'] = self.phase
        return lb_rule


class LBPoolMemberDef(object):
    def __init__(self, ip_address, port=None, name=None,
                 weight=None):
        self.name = name
        self.ip_address = ip_address
        self.port = port
        self.weight = weight

    def get_obj_dict(self):
        body = {'ip_address': self.ip_address}
        if self.name:
            body['name'] = self.name
        if self.ip_address:
            body['port'] = self.port
        if self.weight:
            body['weight'] = self.weight
        return body


class LBClientSslProfileDef(ResourceDef):

    @property
    def path_pattern(self):
        return LB_CLIENT_SSL_PROFILE_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'client_ssl_profile_id')

    @staticmethod
    def resource_type():
        return "LBClientSslProfile"

    def get_obj_dict(self):
        body = super(LBClientSslProfileDef, self).get_obj_dict()
        self._set_attr_if_specified(body, 'protocols')
        return body


class LBPersistenceProfileBase(ResourceDef):

    @property
    def path_pattern(self):
        return LB_PERSISTENCE_PROFILE_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'persistence_profile_id')


class LBCookiePersistenceProfileDef(LBPersistenceProfileBase):

    @staticmethod
    def resource_type():
        return "LBCookiePersistenceProfile"

    def get_obj_dict(self):
        body = super(LBCookiePersistenceProfileDef, self).get_obj_dict()
        self._set_attrs_if_specified(
            body, ['cookie_garble', 'cookie_mode', 'cookie_name',
                   'cookie_path', 'cookie_time', 'persistence_shared'])
        return body


class LBSourceIpPersistenceProfileDef(LBPersistenceProfileBase):

    @staticmethod
    def resource_type():
        return "LBSourceIpPersistenceProfile"

    def get_obj_dict(self):
        body = super(LBSourceIpPersistenceProfileDef, self).get_obj_dict()
        self._set_attrs_if_specified(
            body, ['ha_persistence_mirroring_enabled', 'persistence_shared',
                   'purge', 'timeout'])
        return body


class LBAppProfileBaseDef(ResourceDef):

    @property
    def path_pattern(self):
        return LB_APP_PROFILE_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'lb_app_profile_id')

    def get_obj_dict(self):
        body = super(LBAppProfileBaseDef, self).get_obj_dict()
        self._set_attrs_if_specified(
            body, ['idle_timeout', 'http_redirect_to_https',
                   'http_redirect_to', 'idle_timeout', 'ntlm',
                   'request_body_size', 'request_header_size',
                   'response_timeout', 'x_forwarded_for'])
        return body


class LBHttpProfileDef(LBAppProfileBaseDef):

    @staticmethod
    def resource_type():
        return "LBHttpProfile"


class LBFastTcpProfile(LBAppProfileBaseDef):

    @staticmethod
    def resource_type():
        return "LBFastTcpProfile"


class LBFastUdpProfile(LBAppProfileBaseDef):

    @staticmethod
    def resource_type():
        return "LBFastUdpProfile"


class LBPoolDef(ResourceDef):

    @property
    def path_pattern(self):
        return LB_POOL_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'lb_pool_id')

    @staticmethod
    def resource_type():
        return 'LBPool'

    def get_obj_dict(self):
        body = super(LBPoolDef, self).get_obj_dict()
        self._set_attrs_if_specified(
            body, ['members', 'active_monitor_paths',
                   'algorithm', 'member_group', 'snat_translation'])
        return body


class LBVirtualServerDef(ResourceDef):

    @property
    def path_pattern(self):
        return LB_VIRTUAL_SERVERS_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'virtual_server_id')

    @staticmethod
    def resource_type():
        return 'LBVirtualServer'

    def get_obj_dict(self):
        body = super(LBVirtualServerDef, self).get_obj_dict()
        self._set_attrs_if_specified(
            body, ['application_profile_path', 'lb_persistence_profile_path',
                   'ip_address', 'lb_service_path',
                   'client_ssl_profile_binding', 'pool_path', 'ports',
                   'server_ssl_profile_binding'])
        rules = self.get_attr('rules')
        if rules:
            rules = rules if isinstance(rules, list) else [rules]
            body['rules'] = []
            for rule in rules:
                # the list contains old json rules and newly added ruledef rule
                if isinstance(rule, LBRuleDef):
                    rule = rule.get_obj_dict()
                body['rules'].append(rule)
        client_ssl = self.get_attr('client_ssl_profile_binding')
        if client_ssl:
            body['client_ssl_profile_binding'] = client_ssl.get_obj_dict()
        return body


class ClientSSLProfileBindingDef(object):
    def __init__(self, default_certificate_path, sni_certificate_paths=None,
                 ssl_profile_path=None, client_auth_ca_paths=None,
                 client_auth=None):
        self.default_certificate_path = default_certificate_path
        self.sni_certificate_paths = sni_certificate_paths
        self.ssl_profile_path = ssl_profile_path
        self.client_auth_ca_paths = client_auth_ca_paths
        self.client_auth = client_auth

    def get_obj_dict(self):
        body = {
            'default_certificate_path': self.default_certificate_path
        }
        if self.sni_certificate_paths:
            body['sni_certificate_paths'] = self.sni_certificate_paths
        if self.ssl_profile_path:
            body['ssl_profile_path'] = self.ssl_profile_path
        if self.client_auth_ca_paths:
            body['client_auth_ca_paths'] = self.client_auth_ca_paths
        if self.client_auth:
            body['client_auth'] = self.client_auth
        return body


class LBServiceDef(ResourceDef):

    @property
    def path_pattern(self):
        return LB_SERVICES_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'lb_service_id')

    @staticmethod
    def resource_type():
        return 'LBService'

    def get_obj_dict(self):
        body = super(LBServiceDef, self).get_obj_dict()
        self._set_attr_if_specified(body, 'size')
        return body


class LBServiceStatisticsDef(ResourceDef):

    @property
    def path_pattern(self):
        return LB_SERVICES_PATH_PATTERN + '%s/statistics/'


class LBServiceUsageDef(ResourceDef):

    @property
    def path_pattern(self):
        return LB_SERVICES_PATH_PATTERN + '%s/service-usage/'