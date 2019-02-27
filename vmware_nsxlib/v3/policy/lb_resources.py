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

import abc

from oslo_log import log as logging
import six

from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3.policy import constants
from vmware_nsxlib.v3.policy.core_resources import IGNORE
from vmware_nsxlib.v3.policy.core_resources import NsxPolicyResourceBase
from vmware_nsxlib.v3.policy import lb_defs
from vmware_nsxlib.v3.policy import utils as p_utils


LOG = logging.getLogger(__name__)

# Sentitel object to indicate unspecified attribute value
# None value in attribute would indicate "unset" functionality,
# while "ignore" means that the value not be present in request
# body


class NsxPolicyLBAppProfileBase(NsxPolicyResourceBase):
    """NSX Policy LB app profile"""

    def create_or_overwrite(self, name,
                            lb_app_profile_id=None,
                            description=IGNORE,
                            http_redirect_to_https=IGNORE,
                            http_redirect_to=IGNORE,
                            idle_timeout=IGNORE,
                            ntlm=IGNORE,
                            request_body_size=IGNORE,
                            request_header_size=IGNORE,
                            response_header_size=IGNORE,
                            response_timeout=IGNORE,
                            x_forwarded_for=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        lb_app_profile_id = self._init_obj_uuid(lb_app_profile_id)
        lb_app_profile_def = self._init_def(
            lb_app_profile_id=lb_app_profile_id,
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
            tags=tags,
            tenant=tenant)
        self._create_or_store(lb_app_profile_def)
        return lb_app_profile_id

    def delete(self, lb_app_profile_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lb_app_profile_def = self.entry_def(
            lb_app_profile_id=lb_app_profile_id,
            tenant=tenant)
        self.policy_api.delete(lb_app_profile_def)

    def get(self, lb_app_profile_id,
            tenant=constants.POLICY_INFRA_TENANT):
        lb_app_profile_def = self.entry_def(
            lb_app_profile_id=lb_app_profile_id,
            tenant=tenant)
        return self.policy_api.get(lb_app_profile_def)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lb_app_profile_def = self.entry_def(tenant=tenant)
        return self._list(lb_app_profile_def)

    def update(self, lb_app_profile_id,
               name=IGNORE,
               description=IGNORE,
               http_redirect_to_https=IGNORE,
               http_redirect_to=IGNORE,
               idle_timeout=IGNORE,
               ntlm=IGNORE,
               request_body_size=IGNORE,
               request_header_size=IGNORE,
               response_header_size=IGNORE,
               response_timeout=IGNORE,
               x_forwarded_for=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            lb_app_profile_id=lb_app_profile_id,
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
            tags=tags,
            tenant=tenant)


class NsxPolicyLBAppProfileHttpApi(NsxPolicyLBAppProfileBase):
    """NSX Policy LB app profile"""

    @property
    def entry_def(self):
        return lb_defs.LBHttpProfileDef


class NsxPolicyLBAppProfileFastTcpApi(
    NsxPolicyLBAppProfileBase):
    """NSX Policy LB app profile"""

    @property
    def entry_def(self):
        return lb_defs.LBFastTcpProfile


class NsxPolicyLBAppProfileFastUdpApi(
    NsxPolicyLBAppProfileBase):
    """NSX Policy LB app profile"""

    @property
    def entry_def(self):
        return lb_defs.LBFastUdpProfile


class NsxPolicyLoadBalancerLBClientSSLProfileApi(NsxPolicyResourceBase):
    """NSX Policy LB client ssl profile"""

    @property
    def entry_def(self):
        return lb_defs.LBClientSslProfileDef

    def create_or_overwrite(self, name,
                            client_ssl_profile_id=None,
                            description=IGNORE,
                            tags=IGNORE,
                            protocols=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        client_ssl_profile_id = self._init_obj_uuid(
            client_ssl_profile_id)
        lb_client_ssl_profile_def = self._init_def(
            client_ssl_profile_id=client_ssl_profile_id,
            name=name,
            description=description,
            tags=tags,
            protocols=protocols,
            tenant=tenant)
        self._create_or_store(lb_client_ssl_profile_def)
        return client_ssl_profile_id

    def delete(self, client_ssl_profile_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lb_client_ssl_profile_def = self.entry_def(
            client_ssl_profile_id=client_ssl_profile_id,
            tenant=tenant)
        self.policy_api.delete(lb_client_ssl_profile_def)

    def get(self, client_ssl_profile_id,
            tenant=constants.POLICY_INFRA_TENANT):
        lb_client_ssl_profile_def = self.entry_def(
            client_ssl_profile_id=client_ssl_profile_id,
            tenant=tenant)
        return self.policy_api.get(lb_client_ssl_profile_def)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lb_client_ssl_profile_def = self.entry_def(tenant=tenant)
        return self._list(lb_client_ssl_profile_def)

    def update(self, client_ssl_profile_id,
               name=IGNORE,
               description=IGNORE,
               tags=IGNORE,
               protocols=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            client_ssl_profile_id=client_ssl_profile_id,
            name=name,
            description=description,
            tags=tags,
            protocols=protocols,
            tenant=tenant)


class NsxPolicyLoadBalancerLBCookiePersistenceProfileApi(
    NsxPolicyResourceBase):
    """NSX Policy LB client ssl profile"""

    @property
    def entry_def(self):
        return lb_defs.LBCookiePersistenceProfileDef

    def create_or_overwrite(self, name,
                            persistence_profile_id=None,
                            description=IGNORE,
                            tags=IGNORE,
                            cookie_garble=IGNORE,
                            cookie_name=IGNORE,
                            cookie_mode=IGNORE,
                            cookie_path=IGNORE,
                            cookie_time=IGNORE,
                            persistence_shared=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        persistence_profile_id = self._init_obj_uuid(
            persistence_profile_id)
        lb_cookie_persistence_profile_def = self._init_def(
            persistence_profile_id=persistence_profile_id,
            name=name,
            description=description,
            tags=tags,
            cookie_name=cookie_name,
            cookie_garble=cookie_garble,
            cookie_mode=cookie_mode,
            cookie_path=cookie_path,
            cookie_time=cookie_time,
            persistence_shared=persistence_shared,
            tenant=tenant)
        self._create_or_store(lb_cookie_persistence_profile_def)
        return persistence_profile_id

    def delete(self, persistence_profile_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lb_cookie_persistence_profile_def = self.entry_def(
            persistence_profile_id=persistence_profile_id,
            tenant=tenant)
        self.policy_api.delete(lb_cookie_persistence_profile_def)

    def get(self, persistence_profile_id,
            tenant=constants.POLICY_INFRA_TENANT):
        lb_cookie_persistence_profile_def = self.entry_def(
            persistence_profile_id=persistence_profile_id,
            tenant=tenant)
        return self.policy_api.get(lb_cookie_persistence_profile_def)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lb_cookie_persistence_profile_def = self.entry_def(tenant=tenant)
        return self._list(lb_cookie_persistence_profile_def)

    def update(self, persistence_profile_id,
               name=IGNORE,
               description=IGNORE,
               tags=IGNORE,
               cookie_garble=IGNORE,
               cookie_name=IGNORE,
               cookie_mode=IGNORE,
               cookie_path=IGNORE,
               cookie_time=IGNORE,
               persistence_shared=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            persistence_profile_id=persistence_profile_id,
            name=name,
            description=description,
            tags=tags,
            cookie_garble=cookie_garble,
            cookie_mode=cookie_mode,
            cookie_name=cookie_name,
            cookie_path=cookie_path,
            cookie_time=cookie_time,
            persistence_shared=persistence_shared,
            tenant=tenant)


class NsxPolicyLoadBalancerLBSourceIpPersistenceProfileApi(
    NsxPolicyResourceBase):
    """NSX Policy LB client ssl profile"""

    @property
    def entry_def(self):
        return lb_defs.LBSourceIpPersistenceProfileDef

    def create_or_overwrite(self, name,
                            persistence_profile_id=None,
                            description=IGNORE,
                            tags=IGNORE,
                            ha_persistence_mirroring_enabled=IGNORE,
                            persistence_shared=IGNORE,
                            purge=IGNORE,
                            timeout=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        persistence_profile_id = self._init_obj_uuid(
            persistence_profile_id)
        lb_source_ip_persistence_profile_def = self._init_def(
            persistence_profile_id=persistence_profile_id,
            name=name,
            description=description,
            tags=tags,
            ha_persistence_mirroring_enabled=ha_persistence_mirroring_enabled,
            persistence_shared=persistence_shared,
            purge=purge,
            timeout=timeout,
            tenant=tenant)
        self._create_or_store(lb_source_ip_persistence_profile_def)
        return persistence_profile_id

    def delete(self, persistence_profile_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lb_source_ip_persistence_profile_def = self.entry_def(
            persistence_profile_id=persistence_profile_id,
            tenant=tenant)
        self.policy_api.delete(lb_source_ip_persistence_profile_def)

    def get(self, persistence_profile_id,
            tenant=constants.POLICY_INFRA_TENANT):
        lb_source_ip_persistence_profile_def = self.entry_def(
            persistence_profile_id=persistence_profile_id,
            tenant=tenant)
        return self.policy_api.get(lb_source_ip_persistence_profile_def)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lb_source_ip_persistence_profile_def = self.entry_def(tenant=tenant)
        return self._list(lb_source_ip_persistence_profile_def)

    def update(self, persistence_profile_id,
               name=IGNORE,
               description=IGNORE,
               tags=IGNORE,
               ha_persistence_mirroring_enabled=IGNORE,
               persistence_shared=IGNORE,
               purge=IGNORE,
               timeout=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            persistence_profile_id=persistence_profile_id,
            name=name,
            description=description,
            tags=tags,
            ha_persistence_mirroring_enabled=ha_persistence_mirroring_enabled,
            persistence_shared=persistence_shared,
            purge=purge,
            timeout=timeout,
            tenant=tenant)


class NsxPolicyLoadBalancerPoolApi(NsxPolicyResourceBase):
    """NSX Policy LBService."""
    @property
    def entry_def(self):
        return lb_defs.LBPoolDef

    def create_or_overwrite(self, name, lb_pool_id=None, description=IGNORE,
                            tags=IGNORE, members=IGNORE, algorithm=IGNORE,
                            active_monitor_paths=IGNORE, member_group=IGNORE,
                            snat_translation=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_id = self._init_obj_uuid(lb_pool_id)
        lb_pool_def = self._init_def(
            lb_pool_id=lb_pool_id,
            name=name,
            description=description,
            tags=tags,
            members=members,
            active_monitor_paths=active_monitor_paths,
            algorithm=algorithm,
            member_group=member_group,
            snat_translation=snat_translation,
            tenant=tenant)

        self._create_or_store(lb_pool_def)
        return lb_pool_id

    def delete(self, lb_pool_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_def = self.entry_def(
            lb_pool_id=lb_pool_id, tenant=tenant)
        self.policy_api.delete(lb_pool_def)

    def get(self, lb_pool_id, tenant=constants.POLICY_INFRA_TENANT,
            silent=False):
        lb_pool_def = self.entry_def(
            lb_pool_id=lb_pool_id, tenant=tenant)
        return self.policy_api.get(lb_pool_def)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_def = self.entry_def(tenant=tenant)
        return self.policy_api.list(lb_pool_def)['results']

    def update(self, lb_pool_id, name=IGNORE, description=IGNORE,
               tags=IGNORE, members=IGNORE, algorithm=IGNORE,
               active_monitor_paths=IGNORE, member_group=IGNORE,
               snat_translation=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            lb_pool_id=lb_pool_id,
            name=name,
            description=description,
            tags=tags,
            members=members,
            active_monitor_paths=active_monitor_paths,
            algorithm=algorithm,
            member_group=member_group,
            snat_translation=snat_translation,
            tenant=tenant)

    def add_monitor_to_pool(self, lb_pool_id, active_monitor_paths,
                            tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_def = self.entry_def(
            lb_pool_id=lb_pool_id, tenant=tenant)
        lb_pool = self.policy_api.get(lb_pool_def)
        monitor_paths = lb_pool.get('active_monitor_paths', [])
        monitor_paths.extend(active_monitor_paths)
        self.update(lb_pool_id, active_monitor_paths=monitor_paths)

    def remove_monitor_from_pool(self, lb_pool_id, monitor_path,
                                 tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_def = self.entry_def(
            lb_pool_id=lb_pool_id, tenant=tenant)
        lb_pool = self.policy_api.get(lb_pool_def)
        monitor_paths = lb_pool.get('active_monitor_paths', [])
        if monitor_path in monitor_paths:
            monitor_paths.remove(monitor_path)
            self.update(lb_pool_id, active_monitor_paths=monitor_paths)

    def create_pool_member_and_add_to_pool(
            self, lb_pool_id, ip_address, port=None,
            display_name=None, weight=None,
            tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_member = lb_defs.LBPoolMemberDef(
            ip_address, port=port,
            name=display_name,
            weight=weight)
        lb_pool_def = lb_defs.LBPoolDef(
            lb_pool_id=lb_pool_id, tenant=tenant)
        lb_pool = self.policy_api.get(lb_pool_def)
        lb_pool_members = lb_pool.get('members', [])
        lb_pool_members.append(lb_pool_member)
        self.update(lb_pool_id, members=lb_pool_members)
        return lb_pool_member

    def remove_pool_member(self, lb_pool_id, ip_address, port=None,
                           tenant=constants.POLICY_INFRA_TENANT):
        lb_pool_def = lb_defs.LBPoolDef(
            lb_pool_id=lb_pool_id, tenant=tenant)
        lb_pool = self.policy_api.get(lb_pool_def)
        lb_pool_members = lb_pool.get('members', [])
        lb_pool_members = filter(
            lambda x: (x.get('ip_address') != ip_address or
                       x.get('port') != port), lb_pool_members)
        self.update(lb_pool_id, members=lb_pool_members)


class NsxPolicyLoadBalancerServiceApi(NsxPolicyResourceBase):
    """NSX Policy LBService."""
    @property
    def entry_def(self):
        return lb_defs.LBServiceDef

    def create_or_overwrite(self, name, lb_service_id=None,
                            description=IGNORE,
                            tags=IGNORE,
                            size=IGNORE,
                            connectivity_path=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        lb_service_id = self._init_obj_uuid(lb_service_id)
        lb_service_def = self._init_def(
            lb_service_id=lb_service_id,
            name=name,
            description=description,
            tags=tags,
            size=size,
            connectivity_path=connectivity_path,
            tenant=tenant)

        self._create_or_store(lb_service_def)
        return lb_service_id

    def delete(self, lb_service_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lb_service_def = self.entry_def(
            lb_service_id=lb_service_id, tenant=tenant)
        self.policy_api.delete(lb_service_def)

    def get(self, lb_service_id, tenant=constants.POLICY_INFRA_TENANT):
        lb_service_def = self.entry_def(
            lb_service_id=lb_service_id, tenant=tenant)
        return self.policy_api.get(lb_service_def)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lb_service_def = lb_defs.LBServiceDef(tenant=tenant)
        return self.policy_api.list(lb_service_def)['results']

    def update(self, lb_service_id, name=IGNORE,
               description=IGNORE, tags=IGNORE,
               size=IGNORE, connectivity_path=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(lb_service_id=lb_service_id,
                     name=name,
                     description=description,
                     tags=tags,
                     size=size,
                     connectivity_path=connectivity_path,
                     tenant=tenant)

    def get_status(self, lb_service_id):
        lb_service_status_def = (
            lb_defs.LBServiceStatisticsDef(
                lb_service_id=lb_service_id,
                tenant=constants.POLICY_INFRA_TENANT))
        return self.policy_api.get(lb_service_status_def)

    def get_usage(self, lb_service_id):
        lb_service_status_def = lb_defs.LBServiceUsageDef(
            lb_service_id=lb_service_id,
            tenant=constants.POLICY_INFRA_TENANT)
        return self.policy_api.get(lb_service_status_def)


class NsxPolicyLoadBalancerVirtualServerAPI(NsxPolicyResourceBase):
    """NSX Policy LoadBalancerVirtualServers"""

    @property
    def entry_def(self):
        return lb_defs.LBVirtualServerDef

    def create_or_overwrite(self, name, virtual_server_id=None,
                            description=IGNORE,
                            rules=IGNORE, application_profile_id=IGNORE,
                            ip_address=IGNORE, lb_service_id=IGNORE,
                            client_ssl_profile_binding=IGNORE,
                            pool_id=IGNORE,
                            lb_persistence_profile_id=IGNORE,
                            ports=IGNORE,
                            server_ssl_profile_binding=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT,
                            tags=IGNORE):
        virtual_server_id = self._init_obj_uuid(virtual_server_id)
        lbvs_def = self._init_def(
            virtual_server_id=virtual_server_id,
            name=name,
            description=description,
            tenant=tenant,
            rules=rules,
            application_profile_id=application_profile_id,
            ip_address=ip_address,
            lb_service_id=lb_service_id,
            client_ssl_profile_binding=client_ssl_profile_binding,
            pool_id=pool_id,
            lb_persistence_profile_id=lb_persistence_profile_id,
            ports=ports,
            server_ssl_profile_binding=server_ssl_profile_binding,
            tags=tags
        )
        self._create_or_store(lbvs_def)
        return virtual_server_id

    def delete(self, virtual_server_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lbvs_def = self.entry_def(
            virtual_server_id=virtual_server_id, tenant=tenant)
        self.policy_api.delete(lbvs_def)

    def get(self, virtual_server_id,
            tenant=constants.POLICY_INFRA_TENANT):
        lbvs_def = self.entry_def(
            virtual_server_id=virtual_server_id, tenant=tenant)
        return self.policy_api.get(lbvs_def)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lbvs_def = self.entry_def(tenant=tenant)
        return self.policy_api.list(lbvs_def)['results']

    def _update_helper(self, virtual_server_id, tenant, **kwargs):
        # TODO(kobis) method should be removed and replaced with a simple
        #  call to _update(), once the policy backend PATCH method works
        #  properly
        vs_data = self.get(virtual_server_id, tenant)
        if kwargs['application_profile_id'] == IGNORE:
            kwargs['application_profile_id'] = p_utils.path_to_id(
                vs_data['application_profile_path'])

        if kwargs['name'] == IGNORE:
            kwargs['name'] = vs_data['display_name']

        for k in kwargs.keys():
            if kwargs.get(k) == IGNORE and vs_data.get(k):
                kwargs[k] = vs_data[k]

        self._update(
            virtual_server_id=virtual_server_id,
            tenant=tenant,
            **kwargs)

    def update(self, virtual_server_id, name=IGNORE, description=IGNORE,
               rules=IGNORE, application_profile_id=IGNORE,
               ip_address=IGNORE, lb_service_id=IGNORE,
               client_ssl_profile_binding=IGNORE,
               pool_id=IGNORE,
               lb_persistence_profile_id=IGNORE,
               ports=IGNORE,
               server_ssl_profile_binding=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update_helper(
            virtual_server_id=virtual_server_id,
            name=name,
            description=description,
            tenant=tenant,
            rules=rules,
            application_profile_id=application_profile_id,
            ip_address=ip_address,
            lb_service_id=lb_service_id,
            client_ssl_profile_binding=client_ssl_profile_binding,
            pool_id=pool_id,
            lb_persistence_profile_id=lb_persistence_profile_id,
            ports=ports,
            server_ssl_profile_binding=server_ssl_profile_binding,
            tags=tags)

    def update_virtual_server_with_pool(
            self, virtual_server_id, pool_id=IGNORE):
        body = self.get(virtual_server_id)
        app_profile_id = p_utils.path_to_id(body['application_profile_path'])
        return self.update(virtual_server_id, pool_id=pool_id,
                           ip_address=body['ip_address'],
                           ports=body['ports'],
                           application_profile_id=app_profile_id)

    def update_virtual_server_application_profile(
            self, virtual_server_id, application_profile_id=IGNORE):
        body = self.get(virtual_server_id)
        return self.update(virtual_server_id,
                           application_profile_id=application_profile_id,
                           ip_address=body['ip_address'],
                           ports=body['ports'])

    def update_virtual_server_persistence_profile(
            self, virtual_server_id, lb_persistence_profile_id=IGNORE):
        body = self.get(virtual_server_id)
        app_profile_id = p_utils.path_to_id(body['application_profile_path'])
        return self.update(
            virtual_server_id,
            lb_persistence_profile_id=lb_persistence_profile_id,
            ip_address=body['ip_address'],
            ports=body['ports'],
            application_profile_id=app_profile_id)

    def update_virtual_server_client_ssl_profile_binding(
            self, virtual_server_id, client_ssl_profile_binding=IGNORE):
        body = self.get(virtual_server_id)
        app_profile_id = p_utils.path_to_id(body['application_profile_path'])
        return self.update(
            virtual_server_id,
            client_ssl_profile_binding=client_ssl_profile_binding,
            ip_address=body['ip_address'],
            ports=body['ports'],
            application_profile_id=app_profile_id)

    def update_virtual_server_with_vip(self, virtual_server_id, vip):
        body = self.get(virtual_server_id)
        app_profile_id = p_utils.path_to_id(body['application_profile_path'])
        return self.update(virtual_server_id, ip_address=vip,
                           ports=body['ports'],
                           application_profile_id=app_profile_id)

    def build_client_ssl_profile_binding(self, default_certificate_path,
                                         sni_certificate_paths=None,
                                         ssl_profile_path=None,
                                         client_auth_ca_paths=None,
                                         client_auth=None):
        return lb_defs.ClientSSLProfileBindingDef(
            default_certificate_path,
            sni_certificate_paths=sni_certificate_paths,
            ssl_profile_path=ssl_profile_path,
            client_auth_ca_paths=client_auth_ca_paths, client_auth=client_auth)

    def update_client_ssl_profile_binding(self, virtual_server_id,
                                          default_certificate_path,
                                          sni_certificate_paths=None,
                                          ssl_profile_path=None,
                                          client_auth_ca_paths=None,
                                          client_auth=None):
        lbvs_def = self.entry_def(
            virtual_server_id=virtual_server_id,
            tenant=constants.POLICY_INFRA_TENANT)
        body = self.policy_api.get(lbvs_def)
        app_profile_id = p_utils.path_to_id(body['application_profile_path'])
        client_ssl_def = lb_defs.ClientSSLProfileBindingDef(
            default_certificate_path,
            sni_certificate_paths=sni_certificate_paths,
            ssl_profile_path=ssl_profile_path,
            client_auth_ca_paths=client_auth_ca_paths, client_auth=client_auth)

        return self.update(virtual_server_id,
                           client_ssl_profile_binding=client_ssl_def,
                           ip_address=body['ip_address'],
                           ports=body['ports'],
                           application_profile_id=app_profile_id)

    def build_lb_rule(self, actions=None, display_name=None,
                      match_conditions=None, match_strategy=None, phase=None):
        return lb_defs.LBRuleDef(
            actions, match_conditions, display_name, match_strategy, phase)

    def _add_rule_in_position(self, body, lb_rule, position):
        lb_rules = body.get('rules', [])
        if position < 0:
            lb_rules.append(lb_rule)
        elif position <= len(lb_rules):
            lb_rules.insert(position, lb_rule)
        else:
            raise nsxlib_exc.InvalidInput(
                operation='Insert rule in position',
                arg_val=position,
                arg_name='position')

        return lb_rules

    def add_lb_rule(self, virtual_server_id, actions=None,
                    name=None, match_conditions=None,
                    match_strategy=None, phase=None, position=-1,
                    tenant=constants.POLICY_INFRA_TENANT):
        lb_rule = lb_defs.LBRuleDef(
            actions, match_conditions, name, match_strategy, phase)
        lbvs_def = self.entry_def(
            virtual_server_id=virtual_server_id,
            tenant=tenant)
        body = self.policy_api.get(lbvs_def)
        app_profile_id = p_utils.path_to_id(body['application_profile_path'])
        lb_rules = self._add_rule_in_position(body, lb_rule, position)
        return self.update(virtual_server_id, rules=lb_rules,
                           ip_address=body['ip_address'],
                           ports=body['ports'],
                           application_profile_id=app_profile_id)

    def update_lb_rule(self, virtual_server_id, lb_rule_name,
                       actions=None, match_conditions=None,
                       match_strategy=None, phase=None, position=-1,
                       tenant=constants.POLICY_INFRA_TENANT):
        lb_rule = lb_defs.LBRuleDef(
            actions, match_conditions, lb_rule_name, match_strategy, phase)
        lbvs_def = self.entry_def(
            virtual_server_id=virtual_server_id,
            tenant=tenant)
        body = self.policy_api.get(lbvs_def)
        app_profile_id = p_utils.path_to_id(body['application_profile_path'])
        lb_rules = body.get('rules', [])

        # Remove existing rule
        body['rules'] = filter(lambda x: (x.get('display_name') !=
                                          lb_rule_name), lb_rules)

        # Insert new rule
        lb_rules = self._add_rule_in_position(body, lb_rule, position)
        return self.update(virtual_server_id, rules=lb_rules,
                           ip_address=body['ip_address'],
                           ports=body['ports'],
                           application_profile_id=app_profile_id)

    def remove_lb_rule(self, virtual_server_id, lb_rule_name,
                       tenant=constants.POLICY_INFRA_TENANT):
        lbvs_def = self.entry_def(virtual_server_id=virtual_server_id,
                                  tenant=tenant)
        body = self.policy_api.get(lbvs_def)
        app_profile_id = p_utils.path_to_id(body['application_profile_path'])
        lb_rules = body.get('rules', [])
        lb_rules = filter(lambda x: (x.get('display_name') !=
                                     lb_rule_name), lb_rules)
        return self.update(virtual_server_id, rules=lb_rules,
                           ip_address=body['ip_address'],
                           ports=body['ports'],
                           application_profile_id=app_profile_id)


@six.add_metaclass(abc.ABCMeta)
class NsxPolicyLBMonitorProfileBase(NsxPolicyResourceBase):
    """NSX Policy LB monitor profile"""

    def create_or_overwrite(self,
                            lb_monitor_profile_id=None,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT,
                            **kwargs):
        lb_monitor_profile_id = self._init_obj_uuid(lb_monitor_profile_id)
        lb_monitor_profile_def = self._init_def(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            tenant=tenant,
            **kwargs)
        self._create_or_store(lb_monitor_profile_def)
        return lb_monitor_profile_id

    def delete(self, lb_monitor_profile_id,
               tenant=constants.POLICY_INFRA_TENANT):
        lb_monitor_profile_def = self.entry_def(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tenant=tenant)
        self.policy_api.delete(lb_monitor_profile_def)

    def get(self, lb_monitor_profile_id,
            tenant=constants.POLICY_INFRA_TENANT):
        lb_monitor_profile_def = self.entry_def(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tenant=tenant)
        return self.policy_api.get(lb_monitor_profile_def)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        lb_monitor_profile_def = self.entry_def(tenant=tenant)
        return self._list(lb_monitor_profile_def)

    def update(self,
               lb_monitor_profile_id,
               display_name=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT,
               **kwargs):
        self._update(
            lb_monitor_profile_id=lb_monitor_profile_id,
            display_name=display_name,
            tags=tags,
            tenant=tenant,
            **kwargs)

    def get_path(self, lb_monitor_profile_id,
                 tenant=constants.POLICY_INFRA_TENANT):
        mon_def = self.entry_def(lb_monitor_profile_id=lb_monitor_profile_id,
                                 tenant=tenant)
        return mon_def.get_resource_full_path()


class NsxPolicyLBMonitorProfileHttpApi(NsxPolicyLBMonitorProfileBase):
    """NSX Policy LB HTTP monitor profile"""

    def create_or_overwrite(self,
                            lb_monitor_profile_id=None,
                            tags=IGNORE,
                            display_name=IGNORE,
                            interval=IGNORE,
                            timeout=IGNORE,
                            fall_count=IGNORE,
                            rise_count=IGNORE,
                            monitor_port=IGNORE,
                            request_url=IGNORE,
                            request_method=IGNORE,
                            request_version=IGNORE,
                            request_headers=IGNORE,
                            request_body=IGNORE,
                            response_status_codes=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileHttpApi,
                     self).create_or_overwrite(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            display_name=display_name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            monitor_port=monitor_port,
            request_url=request_url,
            request_method=request_method,
            request_version=request_version,
            request_headers=request_headers,
            request_body=request_body,
            response_status_codes=response_status_codes,
            tenant=tenant)

    def update(self,
               lb_monitor_profile_id,
               tags=IGNORE,
               display_name=IGNORE,
               interval=IGNORE,
               timeout=IGNORE,
               fall_count=IGNORE,
               rise_count=IGNORE,
               monitor_port=IGNORE,
               request_url=IGNORE,
               request_method=IGNORE,
               request_version=IGNORE,
               request_headers=IGNORE,
               request_body=IGNORE,
               response_status_codes=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileHttpApi, self).update(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            display_name=display_name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            monitor_port=monitor_port,
            request_url=request_url,
            request_method=request_method,
            request_version=request_version,
            request_headers=request_headers,
            request_body=request_body,
            response_status_codes=response_status_codes,
            tenant=tenant)

    @property
    def entry_def(self):
        return lb_defs.LBHttpMonitorProfileDef


class NsxPolicyLBMonitorProfileHttpsApi(NsxPolicyLBMonitorProfileHttpApi):
    """NSX Policy LB HTTPS monitor profile"""

    @property
    def entry_def(self):
        return lb_defs.LBHttpsMonitorProfileDef


class NsxPolicyLBMonitorProfileUdpApi(NsxPolicyLBMonitorProfileBase):
    """NSX Policy LB UDP monitor profile"""

    def create_or_overwrite(self,
                            lb_monitor_profile_id=None,
                            tags=IGNORE,
                            display_name=IGNORE,
                            interval=IGNORE,
                            timeout=IGNORE,
                            fall_count=IGNORE,
                            rise_count=IGNORE,
                            monitor_port=IGNORE,
                            receive=IGNORE,
                            send=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileUdpApi,
                     self).create_or_overwrite(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            display_name=display_name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            monitor_port=monitor_port,
            receive=receive,
            send=send,
            tenant=tenant)

    def update(self,
               lb_monitor_profile_id,
               tags=IGNORE,
               display_name=IGNORE,
               interval=IGNORE,
               timeout=IGNORE,
               fall_count=IGNORE,
               rise_count=IGNORE,
               monitor_port=IGNORE,
               receive=IGNORE,
               send=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileUdpApi, self).update(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            display_name=display_name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            monitor_port=monitor_port,
            receive=receive,
            send=send,
            tenant=tenant)

    @property
    def entry_def(self):
        return lb_defs.LBUdpMonitorProfileDef


class NsxPolicyLBMonitorProfileIcmpApi(NsxPolicyLBMonitorProfileBase):
    """NSX Policy LB ICMP monitor profile"""

    def create_or_overwrite(self,
                            lb_monitor_profile_id=None,
                            tags=IGNORE,
                            display_name=IGNORE,
                            interval=IGNORE,
                            timeout=IGNORE,
                            fall_count=IGNORE,
                            rise_count=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileIcmpApi,
                     self).create_or_overwrite(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            display_name=display_name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            tenant=tenant)

    def update(self,
               lb_monitor_profile_id,
               tags=IGNORE,
               display_name=IGNORE,
               interval=IGNORE,
               timeout=IGNORE,
               fall_count=IGNORE,
               rise_count=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileIcmpApi, self).update(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            display_name=display_name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            tenant=tenant)

    @property
    def entry_def(self):
        return lb_defs.LBIcmpMonitorProfileDef


class NsxPolicyLBMonitorProfileTcpApi(NsxPolicyLBMonitorProfileBase):
    """NSX Policy LB TCP monitor profile"""

    def create_or_overwrite(self,
                            lb_monitor_profile_id=None,
                            tags=IGNORE,
                            display_name=IGNORE,
                            interval=IGNORE,
                            timeout=IGNORE,
                            fall_count=IGNORE,
                            rise_count=IGNORE,
                            monitor_port=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileTcpApi,
                     self).create_or_overwrite(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            display_name=display_name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            monitor_port=monitor_port,
            tenant=tenant)

    def update(self,
               lb_monitor_profile_id,
               tags=IGNORE,
               display_name=IGNORE,
               interval=IGNORE,
               timeout=IGNORE,
               fall_count=IGNORE,
               rise_count=IGNORE,
               monitor_port=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxPolicyLBMonitorProfileTcpApi, self).update(
            lb_monitor_profile_id=lb_monitor_profile_id,
            tags=tags,
            display_name=display_name,
            interval=interval,
            timeout=timeout,
            fall_count=fall_count,
            rise_count=rise_count,
            monitor_port=monitor_port,
            tenant=tenant)

    @property
    def entry_def(self):
        return lb_defs.LBTcpMonitorProfileDef


class NsxPolicyLoadBalancerApi(object):
    """This is the class that have all load balancer policy apis"""
    def __init__(self, *args):
        self.lb_http_profile = NsxPolicyLBAppProfileHttpApi(*args)
        self.lb_fast_tcp_profile = NsxPolicyLBAppProfileFastTcpApi(*args)
        self.lb_fast_udp_profile = NsxPolicyLBAppProfileFastUdpApi(*args)
        self.client_ssl_profile = (
            NsxPolicyLoadBalancerLBClientSSLProfileApi(*args))
        self.lb_cookie_persistence_profile = (
            NsxPolicyLoadBalancerLBCookiePersistenceProfileApi(*args))
        self.lb_source_ip_persistence_profile = (
            NsxPolicyLoadBalancerLBSourceIpPersistenceProfileApi(*args))
        self.lb_service = NsxPolicyLoadBalancerServiceApi(*args)
        self.virtual_server = NsxPolicyLoadBalancerVirtualServerAPI(*args)
        self.lb_pool = NsxPolicyLoadBalancerPoolApi(*args)
        self.lb_monitor_profile_http = NsxPolicyLBMonitorProfileHttpApi(*args)
        self.lb_monitor_profile_https = (
            NsxPolicyLBMonitorProfileHttpsApi(*args))
        self.lb_monitor_profile_udp = NsxPolicyLBMonitorProfileUdpApi(*args)
        self.lb_monitor_profile_icmp = NsxPolicyLBMonitorProfileIcmpApi(*args)
        self.lb_monitor_profile_tcp = NsxPolicyLBMonitorProfileTcpApi(*args)
