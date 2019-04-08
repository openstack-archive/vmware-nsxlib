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

from oslo_log import log as logging

from vmware_nsxlib.v3.policy import constants
from vmware_nsxlib.v3.policy import core_resources
from vmware_nsxlib.v3.policy import ipsec_vpn_defs

LOG = logging.getLogger(__name__)
IGNORE = core_resources.IGNORE


class NsxIpsecVpnIkeProfileApi(core_resources.NsxPolicyResourceBase):
    @property
    def entry_def(self):
        return ipsec_vpn_defs.IpsecVpnIkeProfileDef

    def create_or_overwrite(self, name,
                            profile_id=None,
                            description=IGNORE,
                            ike_version=IGNORE,
                            encryption_algorithms=IGNORE,
                            digest_algorithms=IGNORE,
                            dh_groups=IGNORE,
                            sa_life_time=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        profile_id = self._init_obj_uuid(profile_id)
        profile_def = self._init_def(
            profile_id=profile_id,
            name=name,
            description=description,
            ike_version=ike_version,
            encryption_algorithms=encryption_algorithms,
            digest_algorithms=digest_algorithms,
            dh_groups=dh_groups,
            sa_life_time=sa_life_time,
            tags=tags,
            tenant=tenant)
        self._create_or_store(profile_def)
        return profile_id

    def delete(self, profile_id, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(profile_id=profile_id,
                                     tenant=tenant)
        self.policy_api.delete(profile_def)

    def get(self, profile_id, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(profile_id=profile_id,
                                     tenant=tenant)
        return self.policy_api.get(profile_def)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(tenant=tenant)
        return self._list(profile_def)

    def get_by_name(self, name, tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxIpsecVpnIkeProfileApi, self).get_by_name(
            name, tenant=tenant)

    def update(self, profile_id, name=IGNORE, description=IGNORE,
               ike_version=IGNORE, encryption_algorithms=IGNORE,
               digest_algorithms=IGNORE, dh_groups=IGNORE, sa_life_time=IGNORE,
               tags=IGNORE, tenant=constants.POLICY_INFRA_TENANT):
        self._update(profile_id=profile_id,
                     name=name,
                     description=description,
                     ike_version=ike_version,
                     encryption_algorithms=encryption_algorithms,
                     digest_algorithms=digest_algorithms,
                     dh_groups=dh_groups,
                     sa_life_time=sa_life_time,
                     tags=tags,
                     tenant=tenant)


class NsxIpsecVpnTunnelProfileApi(core_resources.NsxPolicyResourceBase):
    @property
    def entry_def(self):
        return ipsec_vpn_defs.IpsecVpnTunnelProfileDef

    def create_or_overwrite(self, name,
                            profile_id=None,
                            description=IGNORE,
                            enable_perfect_forward_secrecy=IGNORE,
                            encryption_algorithms=IGNORE,
                            digest_algorithms=IGNORE,
                            dh_groups=IGNORE,
                            sa_life_time=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        profile_id = self._init_obj_uuid(profile_id)
        profile_def = self._init_def(
            profile_id=profile_id,
            name=name,
            description=description,
            enable_perfect_forward_secrecy=enable_perfect_forward_secrecy,
            encryption_algorithms=encryption_algorithms,
            digest_algorithms=digest_algorithms,
            dh_groups=dh_groups,
            sa_life_time=sa_life_time,
            tags=tags,
            tenant=tenant)
        self._create_or_store(profile_def)
        return profile_id

    def delete(self, profile_id, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(profile_id=profile_id,
                                     tenant=tenant)
        self.policy_api.delete(profile_def)

    def get(self, profile_id, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(profile_id=profile_id,
                                     tenant=tenant)
        return self.policy_api.get(profile_def)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(tenant=tenant)
        return self._list(profile_def)

    def get_by_name(self, name, tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxIpsecVpnTunnelProfileApi, self).get_by_name(
            name, tenant=tenant)

    def update(self, profile_id, name=IGNORE, description=IGNORE,
               enable_perfect_forward_secrecy=IGNORE,
               encryption_algorithms=IGNORE,
               digest_algorithms=IGNORE, dh_groups=IGNORE, sa_life_time=IGNORE,
               tags=IGNORE, tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            profile_id=profile_id,
            name=name,
            description=description,
            enable_perfect_forward_secrecy=enable_perfect_forward_secrecy,
            encryption_algorithms=encryption_algorithms,
            digest_algorithms=digest_algorithms,
            dh_groups=dh_groups,
            sa_life_time=sa_life_time,
            tags=tags,
            tenant=tenant)


class NsxIpsecVpnDpdProfileApi(core_resources.NsxPolicyResourceBase):
    @property
    def entry_def(self):
        return ipsec_vpn_defs.IpsecVpnDpdProfileDef

    def create_or_overwrite(self, name,
                            profile_id=None,
                            description=IGNORE,
                            dpd_probe_interval=IGNORE,
                            enabled=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        profile_id = self._init_obj_uuid(profile_id)
        profile_def = self._init_def(
            profile_id=profile_id,
            name=name,
            description=description,
            dpd_probe_interval=dpd_probe_interval,
            enabled=enabled,
            tags=tags,
            tenant=tenant)
        self._create_or_store(profile_def)
        return profile_id

    def delete(self, profile_id, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(profile_id=profile_id,
                                     tenant=tenant)
        self.policy_api.delete(profile_def)

    def get(self, profile_id, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(profile_id=profile_id,
                                     tenant=tenant)
        return self.policy_api.get(profile_def)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(tenant=tenant)
        return self._list(profile_def)

    def get_by_name(self, name, tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxIpsecVpnDpdProfileApi, self).get_by_name(
            name, tenant=tenant)

    def update(self, profile_id, name=IGNORE, description=IGNORE,
               dpd_probe_interval=IGNORE, enabled=IGNORE,
               tags=IGNORE, tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            profile_id=profile_id,
            name=name,
            description=description,
            dpd_probe_interval=dpd_probe_interval,
            enabled=enabled,
            tags=tags,
            tenant=tenant)


class NsxIpsecVpnServiceApi(core_resources.NsxPolicyResourceBase):
    @property
    def entry_def(self):
        return ipsec_vpn_defs.Tier1IPSecVpnServiceDef

    def _locale_service_id(self, tier1_id):
        return core_resources.NsxPolicyTier1Api._locale_service_id(tier1_id)

    def create_or_overwrite(self, name, tier1_id,
                            vpn_service_id=None,
                            description=IGNORE,
                            enabled=IGNORE,
                            ike_log_level=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        vpn_service_id = self._init_obj_uuid(vpn_service_id)
        service_def = self._init_def(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            vpn_service_id=vpn_service_id,
            name=name,
            description=description,
            enabled=enabled,
            ike_log_level=ike_log_level,
            tags=tags,
            tenant=tenant)
        self._create_or_store(service_def)
        return vpn_service_id

    def delete(self, tier1_id, vpn_service_id,
               tenant=constants.POLICY_INFRA_TENANT):
        service_def = self.entry_def(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            vpn_service_id=vpn_service_id,
            tenant=tenant)
        self.policy_api.delete(service_def)

    def get(self, tier1_id, vpn_service_id,
            tenant=constants.POLICY_INFRA_TENANT):
        service_def = self.entry_def(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            vpn_service_id=vpn_service_id,
            tenant=tenant)
        return self.policy_api.get(service_def)

    def list(self, tier1_id, tenant=constants.POLICY_INFRA_TENANT):
        service_def = self.entry_def(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            tenant=tenant)
        return self._list(service_def)

    def get_by_name(self, tier1_id, name,
                    tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxIpsecVpnServiceApi, self).get_by_name(
            name, tier1_id=tier1_id,
            tenant=tenant)

    def update(self, tier1_id, vpn_service_id, name=IGNORE, description=IGNORE,
               enabled=IGNORE, ike_log_level=IGNORE,
               tags=IGNORE, tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            vpn_service_id=vpn_service_id,
            name=name,
            description=description,
            enabled=enabled,
            ike_log_level=ike_log_level,
            tags=tags,
            tenant=tenant)


class NsxIpsecVpnLocalEndpointApi(core_resources.NsxPolicyResourceBase):
    @property
    def entry_def(self):
        return ipsec_vpn_defs.IpsecVpnLocalEndpointDef

    def _locale_service_id(self, tier1_id):
        return core_resources.NsxPolicyTier1Api._locale_service_id(tier1_id)

    def create_or_overwrite(self, name, tier1_id,
                            vpn_service_id,
                            endpoint_id=None,
                            description=IGNORE,
                            local_address=IGNORE,
                            local_id=IGNORE,
                            certificate_path=IGNORE,
                            trust_ca_ids=IGNORE,
                            trust_crl_ids=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        endpoint_id = self._init_obj_uuid(endpoint_id)
        endpoint_def = self._init_def(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            vpn_service_id=vpn_service_id,
            endpoint_id=endpoint_id,
            name=name,
            description=description,
            local_address=local_address,
            local_id=local_id,
            certificate_path=certificate_path,
            trust_ca_ids=trust_ca_ids,
            trust_crl_ids=trust_crl_ids,
            tags=tags,
            tenant=tenant)
        self._create_or_store(endpoint_def)
        return endpoint_id

    def delete(self, tier1_id, vpn_service_id, endpoint_id,
               tenant=constants.POLICY_INFRA_TENANT):
        endpoint_def = self.entry_def(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            vpn_service_id=vpn_service_id,
            endpoint_id=endpoint_id,
            tenant=tenant)
        self.policy_api.delete(endpoint_def)

    def get(self, tier1_id, vpn_service_id, endpoint_id,
            tenant=constants.POLICY_INFRA_TENANT):
        endpoint_def = self.entry_def(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            vpn_service_id=vpn_service_id,
            endpoint_id=endpoint_id,
            tenant=tenant)
        return self.policy_api.get(endpoint_def)

    def list(self, tier1_id, vpn_service_id,
             tenant=constants.POLICY_INFRA_TENANT):
        endpoint_def = self.entry_def(
            tier1_id=tier1_id,
            vpn_service_id=vpn_service_id,
            service_id=self._locale_service_id(tier1_id),
            tenant=tenant)
        return self._list(endpoint_def)

    def get_by_name(self, tier1_id, vpn_service_id, name,
                    tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxIpsecVpnLocalEndpointApi, self).get_by_name(
            name, tier1_id=tier1_id,
            vpn_service_id=vpn_service_id,
            tenant=tenant)

    def update(self, tier1_id, vpn_service_id, endpoint_id,
               name=IGNORE,
               description=IGNORE,
               local_address=IGNORE,
               local_id=IGNORE,
               certificate_path=IGNORE,
               trust_ca_ids=IGNORE,
               trust_crl_ids=IGNORE,
               tags=IGNORE, tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            vpn_service_id=vpn_service_id,
            endpoint_id=endpoint_id,
            name=name,
            description=description,
            local_address=local_address,
            local_id=local_id,
            certificate_path=certificate_path,
            trust_ca_ids=trust_ca_ids,
            trust_crl_ids=trust_crl_ids,
            tags=tags,
            tenant=tenant)


class NsxIpsecVpnSessionApi(core_resources.NsxPolicyResourceBase):
    @property
    def entry_def(self):
        return ipsec_vpn_defs.Tier1IPSecVpnSessionDef

    def _locale_service_id(self, tier1_id):
        return core_resources.NsxPolicyTier1Api._locale_service_id(tier1_id)

    def create_or_overwrite(self, name, tier1_id,
                            vpn_service_id,
                            session_id=None,
                            description=IGNORE,
                            enabled=IGNORE,
                            peer_address=IGNORE,
                            peer_id=IGNORE,
                            psk=IGNORE,
                            rules=IGNORE,
                            dpd_profile_id=IGNORE,
                            ike_profile_id=IGNORE,
                            tunnel_profile_id=IGNORE,
                            local_endpoint_id=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        session_id = self._init_obj_uuid(session_id)
        session_def = self._init_def(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            vpn_service_id=vpn_service_id,
            session_id=session_id,
            name=name,
            description=description,
            enabled=enabled,
            peer_address=peer_address,
            peer_id=peer_id,
            psk=psk,
            rules=rules,
            dpd_profile_id=dpd_profile_id,
            ike_profile_id=ike_profile_id,
            tunnel_profile_id=tunnel_profile_id,
            local_endpoint_id=local_endpoint_id,
            tags=tags,
            tenant=tenant)
        self._create_or_store(session_def)
        return session_id

    def delete(self, tier1_id, vpn_service_id, session_id,
               tenant=constants.POLICY_INFRA_TENANT):
        session_def = self.entry_def(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            vpn_service_id=vpn_service_id,
            session_id=session_id,
            tenant=tenant)
        self.policy_api.delete(session_def)

    def get(self, tier1_id, vpn_service_id, session_id,
            tenant=constants.POLICY_INFRA_TENANT):
        session_def = self.entry_def(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            vpn_service_id=vpn_service_id,
            session_id=session_id,
            tenant=tenant)
        return self.policy_api.get(session_def)

    def list(self, tier1_id, vpn_service_id,
             tenant=constants.POLICY_INFRA_TENANT):
        session_def = self.entry_def(
            tier1_id=tier1_id,
            vpn_service_id=vpn_service_id,
            service_id=self._locale_service_id(tier1_id),
            tenant=tenant)
        return self._list(session_def)

    def get_by_name(self, tier1_id, vpn_service_id, name,
                    tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxIpsecVpnSessionApi, self).get_by_name(
            name, tier1_id=tier1_id,
            vpn_service_id=vpn_service_id,
            tenant=tenant)

    def update(self, tier1_id, vpn_service_id, session_id,
               name=IGNORE,
               description=IGNORE,
               enabled=IGNORE,
               peer_address=IGNORE,
               peer_id=IGNORE,
               psk=IGNORE,
               rules=IGNORE,
               dpd_profile_id=IGNORE,
               ike_profile_id=IGNORE,
               tunnel_profile_id=IGNORE,
               local_endpoint_id=IGNORE,
               tags=IGNORE, tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            vpn_service_id=vpn_service_id,
            session_id=session_id,
            name=name,
            description=description,
            enabled=enabled,
            peer_address=peer_address,
            peer_id=peer_id,
            psk=psk,
            rules=rules,
            dpd_profile_id=dpd_profile_id,
            ike_profile_id=ike_profile_id,
            tunnel_profile_id=tunnel_profile_id,
            local_endpoint_id=local_endpoint_id,
            tags=tags,
            tenant=tenant)


class NsxPolicyIpsecVpnApi(object):
    """This is the class that have all IPSEC VPN  policy apis"""
    def __init__(self, *args):
        self.ike_profile = NsxIpsecVpnIkeProfileApi(*args)
        self.tunnel_profile = NsxIpsecVpnTunnelProfileApi(*args)
        self.dpd_profile = NsxIpsecVpnDpdProfileApi(*args)
        self.service = NsxIpsecVpnServiceApi(*args)
        self.local_endpoint = NsxIpsecVpnLocalEndpointApi(*args)
        self.session = NsxIpsecVpnSessionApi(*args)
