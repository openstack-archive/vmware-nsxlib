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
from vmware_nsxlib.v3.policy.core_resources import IGNORE
from vmware_nsxlib.v3.policy.core_resources import NsxPolicyResourceBase
from vmware_nsxlib.v3.policy import ipsec_vpn_defs


LOG = logging.getLogger(__name__)


class NsxIpsecVpnIkeProfileApi(NsxPolicyResourceBase):
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


class NsxIpsecVpnTunnelProfileApi(NsxPolicyResourceBase):
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


class NsxIpsecVpnDpdProfileApi(NsxPolicyResourceBase):
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


class NsxPolicyIpsecVpnApi(object):
    """This is the class that have all IPSEC VPN  policy apis"""
    def __init__(self, *args):
        self.ike_profile = NsxIpsecVpnIkeProfileApi(*args)
        self.tunnel_profile = NsxIpsecVpnTunnelProfileApi(*args)
        self.dpd_profile = NsxIpsecVpnDpdProfileApi(*args)
