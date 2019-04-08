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

from vmware_nsxlib.v3.policy.core_defs import ResourceDef

TENANTS_PATH_PATTERN = "%s/"
IPSEC_VPN_IKE_PROFILES_PATH_PATTERN = (TENANTS_PATH_PATTERN +
                                       "ipsec-vpn-ike-profiles/")
IPSEC_VPN_TUNNEL_PROFILES_PATH_PATTERN = (TENANTS_PATH_PATTERN +
                                          "ipsec-vpn-tunnel-profiles/")

IPSEC_VPN_DPD_PROFILES_PATH_PATTERN = (TENANTS_PATH_PATTERN +
                                       "ipsec-vpn-dpd-profiles/")


class IpsecVpnIkeProfileDef(ResourceDef):

    @property
    def path_pattern(self):
        return IPSEC_VPN_IKE_PROFILES_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'profile_id')

    @staticmethod
    def resource_type():
        return "IPSecVpnIkeProfile"

    def get_obj_dict(self):
        body = super(IpsecVpnIkeProfileDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, ["ike_version",
                                            "encryption_algorithms",
                                            "digest_algorithms",
                                            "dh_groups",
                                            "sa_life_time"])
        return body


class IpsecVpnTunnelProfileDef(ResourceDef):

    @property
    def path_pattern(self):
        return IPSEC_VPN_TUNNEL_PROFILES_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'profile_id')

    @staticmethod
    def resource_type():
        return "IPSecVpnTunnelProfile"

    def get_obj_dict(self):
        body = super(IpsecVpnTunnelProfileDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, ["enable_perfect_forward_secrecy",
                                            "encryption_algorithms",
                                            "digest_algorithms",
                                            "dh_groups",
                                            "sa_life_time"])
        return body


class IpsecVpnDpdProfileDef(ResourceDef):

    @property
    def path_pattern(self):
        return IPSEC_VPN_DPD_PROFILES_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'profile_id')

    @staticmethod
    def resource_type():
        return "IPSecVpnDpdProfile"

    def get_obj_dict(self):
        body = super(IpsecVpnDpdProfileDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, ["dpd_probe_interval", "enabled"])
        return body
