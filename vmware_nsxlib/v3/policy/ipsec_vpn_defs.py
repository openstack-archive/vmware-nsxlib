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

from vmware_nsxlib.v3.policy import core_defs

TENANTS_PATH_PATTERN = "%s/"
IPSEC_VPN_IKE_PROFILES_PATH_PATTERN = (TENANTS_PATH_PATTERN +
                                       "ipsec-vpn-ike-profiles/")
IPSEC_VPN_TUNNEL_PROFILES_PATH_PATTERN = (TENANTS_PATH_PATTERN +
                                          "ipsec-vpn-tunnel-profiles/")
IPSEC_VPN_DPD_PROFILES_PATH_PATTERN = (TENANTS_PATH_PATTERN +
                                       "ipsec-vpn-dpd-profiles/")
IPSEC_VPN_SERVICE_PATH_PATTERN = (
    core_defs.TIER1_LOCALE_SERVICES_PATH_PATTERN + "%s/ipsec-vpn-services/")

IPSEC_VPN_DPD_PROFILES_PATH_PATTERN = (TENANTS_PATH_PATTERN +
                                       "ipsec-vpn-dpd-profiles/")


class IpsecVpnIkeProfileDef(core_defs.ResourceDef):

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


class IpsecVpnTunnelProfileDef(core_defs.ResourceDef):

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


class IpsecVpnDpdProfileDef(core_defs.ResourceDef):

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


class Tier1IPSecVpnServiceDef(core_defs.ResourceDef):

    @staticmethod
    def resource_type():
        return 'IPSecVpnService'

    @property
    def path_pattern(self):
        return IPSEC_VPN_SERVICE_PATH_PATTERN

    def get_obj_dict(self):
        body = super(Tier1IPSecVpnServiceDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, ['enabled', 'ike_log_level'])
        return body

    @property
    def path_ids(self):
        return ('tenant', 'tier1_id', 'service_id', 'vpn_service_id')


class IpsecVpnLocalEndpointDef(core_defs.ResourceDef):

    @property
    def path_pattern(self):
        return IPSEC_VPN_SERVICE_PATH_PATTERN + "%s/local-endpoints/"

    @property
    def path_ids(self):
        return ('tenant', 'tier1_id', 'service_id', 'vpn_service_id',
                'endpoint_id')

    @staticmethod
    def resource_type():
        return "IPSecVpnLocalEndpoint"

    def get_obj_dict(self):
        body = super(IpsecVpnDpdProfileDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, ["local_address", "local_id",
                                            "certificate_path",
                                            "trust_ca_ids", "trust_crl_ids"])
        return body


class Tier1IPSecVpnSessionDef(core_defs.ResourceDef):

    @staticmethod
    def resource_type():
        return 'PolicyBasedIPSecVpnSession'

    @property
    def path_pattern(self):
        return IPSEC_VPN_SERVICE_PATH_PATTERN + "%s/sessions/"

    def get_obj_dict(self):
        body = super(Tier1IPSecVpnSessionDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, ['enabled', 'peer_address',
                                            'peer_id', 'psk', 'rules'])

        if self.has_attr('dpd_profile_id'):
            path = ""
            if self.get_attr('dpd_profile_id'):
                profile = IpsecVpnDpdProfileDef(
                    profile_id=self.get_attr('dpd_profile_id'),
                    tenant=self.get_tenant())
                path = profile.get_resource_full_path()
            self._set_attr_if_specified(body, 'dpd_profile_id',
                                        body_attr='dpd_profile_path',
                                        value=path)

        if self.has_attr('ike_profile_id'):
            path = ""
            if self.get_attr('ike_profile_id'):
                profile = IpsecVpnIkeProfileDef(
                    profile_id=self.get_attr('ike_profile_id'),
                    tenant=self.get_tenant())
                path = profile.get_resource_full_path()
            self._set_attr_if_specified(body, 'ike_profile_id',
                                        body_attr='ike_profile_path',
                                        value=path)

        if self.has_attr('tunnel_profile_id'):
            path = ""
            if self.get_attr('tunnel_profile_id'):
                profile = IpsecVpnTunnelProfileDef(
                    profile_id=self.get_attr('tunnel_profile_id'),
                    tenant=self.get_tenant())
                path = profile.get_resource_full_path()
            self._set_attr_if_specified(body, 'tunnel_profile_id',
                                        body_attr='tunnel_profile_path',
                                        value=path)

        if self.has_attr('local_endpoint_id'):
            path = ""
            if self.get_attr('local_endpoint_id'):
                endpoint = IpsecVpnLocalEndpointDef(
                    tier1_id=self.get_attr('tier1_id'),
                    service_id=self.get_attr('service_id'),
                    vpn_service_id=self.get_attr('vpn_service_id'),
                    endpoint_id=self.get_attr('local_endpoint_id'),
                    tenant=self.get_tenant())
                path = endpoint.get_resource_full_path()
            self._set_attr_if_specified(body, 'local_endpoint_id',
                                        body_attr='local_endpoint_path',
                                        value=path)
        return body

    @property
    def path_ids(self):
        return ('tenant', 'tier1_id', 'service_id', 'vpn_service_id',
                'session_id')
