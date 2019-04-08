# Copyright 2016 OpenStack Foundation
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

import copy
from distutils import version

from oslo_log import log

from vmware_nsxlib import v3
from vmware_nsxlib.v3 import client
from vmware_nsxlib.v3 import lib
from vmware_nsxlib.v3 import nsx_constants

from vmware_nsxlib.v3.policy import core_defs
from vmware_nsxlib.v3.policy import core_resources
from vmware_nsxlib.v3.policy import lb_resources

LOG = log.getLogger(__name__)


class NsxPolicyLib(lib.NsxLibBase):

    def init_api(self):
        # Initialize the policy client
        # TODO(annak): move the API class to separate file
        self.policy_api = core_defs.NsxPolicyApi(self.client)

        # NSX manager api will be used as a pass-through for apis which are
        # not implemented by the policy manager yet
        if self.nsxlib_config.allow_passthrough:
            config = copy.deepcopy(self.nsxlib_config)
            # X-Allow-Overwrite must be set for passthrough apis
            config.allow_overwrite_header = True
            self.nsx_api = v3.NsxLib(config)
        else:
            self.nsx_api = None
        self.nsx_version = self.get_version()
        args = (self.policy_api, self.nsx_api, self.nsx_version,
                self.nsxlib_config)

        # Initialize all the different resources
        self.domain = core_resources.NsxPolicyDomainApi(*args)
        self.group = core_resources.NsxPolicyGroupApi(*args)
        self.service = core_resources.NsxPolicyL4ServiceApi(*args)
        self.icmp_service = core_resources.NsxPolicyIcmpServiceApi(
            *args)
        self.ip_protocol_service = (
            core_resources.NsxPolicyIPProtocolServiceApi(*args))
        self.mixed_service = core_resources.NsxPolicyMixedServiceApi(*args)
        self.tier0 = core_resources.NsxPolicyTier0Api(*args)
        self.tier0_nat_rule = core_resources.NsxPolicyTier0NatRuleApi(
            *args)
        self.tier1 = core_resources.NsxPolicyTier1Api(*args)
        self.tier1_segment = core_resources.NsxPolicyTier1SegmentApi(*args)
        self.tier1_nat_rule = core_resources.NsxPolicyTier1NatRuleApi(
            *args)
        self.tier1_static_route = (
            core_resources.NsxPolicyTier1StaticRouteApi(*args))
        self.segment = core_resources.NsxPolicySegmentApi(*args)
        self.segment_port = core_resources.NsxPolicySegmentPortApi(
            *args)
        self.tier1_segment_port = (
            core_resources.NsxPolicyTier1SegmentPortApi(*args))
        self.comm_map = core_resources.NsxPolicyCommunicationMapApi(*args)
        self.gateway_policy = core_resources.NsxPolicyGatewayPolicyApi(*args)
        self.enforcement_point = core_resources.NsxPolicyEnforcementPointApi(
            *args)
        self.transport_zone = core_resources.NsxPolicyTransportZoneApi(
            *args)
        self.edge_cluster = core_resources.NsxPolicyEdgeClusterApi(
            *args)
        self.deployment_map = core_resources.NsxPolicyDeploymentMapApi(
            *args)
        self.ip_block = core_resources.NsxPolicyIpBlockApi(*args)
        self.ip_pool = core_resources.NsxPolicyIpPoolApi(*args)
        self.segment_security_profile = (
            core_resources.NsxSegmentSecurityProfileApi(*args))
        self.qos_profile = (
            core_resources.NsxQosProfileApi(*args))
        self.spoofguard_profile = (
            core_resources.NsxSpoofguardProfileApi(*args))
        self.ip_discovery_profile = (
            core_resources.NsxIpDiscoveryProfileApi(*args))
        self.mac_discovery_profile = (
            core_resources.NsxMacDiscoveryProfileApi(*args))
        self.waf_profile = (
            core_resources.NsxWAFProfileApi(*args))
        self.segment_port_security_profiles = (
            core_resources.SegmentPortSecurityProfilesBindingMapApi(
                *args))
        self.segment_port_discovery_profiles = (
            core_resources.SegmentPortDiscoveryProfilesBindingMapApi(
                *args))
        self.segment_port_qos_profiles = (
            core_resources.SegmentPortQosProfilesBindingMapApi(
                *args))
        self.ipv6_ndra_profile = (
            core_resources.NsxIpv6NdraProfileApi(*args))
        self.dhcp_relay_config = core_resources.NsxDhcpRelayConfigApi(*args)
        self.certificate = core_resources.NsxPolicyCertApi(*args)
        self.exclude_list = core_resources.NsxPolicyExcludeListApi(*args)
        self.load_balancer = lb_resources.NsxPolicyLoadBalancerApi(*args)

    @property
    def keepalive_section(self):
        return 'infra'

    @property
    def validate_connection_method(self):
        # TODO(asarfaty): Find an equivalent api to check policy status
        pass

    def get_version(self):
        """Get the NSX Policy manager version

        Currently the backend does not support it, so the nsx-manager api
        will be used temporarily as a passthrough.
        """
        if self.nsx_version:
            return self.nsx_version

        if self.nsx_api:
            self.nsx_version = self.nsx_api.get_version()
        else:
            # return the initial supported version
            self.nsx_version = nsx_constants.NSX_VERSION_2_4_0
        return self.nsx_version

    def feature_supported(self, feature):
        if (version.LooseVersion(self.get_version()) >=
                version.LooseVersion(nsx_constants.NSX_VERSION_2_4_0)):
            # Features available since 2.4
            if (feature == nsx_constants.FEATURE_NSX_POLICY_NETWORKING):
                return True

        return (feature == nsx_constants.FEATURE_NSX_POLICY)

    def reinitialize_cluster(self, resource, event, trigger, payload=None):
        super(NsxPolicyLib, self).reinitialize_cluster(
            resource, event, trigger, payload=payload)
        if self.nsx_api:
            self.nsx_api.reinitialize_cluster(resource, event, trigger,
                                              payload)

    @property
    def client_url_prefix(self):
        return client.NSX3Client.NSX_POLICY_V1_API_PREFIX
