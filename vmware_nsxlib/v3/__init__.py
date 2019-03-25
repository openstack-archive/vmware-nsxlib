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

from distutils import version

from oslo_log import log

from vmware_nsxlib._i18n import _
from vmware_nsxlib.v3 import client
from vmware_nsxlib.v3 import core_resources
from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import lib
from vmware_nsxlib.v3 import load_balancer
from vmware_nsxlib.v3 import native_dhcp
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import resources
from vmware_nsxlib.v3 import router
from vmware_nsxlib.v3 import security
from vmware_nsxlib.v3 import trust_management
from vmware_nsxlib.v3 import utils
from vmware_nsxlib.v3 import vpn_ipsec

LOG = log.getLogger(__name__)


class NsxLib(lib.NsxLibBase):

    def init_api(self):
        self.port_mirror = core_resources.NsxLibPortMirror(
            self.client, self.nsxlib_config, nsxlib=self)
        self.bridge_endpoint = core_resources.NsxLibBridgeEndpoint(
            self.client, self.nsxlib_config, nsxlib=self)
        self.bridge_endpoint_profile = (
            core_resources.NsxLibBridgeEndpointProfile(
                self.client, self.nsxlib_config, nsxlib=self))
        self.logical_switch = core_resources.NsxLibLogicalSwitch(
            self.client, self.nsxlib_config, nsxlib=self)
        self.logical_router = core_resources.NsxLibLogicalRouter(
            self.client, self.nsxlib_config, nsxlib=self)
        self.switching_profile = core_resources.NsxLibSwitchingProfile(
            self.client, self.nsxlib_config, nsxlib=self)
        self.qos_switching_profile = core_resources.NsxLibQosSwitchingProfile(
            self.client, self.nsxlib_config, nsxlib=self)
        self.edge_cluster = core_resources.NsxLibEdgeCluster(
            self.client, self.nsxlib_config, nsxlib=self)
        self.bridge_cluster = core_resources.NsxLibBridgeCluster(
            self.client, self.nsxlib_config, nsxlib=self)
        self.transport_zone = core_resources.NsxLibTransportZone(
            self.client, self.nsxlib_config, nsxlib=self)
        self.transport_node = core_resources.NsxLibTransportNode(
            self.client, self.nsxlib_config, nsxlib=self)
        self.relay_service = core_resources.NsxLibDhcpRelayService(
            self.client, self.nsxlib_config, nsxlib=self)
        self.relay_profile = core_resources.NsxLibDhcpRelayProfile(
            self.client, self.nsxlib_config, nsxlib=self)
        self.native_dhcp_profile = core_resources.NsxLibDhcpProfile(
            self.client, self.nsxlib_config, nsxlib=self)
        self.native_md_proxy = core_resources.NsxLibMetadataProxy(
            self.client, self.nsxlib_config, nsxlib=self)
        self.firewall_section = security.NsxLibFirewallSection(
            self.client, self.nsxlib_config, nsxlib=self)
        self.ns_group = security.NsxLibNsGroup(
            self.client, self.nsxlib_config, self.firewall_section,
            nsxlib=self)
        self.native_dhcp = native_dhcp.NsxLibNativeDhcp(
            self.client, self.nsxlib_config, nsxlib=self)
        self.ip_block_subnet = core_resources.NsxLibIpBlockSubnet(
            self.client, self.nsxlib_config, nsxlib=self)
        self.ip_block = core_resources.NsxLibIpBlock(
            self.client, self.nsxlib_config, nsxlib=self)
        self.ip_set = security.NsxLibIPSet(
            self.client, self.nsxlib_config, nsxlib=self)
        self.logical_port = resources.LogicalPort(
            self.client, self.nsxlib_config, nsxlib=self)
        self.logical_router_port = resources.LogicalRouterPort(
            self.client, self.nsxlib_config, nsxlib=self)
        self.dhcp_server = resources.LogicalDhcpServer(
            self.client, self.nsxlib_config, nsxlib=self)
        self.ip_pool = resources.IpPool(
            self.client, self.nsxlib_config, nsxlib=self)
        self.load_balancer = load_balancer.LoadBalancer(
            self.client, self.nsxlib_config)
        self.trust_management = trust_management.NsxLibTrustManagement(
            self.client, self.nsxlib_config)
        self.router = router.RouterLib(
            self.logical_router, self.logical_router_port, self)
        self.virtual_machine = core_resources.NsxLibFabricVirtualMachine(
            self.client, self.nsxlib_config, nsxlib=self)
        self.vif = core_resources.NsxLibFabricVirtualInterface(
            self.client, self.nsxlib_config, nsxlib=self)
        self.vpn_ipsec = vpn_ipsec.VpnIpSec(
            self.client, self.nsxlib_config, nsxlib=self)
        self.http_services = resources.NodeHttpServiceProperties(
            self.client, self.nsxlib_config, nsxlib=self)
        self.cluster_nodes = resources.NsxlibClusterNodesConfig(
            self.client, self.nsxlib_config, nsxlib=self)
        self.global_routing = core_resources.NsxLibGlobalRoutingConfig(
            self.client, self.nsxlib_config, nsxlib=self)

        # Update tag limits
        self.tag_limits = self.get_tag_limits()
        utils.update_tag_limits(self.tag_limits)

    @property
    def keepalive_section(self):
        return 'transport-zones'

    @property
    def validate_connection_method(self):
        """Return a method that will validate the NSX manager status"""
        def check_manager_status_v1(client, manager_url):
            """MP healthcheck for Version 2.3 and below"""
            # Try to get the cluster status silently and with no retries
            status = client.get('operational/application/status',
                                silent=True, with_retries=False)
            if (not status or status.get('application_status') != 'WORKING'):
                msg = _("Manager is not in working state: %s") % status
                LOG.warning(msg)
                raise exceptions.ResourceNotFound(
                    manager=manager_url, operation=msg)

        def check_manager_status_v2(client, manager_url):
            """MP healthcheck for Version 2.4 and above"""
            # Try to get the status silently and with no retries
            status = client.get('reverse-proxy/node/health',
                                silent=True, with_retries=False)
            if (not status or not status.get('healthy', False)):
                msg = _("Manager is not in working state: %s") % status
                LOG.warning(msg)
                raise exceptions.ResourceNotFound(
                    manager=manager_url, operation=msg)

        def check_manager_status(client, manager_url):
            # Decide on the healthcheck by the version (if already initialized)
            if (self.nsx_version and
                version.LooseVersion(self.nsx_version) >=
                version.LooseVersion(nsx_constants.NSX_VERSION_2_4_0)):
                return check_manager_status_v2(client, manager_url)
            return check_manager_status_v1(client, manager_url)

        return check_manager_status

    def get_version(self):
        if self.nsx_version:
            return self.nsx_version

        node = self.client.get("node")
        self.nsx_version = node.get('node_version')
        return self.nsx_version

    def export_restricted(self):
        node = self.client.get("node")
        return node.get('export_type') is 'RESTRICTED'

    def feature_supported(self, feature):
        if (version.LooseVersion(self.get_version()) >=
                version.LooseVersion(nsx_constants.NSX_VERSION_2_5_0)):
            # features available since 2.5
            if (feature == nsx_constants.FEATURE_CONTAINER_CLUSTER_INVENTORY):
                return True
            if (feature == nsx_constants.FEATURE_IPV6):
                return True

        if (version.LooseVersion(self.get_version()) >=
                version.LooseVersion(nsx_constants.NSX_VERSION_2_4_0)):
            # Features available since 2.4
            if (feature == nsx_constants.FEATURE_ENS_WITH_SEC):
                return True
            if (feature == nsx_constants.FEATURE_ICMP_STRICT):
                return True
            if (feature == nsx_constants.FEATURE_ENABLE_STANDBY_RELOCATION):
                return True

        if (version.LooseVersion(self.get_version()) >=
                version.LooseVersion(nsx_constants.NSX_VERSION_2_3_0)):
            # Features available since 2.3
            if (feature == nsx_constants.FEATURE_ROUTER_ALLOCATION_PROFILE):
                return True
            if (feature == nsx_constants.FEATURE_LB_HM_RESPONSE_CODES):
                return True

        if (version.LooseVersion(self.get_version()) >=
            version.LooseVersion(nsx_constants.NSX_VERSION_2_2_0)):
            # Features available since 2.2
            if (feature == nsx_constants.FEATURE_VLAN_ROUTER_INTERFACE or
                feature == nsx_constants.FEATURE_IPSEC_VPN or
                feature == nsx_constants.FEATURE_ON_BEHALF_OF or
                feature == nsx_constants.FEATURE_RATE_LIMIT or
                feature == nsx_constants.FEATURE_TRUNK_VLAN or
                feature == nsx_constants.FEATURE_ROUTER_TRANSPORT_ZONE or
                feature == nsx_constants.FEATURE_NO_DNAT_NO_SNAT):
                return True

        if (version.LooseVersion(self.get_version()) >=
            version.LooseVersion(nsx_constants.NSX_VERSION_2_1_0)):
            # Features available since 2.1
            if (feature == nsx_constants.FEATURE_LOAD_BALANCER):
                return True

        if (version.LooseVersion(self.get_version()) >=
            version.LooseVersion(nsx_constants.NSX_VERSION_2_0_0)):
            # Features available since 2.0
            if (feature == nsx_constants.FEATURE_EXCLUDE_PORT_BY_TAG or
                feature == nsx_constants.FEATURE_ROUTER_FIREWALL or
                feature == nsx_constants.FEATURE_DHCP_RELAY):
                return True

        if (version.LooseVersion(self.get_version()) >=
            version.LooseVersion(nsx_constants.NSX_VERSION_1_1_0)):
            # Features available since 1.1
            if (feature == nsx_constants.FEATURE_MAC_LEARNING or
                feature == nsx_constants.FEATURE_DYNAMIC_CRITERIA):
                return True

        return False

    @property
    def client_url_prefix(self):
        return client.NSX3Client.NSX_V1_API_PREFIX
