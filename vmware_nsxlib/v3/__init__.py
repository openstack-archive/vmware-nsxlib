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

import abc
from distutils import version

from oslo_log import log
import six

from vmware_nsxlib._i18n import _
from vmware_nsxlib.v3 import client
from vmware_nsxlib.v3 import cluster
from vmware_nsxlib.v3 import core_resources
from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import load_balancer
from vmware_nsxlib.v3 import native_dhcp
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import policy_defs
from vmware_nsxlib.v3 import policy_resources
from vmware_nsxlib.v3 import resources
from vmware_nsxlib.v3 import router
from vmware_nsxlib.v3 import security
from vmware_nsxlib.v3 import trust_management
from vmware_nsxlib.v3 import utils
from vmware_nsxlib.v3 import vpn_ipsec

LOG = log.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class NsxLibBase(object):
    def __init__(self, nsxlib_config):

        self.set_config(nsxlib_config)

        # create the Cluster
        self.cluster = cluster.NSXClusteredAPI(self.nsxlib_config)

        # create the Client
        self.client = client.NSX3Client(
            self.cluster,
            nsx_api_managers=self.nsxlib_config.nsx_api_managers,
            max_attempts=self.nsxlib_config.max_attempts,
            url_path_base=self.client_url_prefix,
            rate_limit_retry=self.nsxlib_config.rate_limit_retry)

        self.general_apis = utils.NsxLibApiBase(
            self.client, self.nsxlib_config)

        self.init_api()

        super(NsxLibBase, self).__init__()

        self.nsx_version = None

    def set_config(self, nsxlib_config):
        """Set config user provided and extend it according to application"""
        self.nsxlib_config = nsxlib_config
        self.nsxlib_config.extend(keepalive_section=self.keepalive_section,
                                  url_base=self.client_url_prefix)

    @abc.abstractproperty
    def client_url_prefix(self):
        pass

    @abc.abstractproperty
    def keepalive_section(self):
        pass

    @abc.abstractmethod
    def init_api(self):
        pass

    @abc.abstractmethod
    def feature_supported(self, feature):
        pass

    def build_v3_api_version_tag(self):
        return self.general_apis.build_v3_api_version_tag()

    def is_internal_resource(self, nsx_resource):
        return self.general_apis.is_internal_resource(nsx_resource)

    def build_v3_tags_payload(self, resource, resource_type, project_name):
        return self.general_apis.build_v3_tags_payload(
            resource, resource_type, project_name)

    def reinitialize_cluster(self, resource, event, trigger, payload=None):
        self.cluster._reinit_cluster()

    def subscribe(self, callback, event):
        self.cluster.subscribe(callback, event)

    # TODO(abhiraut): Revisit this method to generate complex boolean
    #                 queries to search resources.
    def search_by_tags(self, tags, resource_type=None, cursor=None,
                       page_size=None):
        """Return the list of resources searched based on tags.

        Currently the query only supports AND boolean operator.
        :param tags: List of dictionaries containing tags. Each
                     NSX tag dictionary is of the form:
                     {'scope': <scope_key>, 'tag': <tag_value>}
        :param resource_type: Optional string parameter to limit the
                              scope of the search to the given ResourceType.
        :param cursor: Opaque cursor to be used for getting next page of
                       records (supplied by current result page).
        :param page_size: Maximum number of results to return in this page.
        """
        if not tags:
            reason = _("Missing required argument 'tags'")
            raise exceptions.NsxSearchInvalidQuery(reason=reason)
        # Query will return nothing if the same scope is repeated.
        query_tags = self._build_query(tags)
        query = 'resource_type:%s' % resource_type if resource_type else None
        if query:
            query += " AND %s" % query_tags
        else:
            query = query_tags
        url = "search?query=%s" % query
        if cursor:
            url += "&cursor=%d" % cursor
        if page_size:
            url += "&page_size=%d" % page_size

        # Retry the search on case of error
        @utils.retry_upon_exception(exceptions.NsxIndexingInProgress,
                                    max_attempts=self.client.max_attempts)
        def do_search(url):
            return self.client.url_get(url)

        return do_search(url)

    def search_all_by_tags(self, tags, resource_type=None):
        """Return all the results searched based on tags."""
        results = []
        cursor = 0
        while True:
            response = self.search_by_tags(resource_type=resource_type,
                                           tags=tags, cursor=cursor)
            if not response['results']:
                return results
            results.extend(response['results'])
            cursor = int(response['cursor'])
            result_count = int(response['result_count'])
            if cursor >= result_count:
                return results

    def get_id_by_resource_and_tag(self, resource_type, scope, tag,
                                   alert_not_found=False,
                                   alert_multiple=False):
        """Search a resource type by 1 scope&tag.

        Return the id of the result only if it is single.
        """
        query_tags = [{'scope': utils.escape_tag_data(scope),
                       'tag': utils.escape_tag_data(tag)}]
        query_result = self.search_by_tags(
            tags=query_tags, resource_type=resource_type)
        if not query_result['result_count']:
            if alert_not_found:
                msg = _("No %(type)s found for tag '%(scope)s:%(tag)s'") % {
                    'type': resource_type,
                    'scope': scope,
                    'tag': tag}
                LOG.warning(msg)
                raise exceptions.ResourceNotFound(
                    manager=self.nsxlib_config.nsx_api_managers,
                    operation=msg)
        elif query_result['result_count'] == 1:
            return query_result['results'][0]['id']
        else:
            # multiple results
            if alert_multiple:
                msg = _("Multiple %(type)s found for tag '%(scope)s:"
                        "%(tag)s'") % {
                    'type': resource_type,
                    'scope': scope,
                    'tag': tag}
                LOG.warning(msg)
                raise exceptions.ManagerError(
                    manager=self.nsxlib_config.nsx_api_managers,
                    operation=msg,
                    details='')

    def _build_tag_query(self, tag):
        # Validate that the correct keys are used
        if set(tag.keys()) - set(('scope', 'tag')):
            reason = _("Only 'scope' and 'tag' keys are supported")
            raise exceptions.NsxSearchInvalidQuery(reason=reason)
        _scope = tag.get('scope')
        _tag = tag.get('tag')
        if _scope and _tag:
            return 'tags.scope:%s AND tags.tag:%s' % (_scope, _tag)
        elif _scope:
            return 'tags.scope:%s' % _scope
        else:
            return 'tags.tag:%s' % _tag

    def _build_query(self, tags):
        return " AND ".join([self._build_tag_query(item) for item in tags])

    def get_tag_limits(self):
        try:
            result = self.client.url_get('spec/vmware/types/Tag')
            scope_length = result['properties']['scope']['maxLength']
            tag_length = result['properties']['tag']['maxLength']
        except Exception as e:
            LOG.error("Unable to read tag limits. Reason: %s", e)
            scope_length = utils.MAX_RESOURCE_TYPE_LEN
            tag_length = utils.MAX_TAG_LEN
        try:
            result = self.client.url_get('spec/vmware/types/ManagedResource')
            max_tags = result['properties']['tags']['maxItems']
        except Exception as e:
            LOG.error("Unable to read maximum tags. Reason: %s", e)
            max_tags = utils.MAX_TAGS
        return utils.TagLimits(scope_length, tag_length, max_tags)


class NsxLib(NsxLibBase):

    def init_api(self):
        self.port_mirror = core_resources.NsxLibPortMirror(
            self.client, self.nsxlib_config, nsxlib=self)
        self.bridge_endpoint = core_resources.NsxLibBridgeEndpoint(
            self.client, self.nsxlib_config, nsxlib=self)
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

        # Update tag limits
        self.tag_limits = self.get_tag_limits()
        utils.update_tag_limits(self.tag_limits)

    @property
    def keepalive_section(self):
        return 'transport-zones'

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
                version.LooseVersion(nsx_constants.NSX_VERSION_2_4_0)):
            # Features available since 2.4
            if (feature == nsx_constants.FEATURE_ENS_WITH_SEC):
                return True
            if (feature == nsx_constants.FEATURE_ICMP_STRICT):
                return True

        if (version.LooseVersion(self.get_version()) >=
                version.LooseVersion(nsx_constants.NSX_VERSION_2_3_0)):
            # Features available since 2.3
            if (feature == nsx_constants.FEATURE_ROUTER_ALLOCATION_PROFILE):
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


class NsxPolicyLib(NsxLibBase):

    def init_api(self):
        self.policy_api = policy_defs.NsxPolicyApi(self.client)
        self.domain = policy_resources.NsxPolicyDomainApi(self.policy_api)
        self.group = policy_resources.NsxPolicyGroupApi(self.policy_api)
        self.service = policy_resources.NsxPolicyL4ServiceApi(self.policy_api)
        self.icmp_service = policy_resources.NsxPolicyIcmpServiceApi(
            self.policy_api)
        self.ip_protocol_service = (
            policy_resources.NsxPolicyIPProtocolServiceApi(
                self.policy_api))
        self.tier0 = policy_resources.NsxPolicyTier0Api(self.policy_api)
        self.tier1 = policy_resources.NsxPolicyTier1Api(self.policy_api)
        self.tier1_segment = policy_resources.NsxPolicyTier1SegmentApi(
            self.policy_api)
        self.segment = policy_resources.NsxPolicySegmentApi(self.policy_api)
        self.segment_port = policy_resources.NsxPolicySegmentPortApi(
            self.policy_api)
        self.comm_map = policy_resources.NsxPolicyCommunicationMapApi(
            self.policy_api)
        self.enforcement_point = policy_resources.NsxPolicyEnforcementPointApi(
            self.policy_api)
        self.deployment_map = policy_resources.NsxPolicyDeploymentMapApi(
            self.policy_api)

    @property
    def keepalive_section(self):
        return 'infra'

    def get_version(self):
        """Get the NSX Policy manager version

        Currently the backend does not support it, so the nsx-manager api
        will be used temporarily.
        """
        if self.nsx_version:
            return self.nsx_version

        manager_client = client.NSX3Client(
            self.cluster,
            nsx_api_managers=self.nsxlib_config.nsx_api_managers,
            max_attempts=self.nsxlib_config.max_attempts,
            url_path_base=client.NSX3Client.NSX_V1_API_PREFIX,
            rate_limit_retry=self.nsxlib_config.rate_limit_retry)

        node = manager_client.get('node')
        self.nsx_version = node.get('node_version')
        return self.nsx_version

    def feature_supported(self, feature):
        if (version.LooseVersion(self.get_version()) >=
                version.LooseVersion(nsx_constants.NSX_VERSION_2_4_0)):
            # Features available since 2.4
            if (feature == nsx_constants.FEATURE_NSX_POLICY_NETWORKING):
                return True

        return (feature == nsx_constants.FEATURE_NSX_POLICY)

    @property
    def client_url_prefix(self):
        return client.NSX3Client.NSX_POLICY_V1_API_PREFIX
