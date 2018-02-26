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
from vmware_nsxlib.v3 import security
from vmware_nsxlib.v3 import trust_management
from vmware_nsxlib.v3 import utils

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

    def reinitialize_cluster(self, resource, event, trigger, **kwargs):
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
        return self.client.url_get(url)

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

    def _build_query(self, tags):
        try:
            return " AND ".join(['tags.scope:%(scope)s AND '
                                 'tags.tag:%(tag)s' % item for item in tags])
        except KeyError as e:
            reason = _('Missing key:%s in tags') % str(e)
            raise exceptions.NsxSearchInvalidQuery(reason=reason)


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
        self.relay_service = core_resources.NsxLibDhcpRelayService(
            self.client, self.nsxlib_config, nsxlib=self)
        self.native_dhcp_profile = core_resources.NsxLibDhcpProfile(
            self.client, self.nsxlib_config, nsxlib=self)
        self.native_md_proxy = core_resources.NsxLibMetadataProxy(
            self.client, self.nsxlib_config, nsxlib=self)
        self.firewall_section = security.NsxLibFirewallSection(
            self.client, self.nsxlib_config)
        self.ns_group = security.NsxLibNsGroup(
            self.client, self.nsxlib_config, self.firewall_section)
        self.native_dhcp = native_dhcp.NsxLibNativeDhcp(
            self.client, self.nsxlib_config)
        self.ip_block_subnet = core_resources.NsxLibIpBlockSubnet(
            self.client, self.nsxlib_config, nsxlib=self)
        self.ip_block = core_resources.NsxLibIpBlock(
            self.client, self.nsxlib_config, nsxlib=self)
        self.ip_set = security.NsxLibIPSet(
            self.client, self.nsxlib_config)
        self.logical_port = resources.LogicalPort(
            self.client, self.nsxlib_config)
        self.logical_router_port = resources.LogicalRouterPort(
            self.client, self.nsxlib_config)
        self.dhcp_server = resources.LogicalDhcpServer(
            self.client, self.nsxlib_config)
        self.ip_pool = resources.IpPool(
            self.client, self.nsxlib_config)
        self.load_balancer = load_balancer.LoadBalancer(
            self.client, self.nsxlib_config)
        self.trust_management = trust_management.NsxLibTrustManagement(
            self.client, self.nsxlib_config)
        self.http_services = resources.NodeHttpServiceProperties(
            self.client, self.nsxlib_config, nsxlib=self)

    @property
    def keepalive_section(self):
        return 'transport-zones'

    def get_version(self):
        if self.nsx_version:
            return self.nsx_version

        node = self.client.get("node")
        self.nsx_version = node.get('node_version')
        return self.nsx_version

    def feature_supported(self, feature):
        if (version.LooseVersion(self.get_version()) >=
            version.LooseVersion(nsx_constants.NSX_VERSION_2_2_0)):
            # Features available since 2.2
            if (feature == nsx_constants.FEATURE_VLAN_ROUTER_INTERFACE or
                feature == nsx_constants.FEATURE_RATE_LIMIT or
                feature == nsx_constants.FEATURE_ON_BEHALF_OF):
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
        self.comm_map = policy_resources.NsxPolicyCommunicationMapApi(
            self.policy_api)
        self.enforcement_point = policy_resources.NsxPolicyEnforcementPointApi(
            self.policy_api)
        self.deployment_map = policy_resources.NsxPolicyDeploymentMapApi(
            self.policy_api)

    @property
    def keepalive_section(self):
        return 'infra'

    def feature_supported(self, feature):
        return (feature == nsx_constants.FEATURE_NSX_POLICY)

    @property
    def client_url_prefix(self):
        return client.NSX3Client.NSX_POLICY_V1_API_PREFIX
