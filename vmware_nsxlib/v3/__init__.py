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

from oslo_log import log

from vmware_nsxlib._i18n import _
from vmware_nsxlib.v3 import client
from vmware_nsxlib.v3 import cluster
from vmware_nsxlib.v3 import core_resources
from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import native_dhcp
from vmware_nsxlib.v3 import security
from vmware_nsxlib.v3 import utils

LOG = log.getLogger(__name__)


class NsxLib(object):

    def __init__(self, nsxlib_config):

        self.nsxlib_config = nsxlib_config

        # create the Cluster
        self.cluster = cluster.NSXClusteredAPI(nsxlib_config)

        # create the Client
        self.client = client.NSX3Client(
            self.cluster,
            nsx_api_managers=nsxlib_config.nsx_api_managers,
            max_attempts=nsxlib_config.max_attempts)

        self.general_apis = utils.NsxLibApiBase(
            self.client, nsxlib_config)
        if nsxlib_config.purpose == 'core':
            self._init_core_api(nsxlib_config)
        elif nsxlib_config.purpose == 'policy':
            self._init_policy_api(nsxlib_config)
        else:
            raise exceptions.UnknownPurpose(purpose=nsxlib_config.purpose)

        super(NsxLib, self).__init__()

    def get_version(self):
        node = self.client.get("node")
        version = node.get('node_version')
        return version

    def _init_core_api(self, nsxlib_config):
        self.port_mirror = core_resources.NsxLibPortMirror(
            self.client, nsxlib_config)
        self.bridge_endpoint = core_resources.NsxLibBridgeEndpoint(
            self.client, nsxlib_config)
        self.logical_switch = core_resources.NsxLibLogicalSwitch(
            self.client, nsxlib_config)
        self.logical_router = core_resources.NsxLibLogicalRouter(
            self.client, nsxlib_config)
        self.qos_switching_profile = core_resources.NsxLibQosSwitchingProfile(
            self.client, nsxlib_config)
        self.edge_cluster = core_resources.NsxLibEdgeCluster(
            self.client, nsxlib_config)
        self.bridge_cluster = core_resources.NsxLibBridgeCluster(
            self.client, nsxlib_config)
        self.transport_zone = core_resources.NsxLibTransportZone(
            self.client, nsxlib_config)
        self.native_dhcp_profile = core_resources.NsxLibDhcpProfile(
            self.client, nsxlib_config)
        self.native_md_proxy = core_resources.NsxLibMetadataProxy(
            self.client, nsxlib_config)
        self.firewall_section = security.NsxLibFirewallSection(
            self.client, nsxlib_config)
        self.ns_group = security.NsxLibNsGroup(
            self.client, nsxlib_config, self.firewall_section)
        self.native_dhcp = native_dhcp.NsxLibNativeDhcp(
            self.client, nsxlib_config)
        self.ip_block_subnet = core_resources.NsxLibIpBlockSubnet(
            self.client, nsxlib_config)
        self.ip_block = core_resources.NsxLibIpBlock(
            self.client, nsxlib_config)
        self.ip_set = security.NsxLibIPSet(
            self.client, nsxlib_config)

    def _init_policy_api(self, nsxlib_config):
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
    def search_by_tags(self, tags, resource_type=None):
        """Return the list of resources searched based on tags.

        Currently the query only supports AND boolean operator.
        :param tags: List of dictionaries containing tags. Each
                     NSX tag dictionary is of the form:
                     {'scope': <scope_key>, 'tag': <tag_value>}
        :param resource_type: Optional string parameter to limit the
                              scope of the search to the given ResourceType.
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
        return self.client.url_get(url)

    def _build_query(self, tags):
        try:
            return " AND ".join(['tags.scope:%(scope)s AND '
                                 'tags.tag:%(tag)s' % item for item in tags])
        except KeyError as e:
            reason = _('Missing key:%s in tags') % str(e)
            raise exceptions.NsxSearchInvalidQuery(reason=reason)
