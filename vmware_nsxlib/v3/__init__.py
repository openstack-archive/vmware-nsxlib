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

from vmware_nsxlib._i18n import _, _LW
from vmware_nsxlib.v3 import client
from vmware_nsxlib.v3 import cluster
from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import native_dhcp
from vmware_nsxlib.v3 import nsx_constants
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

        # init the api object
        self.general_apis = utils.NsxLibApiBase(
            self.client, nsxlib_config)
        self.port_mirror = NsxLibPortMirror(
            self.client, nsxlib_config)
        self.bridge_endpoint = NsxLibBridgeEndpoint(
            self.client, nsxlib_config)
        self.logical_switch = NsxLibLogicalSwitch(
            self.client, nsxlib_config)
        self.logical_router = NsxLibLogicalRouter(
            self.client, nsxlib_config)
        self.qos_switching_profile = NsxLibQosSwitchingProfile(
            self.client, nsxlib_config)
        self.edge_cluster = NsxLibEdgeCluster(
            self.client, nsxlib_config)
        self.bridge_cluster = NsxLibBridgeCluster(
            self.client, nsxlib_config)
        self.transport_zone = NsxLibTransportZone(
            self.client, nsxlib_config)
        self.native_dhcp_profile = NsxLibDhcpProfile(
            self.client, nsxlib_config)
        self.native_md_proxy = NsxLibMetadataProxy(
            self.client, nsxlib_config)
        self.firewall_section = security.NsxLibFirewallSection(
            self.client, nsxlib_config)
        self.ns_group = security.NsxLibNsGroup(
            self.client, nsxlib_config, self.firewall_section)
        self.native_dhcp = native_dhcp.NsxLibNativeDhcp(
            self.client, nsxlib_config)
        self.ip_block_subnet = NsxLibIpBlockSubnet(
            self.client, nsxlib_config)
        self.ip_block = NsxLibIpBlock(
            self.client, nsxlib_config)
        self.ip_set = security.NsxLibIPSet(
            self.client, nsxlib_config)

        super(NsxLib, self).__init__()

    def get_version(self):
        node = self.client.get("node")
        version = node.get('node_version')
        return version

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
        query = resource_type
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


class NsxLibPortMirror(utils.NsxLibApiBase):

    def create_session(self, source_ports, dest_ports, direction,
                       description, name, tags):
        """Create a PortMirror Session on the backend.

        :param source_ports: List of UUIDs of the ports whose traffic is to be
                            mirrored.
        :param dest_ports: List of UUIDs of the ports where the mirrored
                          traffic is to be sent.
        :param direction: String representing the direction of traffic to be
                          mirrored. [INGRESS, EGRESS, BIDIRECTIONAL]
        :param description: String representing the description of the session.
        :param name: String representing the name of the session.
        :param tags: nsx backend specific tags.
        """

        resource = 'mirror-sessions'
        body = {'direction': direction,
                'tags': tags,
                'display_name': name,
                'description': description,
                'mirror_sources': source_ports,
                'mirror_destination': dest_ports}
        return self.client.create(resource, body)

    def delete_session(self, mirror_session_id):
        """Delete a PortMirror session on the backend.

        :param mirror_session_id: string representing the UUID of the port
                                  mirror session to be deleted.
        """
        resource = 'mirror-sessions/%s' % mirror_session_id
        self.client.delete(resource)


class NsxLibBridgeEndpoint(utils.NsxLibApiBase):

    def create(self, device_name, seg_id, tags):
        """Create a bridge endpoint on the backend.

        Create a bridge endpoint resource on a bridge cluster for the L2
        gateway network connection.
        :param device_name: device_name actually refers to the bridge cluster's
                            UUID.
        :param seg_id: integer representing the VLAN segmentation ID.
        :param tags: nsx backend specific tags.
        """
        resource = 'bridge-endpoints'
        body = {'bridge_cluster_id': device_name,
                'tags': tags,
                'vlan': seg_id}
        return self.client.create(resource, body)

    def delete(self, bridge_endpoint_id):
        """Delete a bridge endpoint on the backend.

        :param bridge_endpoint_id: string representing the UUID of the bridge
                                   endpoint to be deleted.
        """
        resource = 'bridge-endpoints/%s' % bridge_endpoint_id
        self.client.delete(resource)


class NsxLibLogicalSwitch(utils.NsxLibApiBase):

    def create(self, display_name, transport_zone_id, tags,
               replication_mode=nsx_constants.MTEP,
               admin_state=True, vlan_id=None, ip_pool_id=None,
               mac_pool_id=None):
        # TODO(salv-orlando): Validate Replication mode and admin_state
        # NOTE: These checks might be moved to the API client library if one
        # that performs such checks in the client is available

        resource = 'logical-switches'
        body = {'transport_zone_id': transport_zone_id,
                'replication_mode': replication_mode,
                'display_name': display_name,
                'tags': tags}

        if admin_state:
            body['admin_state'] = nsx_constants.ADMIN_STATE_UP
        else:
            body['admin_state'] = nsx_constants.ADMIN_STATE_DOWN

        if vlan_id:
            body['vlan'] = vlan_id

        if ip_pool_id:
            body['ip_pool_id'] = ip_pool_id

        if mac_pool_id:
            body['mac_pool_id'] = mac_pool_id

        return self.client.create(resource, body)

    def delete(self, lswitch_id):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self.nsxlib_config.max_attempts)
        def _do_delete():
            resource = ('logical-switches/%s?detach=true&cascade=true' %
                        lswitch_id)
            self.client.delete(resource)

        _do_delete()

    def get(self, logical_switch_id):
        resource = "logical-switches/%s" % logical_switch_id
        return self.client.get(resource)

    def update(self, lswitch_id, name=None, admin_state=None, tags=None):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self.nsxlib_config.max_attempts)
        def _do_update():
            resource = "logical-switches/%s" % lswitch_id
            lswitch = self.get(lswitch_id)
            # Assign name to a local variable since 'name' is out of scope
            ls_name = name or lswitch.get('display_name')
            lswitch['display_name'] = ls_name
            if admin_state is not None:
                if admin_state:
                    lswitch['admin_state'] = nsx_constants.ADMIN_STATE_UP
                else:
                    lswitch['admin_state'] = nsx_constants.ADMIN_STATE_DOWN
            if tags is not None:
                lswitch['tags'] = tags
            return self.client.update(resource, lswitch)

        return _do_update()


class NsxLibQosSwitchingProfile(utils.NsxLibApiBase):

    def _build_args(self, tags, name=None, description=None):
        body = {"resource_type": "QosSwitchingProfile",
                "tags": tags}
        return self._update_args(
            body, name=name, description=description)

    def _update_args(self, body, name=None, description=None):
        if name:
            body["display_name"] = name
        if description:
            body["description"] = description
        return body

    def _get_resource_type(self, direction):
        if direction == nsx_constants.EGRESS:
            return nsx_constants.EGRESS_SHAPING
        return nsx_constants.INGRESS_SHAPING

    def _enable_shaping_in_args(self, body, burst_size=None,
                                peak_bandwidth=None, average_bandwidth=None,
                                direction=None):
        resource_type = self._get_resource_type(direction)
        for shaper in body["shaper_configuration"]:
            if shaper["resource_type"] == resource_type:
                shaper["enabled"] = True
                if burst_size is not None:
                    shaper["burst_size_bytes"] = burst_size
                if peak_bandwidth is not None:
                    shaper["peak_bandwidth_mbps"] = peak_bandwidth
                if average_bandwidth is not None:
                    shaper["average_bandwidth_mbps"] = average_bandwidth
                break

        return body

    def _disable_shaping_in_args(self, body, direction=None):
        resource_type = self._get_resource_type(direction)
        for shaper in body["shaper_configuration"]:
            if shaper["resource_type"] == resource_type:
                shaper["enabled"] = False
                shaper["burst_size_bytes"] = 0
                shaper["peak_bandwidth_mbps"] = 0
                shaper["average_bandwidth_mbps"] = 0
                break

        return body

    def _update_dscp_in_args(self, body, qos_marking, dscp):
        body["dscp"] = {}
        body["dscp"]["mode"] = qos_marking.upper()
        if dscp:
            body["dscp"]["priority"] = dscp

        return body

    def create(self, tags, name=None, description=None):
        resource = 'switching-profiles'
        body = self._build_args(tags, name, description)
        return self.client.create(resource, body)

    def update(self, profile_id, tags, name=None, description=None):
        resource = 'switching-profiles/%s' % profile_id
        # get the current configuration
        body = self.get(profile_id)
        # update the relevant fields
        body = self._update_args(body, name, description)
        return self._update_resource_with_retry(resource, body)

    def update_shaping(self, profile_id,
                       shaping_enabled=False,
                       burst_size=None,
                       peak_bandwidth=None,
                       average_bandwidth=None,
                       qos_marking=None, dscp=None,
                       direction=nsx_constants.INGRESS):
        resource = 'switching-profiles/%s' % profile_id
        # get the current configuration
        body = self.get(profile_id)
        # update the relevant fields
        if shaping_enabled:
            body = self._enable_shaping_in_args(
                body, burst_size=burst_size,
                peak_bandwidth=peak_bandwidth,
                average_bandwidth=average_bandwidth,
                direction=direction)
        else:
            body = self._disable_shaping_in_args(body, direction=direction)
        body = self._update_dscp_in_args(body, qos_marking, dscp)
        return self._update_resource_with_retry(resource, body)

    def get(self, profile_id):
        resource = 'switching-profiles/%s' % profile_id
        return self.client.get(resource)

    def list(self):
        resource = 'switching-profiles'
        return self.client.list(resource)

    def delete(self, profile_id):
        resource = 'switching-profiles/%s' % profile_id
        self.client.delete(resource)


class NsxLibLogicalRouter(utils.NsxLibApiBase):

    def _delete_resource_by_values(self, resource,
                                   skip_not_found=True, **kwargs):
        resources_get = self.client.get(resource)
        matched_num = 0
        for res in resources_get['results']:
            if utils.dict_match(kwargs, res):
                LOG.debug("Deleting %s from resource %s", res, resource)
                delete_resource = resource + "/" + str(res['id'])
                self.client.delete(delete_resource)
                matched_num = matched_num + 1
        if matched_num == 0:
            if skip_not_found:
                LOG.warning(_LW("No resource in %(res)s matched for values: "
                                "%(values)s"), {'res': resource,
                                                'values': kwargs})
            else:
                err_msg = (_("No resource in %(res)s matched for values: "
                             "%(values)s") % {'res': resource,
                                              'values': kwargs})
                raise exceptions.ResourceNotFound(
                    manager=self.cluster.nsx_api_managers,
                    operation=err_msg)
        elif matched_num > 1:
            LOG.warning(_LW("%(num)s resources in %(res)s matched for values: "
                            "%(values)s"), {'num': matched_num,
                                            'res': resource,
                                            'values': kwargs})

    def add_nat_rule(self, logical_router_id, action, translated_network,
                     source_net=None, dest_net=None,
                     enabled=True, rule_priority=None,
                     match_ports=None, match_protocol=None,
                     match_resource_type=None):
        resource = 'logical-routers/%s/nat/rules' % logical_router_id
        body = {'action': action,
                'enabled': enabled,
                'translated_network': translated_network}
        if source_net:
            body['match_source_network'] = source_net
        if dest_net:
            body['match_destination_network'] = dest_net
        if rule_priority:
            body['rule_priority'] = rule_priority
        if match_ports:
            body['match_service'] = {
                'resource_type': (match_resource_type or
                                  nsx_constants.L4_PORT_SET_NSSERVICE),
                'destination_ports': match_ports,
                'l4_protocol': match_protocol or nsx_constants.TCP}
        return self.client.create(resource, body)

    def add_static_route(self, logical_router_id, dest_cidr, nexthop):
        resource = ('logical-routers/%s/routing/static-routes' %
                    logical_router_id)
        body = {}
        if dest_cidr:
            body['network'] = dest_cidr
        if nexthop:
            body['next_hops'] = [{"ip_address": nexthop}]
        return self.client.create(resource, body)

    def delete_static_route(self, logical_router_id, static_route_id):
        resource = 'logical-routers/%s/routing/static-routes/%s' % (
            logical_router_id, static_route_id)
        self.client.delete(resource)

    def delete_static_route_by_values(self, logical_router_id,
                                      dest_cidr=None, nexthop=None):
        resource = ('logical-routers/%s/routing/static-routes' %
                    logical_router_id)
        kwargs = {}
        if dest_cidr:
            kwargs['network'] = dest_cidr
        if nexthop:
            kwargs['next_hops'] = [{"ip_address": nexthop}]
        return self._delete_resource_by_values(resource, **kwargs)

    def delete_nat_rule(self, logical_router_id, nat_rule_id):
        resource = 'logical-routers/%s/nat/rules/%s' % (logical_router_id,
                                                        nat_rule_id)
        self.client.delete(resource)

    def delete_nat_rule_by_values(self, logical_router_id, **kwargs):
        resource = 'logical-routers/%s/nat/rules' % logical_router_id
        return self._delete_resource_by_values(resource, **kwargs)

    def update_advertisement(self, logical_router_id, **kwargs):
        resource = ('logical-routers/%s/routing/advertisement' %
                    logical_router_id)
        return self._update_resource_with_retry(resource, kwargs)

    def get_id_by_name_or_id(self, name_or_id):
        """Get a logical router by it's display name or uuid

        Return the logical router data, or raise an exception if not found or
        not unique
        """

        return self._get_resource_by_name_or_id(name_or_id,
                                                'logical-routers')


class NsxLibEdgeCluster(utils.NsxLibApiBase):

    def get(self, edge_cluster_uuid):
        resource = "edge-clusters/%s" % edge_cluster_uuid
        return self.client.get(resource)


class NsxLibTransportZone(utils.NsxLibApiBase):

    def get_id_by_name_or_id(self, name_or_id):
        """Get a transport zone by it's display name or uuid

        Return the transport zone data, or raise an exception if not found or
        not unique
        """

        return self._get_resource_by_name_or_id(name_or_id,
                                                'transport-zones')


class NsxLibDhcpProfile(utils.NsxLibApiBase):

    def get_id_by_name_or_id(self, name_or_id):
        """Get a dhcp profile by it's display name or uuid

        Return the dhcp profile data, or raise an exception if not found or
        not unique
        """

        return self._get_resource_by_name_or_id(name_or_id,
                                                'dhcp/server-profiles')


class NsxLibMetadataProxy(utils.NsxLibApiBase):

    def get_id_by_name_or_id(self, name_or_id):
        """Get a metadata proxy by it's display name or uuid

        Return the metadata proxy data, or raise an exception if not found or
        not unique
        """

        return self._get_resource_by_name_or_id(name_or_id,
                                                'md-proxies')


class NsxLibBridgeCluster(utils.NsxLibApiBase):

    def get_id_by_name_or_id(self, name_or_id):
        """Get a bridge cluster by it's display name or uuid

        Return the bridge cluster data, or raise an exception if not found or
        not unique
        """

        return self._get_resource_by_name_or_id(name_or_id,
                                                'bridge-clusters')


class NsxLibIpBlockSubnet(utils.NsxLibApiBase):

    def create(self, ip_block_id, subnet_size):
        """Create a IP block subnet on the backend."""
        resource = 'pools/ip-subnets'
        body = {'size': subnet_size,
                'block_id': ip_block_id}
        return self.client.create(resource, body)

    def delete(self, subnet_id):
        """Delete a IP block subnet on the backend."""
        resource = 'pools/ip-subnets/%s' % subnet_id
        self.client.delete(resource)

    def list(self, ip_block_id):
        resource = 'pools/ip-subnets?block_id=%s' % ip_block_id
        return self.client.get(resource)


class NsxLibIpBlock(utils.NsxLibApiBase):
    def list(self):
        return self.client.get('pools/ip-blocks')
