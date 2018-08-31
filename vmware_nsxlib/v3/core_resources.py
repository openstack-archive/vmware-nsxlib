# Copyright 2017 VMware, Inc.
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

import collections

from oslo_log import log
from oslo_log import versionutils

from vmware_nsxlib._i18n import _
from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import utils

LOG = log.getLogger(__name__)

SwitchingProfileTypeId = collections.namedtuple(
    'SwitchingProfileTypeId', 'profile_type, profile_id')

PacketAddressClassifier = collections.namedtuple(
    'PacketAddressClassifier', 'ip_address, mac_address, vlan')


class NsxLibPortMirror(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'mirror-sessions'

    @property
    def resource_type(self):
        return 'PortMirroringSession'

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

        body = {'direction': direction,
                'tags': tags,
                'display_name': name,
                'description': description,
                'mirror_sources': source_ports,
                'mirror_destination': dest_ports}
        return self.client.create(self.get_path(), body)

    def delete_session(self, mirror_session_id):
        """Delete a PortMirror session on the backend.

        :param mirror_session_id: string representing the UUID of the port
                                  mirror session to be deleted.
        """
        self.client.delete(self.get_path(mirror_session_id))


class NsxLibBridgeEndpoint(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'bridge-endpoints'

    @property
    def resource_type(self):
        return 'BridgeEndpoint'

    def create(self, device_name, seg_id, tags):
        """Create a bridge endpoint on the backend.

        Create a bridge endpoint resource on a bridge cluster for the L2
        gateway network connection.
        :param device_name: device_name actually refers to the bridge cluster's
                            UUID.
        :param seg_id: integer representing the VLAN segmentation ID.
        :param tags: nsx backend specific tags.
        """
        body = {'bridge_cluster_id': device_name,
                'tags': tags,
                'vlan': seg_id}
        return self.client.create(self.get_path(), body)

    def delete(self, bridge_endpoint_id):
        """Delete a bridge endpoint on the backend.

        :param bridge_endpoint_id: string representing the UUID of the bridge
                                   endpoint to be deleted.
        """
        self.client.delete(self.get_path(bridge_endpoint_id))


class NsxLibLogicalSwitch(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'logical-switches'

    @property
    def resource_type(self):
        return 'LogicalSwitch'

    def create(self, display_name, transport_zone_id, tags,
               replication_mode=nsx_constants.MTEP,
               admin_state=True, vlan_id=None, ip_pool_id=None,
               mac_pool_id=None, description=None,
               trunk_vlan_range=None):
        operation = "Create logical switch"
        if display_name:
            display_name = utils.escape_display_name(display_name)
        # TODO(salv-orlando): Validate Replication mode and admin_state
        # NOTE: These checks might be moved to the API client library if one
        # that performs such checks in the client is available
        body = {'transport_zone_id': transport_zone_id,
                'replication_mode': replication_mode,
                'display_name': display_name,
                'tags': tags}

        if admin_state:
            body['admin_state'] = nsx_constants.ADMIN_STATE_UP
        else:
            body['admin_state'] = nsx_constants.ADMIN_STATE_DOWN

        if trunk_vlan_range:
            failed = False
            if (self.nsxlib and
                self.nsxlib.feature_supported(
                    nsx_constants.FEATURE_TRUNK_VLAN)):
                if vlan_id is not None:
                    failed = True
                    LOG.error("Failed to create logical switch %(name)s with "
                              "trunk vlan: vlan id %(vlan)s is used.",
                              {'name': display_name, 'vlan': vlan_id})
                elif (len(trunk_vlan_range) != 2 or
                      trunk_vlan_range[0] > trunk_vlan_range[1]):
                    failed = True
                    LOG.error("Failed to create logical switch %(name)s with "
                              "trunk vlan: illegal range (%(trunk)s) is used.",
                              {'name': display_name,
                               'trunk': trunk_vlan_range})
                else:
                    body['vlan_trunk_spec'] = {'vlan_ranges': [
                        {'start': trunk_vlan_range[0],
                         'end': trunk_vlan_range[1]}]}
            else:
                LOG.error("Failed to create logical switch %s with trunk "
                          "vlan: this feature is not supported.", display_name)
                failed = True
            if failed:
                raise exceptions.InvalidInput(
                    operation=operation,
                    arg_val=trunk_vlan_range,
                    arg_name='trunk_vlan_range')
        elif vlan_id:
            body['vlan'] = vlan_id

        if ip_pool_id:
            body['ip_pool_id'] = ip_pool_id

        if mac_pool_id:
            body['mac_pool_id'] = mac_pool_id

        if description is not None:
            body['description'] = description

        return self.client.create(self.get_path(), body)

    def delete(self, lswitch_id):
        resource = '%s?detach=true&cascade=true' % lswitch_id
        self._delete_with_retry(resource)

    def update(self, lswitch_id, name=None, admin_state=None, tags=None,
               description=None):
        body = {}
        if name:
            name = utils.escape_display_name(name)
            body['display_name'] = name
        if admin_state is not None:
            if admin_state:
                body['admin_state'] = nsx_constants.ADMIN_STATE_UP
            else:
                body['admin_state'] = nsx_constants.ADMIN_STATE_DOWN
        if tags is not None:
            body['tags'] = tags
        if description is not None:
            body['description'] = description
        return self._update_with_retry(lswitch_id, body)


class SwitchingProfileTypes(object):
    IP_DISCOVERY = 'IpDiscoverySwitchingProfile'
    MAC_LEARNING = 'MacManagementSwitchingProfile'
    PORT_MIRRORING = 'PortMirroringSwitchingProfile'
    QOS = 'QosSwitchingProfile'
    SPOOF_GUARD = 'SpoofGuardSwitchingProfile'
    SWITCH_SECURITY = 'SwitchSecuritySwitchingProfile'


class WhiteListAddressTypes(object):
    PORT = 'LPORT_BINDINGS'
    SWITCH = 'LSWITCH_BINDINGS'


class NsxLibSwitchingProfile(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'switching-profiles'

    def list(self):
        return self.client.list(
            self.get_path('?include_system_owned=True'))

    def create(self, profile_type, display_name=None,
               description=None, **api_args):
        body = {
            'resource_type': profile_type,
            'display_name': display_name or '',
            'description': description or ''
        }
        body.update(api_args)

        return self.client.create(self.get_path(), body=body)

    def update(self, uuid, profile_type, **api_args):
        body = {
            'resource_type': profile_type
        }
        body.update(api_args)

        return self.client.update(self.get_path(uuid), body=body)

    def create_spoofguard_profile(self, display_name,
                                  description,
                                  whitelist_ports=False,
                                  whitelist_switches=False,
                                  tags=None):
        whitelist_providers = []
        if whitelist_ports:
            whitelist_providers.append(WhiteListAddressTypes.PORT)
        if whitelist_switches:
            whitelist_providers.append(WhiteListAddressTypes.SWITCH)

        return self.create(SwitchingProfileTypes.SPOOF_GUARD,
                           display_name=display_name,
                           description=description,
                           white_list_providers=whitelist_providers,
                           tags=tags or [])

    def create_dhcp_profile(self, display_name,
                            description, tags=None):
        dhcp_filter = {
            'client_block_enabled': True,
            'server_block_enabled': False
        }
        rate_limits = {
            'enabled': False,
            'rx_broadcast': 0,
            'tx_broadcast': 0,
            'rx_multicast': 0,
            'tx_multicast': 0
        }
        bpdu_filter = {
            'enabled': True,
            'white_list': []
        }
        return self.create(SwitchingProfileTypes.SWITCH_SECURITY,
                           display_name=display_name,
                           description=description,
                           tags=tags or [],
                           dhcp_filter=dhcp_filter,
                           rate_limits=rate_limits,
                           bpdu_filter=bpdu_filter,
                           block_non_ip_traffic=True)

    def create_mac_learning_profile(self, display_name,
                                    description, tags=None):
        mac_learning = {
            'enabled': True,
        }
        return self.create(SwitchingProfileTypes.MAC_LEARNING,
                           display_name=display_name,
                           description=description,
                           tags=tags or [],
                           mac_learning=mac_learning,
                           mac_change_allowed=True)

    def create_port_mirror_profile(self, display_name, description,
                                   direction, destinations, tags=None):
        return self.create(SwitchingProfileTypes.PORT_MIRRORING,
                           display_name=display_name,
                           description=description,
                           tags=tags or [],
                           direction=direction,
                           destinations=destinations)

    @classmethod
    def build_switch_profile_ids(cls, client, *profiles):
        ids = []
        for profile in profiles:
            if isinstance(profile, str):
                profile = client.get(profile)
            if not isinstance(profile, SwitchingProfileTypeId):
                profile = SwitchingProfileTypeId(
                    profile.get('key', profile.get('resource_type')),
                    profile.get('value', profile.get('id')))
            ids.append(profile)
        return ids


class NsxLibQosSwitchingProfile(NsxLibSwitchingProfile):

    @property
    def resource_type(self):
        return 'QosSwitchingProfile'

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
        body = self._build_args(tags, name, description)
        return self.client.create(self.get_path(), body)

    def update(self, profile_id, tags, name=None, description=None):
        # update the relevant fields
        body = {}
        body = self._update_args(body, name, description)
        if tags is not None:
            body['tags'] = tags
        return self._update_with_retry(profile_id, body)

    def update_shaping(self, profile_id,
                       shaping_enabled=False,
                       burst_size=None,
                       peak_bandwidth=None,
                       average_bandwidth=None,
                       qos_marking=None, dscp=None,
                       direction=nsx_constants.INGRESS):
        versionutils.report_deprecated_feature(
            LOG,
            'NsxLibQosSwitchingProfile.update_shaping is deprecated. '
            'Please use set_profile_shaping instead.')
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
        return self._update_with_retry(profile_id, body)

    def set_profile_shaping(self, profile_id,
                            ingress_bw_enabled=False,
                            ingress_burst_size=None,
                            ingress_peak_bandwidth=None,
                            ingress_average_bandwidth=None,
                            egress_bw_enabled=False,
                            egress_burst_size=None,
                            egress_peak_bandwidth=None,
                            egress_average_bandwidth=None,
                            qos_marking='trusted', dscp=None):
        """Set all shaping parameters in the QoS switch profile"""
        # get the current configuration
        body = self.get(profile_id)

        # update the ingress shaping
        if ingress_bw_enabled:
            body = self._enable_shaping_in_args(
                body, burst_size=ingress_burst_size,
                peak_bandwidth=ingress_peak_bandwidth,
                average_bandwidth=ingress_average_bandwidth,
                direction=nsx_constants.INGRESS)
        else:
            body = self._disable_shaping_in_args(
                body, direction=nsx_constants.INGRESS)

        # update the egress shaping
        if egress_bw_enabled:
            body = self._enable_shaping_in_args(
                body, burst_size=egress_burst_size,
                peak_bandwidth=egress_peak_bandwidth,
                average_bandwidth=egress_average_bandwidth,
                direction=nsx_constants.EGRESS)
        else:
            body = self._disable_shaping_in_args(
                body, direction=nsx_constants.EGRESS)

        # update dscp marking
        body = self._update_dscp_in_args(body, qos_marking, dscp)

        # update the profile in the backend
        return self._update_with_retry(profile_id, body)


class NsxLibLogicalRouter(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'logical-routers'

    @property
    def resource_type(self):
        return 'LogicalRouter'

    def _delete_resource_by_values(self, resource,
                                   skip_not_found=True,
                                   strict_mode=True,
                                   **kwargs):
        """Delete resource objects matching the values in kwargs

        If skip_not_found is True - do not raise an exception if no object was
        found.
        If strict_mode is True - warnings will be issued if 0 or >1 objects
        where deleted.
        """
        resources_list = self.client.list(resource)
        matched_num = 0
        for res in resources_list['results']:
            if utils.dict_match(kwargs, res):
                LOG.debug("Deleting %s from resource %s", res, resource)
                delete_resource = resource + "/" + str(res['id'])
                self.client.delete(delete_resource)
                matched_num = matched_num + 1
        if matched_num == 0:
            if skip_not_found:
                if strict_mode:
                    LOG.warning("No resource in %(res)s matched for values: "
                                "%(values)s", {'res': resource,
                                               'values': kwargs})
            else:
                err_msg = (_("No resource in %(res)s matched for values: "
                             "%(values)s") % {'res': resource,
                                              'values': kwargs})
                raise exceptions.ResourceNotFound(
                    manager=self.client.nsx_api_managers,
                    operation=err_msg)
        elif matched_num > 1 and strict_mode:
            LOG.warning("%(num)s resources in %(res)s matched for values: "
                        "%(values)s", {'num': matched_num,
                                       'res': resource,
                                       'values': kwargs})

    def _validate_nat_rule_action(self, action):
        if not action:
            return
        if action in ['SNAT', 'DNAT', 'NO_NAT', 'REFLEXIVE']:
            # legal values for all NSX versions
            return
        if (action not in ['NO_SNAT', 'NO_DNAT'] or (
            self.nsxlib and not self.nsxlib.feature_supported(
                nsx_constants.FEATURE_NO_DNAT_NO_SNAT))):
            raise exceptions.InvalidInput(
                operation="Create/Update NAT rule",
                arg_val=action,
                arg_name='action')

    def add_nat_rule(self, logical_router_id, action, translated_network,
                     source_net=None, dest_net=None,
                     enabled=True, rule_priority=None,
                     match_ports=None, match_protocol=None,
                     match_resource_type=None,
                     bypass_firewall=True,
                     tags=None,
                     display_name=None):
        self._validate_nat_rule_action(action)
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

        # nat_pass parameter is supported with the router firewall feature
        if (self.nsxlib and
            self.nsxlib.feature_supported(
                nsx_constants.FEATURE_ROUTER_FIREWALL)):
            body['nat_pass'] = bypass_firewall
        elif not bypass_firewall:
            LOG.error("Ignoring bypass_firewall for router %s nat rule: "
                      "this feature is not supported.", logical_router_id)
        if tags is not None:
            body['tags'] = tags
        if display_name:
            body['display_name'] = display_name
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

    def delete_nat_rule_by_values(self, logical_router_id,
                                  strict_mode=True,
                                  skip_not_found=True,
                                  **kwargs):
        resource = 'logical-routers/%s/nat/rules' % logical_router_id
        return self._delete_resource_by_values(
            resource,
            skip_not_found=skip_not_found,
            strict_mode=strict_mode,
            **kwargs)

    def list_nat_rules(self, logical_router_id):
        resource = 'logical-routers/%s/nat/rules' % logical_router_id
        return self.client.list(resource)

    def update_nat_rule(self, logical_router_id, nat_rule_id, **kwargs):
        if 'action' in kwargs:
            self._validate_nat_rule_action(kwargs['action'])
        resource = 'logical-routers/%s/nat/rules/%s' % (
            logical_router_id, nat_rule_id)
        return self._update_resource(resource, kwargs, retry=True)

    def update_advertisement(self, logical_router_id, **kwargs):
        resource = ('logical-routers/%s/routing/advertisement' %
                    logical_router_id)
        # ignore load balancing flags if lb is the not supported
        if (self.nsxlib and
            not self.nsxlib.feature_supported(
                nsx_constants.FEATURE_LOAD_BALANCER)):
            for arg in ('advertise_lb_vip', 'advertise_lb_snat_ip'):
                if kwargs[arg]:
                    LOG.error("Ignoring %(arg)s for router %(rtr)s "
                              "update_advertisement: This feature is not "
                              "supported.",
                              {'arg': arg, 'rtr': logical_router_id})
                del kwargs[arg]

        return self._update_resource(resource, kwargs, retry=True)

    def update_advertisement_rules(self, logical_router_id, rules):
        resource = ('logical-routers/%s/routing/advertisement/rules' %
                    logical_router_id)
        return self._update_resource(resource, {'rules': rules}, retry=True)

    def get_advertisement_rules(self, logical_router_id):
        resource = ('logical-routers/%s/routing/advertisement/rules' %
                    logical_router_id)
        return self.client.get(resource)

    def get_debug_info(self, logical_router_id):
        resource = ('logical-routers/%s/debug-info?format=text' %
                    logical_router_id)
        return self.client.get(resource)

    def get_transportzone_id(self, logical_router_id):
        res = self.get_debug_info(logical_router_id)
        for item in res['componentInfo']:
            if item['componentType'] == nsx_constants.ROUTER_TYPE_TIER0_DR:
                if item['transportZoneId']:
                    return item['transportZoneId'][0]
        LOG.warning('OverlayTransportZone is not yet available on'
                    ' %s.' % (logical_router_id))

    def create(self, display_name, tags, edge_cluster_uuid=None, tier_0=False,
               description=None, transport_zone_id=None, allocation_pool=None):
        # TODO(salv-orlando): If possible do not manage edge clusters
        # in the main plugin logic.
        router_type = (nsx_constants.ROUTER_TYPE_TIER0 if tier_0 else
                       nsx_constants.ROUTER_TYPE_TIER1)
        body = {'display_name': display_name,
                'router_type': router_type,
                'tags': tags}
        if edge_cluster_uuid:
            body['edge_cluster_id'] = edge_cluster_uuid
        if description:
            body['description'] = description
        if transport_zone_id:
            body['advanced_config'] = {
                'transport_zone_id': transport_zone_id}
        if allocation_pool:
            body['allocation_profile'] = {
                'allocation_pool': allocation_pool}
        return self.client.create(self.get_path(), body=body)

    def delete(self, lrouter_id, force=False):
        url = lrouter_id
        if force:
            url += '?force=%s' % force
        return self.client.delete(self.get_path(url))

    def update(self, lrouter_id, *args, **kwargs):
        body = {}
        for arg in kwargs:
            # special care for transport_zone_id
            if arg == 'transport_zone_id':
                body['advanced_config'] = {
                    'transport_zone_id': kwargs['transport_zone_id']}
            else:
                body[arg] = kwargs[arg]

        return self._update_with_retry(lrouter_id, body)

    def get_firewall_section_id(self, lrouter_id, router_body=None):
        """Return the id of the auto created firewall section of the router

        If the router was already retrieved from the backend it is possible
        to give it as an input to avoid another backend call.
        """
        if not router_body:
            router_body = self.get(lrouter_id)
        if 'firewall_sections' in router_body:
            firewall_sections = router_body['firewall_sections']
            for sec in firewall_sections:
                if (sec.get('is_valid') and
                    sec.get('target_type') == "FirewallSection"):
                    return firewall_sections[0].get('target_id')

    def list(self, router_type=None):
        """List all/by type logical routers."""
        if router_type:
            resource = '%s?router_type=%s' % (self.get_path(), router_type)
        else:
            resource = self.get_path()
        return self.client.list(resource)


class NsxLibEdgeCluster(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'edge-clusters'

    @property
    def resource_type(self):
        return 'EdgeCluster'

    def get_transport_nodes(self, uuid):
        ec = self.get(uuid)
        members = []
        for member in ec.get('members', []):
            members.append(member.get('transport_node_id'))
        return members


class NsxLibTransportZone(utils.NsxLibApiBase):

    TRANSPORT_TYPE_VLAN = 'VLAN'
    TRANSPORT_TYPE_OVERLAY = 'OVERLAY'
    HOST_SWITCH_MODE_ENS = 'ENS'
    HOST_SWITCH_MODE_STANDARD = 'STANDARD'

    @property
    def uri_segment(self):
        return 'transport-zones'

    @property
    def resource_type(self):
        return 'TransportZone'

    @property
    def use_cache_for_get(self):
        return True

    def get_transport_type(self, uuid):
        tz = self.get(uuid)
        return tz['transport_type']

    def get_host_switch_mode(self, uuid):
        tz = self.get(uuid)
        return tz.get('host_switch_mode', self.HOST_SWITCH_MODE_STANDARD)


class NsxLibTransportNode(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'transport-nodes'

    @property
    def resource_type(self):
        return 'TransportNode'

    @property
    def use_cache_for_get(self):
        return True

    def get_transport_zones(self, uuid):
        tz = self.get(uuid)
        return [ep.get('transport_zone_id') for ep in
                tz.get('transport_zone_endpoints', [])]


class NsxLibDhcpProfile(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'dhcp/server-profiles'

    @property
    def resource_type(self):
        return 'DhcpProfile'


class NsxLibDhcpRelayService(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'dhcp/relays'

    @property
    def resource_type(self):
        return 'DhcpRelayService'

    @property
    def use_cache_for_get(self):
        return True

    def get_server_ips(self, uuid):
        # Return the server ips of the relay profile attached to this service
        service = self.get(uuid)
        profile_id = service.get('dhcp_relay_profile_id')
        if profile_id and self.nsxlib:
            return self.nsxlib.relay_profile.get_server_ips(profile_id)


class NsxLibDhcpRelayProfile(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'dhcp/relay-profiles'

    @property
    def resource_type(self):
        return 'DhcpRelayProfile'

    @property
    def use_cache_for_get(self):
        return True

    def get_server_ips(self, uuid):
        profile = self.get(uuid)
        return profile.get('server_addresses')


class NsxLibMetadataProxy(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'md-proxies'

    @property
    def resource_type(self):
        return 'MetadataProxy'

    def update(self, uuid, server_url=None, secret=None, edge_cluster_id=None):
        body = {}
        # update the relevant fields
        if server_url is not None:
            body['metadata_server_url'] = server_url
        if secret is not None:
            body['secret'] = secret
        if edge_cluster_id is not None:
            body['edge_cluster_id'] = edge_cluster_id
        return self._update_with_retry(uuid, body)

    def get_md_proxy_status(self, attachment_id, logical_switch_id):
        """Return all matching logical port statuses"""
        url_suffix = ('/%s/%s/status' %
                      (attachment_id, logical_switch_id))
        return self.client.get(self.get_path(url_suffix))


class NsxLibBridgeCluster(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'bridge-clusters'

    @property
    def resource_type(self):
        return 'BridgeCluster'


class NsxLibIpBlockSubnet(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'pools/ip-subnets'

    @property
    def resource_type(self):
        return 'IpBlockSubnet'

    def create(self, ip_block_id, subnet_size):
        """Create a IP block subnet on the backend."""
        body = {'size': subnet_size,
                'block_id': ip_block_id}
        return self.client.create(self.get_path(), body)

    def delete(self, subnet_id):
        """Delete a IP block subnet on the backend."""
        self.client.delete(self.get_path(subnet_id))

    def list(self, ip_block_id):
        resource = '%s?block_id=%s' % (self.get_path(), ip_block_id)
        return self.client.get(resource)


class NsxLibIpBlock(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'pools/ip-blocks'

    @property
    def resource_type(self):
        return 'IpBlock'


class NsxLibFabricVirtualMachine(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'fabric/virtual-machines'

    @property
    def resource_type(self):
        return 'VirtualMachine'

    def get_by_display_name(self, display_name):
        url = '%s?display_name=%s' % (self.get_path(), display_name)
        return self.client.get(url)


class NsxLibFabricVirtualInterface(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'fabric/vifs'

    @property
    def resource_type(self):
        return 'VirtualNetworkInterface'

    def get_by_owner_vm_id(self, owner_vm_id):
        url = '%s?owner_vm_id=%s' % (self.get_path(), owner_vm_id)
        return self.client.get(url)
