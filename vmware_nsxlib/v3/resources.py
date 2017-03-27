# Copyright 2015 VMware, Inc.
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
import abc
import collections
import netaddr
import six

from vmware_nsxlib._i18n import _
from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import utils


SwitchingProfileTypeId = collections.namedtuple(
    'SwitchingProfileTypeId', 'profile_type, profile_id')


PacketAddressClassifier = collections.namedtuple(
    'PacketAddressClassifier', 'ip_address, mac_address, vlan')


@six.add_metaclass(abc.ABCMeta)
class AbstractRESTResource(object):

    def __init__(self, rest_client, *args, **kwargs):
        self._client = rest_client.new_client_for(self.uri_segment)

    @abc.abstractproperty
    def uri_segment(self):
        pass

    def list(self):
        return self._client.list()

    def get(self, uuid):
        return self._client.get(uuid)

    def delete(self, uuid):
        return self._client.delete(uuid)

    @abc.abstractmethod
    def create(self, *args, **kwargs):
        pass

    @abc.abstractmethod
    def update(self, uuid, *args, **kwargs):
        pass

    def find_by_display_name(self, display_name):
        found = []
        for resource in self.list()['results']:
            if resource['display_name'] == display_name:
                found.append(resource)
        return found


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


class SwitchingProfile(AbstractRESTResource):

    @property
    def uri_segment(self):
        return 'switching-profiles'

    def list(self):
        return self._client.url_get('?include_system_owned=True')

    def create(self, profile_type, display_name=None,
               description=None, **api_args):
        body = {
            'resource_type': profile_type,
            'display_name': display_name or '',
            'description': description or ''
        }
        body.update(api_args)

        return self._client.create(body=body)

    def update(self, uuid, profile_type, **api_args):
        body = {
            'resource_type': profile_type
        }
        body.update(api_args)

        return self._client.update(uuid, body=body)

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


class LogicalPort(AbstractRESTResource):

    @property
    def uri_segment(self):
        return 'logical-ports'

    def _build_body_attrs(
            self, display_name=None,
            admin_state=True, tags=None,
            address_bindings=None,
            switch_profile_ids=None,
            attachment=None):
        tags = tags or []
        address_bindings = address_bindings or []
        switch_profile_ids = switch_profile_ids or []
        body = {}
        if tags:
            body['tags'] = tags
        if display_name is not None:
            body['display_name'] = display_name

        if admin_state is not None:
            if admin_state:
                body['admin_state'] = nsx_constants.ADMIN_STATE_UP
            else:
                body['admin_state'] = nsx_constants.ADMIN_STATE_DOWN

        if address_bindings:
            bindings = []
            for binding in address_bindings:
                address_classifier = {
                    'ip_address': binding.ip_address,
                    'mac_address': binding.mac_address
                }
                if binding.vlan is not None:
                    address_classifier['vlan'] = int(binding.vlan)
                bindings.append(address_classifier)
            body['address_bindings'] = bindings
        elif address_bindings == []:
            # explicitly clear out address bindings
            body['address_bindings'] = []

        if switch_profile_ids:
            profiles = []
            for profile in switch_profile_ids:
                profiles.append({
                    'value': profile.profile_id,
                    'key': profile.profile_type
                })
            body['switching_profile_ids'] = profiles

        # Note that attachment could be None, meaning reset it.
        if attachment is not False:
            body['attachment'] = attachment

        return body

    def _prepare_attachment(self, attachment_type, vif_uuid,
                            allocate_addresses, vif_type,
                            parent_vif_id, traffic_tag, app_id):
        if attachment_type and vif_uuid:
            attachment = {'attachment_type': attachment_type,
                          'id': vif_uuid}
            if vif_type:
                context = {'resource_type': nsx_constants.VIF_RESOURCE_TYPE,
                           'allocate_addresses': allocate_addresses,
                           'vif_type': vif_type}
                if parent_vif_id:
                    context['parent_vif_id'] = parent_vif_id
                    context['traffic_tag'] = traffic_tag
                    context['app_id'] = app_id
                attachment['context'] = context
            return attachment
        elif attachment_type is None and vif_uuid is None:
            return None   # reset attachment
        else:
            return False  # no attachment change

    def _build_address_bindings(self, address_bindings):
        addr_bindings = []
        for binding in address_bindings:
            addr_bindings.append(PacketAddressClassifier(
                binding.get('ip_address'), binding.get('mac_address'),
                binding.get('vlan')))
        return addr_bindings

    def create(self, lswitch_id, vif_uuid, tags=None,
               attachment_type=nsx_constants.ATTACHMENT_VIF,
               admin_state=True, name=None, address_bindings=None,
               parent_vif_id=None, traffic_tag=None,
               switch_profile_ids=None, vif_type=None, app_id=None,
               allocate_addresses=nsx_constants.ALLOCATE_ADDRESS_NONE):
        tags = tags or []

        body = {'logical_switch_id': lswitch_id}
        # NOTE(arosen): If parent_vif_id is specified we need to use
        # CIF attachment type.
        attachment = self._prepare_attachment(attachment_type, vif_uuid,
                                              allocate_addresses, vif_type,
                                              parent_vif_id, traffic_tag,
                                              app_id)
        body.update(self._build_body_attrs(
            display_name=name,
            admin_state=admin_state, tags=tags,
            address_bindings=address_bindings,
            switch_profile_ids=switch_profile_ids,
            attachment=attachment))
        return self._client.create(body=body)

    def delete(self, lport_id):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self._client.max_attempts)
        def _do_delete():
            return self._client.url_delete('%s?detach=true' % lport_id)

        return _do_delete()

    def update(self, lport_id, vif_uuid,
               name=None, admin_state=None,
               address_bindings=None, switch_profile_ids=None,
               tags_update=None,
               attachment_type=nsx_constants.ATTACHMENT_VIF,
               parent_vif_id=None, traffic_tag=None,
               vif_type=None, app_id=None,
               allocate_addresses=nsx_constants.ALLOCATE_ADDRESS_NONE):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self._client.max_attempts)
        def do_update():
            lport = self.get(lport_id)
            tags = lport.get('tags', [])
            if tags_update:
                tags = utils.update_v3_tags(tags, tags_update)
            # Assign outer function argument to a local scope
            addr_bindings = address_bindings
            if addr_bindings is None:
                addr_bindings = self._build_address_bindings(
                    lport.get('address_bindings'))
            attachment = self._prepare_attachment(attachment_type, vif_uuid,
                                                  allocate_addresses, vif_type,
                                                  parent_vif_id, traffic_tag,
                                                  app_id)
            lport.update(self._build_body_attrs(
                display_name=name,
                admin_state=admin_state, tags=tags,
                address_bindings=addr_bindings,
                switch_profile_ids=switch_profile_ids,
                attachment=attachment))

            # If revision_id of the payload that we send is older than what
            # NSX has, we will get a 412: Precondition Failed.
            # In that case we need to re-fetch, patch the response and send
            # it again with the new revision_id
            return self._client.update(lport_id, body=lport)
        return do_update()


class LogicalRouter(AbstractRESTResource):

    @property
    def uri_segment(self):
        return 'logical-routers'

    def create(self, display_name, tags, edge_cluster_uuid=None, tier_0=False,
               description=None):
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
        return self._client.create(body=body)

    def delete(self, lrouter_id, force=False):
        url = lrouter_id
        if force:
            url += '?force=%s' % force
        return self._client.url_delete(url)

    def update(self, lrouter_id, *args, **kwargs):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self._client.max_attempts)
        def _do_update():
            lrouter = self.get(lrouter_id)
            for k in kwargs:
                lrouter[k] = kwargs[k]
            # If revision_id of the payload that we send is older than what
            # NSX has, we will get a 412: Precondition Failed.
            # In that case we need to re-fetch, patch the response and send
            # it again with the new revision_id
            return self._client.update(lrouter_id, body=lrouter)

        return _do_update()


class LogicalRouterPort(AbstractRESTResource):

    @property
    def uri_segment(self):
        return 'logical-router-ports'

    def create(self, logical_router_id,
               display_name,
               tags,
               resource_type,
               logical_port_id,
               address_groups,
               edge_cluster_member_index=None,
               urpf_mode=None):
        body = {'display_name': display_name,
                'resource_type': resource_type,
                'logical_router_id': logical_router_id,
                'tags': tags or []}
        if address_groups:
            body['subnets'] = address_groups
        if resource_type in [nsx_constants.LROUTERPORT_UPLINK,
                             nsx_constants.LROUTERPORT_DOWNLINK]:
            body['linked_logical_switch_port_id'] = {
                'target_id': logical_port_id}
        elif resource_type == nsx_constants.LROUTERPORT_LINKONTIER1:
            body['linked_logical_router_port_id'] = {
                'target_id': logical_port_id}
        elif logical_port_id:
            body['linked_logical_router_port_id'] = logical_port_id
        if edge_cluster_member_index:
            body['edge_cluster_member_index'] = edge_cluster_member_index
        if urpf_mode:
            body['urpf_mode'] = urpf_mode

        return self._client.create(body=body)

    def update(self, logical_port_id, **kwargs):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self._client.max_attempts)
        def _do_update():
            logical_router_port = self.get(logical_port_id)
            for k in kwargs:
                logical_router_port[k] = kwargs[k]
            # If revision_id of the payload that we send is older than what
            # NSX has, we will get a 412: Precondition Failed.
            # In that case we need to re-fetch, patch the response and send
            # it again with the new revision_id
            return self._client.update(logical_port_id,
                                       body=logical_router_port)
        return _do_update()

    def delete(self, logical_port_id):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self._client.max_attempts)
        def _do_delete():
            return self._client.url_delete(logical_port_id)

        return _do_delete()

    def get_by_lswitch_id(self, logical_switch_id):
        resource = '?logical_switch_id=%s' % logical_switch_id
        router_ports = self._client.url_get(resource)
        result_count = int(router_ports.get('result_count', "0"))
        if result_count >= 2:
            raise exceptions.ManagerError(
                details=_("Can't support more than one logical router ports "
                          "on same logical switch %s ") % logical_switch_id)
        elif result_count == 1:
            return router_ports['results'][0]
        else:
            err_msg = (_("Logical router link port not found on logical "
                         "switch %s") % logical_switch_id)
            raise exceptions.ResourceNotFound(
                manager=self._client.nsx_api_managers,
                operation=err_msg)

    def update_by_lswitch_id(self, logical_router_id, ls_id, **payload):
        port = self.get_by_lswitch_id(ls_id)
        return self.update(port['id'], **payload)

    def delete_by_lswitch_id(self, ls_id):
        port = self.get_by_lswitch_id(ls_id)
        self.delete(port['id'])

    def get_by_router_id(self, logical_router_id):
        resource = '?logical_router_id=%s' % logical_router_id
        logical_router_ports = self._client.url_get(resource)
        return logical_router_ports['results']

    def get_tier1_link_port(self, logical_router_id):
        logical_router_ports = self.get_by_router_id(logical_router_id)
        for port in logical_router_ports:
            if port['resource_type'] == nsx_constants.LROUTERPORT_LINKONTIER1:
                return port
        raise exceptions.ResourceNotFound(
            manager=self._client.nsx_api_managers,
            operation="get router link port")


class MetaDataProxy(AbstractRESTResource):

    @property
    def uri_segment(self):
        return 'md-proxies'

    def create(self, *args, **kwargs):
        pass

    def update(self, uuid, *args, **kwargs):
        pass


class DhcpProfile(AbstractRESTResource):

    @property
    def uri_segment(self):
        return 'dhcp/server-profiles'

    def create(self, *args, **kwargs):
        pass

    def update(self, uuid, *args, **kwargs):
        pass


class LogicalDhcpServer(AbstractRESTResource):

    def get_dhcp_opt_code(self, name):
        _supported_options = {
            'subnet-mask': 1,
            'time-offset': 2,
            'router': 3,
            'dns-name': 6,
            'host-name': 12,
            'boot-file-size': 13,
            'domain-name': 15,
            'ip-forwarding': 19,
            'interface-mtu': 26,
            'broadcast-address': 28,
            'arp-cache-timeout': 35,
            'nis-domain': 40,
            'nis-servers': 41,
            'ntp-servers': 42,
            'netbios-name-servers': 44,
            'netbios-dd-server': 45,
            'netbios-node-type': 46,
            'netbios-scope': 47,
            'dhcp-renewal-time': 58,
            'dhcp-rebinding-time': 59,
            'class-id': 60,
            'dhcp-client-identifier': 61,
            'nisplus-domain': 64,
            'nisplus-servers': 65,
            'tftp-server-name': 66,
            'bootfile-name': 67,
            'system-architecture': 93,
            'interface-id': 94,
            'machine-id': 97,
            'name-search': 117,
            'subnet-selection': 118,
            'domain-search': 119,
            'classless-static-route': 121,
            'tftp-server-address': 150,
            'etherboot': 175,
            'config-file': 209,
            'path-prefix': 210,
            'reboot-time': 211,
        }
        return _supported_options.get(name)

    @property
    def uri_segment(self):
        return 'dhcp/servers'

    def _construct_server(self, body, dhcp_profile_id=None, server_ip=None,
                          name=None, dns_nameservers=None, domain_name=None,
                          gateway_ip=False, options=None, tags=None):
        if name:
            body['display_name'] = name
        if dhcp_profile_id:
            body['dhcp_profile_id'] = dhcp_profile_id
        if server_ip:
            body['ipv4_dhcp_server']['dhcp_server_ip'] = server_ip
        if dns_nameservers is not None:
            # Note that [] is valid for dns_nameservers, means deleting it.
            body['ipv4_dhcp_server']['dns_nameservers'] = dns_nameservers
        if domain_name:
            body['ipv4_dhcp_server']['domain_name'] = domain_name
        if gateway_ip is not False:
            # Note that None is valid for gateway_ip, means deleting it.
            body['ipv4_dhcp_server']['gateway_ip'] = gateway_ip
        if options:
            body['ipv4_dhcp_server']['options'] = options
        if tags:
            body['tags'] = tags

    def create(self, dhcp_profile_id, server_ip, name=None,
               dns_nameservers=None, domain_name=None, gateway_ip=False,
               options=None, tags=None):
        body = {'ipv4_dhcp_server': {}}
        self._construct_server(body, dhcp_profile_id, server_ip, name,
                               dns_nameservers, domain_name, gateway_ip,
                               options, tags)
        return self._client.create(body=body)

    def update(self, uuid, dhcp_profile_id=None, server_ip=None, name=None,
               dns_nameservers=None, domain_name=None, gateway_ip=False,
               options=None, tags=None):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self._client.max_attempts)
        def _do_update():
            body = self._client.get(uuid)
            self._construct_server(body, dhcp_profile_id, server_ip, name,
                                   dns_nameservers, domain_name, gateway_ip,
                                   options, tags)
            return self._client.update(uuid, body=body)

        return _do_update()

    def create_binding(self, server_uuid, mac, ip, hostname=None,
                       lease_time=None, options=None, gateway_ip=False):
        body = {'mac_address': mac, 'ip_address': ip}
        if hostname:
            body['host_name'] = hostname
        if lease_time:
            body['lease_time'] = lease_time
        if options:
            body['options'] = options
        if gateway_ip is not False:
            # Note that None is valid for gateway_ip, means deleting it.
            body['gateway_ip'] = gateway_ip
        url = "%s/static-bindings" % server_uuid
        return self._client.url_post(url, body)

    def get_binding(self, server_uuid, binding_uuid):
        url = "%s/static-bindings/%s" % (server_uuid, binding_uuid)
        return self._client.url_get(url)

    def update_binding(self, server_uuid, binding_uuid, **kwargs):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self._client.max_attempts)
        def _do_update():
            body = self.get_binding(server_uuid, binding_uuid)
            body.update(kwargs)
            url = "%s/static-bindings/%s" % (server_uuid, binding_uuid)
            return self._client.url_put(url, body)

        return _do_update()

    def delete_binding(self, server_uuid, binding_uuid):
        url = "%s/static-bindings/%s" % (server_uuid, binding_uuid)
        return self._client.url_delete(url)


class IpPool(AbstractRESTResource):
    # TODO(asarfaty): Check the DK api - could be different
    @property
    def uri_segment(self):
        return 'pools/ip-pools'

    def _generate_ranges(self, cidr, gateway_ip):
        """Create list of ranges from the given cidr.

        Ignore the gateway_ip, if defined
        """
        ip_set = netaddr.IPSet(netaddr.IPNetwork(cidr))
        if gateway_ip:
            ip_set.remove(gateway_ip)
        return [{"start": str(r[0]),
                 "end": str(r[-1])} for r in ip_set.iter_ipranges()]

    def create(self, cidr, allocation_ranges=None, display_name=None,
               description=None, gateway_ip=None, dns_nameservers=None,
               tags=None):
        """Create an IpPool.

        Arguments:
        cidr: (required)
        allocation_ranges: (optional) a list of dictionaries, each with
           'start' and 'end' keys, and IP values.
            If None: the cidr will be used to create the ranges,
            excluding the gateway.
        display_name: (optional)
        description: (optional)
        gateway_ip: (optional)
        dns_nameservers: (optional) list of addresses
        """
        if not cidr:
            raise exceptions.InvalidInput(operation="IP Pool create",
                                          arg_name="cidr", arg_val=cidr)
        if not allocation_ranges:
            # generate ranges from (cidr - gateway)
            allocation_ranges = self._generate_ranges(cidr, gateway_ip)

        subnet = {"allocation_ranges": allocation_ranges,
                  "cidr": cidr}
        if gateway_ip:
            subnet["gateway_ip"] = gateway_ip
        if dns_nameservers:
            subnet["dns_nameservers"] = dns_nameservers

        body = {"subnets": [subnet]}
        if description:
            body["description"] = description
        if display_name:
            body["display_name"] = display_name
        if tags:
            body['tags'] = tags

        return self._client.create(body=body)

    def delete(self, pool_id):
        """Delete an IPPool by its ID."""
        return self._client.delete(pool_id)

    def _update_param_in_pool(self, args_dict, key, pool_data):
        # update the arg only if it exists in the args dictionary
        if key in args_dict:
            if args_dict[key]:
                pool_data[key] = args_dict[key]
            else:
                # remove the current value
                del pool_data[key]

    def update(self, pool_id, **kwargs):
        """Update the given attributes in the current pool configuration."""
        # Get the current pool, and remove irrelevant fields
        pool = self.get(pool_id)
        for key in ["resource_type", "_create_time", "_create_user"
                    "_last_modified_user", "_last_modified_time"]:
            pool.pop(key, None)

        # update only the attributes in kwargs
        self._update_param_in_pool(kwargs, 'display_name', pool)
        self._update_param_in_pool(kwargs, 'description', pool)
        self._update_param_in_pool(kwargs, 'tags', pool)
        self._update_param_in_pool(kwargs, 'gateway_ip',
                                   pool["subnets"][0])
        self._update_param_in_pool(kwargs, 'dns_nameservers',
                                   pool["subnets"][0])
        self._update_param_in_pool(kwargs, 'allocation_ranges',
                                   pool["subnets"][0])
        self._update_param_in_pool(kwargs, 'cidr',
                                   pool["subnets"][0])
        return self._client.update(pool_id, pool)

    def get(self, pool_id):
        return self._client.get(pool_id)

    def allocate(self, pool_id, ip_addr=None, display_name=None, tags=None):
        """Allocate an IP from a pool."""
        # Note: Currently the backend does not support allocation of a
        # specific IP, so an exception will be raised by the backend.
        # Depending on the backend version, this may be allowed in the future
        url = "%s?action=ALLOCATE" % pool_id
        body = {"allocation_id": ip_addr}
        if tags is not None:
            body['tags'] = tags
        if display_name is not None:
            body['display_name'] = display_name
        return self._client.url_post(url, body=body)

    def release(self, pool_id, ip_addr):
        """Release an IP back to a pool."""
        url = "%s?action=RELEASE" % pool_id
        body = {"allocation_id": ip_addr}
        return self._client.url_post(url, body=body)

    def get_allocations(self, pool_id):
        """Return information about the allocated IPs in the pool."""
        url = "%s/allocations" % pool_id
        return self._client.url_get(url)
