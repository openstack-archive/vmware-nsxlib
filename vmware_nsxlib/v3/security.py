# Copyright 2015 OpenStack Foundation

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

"""
NSX-V3 Plugin security & Distributed Firewall integration module
"""

from neutron_lib import constants
from oslo_log import log
from oslo_utils import excutils

from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import nsx_constants as consts
from vmware_nsxlib.v3 import utils


LOG = log.getLogger(__name__)

PORT_SG_SCOPE = 'os-security-group'
MAX_NSGROUPS_CRITERIA_TAGS = 10


class NsxLibNsGroup(utils.NsxLibApiBase):

    def __init__(self, client, max_attempts, firewall_section_handler):
        self.firewall_section = firewall_section_handler
        super(NsxLibNsGroup, self).__init__(client, max_attempts)

    def update_on_backend(self, context, security_group,
                          nsgroup_id, section_id,
                          log_sg_allowed_traffic):
        name = self.get_name(security_group)
        description = security_group['description']
        logging = (log_sg_allowed_traffic or
                   security_group[consts.LOGGING])
        rules = self.firewall_section._process_rules_logging_for_update(
            section_id, logging)
        self.update(nsgroup_id, name, description)
        self.firewall_section.update(section_id, name, description,
                                     rules=rules)

    def get_name(self, security_group):
        # NOTE(roeyc): We add the security-group id to the NSGroup name,
        # for usability purposes.
        return '%(name)s - %(id)s' % security_group

    def get_lport_tags(self, secgroups):
        if len(secgroups) > MAX_NSGROUPS_CRITERIA_TAGS:
            raise exceptions.NumberOfNsgroupCriteriaTagsReached(
                max_num=MAX_NSGROUPS_CRITERIA_TAGS)
        tags = []
        for sg in secgroups:
            tags = utils.add_v3_tag(tags, PORT_SG_SCOPE, sg)
        if not tags:
            # This port shouldn't be associated with any security-group
            tags = [{'scope': PORT_SG_SCOPE, 'tag': None}]
        return tags

    def update_lport(self, context, lport_id, original, updated):
        added = set(updated) - set(original)
        removed = set(original) - set(updated)
        for nsgroup_id in added:
            try:
                self.add_members(
                    nsgroup_id, consts.TARGET_TYPE_LOGICAL_PORT,
                    [lport_id])
            except exceptions.NSGroupIsFull:
                for nsgroup_id in added:
                    # NOTE(roeyc): If the port was not added to the nsgroup
                    # yet, then this request will silently fail.
                    self.remove_member(
                        nsgroup_id, consts.TARGET_TYPE_LOGICAL_PORT,
                        lport_id)
                raise exceptions.SecurityGroupMaximumCapacityReached(
                    sg_id=nsgroup_id)
            except exceptions.ResourceNotFound:
                with excutils.save_and_reraise_exception():
                    LOG.error("NSGroup %s doesn't exists", nsgroup_id)
        for nsgroup_id in removed:
            self.remove_member(
                nsgroup_id, consts.TARGET_TYPE_LOGICAL_PORT, lport_id)

    def get_nsservice(self, resource_type, **properties):
        service = {'resource_type': resource_type}
        service.update(properties)
        return {'service': service}

    def get_nsgroup_complex_expression(self, expressions):
        return {'resource_type': consts.NSGROUP_COMPLEX_EXP,
                'expressions': expressions}

    def get_switch_tag_expression(self, scope, tag):
        return {'resource_type': consts.NSGROUP_TAG_EXP,
                'target_type': consts.TARGET_TYPE_LOGICAL_SWITCH,
                'scope': scope,
                'tag': tag}

    def get_port_tag_expression(self, scope, tag):
        return {'resource_type': consts.NSGROUP_TAG_EXP,
                'target_type': consts.TARGET_TYPE_LOGICAL_PORT,
                'scope': scope,
                'tag': tag}

    def create(self, display_name, description, tags,
               membership_criteria=None):
        body = {'display_name': display_name,
                'description': description,
                'tags': tags,
                'members': []}
        if membership_criteria:
            # Allow caller to pass a list of membership criterias.
            # The 'else' block is maintained for backwards compatibility
            # where in a caller might only send a single membership criteria.
            if isinstance(membership_criteria, list):
                body.update({'membership_criteria': membership_criteria})
            else:
                body.update({'membership_criteria': [membership_criteria]})
        return self.client.create('ns-groups', body)

    def list(self):
        return self.client.list(
            'ns-groups?populate_references=false').get('results', [])

    def update(self, nsgroup_id, display_name=None, description=None,
               membership_criteria=None, members=None):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self.nsxlib_config.max_attempts)
        def _do_update():
            nsgroup = self.read(nsgroup_id)
            if display_name is not None:
                nsgroup['display_name'] = display_name
            if description is not None:
                nsgroup['description'] = description
            if members is not None:
                nsgroup['members'] = members
            if membership_criteria is not None:
                nsgroup['membership_criteria'] = [membership_criteria]
            return self.client.update(
                'ns-groups/%s' % nsgroup_id, nsgroup)

        return _do_update()

    def get_member_expression(self, target_type, target_id):
        return {
            'resource_type': consts.NSGROUP_SIMPLE_EXP,
            'target_property': 'id',
            'target_type': target_type,
            'op': consts.EQUALS,
            'value': target_id}

    def _update_with_members(self, nsgroup_id, members, action):
        members_update = 'ns-groups/%s?action=%s' % (nsgroup_id, action)
        return self.client.create(members_update, members)

    def add_members(self, nsgroup_id, target_type, target_ids):
        members = []
        for target_id in target_ids:
            member_expr = self.get_member_expression(
                target_type, target_id)
            members.append(member_expr)
        members = {'members': members}
        try:
            return self._update_with_members(
                nsgroup_id, members, consts.NSGROUP_ADD_MEMBERS)
        except (exceptions.StaleRevision, exceptions.ResourceNotFound):
            raise
        except exceptions.ManagerError:
            # REVISIT(roeyc): A ManagerError might have been raised for a
            # different reason, e.g - NSGroup does not exists.
            LOG.warning("Failed to add %(target_type)s resources "
                        "(%(target_ids)s) to NSGroup %(nsgroup_id)s",
                        {'target_type': target_type,
                         'target_ids': target_ids,
                         'nsgroup_id': nsgroup_id})

            raise exceptions.NSGroupIsFull(nsgroup_id=nsgroup_id)

    def remove_member(self, nsgroup_id, target_type,
                      target_id, verify=False):
        member_expr = self.get_member_expression(
            target_type, target_id)
        members = {'members': [member_expr]}
        try:
            return self._update_with_members(
                nsgroup_id, members, consts.NSGROUP_REMOVE_MEMBERS)
        except exceptions.ManagerError:
            if verify:
                raise exceptions.NSGroupMemberNotFound(member_id=target_id,
                                                       nsgroup_id=nsgroup_id)

    def read(self, nsgroup_id):
        return self.client.get(
            'ns-groups/%s?populate_references=true' % nsgroup_id)

    def delete(self, nsgroup_id):
        try:
            return self.client.delete(
                'ns-groups/%s?force=true' % nsgroup_id)
        # FIXME(roeyc): Should only except NotFound error.
        except Exception:
            LOG.debug("NSGroup %s does not exists for delete request.",
                      nsgroup_id)

    def find_by_display_name(self, display_name):
        found = []
        for resource in self.list():
            if resource['display_name'] == display_name:
                found.append(resource)
        return found


class NsxLibFirewallSection(utils.NsxLibApiBase):

    def add_member_to_fw_exclude_list(self, target_id, target_type):
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self.nsxlib_config.max_attempts)
        def _add_member_to_fw_exclude_list():
            resource = 'firewall/excludelist?action=add_member'
            body = {"target_id": target_id,
                    "target_type": target_type}
            self.client.create(resource, body)

        _add_member_to_fw_exclude_list()

    def remove_member_from_fw_exclude_list(self, target_id, target_type):
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self.nsxlib_config.max_attempts)
        def _remove_member_from_fw_exclude_list():
            resource = ('firewall/excludelist?action=remove_member&object_id='
                        + target_id)
            self.client.create(resource)

        _remove_member_from_fw_exclude_list()

    def get_excludelist(self):
        return self.client.list('firewall/excludelist')

    def _get_direction(self, sg_rule):
        return (
            consts.IN if sg_rule['direction'] == 'ingress'
            else consts.OUT
        )

    def _get_l4_protocol_name(self, protocol_number):
        if protocol_number is None:
            return
        protocol_number = constants.IP_PROTOCOL_MAP.get(protocol_number,
                                                        protocol_number)
        protocol_number = int(protocol_number)
        if protocol_number == 6:
            return consts.TCP
        elif protocol_number == 17:
            return consts.UDP
        elif protocol_number == 1:
            return consts.ICMPV4
        else:
            return protocol_number

    def get_nsservice(self, resource_type, **properties):
        service = {'resource_type': resource_type}
        service.update(properties)
        return {'service': service}

    def _decide_service(self, sg_rule):
        l4_protocol = self._get_l4_protocol_name(sg_rule['protocol'])
        direction = self._get_direction(sg_rule)

        if l4_protocol in [consts.TCP, consts.UDP]:
            # If port_range_min is not specified then we assume all ports are
            # matched, relying on neutron to perform validation.
            source_ports = []
            if sg_rule['port_range_min'] is None:
                destination_ports = []
            elif sg_rule['port_range_min'] != sg_rule['port_range_max']:
                # NSX API requires a non-empty range (e.g - '22-23')
                destination_ports = ['%(port_range_min)s-%(port_range_max)s'
                                     % sg_rule]
            else:
                destination_ports = ['%(port_range_min)s' % sg_rule]

            if direction == consts.OUT:
                source_ports, destination_ports = destination_ports, []

            return self.get_nsservice(
                consts.L4_PORT_SET_NSSERVICE,
                l4_protocol=l4_protocol,
                source_ports=source_ports,
                destination_ports=destination_ports)
        elif l4_protocol == consts.ICMPV4:
            return self.get_nsservice(
                consts.ICMP_TYPE_NSSERVICE,
                protocol=l4_protocol,
                icmp_type=sg_rule['port_range_min'],
                icmp_code=sg_rule['port_range_max'])
        elif l4_protocol is not None:
            return self.get_nsservice(
                consts.IP_PROTOCOL_NSSERVICE,
                protocol_number=l4_protocol)

    def _build(self, display_name, description, applied_tos, tags):
        return {'display_name': display_name,
                'description': description,
                'stateful': True,
                'section_type': consts.FW_SECTION_LAYER3,
                'applied_tos': [self.get_nsgroup_reference(t_id)
                                for t_id in applied_tos],
                'tags': tags}

    def create_empty(self, display_name, description,
                     applied_tos, tags,
                     operation=consts.FW_INSERT_BOTTOM,
                     other_section=None):
        resource = 'firewall/sections?operation=%s' % operation
        body = self._build(display_name, description,
                           applied_tos, tags)
        if other_section:
            resource += '&id=%s' % other_section
        return self.client.create(resource, body)

    def create_with_rules(self, display_name, description, applied_tos=None,
                          tags=None, operation=consts.FW_INSERT_BOTTOM,
                          other_section=None, rules=None):
        resource = 'firewall/sections?operation=%s' % operation
        body = {
            'display_name': display_name,
            'description': description,
            'stateful': True,
            'section_type': consts.FW_SECTION_LAYER3,
            'applied_tos': applied_tos or [],
            'rules': rules or [],
            'tags': tags or []
        }
        if rules:
            resource += '&action=create_with_rules'
        if other_section:
            resource += '&id=%s' % other_section
        return self.client.create(resource, body)

    def update(self, section_id, display_name=None, description=None,
               applied_tos=None, rules=None, tags_update=None, force=False):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self.nsxlib_config.max_attempts)
        def _do_update():
            resource = 'firewall/sections/%s' % section_id
            section = self.read(section_id)

            if rules is not None:
                resource += '?action=update_with_rules'
                section.update({'rules': rules})
            if display_name is not None:
                section['display_name'] = display_name
            if description is not None:
                section['description'] = description
            if applied_tos is not None:
                section['applied_tos'] = [self.get_nsgroup_reference(nsg_id)
                                          for nsg_id in applied_tos]
            if tags_update is not None:
                section['tags'] = utils.update_v3_tags(section.get('tags', []),
                                                       tags_update)
            headers = None
            if force:
                # shared sections (like default section) can serve multiple
                # openstack deployments. If some operate under protected
                # identities, force-owerwrite is needed.
                # REVISIT(annak): find better solution for shared sections
                headers = {'X-Allow-Overwrite': 'true'}

            if rules is not None:
                return self.client.create(resource, section, headers=headers)

            elif any(p is not None for p in (display_name, description,
                                             applied_tos)):
                return self.client.update(resource, section, headers=headers)

        return _do_update()

    def read(self, section_id):
        resource = 'firewall/sections/%s' % section_id
        return self.client.get(resource)

    def list(self):
        resource = 'firewall/sections'
        return self.client.list(resource).get('results', [])

    def delete(self, section_id):
        resource = 'firewall/sections/%s?cascade=true' % section_id
        return self.client.delete(resource)

    def get_nsgroup_reference(self, nsgroup_id):
        return {'target_id': nsgroup_id,
                'target_type': consts.NSGROUP}

    def get_logicalport_reference(self, port_id):
        return {'target_id': port_id,
                'target_type': consts.TARGET_TYPE_LOGICAL_PORT}

    def get_ip_cidr_reference(self, ip_cidr_block, ip_protocol):
        target_type = (consts.TARGET_TYPE_IPV4ADDRESS
                       if ip_protocol == consts.IPV4
                       else consts.TARGET_TYPE_IPV6ADDRESS)
        return {'target_id': ip_cidr_block,
                'target_type': target_type}

    def get_rule_address(self, target_id, display_name=None, is_valid=True,
                         target_type=consts.TARGET_TYPE_IPV4ADDRESS):
        return {'target_display_name': display_name or '',
                'target_id': target_id,
                'is_valid': is_valid,
                'target_type': target_type}

    def get_l4portset_nsservice(self, sources=None, destinations=None,
                                protocol=consts.TCP):
        return {
            'service': {
                'resource_type': 'L4PortSetNSService',
                'source_ports': sources or [],
                'destination_ports': destinations or [],
                'l4_protocol': protocol}
        }

    def get_rule_dict(self, display_name, sources=None, destinations=None,
                      direction=consts.IN_OUT, ip_protocol=consts.IPV4_IPV6,
                      services=None, action=consts.FW_ACTION_ALLOW,
                      logged=False, disabled=False, applied_tos=None):
        rule_dict = {'display_name': display_name,
                     'direction': direction,
                     'ip_protocol': ip_protocol,
                     'action': action,
                     'logged': logged,
                     'disabled': disabled,
                     'sources': sources or [],
                     'destinations': destinations or [],
                     'services': services or []}
        if applied_tos is not None:
            rule_dict['applied_tos'] = applied_tos
        return rule_dict

    def add_rule(self, rule, section_id):
        resource = 'firewall/sections/%s/rules' % section_id
        params = '?operation=insert_bottom'
        return self.client.create(resource + params, rule)

    def add_rules(self, rules, section_id):
        resource = 'firewall/sections/%s/rules' % section_id
        params = '?action=create_multiple&operation=insert_bottom'
        return self.client.create(resource + params, {'rules': rules})

    def delete_rule(self, section_id, rule_id):
        resource = 'firewall/sections/%s/rules/%s' % (section_id, rule_id)
        return self.client.delete(resource)

    def get_rules(self, section_id):
        resource = 'firewall/sections/%s/rules' % section_id
        return self.client.get(resource)

    def get_default_rule(self, section_id):
        rules = self.get_rules(section_id)['results']
        last_rule = rules[-1]
        if last_rule['is_default']:
            return last_rule

    def _get_fw_rule_from_sg_rule(self, sg_rule, nsgroup_id, rmt_nsgroup_id,
                                  logged, action):
        # IPV4 or IPV6
        ip_protocol = sg_rule['ethertype'].upper()
        direction = self._get_direction(sg_rule)

        if sg_rule.get(consts.LOCAL_IP_PREFIX):
            local_ip_prefix = self.get_ip_cidr_reference(
                sg_rule[consts.LOCAL_IP_PREFIX],
                ip_protocol)
        else:
            local_ip_prefix = None

        source = None
        local_group = self.get_nsgroup_reference(nsgroup_id)
        if sg_rule['remote_ip_prefix'] is not None:
            source = self.get_ip_cidr_reference(
                sg_rule['remote_ip_prefix'], ip_protocol)
            destination = local_ip_prefix or local_group
        else:
            if rmt_nsgroup_id:
                source = self.get_nsgroup_reference(rmt_nsgroup_id)
            destination = local_ip_prefix or local_group
        if direction == consts.OUT:
            source, destination = destination, source

        service = self._decide_service(sg_rule)
        name = sg_rule['id']

        return self.get_rule_dict(name, [source] if source else None,
                                  [destination] if destination else None,
                                  direction,
                                  ip_protocol,
                                  [service] if service else None,
                                  action, logged)

    def create_rules(self, context, section_id, nsgroup_id,
                     logging_enabled, action, security_group_rules,
                     ruleid_2_remote_nsgroup_map):
        # 1. translate rules
        # 2. insert in section
        # 3. return the rules
        firewall_rules = []
        for sg_rule in security_group_rules:
            remote_nsgroup_id = ruleid_2_remote_nsgroup_map[sg_rule['id']]
            fw_rule = self._get_fw_rule_from_sg_rule(
                sg_rule, nsgroup_id, remote_nsgroup_id,
                logging_enabled, action)

            firewall_rules.append(fw_rule)

        return self.add_rules(firewall_rules, section_id)

    def set_rule_logging(self, section_id, logging):
        rules = self._process_rules_logging_for_update(
            section_id, logging)
        self.update(section_id, rules=rules)

    def _process_rules_logging_for_update(self, section_id, logging_enabled):
        rules = self.get_rules(section_id).get('results', [])
        update_rules = False
        for rule in rules:
            if rule['logged'] != logging_enabled:
                rule['logged'] = logging_enabled
                update_rules = True
        return rules if update_rules else None

    def init_default(self, name, description, nested_groups,
                     log_sg_blocked_traffic):
        fw_sections = self.list()
        for section in reversed(fw_sections):
            if section['display_name'] == name:
                break
        else:
            tags = self.build_v3_api_version_tag()
            section = self.create_empty(
                name, description, nested_groups, tags)

        block_rule = self.get_rule_dict(
            'Block All', action=consts.FW_ACTION_DROP,
            logged=log_sg_blocked_traffic)
        # TODO(roeyc): Add additional rules to allow IPV6 NDP.
        dhcp_client = self.get_nsservice(
            consts.L4_PORT_SET_NSSERVICE,
            l4_protocol=consts.UDP,
            source_ports=[67],
            destination_ports=[68])
        dhcp_client_rule_in = self.get_rule_dict(
            'DHCP Reply', direction=consts.IN,
            services=[dhcp_client])

        dhcp_server = (
            self.get_nsservice(
                consts.L4_PORT_SET_NSSERVICE,
                l4_protocol=consts.UDP,
                source_ports=[68],
                destination_ports=[67]))
        dhcp_client_rule_out = self.get_rule_dict(
            'DHCP Request', direction=consts.OUT,
            services=[dhcp_server])

        self.update(section['id'],
                    name, section['description'],
                    applied_tos=nested_groups,
                    rules=[dhcp_client_rule_out,
                           dhcp_client_rule_in,
                           block_rule],
                    force=True)
        return section['id']


class NsxLibIPSet(utils.NsxLibApiBase):

    def create(self, display_name, description=None, ip_addresses=None,
               tags=None):
        resource = 'ip-sets'
        body = {
            'display_name': display_name,
            'description': description or '',
            'ip_addresses': ip_addresses or [],
            'tags': tags or []
        }
        return self.client.create(resource, body)

    def update(self, ip_set_id, display_name=None, description=None,
               ip_addresses=None, tags_update=None):
        # Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self.nsxlib_config.max_attempts)
        def _do_update():
            resource = 'ip-sets/%s' % ip_set_id
            ip_set = self.read(ip_set_id)
            tags = ip_set.get('tags', [])
            if tags_update:
                tags = utils.update_v3_tags(tags, tags_update)
            if display_name is not None:
                ip_set['display_name'] = display_name
            if description is not None:
                ip_set['description'] = description
            if ip_addresses is not None:
                ip_set['ip_addresses'] = ip_addresses
            return self.client.update(resource, ip_set)

        return _do_update()

    def read(self, ip_set_id):
        return self.client.get('ip-sets/%s' % ip_set_id)

    def delete(self, ip_set_id):
        return self.client.delete('ip-sets/%s' % ip_set_id)

    def get_ipset_reference(self, ip_set_id):
        return {'target_id': ip_set_id,
                'target_type': consts.IP_SET}
