# Copyright (c) 2015 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
import six

from oslo_utils import uuidutils

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.tests.unit.v3 import test_constants
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import nsx_constants as const


class TestNsxLibFirewallSection(nsxlib_testcase.NsxLibTestCase):
    """Tests for vmware_nsxlib.v3.security.NsxLibFirewallSection"""

    def test_get_logicalport_reference(self):
        mock_port = '3ed55c9f-f879-4048-bdd3-eded92465252'
        result = self.nsxlib.firewall_section.get_logicalport_reference(
            mock_port)
        expected = {
            'target_id': '3ed55c9f-f879-4048-bdd3-eded92465252',
            'target_type': 'LogicalPort'
        }
        self.assertEqual(expected, result)

    def test_get_rule_address(self):
        result = self.nsxlib.firewall_section.get_rule_address(
            'target-id', 'display-name')
        expected = {
            'target_display_name': 'display-name',
            'target_id': 'target-id',
            'is_valid': True,
            'target_type': 'IPv4Address'
        }
        self.assertEqual(expected, result)

    def test_get_l4portset_nsservice(self):
        result = self.nsxlib.firewall_section.get_l4portset_nsservice()
        expected = {
            'service': {
                'resource_type': 'L4PortSetNSService',
                'source_ports': [],
                'destination_ports': [],
                'l4_protocol': 'TCP'
            }
        }
        self.assertEqual(expected, result)

    def test_create_rules_with_protocol(self):
        with mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection"
                        ".add_rules") as add_rules:
            rule_id = uuidutils.generate_uuid()
            rule = {'id': rule_id,
                    'ethertype': 'IPv4',
                    'protocol': 'ipip',
                    'direction': 'ingress',
                    'remote_ip_prefix': None}
            rules = [rule]
            section_id = 'section-id'
            group_id = 'nsgroup-id'
            target_id = 'dummy'
            self.nsxlib.firewall_section.create_rules(
                None, section_id, group_id, False,
                "ALLOW", rules, {rule_id: target_id})
            add_rules.assert_called_once_with([
                {'display_name': mock.ANY,
                 'ip_protocol': 'IPV4',
                 'direction': 'IN',
                 'services': [{'service': {
                     'resource_type': 'IPProtocolNSService',
                     'protocol_number': 4}}],
                 'disabled': False,
                 'sources': [{'target_id': target_id,
                              'target_type': 'NSGroup'}],
                 'destinations': [{'target_id': group_id,
                                   'target_type': 'NSGroup'}],
                 'logged': False, 'action': 'ALLOW'}], section_id)

    def test_create_rules_ingress_with_port(self):
        with mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection"
                        ".add_rules") as add_rules:
            rule_id = uuidutils.generate_uuid()
            rule = {'id': rule_id,
                    'ethertype': 'IPv4',
                    'protocol': 'tcp',
                    'direction': 'ingress',
                    'port_range_min': 80,
                    'port_range_max': 80,
                    'remote_ip_prefix': None}
            rules = [rule]
            section_id = 'section-id'
            group_id = 'nsgroup-id'
            target_id = 'dummy'
            self.nsxlib.firewall_section.create_rules(
                None, section_id, group_id, False,
                "ALLOW", rules, {rule_id: target_id})
            add_rules.assert_called_once_with([
                {'display_name': mock.ANY,
                 'ip_protocol': 'IPV4',
                 'direction': 'IN',
                 'services': [{'service': {
                     'l4_protocol': 'TCP',
                     'destination_ports': ['80'],
                     'source_ports': [],
                     'resource_type': 'L4PortSetNSService'}}],
                 'disabled': False,
                 'sources': [{'target_id': target_id,
                              'target_type': 'NSGroup'}],
                 'destinations': [{'target_id': group_id,
                                   'target_type': 'NSGroup'}],
                 'logged': False, 'action': 'ALLOW'}], section_id)

    def test_create_rules_egress_with_port(self):
        with mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection"
                        ".add_rules") as add_rules:
            rule_id = uuidutils.generate_uuid()
            rule = {'id': rule_id,
                    'ethertype': 'IPv4',
                    'protocol': 'tcp',
                    'direction': 'egress',
                    'port_range_min': 80,
                    'port_range_max': 80,
                    'remote_ip_prefix': None}
            rules = [rule]
            section_id = 'section-id'
            group_id = 'nsgroup-id'
            target_id = 'dummy'
            self.nsxlib.firewall_section.create_rules(
                None, section_id, group_id, False,
                "ALLOW", rules, {rule_id: target_id})
            add_rules.assert_called_once_with([
                {'display_name': mock.ANY,
                 'ip_protocol': 'IPV4',
                 'direction': 'OUT',
                 'services': [{'service': {
                     'l4_protocol': 'TCP',
                     'destination_ports': ['80'],
                     'source_ports': [],
                     'resource_type': 'L4PortSetNSService'}}],
                 'disabled': False,
                 'destinations': [{'target_id': target_id,
                                   'target_type': 'NSGroup'}],
                 'sources': [{'target_id': group_id,
                              'target_type': 'NSGroup'}],
                 'logged': False, 'action': 'ALLOW'}], section_id)

    def test_create_rule_with_illegal_protocol(self):
        rule_id = uuidutils.generate_uuid()
        rule = {'id': rule_id,
                'ethertype': 'IPv4',
                'protocol': 'bad',
                'direction': 'ingress',
                'remote_ip_prefix': None}
        rules = [rule]
        self.assertRaises(nsxlib_exc.InvalidInput,
                          self.nsxlib.firewall_section.create_section_rules,
                          'section-id', 'nsgroup-id', False,
                          "ALLOW", rules, {rule_id: 'dummy'})

    def test_create_rule_with_icmp(self):
        nsx_ver = ["2.3.0", "2.4.0"]
        for nsx_ver in nsx_ver:
            with mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection"
                            ".add_rules") as add_rules:
                with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                                return_value=nsx_ver):
                    rule_id = uuidutils.generate_uuid()
                    rule = {'id': rule_id,
                            'ethertype': 'IPv4',
                            'protocol': 'icmp',
                            'direction': 'egress',
                            'port_range_min': 33,
                            'port_range_max': 0,
                            'remote_ip_prefix': None}
                    rules = [rule]
                    section_id = 'section-id'
                    group_id = 'nsgroup-id'
                    target_id = 'dummy'
                    self.nsxlib.firewall_section.create_rules(
                        None, section_id, group_id, False,
                        "ALLOW", rules, {rule_id: target_id})
                    add_rules.assert_called_once_with([
                        {'display_name': mock.ANY,
                            'ip_protocol': 'IPV4',
                            'direction': 'OUT',
                            'services': [{'service': {
                                'protocol': 'ICMPv4',
                                'icmp_type': 33,
                                'icmp_code': 0,
                                'resource_type': 'ICMPTypeNSService'}}],
                            'disabled': False,
                            'destinations': [{'target_id': target_id,
                                              'target_type': 'NSGroup'}],
                            'sources': [{'target_id': group_id,
                                        'target_type': 'NSGroup'}],
                            'logged': False, 'action': 'ALLOW'}], section_id)

    def test_create_rule_with_illegal_icmp(self):
        rule_id = uuidutils.generate_uuid()
        rule = {'id': rule_id,
                'ethertype': 'IPv4',
                'protocol': 'icmp',
                'direction': 'egress',
                'port_range_min': 2,
                'port_range_max': 3,
                'remote_ip_prefix': None}
        rules = [rule]
        section_id = 'section-id'
        group_id = 'nsgroup-id'
        target_id = 'dummy'
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value="2.3.0"):
            self.assertRaises(nsxlib_exc.InvalidInput,
                              self.nsxlib.firewall_section.create_rules,
                              None, section_id, group_id, False,
                              "ALLOW", rules, {rule_id: target_id})
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value="2.4.0"):
            self.assertRaises(nsxlib_exc.InvalidInput,
                              self.nsxlib.firewall_section.create_rules,
                              None, section_id, group_id, False,
                              "ALLOW", rules, {rule_id: target_id})

    def test_create_rule_with_illegal_icmp_2_4(self):
        rule_id = uuidutils.generate_uuid()
        rule = {'id': rule_id,
                'ethertype': 'IPv4',
                'protocol': 'icmp',
                'direction': 'egress',
                'port_range_min': 9,
                'port_range_max': 16,
                'remote_ip_prefix': None}
        rules = [rule]
        section_id = 'section-id'
        group_id = 'nsgroup-id'
        target_id = 'dummy'
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value="2.4.0"):
            self.assertRaises(nsxlib_exc.InvalidInput,
                              self.nsxlib.firewall_section.create_rules,
                              None, section_id, group_id, False,
                              "ALLOW", rules, {rule_id: target_id})

    def test_create_with_rules(self):
        expected_body = {
            'display_name': 'display-name',
            'description': 'section-description',
            'stateful': True,
            'section_type': "LAYER3",
            'applied_tos': [],
            'rules': [{
                'display_name': 'rule-name',
                'direction': 'IN_OUT',
                'ip_protocol': "IPV4_IPV6",
                'action': "ALLOW",
                'logged': False,
                'disabled': False,
                'sources': [],
                'destinations': [],
                'services': []
            }],
            'tags': []
        }
        with mock.patch.object(self.nsxlib.client, 'create') as create:
            rule = self.nsxlib.firewall_section.get_rule_dict('rule-name')
            self.nsxlib.firewall_section.create_with_rules(
                'display-name', 'section-description', rules=[rule])
            resource = 'firewall/sections?operation=insert_bottom' \
                '&action=create_with_rules'
            create.assert_called_with(resource, expected_body, headers=None)

    def test_get_excludelist(self):
        with mock.patch.object(self.nsxlib.client, 'list') as clist:
            self.nsxlib.firewall_section.get_excludelist()
            clist.assert_called_with('firewall/excludelist')

    def test_update(self):
        fws_tags = [{"scope": "name", "tag": "new_name"}]
        with mock.patch.object(self.nsxlib.client, 'update') as update:
            with mock.patch.object(self.nsxlib.client, 'get') as get:
                get.return_value = {}
                self.nsxlib.firewall_section.update('fw_section_id',
                                                    tags_update=fws_tags)
                resource = 'firewall/sections/%s' % 'fw_section_id'
                data = {'tags': fws_tags}
                update.assert_called_with(resource, data, headers=None)


class TestNsxLibIPSet(nsxlib_testcase.NsxClientTestCase):
    """Tests for vmware_nsxlib.v3.security.NsxLibIPSet"""

    def test_get_ipset_reference(self):
        mock_ip_set = uuidutils.generate_uuid()
        result = self.nsxlib.ip_set.get_ipset_reference(
            mock_ip_set)
        expected = {
            'target_id': mock_ip_set,
            'target_type': const.IP_SET
        }
        self.assertEqual(expected, result)

    def test_create_ip_set(self):
        fake_ip_set = test_constants.FAKE_IP_SET.copy()
        data = {
            'display_name': fake_ip_set['display_name'],
            'ip_addresses': fake_ip_set['ip_addresses'],
            'description': 'ipset-desc',
            'tags': []
        }
        with mock.patch.object(self.nsxlib.client, 'create') as create:
            self.nsxlib.ip_set.create(
                fake_ip_set['display_name'], 'ipset-desc',
                ip_addresses=fake_ip_set['ip_addresses'])
            resource = 'ip-sets'
            create.assert_called_with(resource, data)

    def test_delete_ip_set(self):
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_ip_set = test_constants.FAKE_IP_SET.copy()
            self.nsxlib.ip_set.delete(fake_ip_set['id'])
            delete.assert_called_with('ip-sets/%s' % fake_ip_set['id'])

    def test_update_ip_set(self):
        fake_ip_set = test_constants.FAKE_IP_SET.copy()
        new_ip_addresses = ['10.0.0.0']
        data = {
            'id': fake_ip_set['id'],
            'display_name': fake_ip_set['display_name'],
            'ip_addresses': new_ip_addresses,
            'resource_type': 'IPSet'
        }
        with mock.patch.object(self.nsxlib.client, 'get',
                               return_value=fake_ip_set):
            with mock.patch.object(self.nsxlib.client, 'update') as update:
                self.nsxlib.ip_set.update(
                    fake_ip_set['id'], ip_addresses=new_ip_addresses)
                resource = 'ip-sets/%s' % fake_ip_set['id']
                update.assert_called_with(resource, data, headers=None)

    def test_update_ip_set_empty_ip_addresses(self):
        fake_ip_set = test_constants.FAKE_IP_SET.copy()
        new_ip_addresses = []
        data = {
            'id': fake_ip_set['id'],
            'display_name': fake_ip_set['display_name'],
            'ip_addresses': new_ip_addresses,
            'resource_type': 'IPSet'
        }
        with mock.patch.object(self.nsxlib.client, 'get',
                               return_value=fake_ip_set):
            with mock.patch.object(self.nsxlib.client, 'update') as update:
                self.nsxlib.ip_set.update(
                    fake_ip_set['id'], ip_addresses=new_ip_addresses)
                resource = 'ip-sets/%s' % fake_ip_set['id']
                update.assert_called_with(resource, data, headers=None)


class TestNsxLibNSGroup(nsxlib_testcase.NsxClientTestCase):
    """Tests for vmware_nsxlib.v3.security.NsxLibNSGroup"""

    def test_get_nsgroup_complex_expression(self):
        port_tags = {'app': 'foo', 'project': 'myproject'}
        port_exp = [self.nsxlib.ns_group.get_port_tag_expression(k, v)
                    for k, v in six.iteritems(port_tags)]
        complex_exp = self.nsxlib.ns_group.get_nsgroup_complex_expression(
            expressions=port_exp)
        expected_exp = {'resource_type': const.NSGROUP_COMPLEX_EXP,
                        'expressions': port_exp}
        self.assertEqual(expected_exp, complex_exp)

    def test_update(self):
        nsg_tags = [{"scope": "name", "tag": "new_name"}]
        membership_criteria = []
        with mock.patch.object(self.nsxlib.client, 'update') as update:
            with mock.patch.object(self.nsxlib.client, 'get') as get:
                get.return_value = {}
                self.nsxlib.ns_group.update(
                    'nsgroupid', tags_update=nsg_tags,
                    membership_criteria=membership_criteria)
                resource = 'ns-groups/nsgroupid'
                data = {'tags': nsg_tags,
                        'membership_criteria': membership_criteria}
                update.assert_called_with(resource, data, headers=None)

    def test_update_nsgroup_and_section(self):
        security_group = {
            'name': 'name',
            'id': uuidutils.generate_uuid(),
            'description': None,
            'logging': False}
        nsgroup_id = uuidutils.generate_uuid()
        section_id = uuidutils.generate_uuid()
        log_sg_allowed_traffic = True

        with mock.patch.object(self.nsxlib.client, 'update') as update_mock,\
            mock.patch.object(self.nsxlib.client, 'get') as get_mock:
            self.nsxlib.ns_group.update_nsgroup_and_section(
                security_group, nsgroup_id, section_id,
                log_sg_allowed_traffic)
            # updating the nsgroup and the section
            self.assertEqual(2, update_mock.call_count)
            # getting the rules, and get before each update
            self.assertEqual(3, get_mock.call_count)

    def test_update_lport_nsgroups(self):
        nsgroup_id1 = uuidutils.generate_uuid()
        nsgroup_id2 = uuidutils.generate_uuid()
        lport_id = uuidutils.generate_uuid()
        original_nsgroups = [nsgroup_id1]
        updated_nsgroups = [nsgroup_id2]

        with mock.patch('vmware_nsxlib.v3.security.NsxLibNsGroup.'
                        'remove_member') as remove_mock,\
            mock.patch('vmware_nsxlib.v3.security.NsxLibNsGroup.'
                       'add_members') as add_mock:
            self.nsxlib.ns_group.update_lport_nsgroups(
                lport_id, original_nsgroups, updated_nsgroups)
            add_mock.assert_called_once_with(nsgroup_id2, 'LogicalPort',
                                             [lport_id])
            remove_mock.assert_called_once_with(nsgroup_id1, 'LogicalPort',
                                                lport_id)
