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
#
from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.v3 import client
from vmware_nsxlib.v3 import policy_constants
from vmware_nsxlib.v3 import policy_defs as policy

BASE_POLICY_URI = "https://1.2.3.4/policy/api/v1/"


class TestPolicyApi(nsxlib_testcase.NsxClientTestCase):

    def setUp(self):
        self.client = self.new_mocked_client(client.NSX3Client,
                                             url_prefix='policy/api/v1/')
        self.policy_api = policy.NsxPolicyApi(self.client)

        super(TestPolicyApi, self).setUp()

    def assert_json_call(self, method, client, url, data=None):
        url = BASE_POLICY_URI + url
        return super(TestPolicyApi, self).assert_json_call(
            method, client, url, data=data)


class TestPolicyDomain(TestPolicyApi):

    def test_create(self):
        domain_def = policy.DomainDef(
            'archaea',
            'prokaryotic cells',
            'typically characterized by membrane lipids')
        self.policy_api.create_or_update(domain_def)
        self.assert_json_call('PATCH', self.client,
                              'infra/domains/archaea',
                              data=domain_def.get_obj_dict())

    def test_delete(self):
        domain_def = policy.DomainDef('bacteria')
        self.policy_api.delete(domain_def)
        self.assert_json_call('DELETE', self.client,
                              'infra/domains/bacteria')

    def test_get(self):
        domain_def = policy.DomainDef('eukarya')
        self.policy_api.get(domain_def)
        self.assert_json_call('GET', self.client,
                              'infra/domains/eukarya')

    def test_list(self):
        domain_def = policy.DomainDef()
        self.policy_api.list(domain_def)
        self.assert_json_call('GET', self.client, 'infra/domains')


class TestPolicyGroup(TestPolicyApi):

    def test_create(self):
        group_def = policy.GroupDef(
            'eukarya',
            'cats',
            'felis catus')
        self.policy_api.create_or_update(group_def)
        self.assert_json_call('PATCH', self.client,
                              'infra/domains/eukarya/groups/cats',
                              data=group_def.get_obj_dict())

    def test_create_with_domain(self):
        domain_def = policy.DomainDef('eukarya',
                                      'eukarya',
                                      'dude with cell membranes')
        group_def = policy.GroupDef('eukarya',
                                    'cats',
                                    'Ailuropoda melanoleuca')

        self.policy_api.create_with_parent(domain_def, group_def)
        data = domain_def.get_obj_dict()
        data['groups'] = [group_def.get_obj_dict()]
        self.assert_json_call('PATCH', self.client,
                              'infra/domains/eukarya',
                              data=data)

    def test_create_with_single_tag(self):
        domain_def = policy.DomainDef('eukarya')
        group_def = policy.GroupDef('eukarya', 'dogs',
                                    conditions=policy.Condition('spaniel'))
        self.policy_api.create_with_parent(domain_def, group_def)
        data = domain_def.get_obj_dict()
        data['groups'] = [group_def.get_obj_dict()]

        # validate body structure and defaults
        expected_condition = {'value': 'spaniel',
                              'operator': 'EQUALS',
                              'member_type': 'LogicalPort',
                              'resource_type': 'Condition',
                              'key': 'Tag'}
        expected_group = {'id': 'dogs',
                          'display_name': None,
                          'description': None,
                          'expression': [expected_condition]}
        expected_data = {'id': 'eukarya',
                         'display_name': None,
                         'description': None,
                         'groups': [expected_group]}
        self.assert_json_call('PATCH', self.client,
                              'infra/domains/eukarya',
                              data=expected_data)

    def test_create_with_multi_tag(self):
        domain_def = policy.DomainDef('eukarya')
        pines = policy.Condition(
            'pine',
            operator=policy_constants.CONDITION_OP_CONTAINS)
        maples = policy.Condition(
            'maple',
            operator=policy_constants.CONDITION_OP_STARTS_WITH)
        group_def = policy.GroupDef('eukarya', 'trees',
                                    conditions=[pines, maples])
        self.policy_api.create_with_parent(domain_def, group_def)
        data = domain_def.get_obj_dict()
        data['groups'] = [group_def.get_obj_dict()]
        self.assert_json_call('PATCH', self.client,
                              'infra/domains/eukarya',
                              data=data)

    def test_delete(self):
        group_def = policy.GroupDef(domain_id='eukarya', group_id='giraffe')
        self.policy_api.delete(group_def)
        self.assert_json_call('DELETE', self.client,
                              'infra/domains/eukarya/groups/giraffe')


class TestPolicyService(TestPolicyApi):

    def test_create(self):
        service_def = policy.ServiceDef('roomservice')
        self.policy_api.create_or_update(service_def)
        self.assert_json_call('PATCH', self.client,
                              'infra/services/roomservice',
                              data=service_def.get_obj_dict())

    def test_create_l4_with_parent(self):
        service_def = policy.ServiceDef('roomservice')
        entry_def = policy.L4ServiceEntryDef('roomservice',
                                             'http',
                                             name='room http',
                                             dest_ports=[80, 8080])

        self.policy_api.create_with_parent(service_def, entry_def)
        expected_entry = {'id': 'http',
                          'resource_type': 'L4PortSetServiceEntry',
                          'display_name': 'room http',
                          'description': None,
                          'l4_protocol': 'TCP',
                          'destination_ports': [80, 8080]}
        expected_data = {'id': 'roomservice',
                         'display_name': None,
                         'description': None,
                         'service_entries': [expected_entry]}
        self.assert_json_call('PATCH', self.client,
                              'infra/services/roomservice',
                              data=expected_data)

    def test_create_icmp_with_parent(self):
        service_def = policy.ServiceDef('icmpservice')
        entry_def = policy.IcmpServiceEntryDef('icmpservice',
                                               'icmp',
                                               name='icmpv4')

        self.policy_api.create_with_parent(service_def, entry_def)
        expected_entry = {'id': 'icmp',
                          'resource_type': 'ICMPTypeServiceEntry',
                          'display_name': 'icmpv4',
                          'description': None,
                          'protocol': 'ICMPv4'}
        expected_data = {'id': 'icmpservice',
                         'display_name': None,
                         'description': None,
                         'service_entries': [expected_entry]}
        self.assert_json_call('PATCH', self.client,
                              'infra/services/icmpservice',
                              data=expected_data)


class TestPolicyCommunicationMap(TestPolicyApi):

    def setUp(self):
        super(TestPolicyCommunicationMap, self).setUp()
        self.entry1 = policy.CommunicationMapEntryDef(
            'd1', 'cm1', 'en1',
            sequence_number=12,
            source_groups=["group1",
                           "group2"],
            dest_groups=["group1"],
            service_id="service1")

        self.entry2 = policy.CommunicationMapEntryDef(
            'd1', 'cm2', 'en2',
            sequence_number=13,
            source_groups=["group1",
                           "group2"],
            dest_groups=["group3"],
            service_id="service2")

        self.expected_data1 = {'id': 'en1',
                               'display_name': None,
                               'description': None,
                               'sequence_number': 12,
                               'action': 'ALLOW',
                               'scope': ['ANY'],
                               'source_groups':
                               ['/infra/domains/d1/groups/group1',
                                '/infra/domains/d1/groups/group2'],
                               'destination_groups':
                               ['/infra/domains/d1/groups/group1'],
                               'services':
                               ['/infra/services/service1']}

        self.expected_data2 = {'id': 'en2',
                               'display_name': None,
                               'description': None,
                               'sequence_number': 13,
                               'action': 'ALLOW',
                               'scope': ['ANY'],
                               'source_groups':
                               ['/infra/domains/d1/groups/group1',
                                '/infra/domains/d1/groups/group2'],
                               'destination_groups':
                               ['/infra/domains/d1/groups/group3'],
                               'services':
                               ['/infra/services/service2']}

    def test_create_with_one_entry(self):
        map_def = policy.CommunicationMapDef(domain_id='d1', map_id='cm1')

        self.policy_api.create_with_parent(map_def, self.entry1)
        expected_data = map_def.get_obj_dict()
        expected_data['communication_entries'] = [self.expected_data1]
        self.assert_json_call('PATCH', self.client,
                              'infra/domains/d1/communication-maps/cm1',
                              data=expected_data)

    def test_create_with_two_entries(self):
        map_def = policy.CommunicationMapDef(domain_id='d1', map_id='cm1')

        self.policy_api.create_with_parent(map_def,
                                           [self.entry1, self.entry2])
        expected_data = map_def.get_obj_dict()
        expected_data['communication_entries'] = [self.expected_data1,
                                                  self.expected_data2]
        self.assert_json_call('PATCH', self.client,
                              'infra/domains/d1/communication-maps/cm1',
                              data=expected_data)

    def test_update_entry(self):
        self.policy_api.create_or_update(self.entry1)

        self.assert_json_call('PATCH', self.client,
                              'infra/domains/d1/communication-maps/cm1/'
                              'communication-entries/en1',
                              data=self.expected_data1)

    def test_delete_entry(self):
        self.policy_api.delete(self.entry2)

        self.assert_json_call('DELETE', self.client,
                              'infra/domains/d1/communication-maps/cm2/'
                              'communication-entries/en2')


class TestPolicyEnforcementPoint(TestPolicyApi):

    def test_create(self):
        ep_def = policy.EnforcementPointDef('ep1', name='The Point',
                                            ip_address='1.1.1.1',
                                            username='admin',
                                            password='a')

        self.policy_api.create_or_update(ep_def)
        ep_path = policy.EnforcementPointDef('ep1').get_resource_path()
        self.assert_json_call('PATCH', self.client,
                              ep_path,
                              data=ep_def.get_obj_dict())


class TestPolicyDeploymentMap(TestPolicyApi):

    def test_create(self):
        map_def = policy.DeploymentMapDef('dm1', domain_id='d1', ep_id='ep1')

        self.policy_api.create_or_update(map_def)
        ep_path = policy.EnforcementPointDef('ep1').get_resource_full_path()
        expected_data = {'id': 'dm1',
                         'display_name': None,
                         'description': None,
                         'enforcement_point_path': ep_path}

        self.assert_json_call('PATCH', self.client,
                              'infra/domains/d1/domain-deployment-maps/dm1',
                              data=expected_data)
