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

import mock

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.tests.unit.v3 import policy_testcase
from vmware_nsxlib import v3
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import policy_constants
from vmware_nsxlib.v3 import policy_defs

TEST_TENANT = 'test'


class NsxPolicyLibTestCase(policy_testcase.TestPolicyApi):

    def setUp(self, *args, **kwargs):
        super(NsxPolicyLibTestCase, self).setUp()

        nsxlib_config = nsxlib_testcase.get_default_nsxlib_config()
        # Mock the nsx-lib for the passthrough api
        with mock.patch('vmware_nsxlib.v3.NsxLib'):
            self.policy_lib = v3.NsxPolicyLib(nsxlib_config)
        self.policy_api = self.policy_lib.policy_api
        self.policy_api.client = self.client

        self.maxDiff = None

    def _compare_def(self, expected_def, actual_def):
        # verify the resource definition class
        self.assertEqual(expected_def.__class__, actual_def.__class__)
        # verify the resource definition tenant
        self.assertEqual(expected_def.get_tenant(), actual_def.get_tenant())
        # verify the resource definition values
        self.assertEqual(expected_def.get_obj_dict(),
                         actual_def.get_obj_dict())

    def assert_called_with_def(self, mock_api, expected_def, call_num=0):
        # verify the api was called
        mock_api.assert_called()
        actual_def = mock_api.call_args_list[call_num][0][0]
        self._compare_def(expected_def, actual_def)

    def assert_called_with_defs(self, mock_api, expected_defs, call_num=0):
        # verify the api & first resource definition
        self.assert_called_with_def(mock_api, expected_defs[0],
                                    call_num=call_num)
        # compare the 2nd resource definition class & values
        def_list = mock_api.call_args_list[call_num][0][1]
        if not isinstance(def_list, list):
            def_list = [def_list]

        for i in range(1, len(expected_defs)):
            actual_def = def_list[i - 1]
            expected_def = expected_defs[i]
            self._compare_def(expected_def, actual_def)

    def assert_called_with_def_and_dict(self, mock_api,
                                        expected_def, expected_dict,
                                        call_num=0):
        # verify the api & resource definition
        self.assert_called_with_def(mock_api, expected_def,
                                    call_num=call_num)
        # compare the 2nd api parameter which is a dictionary
        actual_dict = mock_api.call_args_list[call_num][0][0].body
        self.assertEqual(expected_dict, actual_dict)


class TestPolicyDomain(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyDomain, self).setUp()
        self.resourceApi = self.policy_lib.domain

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        id = '111'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite(name,
                                                 domain_id=id,
                                                 description=description,
                                                 tenant=TEST_TENANT)
            expected_def = policy_defs.DomainDef(domain_id=id,
                                                 name=name,
                                                 description=description,
                                                 tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite(name, description=description,
                                                 tenant=TEST_TENANT)
            expected_def = policy_defs.DomainDef(domain_id=mock.ANY,
                                                 name=name,
                                                 description=description,
                                                 tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_delete(self):
        id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(id, tenant=TEST_TENANT)
            expected_def = policy_defs.DomainDef(domain_id=id,
                                                 tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        id = '111'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(id, tenant=TEST_TENANT)
            expected_def = policy_defs.DomainDef(domain_id=id,
                                                 tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = policy_defs.DomainDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = policy_defs.DomainDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        id = '111'
        name = 'new name'
        description = 'new desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.DomainDef(domain_id=id,
                                                 name=name,
                                                 description=description,
                                                 tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)

    def test_unset(self):
        domain_id = '111'
        self.resourceApi.update(domain_id,
                                description=None,
                                tags=None,
                                tenant=TEST_TENANT)

        expected_body = {'id': domain_id,
                         'resource_type': 'Domain',
                         'description': None,
                         'tags': None}

        self.assert_json_call('PATCH', self.client,
                              '%s/domains/%s' % (TEST_TENANT, domain_id),
                              data=expected_body)


class TestPolicyGroup(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyGroup, self).setUp()
        self.resourceApi = self.policy_lib.group

    def test_create_with_id(self):
        domain_id = '111'
        name = 'g1'
        description = 'desc'
        id = '222'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite(name,
                                                 domain_id,
                                                 group_id=id,
                                                 description=description,
                                                 tenant=TEST_TENANT)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=id,
                                                name=name,
                                                description=description,
                                                conditions=[],
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_create_without_id(self):
        domain_id = '111'
        name = 'g1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite(name, domain_id,
                                                 description=description,
                                                 tenant=TEST_TENANT)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=mock.ANY,
                                                name=name,
                                                description=description,
                                                conditions=[],
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_create_with_condition(self):
        domain_id = '111'
        name = 'g1'
        description = 'desc'
        cond_val = '123'
        cond_op = policy_constants.CONDITION_OP_EQUALS
        cond_member_type = policy_constants.CONDITION_MEMBER_VM
        cond_key = policy_constants.CONDITION_KEY_TAG
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite(
                name, domain_id, description=description,
                cond_val=cond_val,
                cond_op=cond_op,
                cond_member_type=cond_member_type,
                cond_key=cond_key,
                tenant=TEST_TENANT)
            exp_cond = policy_defs.Condition(value=cond_val,
                                             key=cond_key,
                                             operator=cond_op,
                                             member_type=cond_member_type)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=mock.ANY,
                                                name=name,
                                                description=description,
                                                conditions=[exp_cond],
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_create_with_simple_condition(self):
        domain_id = '111'
        name = 'g1'
        description = 'desc'
        cond_val = '123'
        cond_op = policy_constants.CONDITION_OP_EQUALS
        cond_member_type = policy_constants.CONDITION_MEMBER_VM
        cond_key = policy_constants.CONDITION_KEY_TAG

        cond = self.resourceApi.build_condition(
            cond_val=cond_val,
            cond_op=cond_op,
            cond_member_type=cond_member_type,
            cond_key=cond_key)

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite_with_conditions(
                name, domain_id, description=description,
                conditions=[cond],
                tenant=TEST_TENANT)
            exp_cond = policy_defs.Condition(value=cond_val,
                                             key=cond_key,
                                             operator=cond_op,
                                             member_type=cond_member_type)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=mock.ANY,
                                                name=name,
                                                description=description,
                                                conditions=[exp_cond],
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_create_with_nested_condition(self):
        domain_id = '111'
        name = 'g1'
        description = 'desc'
        cond_val1 = '123'
        cond_val2 = '456'
        cond_op = policy_constants.CONDITION_OP_EQUALS
        cond_member_type = policy_constants.CONDITION_MEMBER_VM
        cond_key = policy_constants.CONDITION_KEY_TAG

        cond1 = self.resourceApi.build_condition(
            cond_val=cond_val1,
            cond_op=cond_op,
            cond_member_type=cond_member_type,
            cond_key=cond_key)
        cond2 = self.resourceApi.build_condition(
            cond_val=cond_val2,
            cond_op=cond_op,
            cond_member_type=cond_member_type,
            cond_key=cond_key)
        nested = self.resourceApi.build_nested_condition(
            conditions=[cond1, cond2])

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite_with_conditions(
                name, domain_id, description=description,
                conditions=[nested],
                tenant=TEST_TENANT)
            exp_cond1 = policy_defs.Condition(value=cond_val1,
                                              key=cond_key,
                                              operator=cond_op,
                                              member_type=cond_member_type)
            exp_cond2 = policy_defs.Condition(value=cond_val2,
                                              key=cond_key,
                                              operator=cond_op,
                                              member_type=cond_member_type)
            and_cond = policy_defs.ConjunctionOperator()
            nested_cond = policy_defs.NestedExpression(
                expressions=[exp_cond1, and_cond, exp_cond2])
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=mock.ANY,
                                                name=name,
                                                description=description,
                                                conditions=[nested_cond],
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_create_with_ip_expression(self):
        domain_id = '111'
        name = 'g1'
        description = 'desc'
        cidr = '1.1.1.0/24'

        cond = self.resourceApi.build_ip_address_expression([cidr])

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite_with_conditions(
                name, domain_id, description=description,
                conditions=[cond],
                tenant=TEST_TENANT)
            exp_cond = policy_defs.IPAddressExpression([cidr])
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=mock.ANY,
                                                name=name,
                                                description=description,
                                                conditions=[exp_cond],
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_delete(self):
        domain_id = '111'
        id = '222'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(domain_id, id, tenant=TEST_TENANT)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        domain_id = '111'
        id = '222'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(domain_id, id, tenant=TEST_TENANT)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_by_name(self):
        domain_id = '111'
        name = 'g1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(domain_id, name,
                                               tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        domain_id = '111'
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(domain_id, tenant=TEST_TENANT)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        domain_id = '111'
        id = '222'
        name = 'new name'
        description = 'new desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(domain_id, id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=id,
                                                name=name,
                                                description=description,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(
                update_call, expected_def)

    def test_unset(self):
        domain_id = '111'
        group_id = '222'
        description = 'new'

        self.resourceApi.update(domain_id,
                                group_id,
                                name=None,
                                description=description,
                                tenant=TEST_TENANT)

        expected_body = {'id': group_id,
                         'resource_type': 'Group',
                         'display_name': None,
                         'description': description}

        self.assert_json_call('PATCH', self.client,
                              '%s/domains/%s/groups/%s' % (TEST_TENANT,
                                                           domain_id,
                                                           group_id),
                              data=expected_body)

    def test_get_realized(self):
        domain_id = 'd1'
        group_id = 'g1'
        result = [{'state': policy_constants.STATE_REALIZED,
                   'entity_type': 'RealizedGroup'}]
        with mock.patch.object(
            self.policy_api, "get_realized_entities",
            return_value=result) as api_get:
            state = self.resourceApi.get_realized_state(
                domain_id, group_id, tenant=TEST_TENANT)
            self.assertEqual(policy_constants.STATE_REALIZED, state)
            path = "/%s/domains/%s/groups/%s" % (
                TEST_TENANT, domain_id, group_id)
            api_get.assert_called_once_with(path)

    def test_get_realized_multiple_results(self):
        domain_id = 'd1'
        group_id = 'g1'
        result = [{'state': policy_constants.STATE_UNREALIZED,
                   'entity_type': 'NotRealizedGroup'},
                  {'state': policy_constants.STATE_REALIZED,
                   'entity_type': 'RealizedGroup'}]
        with mock.patch.object(
            self.policy_api, "get_realized_entities",
            return_value=result) as api_get:
            state = self.resourceApi.get_realized_state(
                domain_id, group_id, tenant=TEST_TENANT)
            self.assertEqual(policy_constants.STATE_REALIZED, state)
            path = "/%s/domains/%s/groups/%s" % (
                TEST_TENANT, domain_id, group_id)
            api_get.assert_called_once_with(path)

    def test_get_realized_id(self):
        domain_id = 'd1'
        group_id = 'g1'
        realized_id = 'realized_111'
        result = [{'state': policy_constants.STATE_REALIZED,
                   'entity_type': 'RealizedGroup',
                   'realization_specific_identifier': realized_id}]
        with mock.patch.object(
            self.policy_api, "get_realized_entities",
            return_value=result) as api_get:
            result_id = self.resourceApi.get_realized_id(
                domain_id, group_id, tenant=TEST_TENANT)
            self.assertEqual(realized_id, result_id)
            path = "/%s/domains/%s/groups/%s" % (
                TEST_TENANT, domain_id, group_id)
            api_get.assert_called_once_with(path)


class TestPolicyService(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyService, self).setUp()
        self.resourceApi = self.policy_lib.service

    def test_create(self):
        name = 's1'
        description = 'desc'
        protocol = policy_constants.TCP
        dest_ports = [81, 82]
        tags = [{'scope': 'a', 'tag': 'b'}]
        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call:
            self.resourceApi.create_or_overwrite(name,
                                                 description=description,
                                                 protocol=protocol,
                                                 dest_ports=dest_ports,
                                                 tags=tags,
                                                 tenant=TEST_TENANT)
            exp_srv_def = policy_defs.ServiceDef(service_id=mock.ANY,
                                                 name=name,
                                                 description=description,
                                                 tags=tags,
                                                 tenant=TEST_TENANT)
            exp_entry_def = policy_defs.L4ServiceEntryDef(
                service_id=mock.ANY,
                entry_id='entry',
                name='entry',
                protocol=protocol,
                dest_ports=dest_ports,
                tenant=TEST_TENANT)
            self.assert_called_with_defs(
                api_call, [exp_srv_def, exp_entry_def])

    def test_delete(self):
        id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(id, tenant=TEST_TENANT)
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        id = '111'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(id, tenant=TEST_TENANT)
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_by_name(self):
        name = 's1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = policy_defs.ServiceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = policy_defs.ServiceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        id = '111'
        name = 'newName'
        description = 'new desc'
        protocol = 'tcp'
        tags = [{'scope': 'a', 'tag': 'b'}]
        entry_body = {'id': 'entry',
                      'l4_protocol': protocol}

        with mock.patch.object(self.policy_api,
                               "get",
                               return_value=entry_body),\
            mock.patch.object(self.policy_api,
                              "create_with_parent") as update_call:

            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    tags=tags,
                                    tenant=TEST_TENANT)
            service_def = policy_defs.ServiceDef(service_id=id,
                                                 name=name,
                                                 description=description,
                                                 tags=tags,
                                                 tenant=TEST_TENANT)
            entry_def = policy_defs.L4ServiceEntryDef(
                service_id=id,
                entry_id='entry',
                protocol=protocol,
                tenant=TEST_TENANT)
            self.assert_called_with_defs(update_call, [service_def, entry_def])

    def test_update_all(self):
        id = '111'
        name = 'newName'
        description = 'new desc'
        protocol = 'udp'
        dest_ports = [555]

        entry_body = {'id': 'entry',
                      'l4_protocol': 'tcp'}

        with mock.patch.object(self.policy_api,
                               "get",
                               return_value=entry_body),\
            mock.patch.object(self.policy_api,
                              "create_with_parent") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    protocol=protocol,
                                    dest_ports=dest_ports,
                                    tenant=TEST_TENANT)

            service_def = policy_defs.ServiceDef(service_id=id,
                                                 name=name,
                                                 description=description,
                                                 tenant=TEST_TENANT)
            entry_def = policy_defs.L4ServiceEntryDef(
                service_id=id,
                entry_id=mock.ANY,
                protocol=protocol,
                dest_ports=dest_ports,
                tenant=TEST_TENANT)

            self.assert_called_with_defs(
                update_call, [service_def, entry_def])

    def test_unset(self):
        name = 'hello'
        service_id = '111'

        # Until policy PATCH is fixed to accept partial update, we
        # call get on child entry
        with mock.patch.object(
            self.policy_api, "get",
            return_value={'display_name': name}):
            self.resourceApi.update(service_id,
                                    description=None,
                                    dest_ports=None,
                                    tenant=TEST_TENANT)

        expected_body = {'id': service_id,
                         'description': None,
                         'resource_type': 'Service',
                         'service_entries': [{
                             'display_name': name,
                             'id': 'entry',
                             'resource_type': 'L4PortSetServiceEntry',
                             'destination_ports': None}]
                         }

        self.assert_json_call('PATCH', self.client,
                              '%s/services/%s' % (TEST_TENANT, service_id),
                              data=expected_body)


class TestPolicyIcmpService(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyIcmpService, self).setUp()
        self.resourceApi = self.policy_lib.icmp_service

    def test_create(self):
        name = 's1'
        description = 'desc'
        icmp_type = 2
        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call:
            self.resourceApi.create_or_overwrite(name,
                                                 description=description,
                                                 icmp_type=icmp_type,
                                                 tenant=TEST_TENANT)
            exp_srv_def = policy_defs.ServiceDef(service_id=mock.ANY,
                                                 name=name,
                                                 description=description,
                                                 tenant=TEST_TENANT)
            exp_entry_def = policy_defs.IcmpServiceEntryDef(
                service_id=mock.ANY,
                entry_id='entry',
                name='entry',
                version=4,
                icmp_type=icmp_type,
                tenant=TEST_TENANT)
            self.assert_called_with_defs(
                api_call, [exp_srv_def, exp_entry_def])

    def test_delete(self):
        id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(id, tenant=TEST_TENANT)
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        id = '111'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(id, tenant=TEST_TENANT)
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_by_name(self):
        name = 's1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = policy_defs.ServiceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = policy_defs.ServiceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        id = '111'
        name = 'new_name'
        description = 'new desc'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': 'entry',
                                             'protocol': 'ICMPv4'}),\
            mock.patch.object(self.policy_api,
                              "create_with_parent") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)

            service_def = policy_defs.ServiceDef(service_id=id,
                                                 name=name,
                                                 description=description,
                                                 tenant=TEST_TENANT)

            entry_def = policy_defs.IcmpServiceEntryDef(
                service_id=id,
                entry_id='entry',
                version=4,
                tenant=TEST_TENANT)

            self.assert_called_with_defs(update_call, [service_def, entry_def])

    def test_update_all(self):
        id = '111'
        name = 'newName'
        description = 'new desc'
        version = 6
        icmp_type = 3
        icmp_code = 3

        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': 'entry'}),\
            mock.patch.object(self.policy_api,
                              "create_with_parent") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    version=version,
                                    icmp_type=icmp_type,
                                    icmp_code=icmp_code,
                                    tenant=TEST_TENANT)
            # get will be called for the entire service
            service_def = policy_defs.ServiceDef(service_id=id,
                                                 name=name,
                                                 description=description,
                                                 tenant=TEST_TENANT)
            entry_def = policy_defs.IcmpServiceEntryDef(
                service_id=id,
                entry_id=mock.ANY,
                version=version,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
                tenant=TEST_TENANT)

            self.assert_called_with_defs(
                update_call, [service_def, entry_def])


class TestPolicyIPProtocolService(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyIPProtocolService, self).setUp()
        self.resourceApi = self.policy_lib.ip_protocol_service

    def test_create(self):
        name = 's1'
        description = 'desc'
        protocol_number = 2
        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call:
            self.resourceApi.create_or_overwrite(
                name,
                description=description,
                protocol_number=protocol_number,
                tenant=TEST_TENANT)
            exp_srv_def = policy_defs.ServiceDef(service_id=mock.ANY,
                                                 name=name,
                                                 description=description,
                                                 tenant=TEST_TENANT)
            exp_entry_def = policy_defs.IPProtocolServiceEntryDef(
                service_id=mock.ANY,
                entry_id='entry',
                name='entry',
                protocol_number=protocol_number,
                tenant=TEST_TENANT)
            self.assert_called_with_defs(
                api_call, [exp_srv_def, exp_entry_def])

    def test_delete(self):
        id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(id, tenant=TEST_TENANT)
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        id = '111'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(id, tenant=TEST_TENANT)
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_by_name(self):
        name = 's1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = policy_defs.ServiceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = policy_defs.ServiceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        id = '111'
        name = 'new_name'
        description = 'new desc'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': 'entry'}),\
            mock.patch.object(self.policy_api,
                              "create_with_parent") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            service_def = policy_defs.ServiceDef(service_id=id,
                                                 name=name,
                                                 description=description,
                                                 tenant=TEST_TENANT)

            entry_def = policy_defs.IPProtocolServiceEntryDef(
                service_id=id,
                entry_id='entry',
                tenant=TEST_TENANT)

            self.assert_called_with_defs(update_call, [service_def, entry_def])

    def test_update_all(self):
        id = '111'
        name = 'newName'
        description = 'new desc'
        protocol_number = 3

        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': 'entry'}),\
            mock.patch.object(self.policy_api,
                              "create_with_parent") as service_update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    protocol_number=protocol_number,
                                    tenant=TEST_TENANT)

            service_def = policy_defs.ServiceDef(service_id=id,
                                                 name=name,
                                                 description=description,
                                                 tenant=TEST_TENANT)
            entry_def = policy_defs.IPProtocolServiceEntryDef(
                service_id=id,
                entry_id='entry',
                protocol_number=protocol_number,
                tenant=TEST_TENANT)

            self.assert_called_with_defs(service_update_call,
                                         [service_def, entry_def])


class TestPolicyCommunicationMap(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyCommunicationMap, self).setUp()
        self.resourceApi = self.policy_lib.comm_map

    def test_create_another(self):
        domain_id = '111'
        map_id = '222'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        seq_num = 7
        service_id = 'c1'
        direction = nsx_constants.IN_OUT
        get_return_value = {'rules': [{'sequence_number': 1}]}
        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call,\
            mock.patch.object(self.policy_api, "get",
                              return_value=get_return_value):
            self.resourceApi.create_or_overwrite(name, domain_id,
                                                 map_id=map_id,
                                                 description=description,
                                                 sequence_number=seq_num,
                                                 service_ids=[service_id],
                                                 source_groups=[source_group],
                                                 dest_groups=[dest_group],
                                                 direction=direction,
                                                 logged=True,
                                                 tenant=TEST_TENANT)
            map_def = policy_defs.CommunicationMapDef(
                domain_id=domain_id,
                map_id=map_id,
                name=name,
                description=description,
                category=policy_constants.CATEGORY_APPLICATION,
                tenant=TEST_TENANT)

            entry_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id='entry',
                name=name,
                action=policy_constants.ACTION_ALLOW,
                description=description,
                sequence_number=seq_num,
                service_ids=[service_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                direction=direction,
                logged=True,
                tenant=TEST_TENANT)
            self.assert_called_with_defs(api_call, [map_def, entry_def])

    def test_create_first_seqnum(self):
        domain_id = '111'
        map_id = '222'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        service_id = 'c1'
        category = 'Emergency'
        get_return_value = {'rules': []}
        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call, \
            mock.patch.object(self.resourceApi, "get",
                              return_value=get_return_value):
            self.resourceApi.create_or_overwrite(name, domain_id,
                                                 map_id=map_id,
                                                 description=description,
                                                 service_ids=[service_id],
                                                 source_groups=[source_group],
                                                 dest_groups=[dest_group],
                                                 category=category,
                                                 logged=False,
                                                 tenant=TEST_TENANT)

            map_def = policy_defs.CommunicationMapDef(
                domain_id=domain_id,
                map_id=map_id,
                name=name,
                description=description,
                category=category,
                tenant=TEST_TENANT)

            entry_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id='entry',
                name=name,
                action=policy_constants.ACTION_ALLOW,
                direction=nsx_constants.IN_OUT,
                description=description,
                sequence_number=1,
                service_ids=[service_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                logged=False,
                tenant=TEST_TENANT)
            self.assert_called_with_defs(api_call, [map_def, entry_def])

    def test_create_without_seqnum(self):
        domain_id = '111'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        service1_id = 'c1'
        service2_id = 'c2'
        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call:
            self.resourceApi.create_or_overwrite(name, domain_id,
                                                 description=description,
                                                 service_ids=[service1_id,
                                                              service2_id],
                                                 source_groups=[source_group],
                                                 dest_groups=[dest_group],
                                                 tenant=TEST_TENANT)

            expected_map_def = policy_defs.CommunicationMapDef(
                domain_id=domain_id,
                map_id=mock.ANY,
                name=name,
                description=description,
                category=policy_constants.CATEGORY_APPLICATION,
                tenant=TEST_TENANT)

            expected_entry_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=mock.ANY,
                entry_id=mock.ANY,
                action=policy_constants.ACTION_ALLOW,
                direction=nsx_constants.IN_OUT,
                name=name,
                description=description,
                sequence_number=1,
                service_ids=[service1_id, service2_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                tenant=TEST_TENANT)

            self.assert_called_with_defs(
                api_call,
                [expected_map_def, expected_entry_def])

    def test_create_map_only(self):
        domain_id = '111'
        name = 'cm1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite_map_only(
                name, domain_id, description=description,
                tenant=TEST_TENANT)

            expected_map_def = policy_defs.CommunicationMapDef(
                domain_id=domain_id,
                map_id=mock.ANY,
                name=name,
                description=description,
                category=policy_constants.CATEGORY_APPLICATION,
                tenant=TEST_TENANT)

            self.assert_called_with_def(
                api_call, expected_map_def)

    def test_create_entry(self):
        domain_id = '111'
        map_id = '333'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        service1_id = 'c1'
        service2_id = 'c2'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_entry(name=name,
                                          domain_id=domain_id,
                                          map_id=map_id,
                                          description=description,
                                          service_ids=[service1_id,
                                                       service2_id],
                                          source_groups=[source_group],
                                          dest_groups=[dest_group],
                                          sequence_number=1,
                                          direction=nsx_constants.IN,
                                          tenant=TEST_TENANT)

            expected_entry_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id=mock.ANY,
                name=name,
                action=policy_constants.ACTION_ALLOW,
                description=description,
                sequence_number=1,
                service_ids=[service1_id, service2_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                direction=nsx_constants.IN,
                logged=False,
                tenant=TEST_TENANT)

            self.assert_called_with_def(
                api_call, expected_entry_def)

    def test_create_entry_no_service(self):
        domain_id = '111'
        map_id = '333'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_entry(name, domain_id, map_id,
                                          description=description,
                                          source_groups=[source_group],
                                          dest_groups=[dest_group],
                                          sequence_number=1,
                                          tenant=TEST_TENANT)

            expected_entry_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id=mock.ANY,
                name=name,
                action=policy_constants.ACTION_ALLOW,
                direction=nsx_constants.IN_OUT,
                description=description,
                sequence_number=1,
                service_ids=None,
                source_groups=[source_group],
                dest_groups=[dest_group],
                logged=False,
                tenant=TEST_TENANT)

            self.assert_called_with_def(
                api_call, expected_entry_def)

    def test_create_entry_no_seq_num(self):
        domain_id = '111'
        map_id = '333'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        service1_id = 'c1'
        service2_id = 'c2'
        seq_num = 1
        ret_comm = {'rules': [{'sequence_number': seq_num}]}
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call,\
            mock.patch.object(self.policy_api,
                              "get", return_value=ret_comm):
            self.resourceApi.create_entry(name, domain_id, map_id,
                                          description=description,
                                          service_ids=[service1_id,
                                                       service2_id],
                                          source_groups=[source_group],
                                          dest_groups=[dest_group],
                                          logged=False,
                                          tenant=TEST_TENANT)

            expected_entry_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id=mock.ANY,
                name=name,
                action=policy_constants.ACTION_ALLOW,
                direction=nsx_constants.IN_OUT,
                description=description,
                service_ids=[service1_id, service2_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                sequence_number=seq_num + 1,
                logged=False,
                tenant=TEST_TENANT)

            self.assert_called_with_def(
                api_call, expected_entry_def)

    def test_create_with_entries(self):
        domain_id = '111'
        map_id = '222'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        service_id = 'c1'
        category = 'Emergency'

        rule_id = 1
        entry1 = self.resourceApi.build_entry(
            'DHCP Reply', domain_id, map_id,
            rule_id, sequence_number=rule_id, service_ids=[service_id],
            action=policy_constants.ACTION_DENY,
            source_groups=None,
            dest_groups=[dest_group],
            direction=nsx_constants.IN)
        rule_id += 1
        entry2 = self.resourceApi.build_entry(
            'DHCP Request', domain_id, map_id,
            rule_id, sequence_number=rule_id, service_ids=None,
            action=policy_constants.ACTION_DENY,
            source_groups=[source_group],
            dest_groups=None,
            direction=nsx_constants.OUT)

        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call:
            self.resourceApi.create_with_entries(name, domain_id,
                                                 map_id=map_id,
                                                 description=description,
                                                 entries=[entry1, entry2],
                                                 category=category,
                                                 tenant=TEST_TENANT)

            expected_def = policy_defs.CommunicationMapDef(
                domain_id=domain_id,
                map_id=map_id,
                name=name,
                description=description,
                category=category,
                tenant=TEST_TENANT)

            self.assert_called_with_defs(api_call,
                                         [expected_def, entry1, entry2])

    def test_delete(self):
        domain_id = '111'
        id = '222'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(domain_id, id, tenant=TEST_TENANT)
            expected_def = policy_defs.CommunicationMapDef(
                domain_id=domain_id,
                map_id=id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_entry(self):
        domain_id = '111'
        map_id = '222'
        entry_id = '333'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete_entry(domain_id, map_id, entry_id,
                                          tenant=TEST_TENANT)
            expected_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id=entry_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        domain_id = '111'
        id = '222'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(domain_id, id, tenant=TEST_TENANT)
            expected_def = policy_defs.CommunicationMapDef(
                domain_id=domain_id,
                map_id=id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_by_name(self):
        domain_id = '111'
        name = 'cm1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(domain_id, name,
                                               tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = policy_defs.CommunicationMapDef(
                domain_id=domain_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        domain_id = '111'
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(domain_id, tenant=TEST_TENANT)
            expected_def = policy_defs.CommunicationMapDef(
                domain_id=domain_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        domain_id = '111'
        map_id = '222'
        name = 'new name'
        description = 'new desc'
        source_group = 'ng1'
        dest_group = 'ng2'
        service1_id = 'nc1'
        service2_id = 'nc2'
        with mock.patch.object(self.policy_api, "get",
                               return_value={}),\
            mock.patch.object(self.policy_api,
                              "create_with_parent") as update_call:
            self.resourceApi.update(domain_id, map_id,
                                    name=name,
                                    description=description,
                                    service_ids=[service1_id, service2_id],
                                    source_groups=[source_group],
                                    dest_groups=[dest_group],
                                    tenant=TEST_TENANT)
            map_def = policy_defs.CommunicationMapDef(
                domain_id=domain_id,
                map_id=map_id,
                name=name,
                description=description,
                tenant=TEST_TENANT)

            entry_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id='entry',
                service_ids=[service1_id, service2_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                tenant=TEST_TENANT)

            self.assert_called_with_defs(update_call, [map_def, entry_def])

    def test_unset(self):
        name = 'hello'
        domain_id = 'test'
        map_id = '111'
        dest_groups = ['/infra/stuff']

        # Until policy PATCH is fixed to accept partial update, we
        # call get on child entry
        with mock.patch.object(
            self.policy_api, "get",
            return_value={'display_name': name,
                          'source_groups': ['/infra/other/stuff'],
                          'destination_groups': dest_groups}):
            self.resourceApi.update(domain_id, map_id,
                                    description=None,
                                    source_groups=None,
                                    service_ids=None,
                                    tenant=TEST_TENANT)

        expected_body = {'id': map_id,
                         'description': None,
                         'resource_type': 'SecurityPolicy',
                         'rules': [{
                             'display_name': name,
                             'id': 'entry',
                             'resource_type': 'Rule',
                             'services': ["ANY"],
                             'source_groups': ["ANY"],
                             'destination_groups': dest_groups}]
                         }

        url = '%s/domains/%s/security-policies/%s' % (TEST_TENANT,
                                                      domain_id,
                                                      map_id)
        self.assert_json_call('PATCH', self.client, url, data=expected_body)

    def test_update_entries_logged(self):
        domain_id = '111'
        map_id = '222'
        dummy_map = {'rules': [{'logged': False}]}
        updated_map = {'rules': [{'logged': True}]}
        map_def = policy_defs.CommunicationMapDef(
            domain_id=domain_id,
            map_id=map_id,
            tenant=TEST_TENANT)
        with mock.patch.object(self.policy_api, "get",
                               return_value=dummy_map),\
            mock.patch.object(self.policy_api.client,
                              "update") as update_call:
            self.resourceApi.update_entries_logged(
                domain_id, map_id,
                logged=True,
                tenant=TEST_TENANT)
            update_call.assert_called_once_with(
                map_def.get_resource_path(), updated_map)

    def test_get_realized(self):
        domain_id = 'd1'
        map_id = '111'
        result = [{'state': policy_constants.STATE_REALIZED,
                   'entity_type': 'RealizedFirewallSection'}]
        with mock.patch.object(
            self.policy_api, "get_realized_entities",
            return_value=result) as api_get:
            state = self.resourceApi.get_realized_state(
                domain_id, map_id, tenant=TEST_TENANT)
            self.assertEqual(policy_constants.STATE_REALIZED, state)
            path = "/%s/domains/%s/security-policies/%s" % (
                TEST_TENANT, domain_id, map_id)
            api_get.assert_called_once_with(path)


class TestPolicyEnforcementPoint(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyEnforcementPoint, self).setUp()
        self.resourceApi = self.policy_lib.enforcement_point

    def test_create(self):
        name = 'ep'
        description = 'desc'
        ip_address = '1.1.1.1'
        username = 'admin'
        password = 'zzz'
        thumbprint = 'abc'
        edge_cluster_id = 'ec1'
        transport_zone_id = 'tz1'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite(
                name, description=description,
                ip_address=ip_address,
                thumbprint=thumbprint,
                username=username,
                password=password,
                edge_cluster_id=edge_cluster_id,
                transport_zone_id=transport_zone_id,
                tenant=TEST_TENANT)

            expected_def = policy_defs.EnforcementPointDef(
                ep_id=mock.ANY,
                name=name,
                description=description,
                ip_address=ip_address,
                username=username,
                thumbprint=thumbprint,
                password=password,
                edge_cluster_id=edge_cluster_id,
                transport_zone_id=transport_zone_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_delete(self):
        id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(id, tenant=TEST_TENANT)
            expected_def = policy_defs.EnforcementPointDef(ep_id=id,
                                                           tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        id = '111'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(id, tenant=TEST_TENANT)
            expected_def = policy_defs.EnforcementPointDef(ep_id=id,
                                                           tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_by_name(self):
        name = 'ep1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = policy_defs.EnforcementPointDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = policy_defs.EnforcementPointDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        id = '111'
        name = 'new name'
        username = 'admin'
        password = 'zzz'
        ip_address = '1.1.1.1'
        thumbprint = 'abc'
        edge_cluster_id = 'ec1'
        transport_zone_id = 'tz1'
        entry = {'id': id,
                 'connection_info': {'thumbprint': thumbprint,
                                     'resource_type': 'NSXTConnectionInfo'}}

        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call,\
            mock.patch.object(self.policy_api, "get",
                              return_value=entry):
            self.resourceApi.update(id,
                                    name=name,
                                    username=username,
                                    password=password,
                                    ip_address=ip_address,
                                    edge_cluster_id=edge_cluster_id,
                                    transport_zone_id=transport_zone_id,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.EnforcementPointDef(
                ep_id=id,
                name=name,
                username=username,
                password=password,
                ip_address=ip_address,
                thumbprint=thumbprint,
                edge_cluster_id=edge_cluster_id,
                transport_zone_id=transport_zone_id,
                tenant=TEST_TENANT)

            self.assert_called_with_def(update_call, expected_def)

    def test_get_realized(self):
        ep_id = 'ef1'
        result = [{'state': policy_constants.STATE_REALIZED}]
        with mock.patch.object(
            self.policy_api, "get_realized_entities",
            return_value=result) as api_get:
            state = self.resourceApi.get_realized_state(
                ep_id, tenant=TEST_TENANT)
            self.assertEqual(policy_constants.STATE_REALIZED, state)
            path = "/%s/sites/default/enforcement-points/%s" % (
                TEST_TENANT, ep_id)
            api_get.assert_called_once_with(path)


class TestPolicyDeploymentMap(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyDeploymentMap, self).setUp()
        self.resourceApi = self.policy_lib.deployment_map

    def test_create(self):
        name = 'map1'
        description = 'desc'
        domain_id = 'domain1'
        ep_id = 'ep1'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite(name,
                                                 description=description,
                                                 ep_id=ep_id,
                                                 domain_id=domain_id,
                                                 tenant=TEST_TENANT)
            expected_def = policy_defs.DeploymentMapDef(
                map_id=mock.ANY,
                name=name,
                description=description,
                ep_id=ep_id,
                domain_id=domain_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_delete(self):
        id = '111'
        domain_id = 'domain1'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(id, domain_id=domain_id,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.DeploymentMapDef(map_id=id,
                                                        domain_id=domain_id,
                                                        tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        id = '111'
        domain_id = 'domain1'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(id, domain_id=domain_id, tenant=TEST_TENANT)
            expected_def = policy_defs.DeploymentMapDef(map_id=id,
                                                        domain_id=domain_id,
                                                        tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_by_name(self):
        name = 'ep1'
        domain_id = 'domain1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, domain_id=domain_id,
                                               tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = policy_defs.DeploymentMapDef(domain_id=domain_id,
                                                        tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        domain_id = 'domain1'
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(domain_id=domain_id, tenant=TEST_TENANT)
            expected_def = policy_defs.DeploymentMapDef(domain_id=domain_id,
                                                        tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        id = '111'
        name = 'new name'
        domain_id = 'domain2'
        ep_id = 'ep2'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    ep_id=ep_id,
                                    domain_id=domain_id,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.DeploymentMapDef(
                map_id=id,
                name=name,
                ep_id=ep_id,
                domain_id=domain_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(
                update_call, expected_def)


class TestPolicyTransportZone(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTransportZone, self).setUp()
        self.resourceApi = self.policy_lib.transport_zone

    def test_get(self):
        id = '111'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(id, tenant=TEST_TENANT)
            expected_def = policy_defs.TransportZoneDef(tz_id=id,
                                                        tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_by_name(self):
        name = 'tz1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = policy_defs.TransportZoneDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_tz_type(self):
        id = '111'
        tz_type = self.resourceApi.TZ_TYPE_OVERLAY
        with mock.patch.object(self.policy_api, "get",
                               return_value={'tz_type': tz_type}) as api_call:
            actual_tz_type = self.resourceApi.get_tz_type(
                id, tenant=TEST_TENANT)
            expected_def = policy_defs.TransportZoneDef(tz_id=id,
                                                        tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(tz_type, actual_tz_type)

    def test_get_transport_type(self):
        id = '111'
        tz_type = self.resourceApi.TZ_TYPE_OVERLAY
        with mock.patch.object(self.policy_api, "get",
                               return_value={'tz_type': tz_type}) as api_call:
            actual_tz_type = self.resourceApi.get_transport_type(
                id, tenant=TEST_TENANT)
            expected_def = policy_defs.TransportZoneDef(tz_id=id,
                                                        tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(nsx_constants.TRANSPORT_TYPE_OVERLAY,
                             actual_tz_type)

    def test_get_switch_mode(self):
        id = '111'
        tz_type = self.resourceApi.TZ_TYPE_OVERLAY
        with mock.patch.object(self.policy_api, "get",
                               return_value={'tz_type': tz_type}) as api_call:
            actual_sm = self.resourceApi.get_host_switch_mode(
                id, tenant=TEST_TENANT)
            expected_def = policy_defs.TransportZoneDef(tz_id=id,
                                                        tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(nsx_constants.HOST_SWITCH_MODE_STANDARD,
                             actual_sm)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = policy_defs.TransportZoneDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)


class TestPolicyTier1(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTier1, self).setUp()
        self.resourceApi = self.policy_lib.tier1

    def test_create(self):
        name = 'test'
        description = 'desc'
        tier0_id = '111'
        route_adv = self.resourceApi.build_route_advertisement(
            lb_vip=True,
            lb_snat=True)

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite(
                name, description=description,
                tier0=tier0_id,
                force_whitelisting=True,
                route_advertisement=route_adv,
                tenant=TEST_TENANT)

            expected_def = policy_defs.Tier1Def(
                tier1_id=mock.ANY,
                name=name,
                description=description,
                tier0=tier0_id,
                force_whitelisting=True,
                failover_mode=policy_constants.NON_PREEMPTIVE,
                route_advertisement=route_adv,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_delete(self):
        id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(id, tenant=TEST_TENANT)
            expected_def = policy_defs.Tier1Def(tier1_id=id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        id = '111'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(id, tenant=TEST_TENANT)
            expected_def = policy_defs.Tier1Def(tier1_id=id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_by_name(self):
        name = 'test'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = policy_defs.Tier1Def(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = policy_defs.Tier1Def(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        id = '111'
        name = 'new name'
        tier0 = 'tier0'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    name=name, tier0=tier0,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.Tier1Def(tier1_id=id,
                                                name=name,
                                                tier0=tier0,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(
                update_call, expected_def)

    def test_update_ignore_tier0(self):
        id = '111'
        name = 'new name'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.Tier1Def(tier1_id=id,
                                                name=name,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)
            # make sure tier0 is not in the body
            actual_def = update_call.call_args_list[0][0][0]
            self.assertNotIn('tier0_path', actual_def.get_obj_dict())

    def test_update_unset_tier0(self):
        id = '111'
        name = 'new name'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    tier0=None,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.Tier1Def(tier1_id=id,
                                                name=name,
                                                tier0=None,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)
            # make sure tier0 is in the body with value None
            actual_def = update_call.call_args_list[0][0][0]
            self.assertIn('tier0_path', actual_def.get_obj_dict())
            self.assertIsNone(actual_def.get_obj_dict()['tier0_path'])

    def test_update_route_adv(self):
        id = '111'
        rtr_name = 'rtr111'
        get_result = {'id': '111',
                      'display_name': rtr_name,
                      'route_advertisement_types': ['TIER1_NAT',
                                                    'TIER1_LB_VIP']}
        with mock.patch.object(self.policy_api, "get",
                               return_value=get_result),\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update_route_advertisement(
                id,
                static_routes=True,
                lb_vip=False,
                lb_snat=True,
                tenant=TEST_TENANT)

            new_adv = self.resourceApi.build_route_advertisement(
                nat=True, static_routes=True, lb_snat=True)

            expected_def = policy_defs.Tier1Def(tier1_id=id,
                                                name=rtr_name,
                                                route_adv=new_adv,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(
                update_call, expected_def)

    def test_wait_until_realized_fail(self):
        tier1_id = '111'
        logical_router_id = 'realized_111'
        info = {'state': policy_constants.STATE_UNREALIZED,
                'realization_specific_identifier': logical_router_id,
                'entity_type': 'RealizedLogicalRouter'}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            self.assertRaises(nsxlib_exc.ManagerError,
                              self.resourceApi.wait_until_realized,
                              tier1_id, tenant=TEST_TENANT)

    def test_wait_until_realized_succeed(self):
        tier1_id = '111'
        logical_router_id = 'realized_111'
        info = {'state': policy_constants.STATE_REALIZED,
                'realization_specific_identifier': logical_router_id,
                'entity_type': 'RealizedLogicalRouter'}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            actual_info = self.resourceApi.wait_until_realized(
                tier1_id, tenant=TEST_TENANT)
            self.assertEqual(info, actual_info)

    def test_update_tz(self):
        # Test a passthrough api
        tier1_id = '111'
        logical_router_id = 'realized_111'
        tz_uuid = 'dummy_tz'
        info = {'state': policy_constants.STATE_REALIZED,
                'realization_specific_identifier': logical_router_id}
        passthrough_mock = self.resourceApi.nsx_api.logical_router.update
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info) as realization:
            self.resourceApi.update_transport_zone(tier1_id, tz_uuid,
                                                   tenant=TEST_TENANT)
            realization.assert_called_once()
            passthrough_mock.assert_called_once_with(
                logical_router_id, transport_zone_id=tz_uuid)


class TestPolicyTier1NatRule(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTier1NatRule, self).setUp()
        self.resourceApi = self.policy_lib.tier1_nat_rule

    def test_create(self):
        name = 'test'
        description = 'desc'
        tier1_id = '111'
        nat_rule_id = 'rule1'
        action = policy_constants.NAT_ACTION_SNAT
        cidr1 = '1.1.1.1/32'
        cidr2 = '2.2.2.0/24'

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite(
                name, tier1_id,
                nat_rule_id=nat_rule_id,
                description=description,
                action=action,
                translated_network=cidr1,
                source_network=cidr2,
                tenant=TEST_TENANT)

            expected_def = policy_defs.Tier1NatRule(
                tier1_id=tier1_id,
                nat_rule_id=nat_rule_id,
                nat_id=self.resourceApi.DEFAULT_NAT_ID,
                name=name,
                description=description,
                action=action,
                translated_network=cidr1,
                source_network=cidr2,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_delete(self):
        tier1_id = '111'
        nat_rule_id = 'rule1'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(
                tier1_id,
                nat_rule_id,
                tenant=TEST_TENANT)
            expected_def = policy_defs.Tier1NatRule(
                tier1_id=tier1_id,
                nat_rule_id=nat_rule_id,
                nat_id=self.resourceApi.DEFAULT_NAT_ID,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)


class TestPolicyTier0(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTier0, self).setUp()
        self.resourceApi = self.policy_lib.tier0

    def test_create(self):
        name = 'test'
        description = 'desc'
        dhcp_config = '111'
        subnets = ["2.2.2.0/24"]

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite(
                name, description=description,
                dhcp_config=dhcp_config,
                force_whitelisting=True,
                default_rule_logging=True,
                transit_subnets=subnets,
                tenant=TEST_TENANT)

            expected_def = policy_defs.Tier0Def(
                tier0_id=mock.ANY,
                name=name,
                description=description,
                dhcp_config=dhcp_config,
                default_rule_logging=True,
                force_whitelisting=True,
                ha_mode=policy_constants.ACTIVE_ACTIVE,
                failover_mode=policy_constants.NON_PREEMPTIVE,
                transit_subnets=subnets,
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_def)

    def test_delete(self):
        id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(id, tenant=TEST_TENANT)
            expected_def = policy_defs.Tier0Def(tier0_id=id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        id = '111'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(id, tenant=TEST_TENANT)
            expected_def = policy_defs.Tier0Def(tier0_id=id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_by_name(self):
        name = 'test'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = policy_defs.Tier0Def(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = policy_defs.Tier0Def(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        id = '111'
        name = 'new name'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.Tier0Def(tier0_id=id,
                                                name=name,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(
                update_call, expected_def)
