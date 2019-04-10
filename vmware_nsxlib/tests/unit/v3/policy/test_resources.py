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
from vmware_nsxlib.tests.unit.v3.policy import policy_testcase
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import policy
from vmware_nsxlib.v3.policy import constants
from vmware_nsxlib.v3.policy import core_defs
from vmware_nsxlib.v3.policy import core_resources

TEST_TENANT = 'test'


class NsxPolicyLibTestCase(policy_testcase.TestPolicyApi):

    def setUp(self, *args, **kwargs):
        super(NsxPolicyLibTestCase, self).setUp()

        nsxlib_config = nsxlib_testcase.get_default_nsxlib_config(
            allow_passthrough=kwargs.get('allow_passthrough', True))

        # Mock the nsx-lib for the passthrough api
        with mock.patch('vmware_nsxlib.v3.NsxLib'):
            self.policy_lib = policy.NsxPolicyLib(nsxlib_config)
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
        domain_id = '111'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                domain_id=domain_id,
                description=description,
                tenant=TEST_TENANT)
            expected_def = core_defs.DomainDef(domain_id=domain_id,
                                               name=name,
                                               description=description,
                                               tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(domain_id, result)

    def test_minimalistic_create(self):
        name = 'test'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(name,
                                                          tenant=TEST_TENANT)
            expected_def = core_defs.DomainDef(domain_id=mock.ANY,
                                               name=name,
                                               tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description, tenant=TEST_TENANT)
            expected_def = core_defs.DomainDef(domain_id=mock.ANY,
                                               name=name,
                                               description=description,
                                               tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        domain_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(domain_id, tenant=TEST_TENANT)
            expected_def = core_defs.DomainDef(domain_id=domain_id,
                                               tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        domain_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': domain_id}) as api_call:
            result = self.resourceApi.get(domain_id, tenant=TEST_TENANT)
            expected_def = core_defs.DomainDef(domain_id=domain_id,
                                               tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(domain_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = core_defs.DomainDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = core_defs.DomainDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        domain_id = '111'
        name = 'new name'
        description = 'new desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(domain_id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = core_defs.DomainDef(domain_id=domain_id,
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
        group_id = '222'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, domain_id,
                group_id=group_id,
                description=description,
                tenant=TEST_TENANT)
            expected_def = core_defs.GroupDef(domain_id=domain_id,
                                              group_id=group_id,
                                              name=name,
                                              description=description,
                                              conditions=[],
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(group_id, result)

    def test_create_without_id(self):
        domain_id = '111'
        name = 'g1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, domain_id,
                description=description,
                tenant=TEST_TENANT)
            expected_def = core_defs.GroupDef(domain_id=domain_id,
                                              group_id=mock.ANY,
                                              name=name,
                                              description=description,
                                              conditions=[],
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_create_with_condition(self):
        domain_id = '111'
        name = 'g1'
        description = 'desc'
        cond_val = '123'
        cond_op = constants.CONDITION_OP_EQUALS
        cond_member_type = constants.CONDITION_MEMBER_VM
        cond_key = constants.CONDITION_KEY_TAG
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, domain_id, description=description,
                cond_val=cond_val,
                cond_op=cond_op,
                cond_member_type=cond_member_type,
                cond_key=cond_key,
                tenant=TEST_TENANT)
            exp_cond = core_defs.Condition(value=cond_val,
                                           key=cond_key,
                                           operator=cond_op,
                                           member_type=cond_member_type)
            expected_def = core_defs.GroupDef(domain_id=domain_id,
                                              group_id=mock.ANY,
                                              name=name,
                                              description=description,
                                              conditions=[exp_cond],
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_create_with_simple_condition(self):
        domain_id = '111'
        name = 'g1'
        description = 'desc'
        cond_val = '123'
        cond_op = constants.CONDITION_OP_EQUALS
        cond_member_type = constants.CONDITION_MEMBER_VM
        cond_key = constants.CONDITION_KEY_TAG

        cond = self.resourceApi.build_condition(
            cond_val=cond_val,
            cond_op=cond_op,
            cond_member_type=cond_member_type,
            cond_key=cond_key)

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite_with_conditions(
                name, domain_id, description=description,
                conditions=[cond],
                tenant=TEST_TENANT)
            exp_cond = core_defs.Condition(value=cond_val,
                                           key=cond_key,
                                           operator=cond_op,
                                           member_type=cond_member_type)
            expected_def = core_defs.GroupDef(domain_id=domain_id,
                                              group_id=mock.ANY,
                                              name=name,
                                              description=description,
                                              conditions=[exp_cond],
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def _test_create_with_condition(self, condition, exp_condition):
        domain_id = '111'
        name = 'g1'
        description = 'desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite_with_conditions(
                name, domain_id, description=description,
                conditions=condition, tenant=TEST_TENANT)
            expected_def = core_defs.GroupDef(domain_id=domain_id,
                                              group_id=mock.ANY,
                                              name=name,
                                              description=description,
                                              conditions=exp_condition,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_create_with_union_condition(self):
        cond_val1 = '123'
        cond_val2 = '456'
        cond_op = constants.CONDITION_OP_EQUALS
        cond_member_type = constants.CONDITION_MEMBER_VM
        cond_key = constants.CONDITION_KEY_TAG

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
        union_cond = self.resourceApi.build_union_condition(
            conditions=[cond1, cond2])

        exp_cond1 = core_defs.Condition(value=cond_val1,
                                        key=cond_key,
                                        operator=cond_op,
                                        member_type=cond_member_type)
        exp_cond2 = core_defs.Condition(value=cond_val2,
                                        key=cond_key,
                                        operator=cond_op,
                                        member_type=cond_member_type)
        or_cond = core_defs.ConjunctionOperator(
            operator=constants.CONDITION_OP_OR)
        exp_cond = [exp_cond1, or_cond, exp_cond2]
        self._test_create_with_condition(union_cond, exp_cond)

    def test_create_with_nested_condition(self):
        cond_val1 = '123'
        cond_val2 = '456'
        cond_op = constants.CONDITION_OP_EQUALS
        cond_member_type = constants.CONDITION_MEMBER_VM
        cond_key = constants.CONDITION_KEY_TAG

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

        exp_cond1 = core_defs.Condition(value=cond_val1,
                                        key=cond_key,
                                        operator=cond_op,
                                        member_type=cond_member_type)
        exp_cond2 = core_defs.Condition(value=cond_val2,
                                        key=cond_key,
                                        operator=cond_op,
                                        member_type=cond_member_type)
        and_cond = core_defs.ConjunctionOperator()
        exp_cond = core_defs.NestedExpression(
            expressions=[exp_cond1, and_cond, exp_cond2])
        self._test_create_with_condition(nested, exp_cond)

    def test_create_with_ip_expression(self):
        domain_id = '111'
        name = 'g1'
        description = 'desc'
        cidr = '1.1.1.0/24'

        cond = self.resourceApi.build_ip_address_expression([cidr])

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite_with_conditions(
                name, domain_id, description=description,
                conditions=[cond],
                tenant=TEST_TENANT)
            exp_cond = core_defs.IPAddressExpression([cidr])
            expected_def = core_defs.GroupDef(domain_id=domain_id,
                                              group_id=mock.ANY,
                                              name=name,
                                              description=description,
                                              conditions=[exp_cond],
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_create_with_path_expression(self):
        domain_id = '111'
        name = 'g1'
        description = 'desc'
        path = '/test/path1'

        cond = self.resourceApi.build_path_expression([path])

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite_with_conditions(
                name, domain_id, description=description,
                conditions=[cond],
                tenant=TEST_TENANT)
            exp_cond = core_defs.PathExpression([path])
            expected_def = core_defs.GroupDef(domain_id=domain_id,
                                              group_id=mock.ANY,
                                              name=name,
                                              description=description,
                                              conditions=[exp_cond],
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        domain_id = '111'
        group_id = '222'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(domain_id, group_id, tenant=TEST_TENANT)
            expected_def = core_defs.GroupDef(domain_id=domain_id,
                                              group_id=group_id,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        domain_id = '111'
        group_id = '222'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': group_id}) as api_call:
            result = self.resourceApi.get(domain_id, group_id,
                                          tenant=TEST_TENANT)
            expected_def = core_defs.GroupDef(domain_id=domain_id,
                                              group_id=group_id,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(group_id, result['id'])

    def test_get_by_name(self):
        domain_id = '111'
        name = 'g1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(domain_id, name,
                                               tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = core_defs.GroupDef(domain_id=domain_id,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        domain_id = '111'
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(domain_id, tenant=TEST_TENANT)
            expected_def = core_defs.GroupDef(domain_id=domain_id,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        domain_id = '111'
        group_id = '222'
        name = 'new name'
        description = 'new desc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(domain_id, group_id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = core_defs.GroupDef(domain_id=domain_id,
                                              group_id=group_id,
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
        result = [{'state': constants.STATE_REALIZED,
                   'entity_type': 'RealizedGroup'}]
        with mock.patch.object(
            self.policy_api, "get_realized_entities",
            return_value=result) as api_get:
            state = self.resourceApi.get_realized_state(
                domain_id, group_id, tenant=TEST_TENANT)
            self.assertEqual(constants.STATE_REALIZED, state)
            path = "/%s/domains/%s/groups/%s" % (
                TEST_TENANT, domain_id, group_id)
            api_get.assert_called_once_with(path, silent=False)

    def test_get_realized_multiple_results_get_default(self):
        domain_id = 'd1'
        group_id = 'g1'
        result = [{'state': constants.STATE_UNREALIZED,
                   'entity_type': 'NotRealizedGroup'},
                  {'state': constants.STATE_REALIZED,
                   'entity_type': 'RealizedGroup'}]
        with mock.patch.object(
            self.policy_api, "get_realized_entities",
            return_value=result) as api_get:
            state = self.resourceApi.get_realized_state(
                domain_id, group_id, tenant=TEST_TENANT)
            self.assertEqual(constants.STATE_UNREALIZED, state)
            path = "/%s/domains/%s/groups/%s" % (
                TEST_TENANT, domain_id, group_id)
            api_get.assert_called_once_with(path, silent=False)

    def test_get_realized_multiple_results_get_specific(self):
        domain_id = 'd1'
        group_id = 'g1'
        result = [{'state': constants.STATE_UNREALIZED,
                   'entity_type': 'NotRealizedGroup'},
                  {'state': constants.STATE_REALIZED,
                   'entity_type': 'RealizedGroup'}]
        with mock.patch.object(
            self.policy_api, "get_realized_entities",
            return_value=result) as api_get:
            state = self.resourceApi.get_realized_state(
                domain_id, group_id, entity_type='RealizedGroup',
                tenant=TEST_TENANT)
            self.assertEqual(constants.STATE_REALIZED, state)
            path = "/%s/domains/%s/groups/%s" % (
                TEST_TENANT, domain_id, group_id)
            api_get.assert_called_once_with(path, silent=False)

    def test_get_realized_id(self):
        domain_id = 'd1'
        group_id = 'g1'
        realized_id = 'realized_111'
        result = [{'state': constants.STATE_REALIZED,
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
            api_get.assert_called_once_with(path, silent=False)

    def test_get_path(self):
        domain_id = 'd1'
        group_id = 'g1'
        result = self.resourceApi.get_path(domain_id, group_id,
                                           tenant=TEST_TENANT)
        expected_path = '/%s/domains/%s/groups/%s' % (
            TEST_TENANT, domain_id, group_id)
        self.assertEqual(expected_path, result)

    def test_wait_until_realized_fail(self):
        domain_id = 'd1'
        group_id = 'g1'
        info = {'state': constants.STATE_UNREALIZED,
                'realization_specific_identifier': group_id,
                'entity_type': 'RealizedGroup'}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            self.assertRaises(nsxlib_exc.ManagerError,
                              self.resourceApi.wait_until_realized,
                              domain_id, group_id, max_attempts=5,
                              sleep=0.1, tenant=TEST_TENANT)

    def test_wait_until_realized_succeed(self):
        domain_id = 'd1'
        group_id = 'g1'
        info = {'state': constants.STATE_REALIZED,
                'realization_specific_identifier': group_id,
                'entity_type': 'RealizedGroup'}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            actual_info = self.resourceApi.wait_until_realized(
                domain_id, group_id, max_attempts=5, sleep=0.1,
                tenant=TEST_TENANT)
            self.assertEqual(info, actual_info)


class TestPolicyL4Service(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyL4Service, self).setUp()
        self.resourceApi = self.policy_lib.service

    def test_create(self):
        name = 's1'
        description = 'desc'
        protocol = constants.TCP
        dest_ports = [81, 82]
        source_ports = [83, 84]
        tags = [{'scope': 'a', 'tag': 'b'}]
        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                description=description,
                protocol=protocol,
                dest_ports=dest_ports,
                source_ports=source_ports,
                tags=tags,
                tenant=TEST_TENANT)
            exp_srv_def = core_defs.ServiceDef(service_id=mock.ANY,
                                               name=name,
                                               description=description,
                                               tags=tags,
                                               tenant=TEST_TENANT)
            exp_entry_def = core_defs.L4ServiceEntryDef(
                service_id=mock.ANY,
                entry_id='entry',
                name='entry',
                protocol=protocol,
                dest_ports=dest_ports,
                source_ports=source_ports,
                tenant=TEST_TENANT)
            self.assert_called_with_defs(
                api_call, [exp_srv_def, exp_entry_def])
            self.assertIsNotNone(result)

    def test_delete(self):
        srv_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(srv_id, tenant=TEST_TENANT)
            expected_def = core_defs.ServiceDef(service_id=srv_id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        srv_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': srv_id}) as api_call:
            result = self.resourceApi.get(srv_id, tenant=TEST_TENANT)
            expected_def = core_defs.ServiceDef(service_id=srv_id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(srv_id, result['id'])

    def test_get_by_name(self):
        name = 's1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = core_defs.ServiceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = core_defs.ServiceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        srv_id = '111'
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

            self.resourceApi.update(srv_id,
                                    name=name,
                                    description=description,
                                    tags=tags,
                                    tenant=TEST_TENANT)
            service_def = core_defs.ServiceDef(service_id=srv_id,
                                               name=name,
                                               description=description,
                                               tags=tags,
                                               tenant=TEST_TENANT)
            entry_def = core_defs.L4ServiceEntryDef(
                service_id=id,
                entry_id='entry',
                protocol=protocol,
                tenant=TEST_TENANT)
            self.assert_called_with_defs(update_call, [service_def, entry_def])

    def test_update_all(self):
        srv_id = '111'
        name = 'newName'
        description = 'new desc'
        protocol = 'udp'
        dest_ports = [555]
        source_ports = [666]

        entry_body = {'id': 'entry',
                      'l4_protocol': 'tcp'}

        with mock.patch.object(self.policy_api,
                               "get",
                               return_value=entry_body),\
            mock.patch.object(self.policy_api,
                              "create_with_parent") as update_call:
            self.resourceApi.update(srv_id,
                                    name=name,
                                    description=description,
                                    protocol=protocol,
                                    dest_ports=dest_ports,
                                    source_ports=source_ports,
                                    tenant=TEST_TENANT)

            service_def = core_defs.ServiceDef(service_id=srv_id,
                                               name=name,
                                               description=description,
                                               tenant=TEST_TENANT)
            entry_def = core_defs.L4ServiceEntryDef(
                service_id=srv_id,
                entry_id=mock.ANY,
                protocol=protocol,
                dest_ports=dest_ports,
                source_ports=source_ports,
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
            result = self.resourceApi.create_or_overwrite(
                name,
                description=description,
                icmp_type=icmp_type,
                tenant=TEST_TENANT)
            exp_srv_def = core_defs.ServiceDef(service_id=mock.ANY,
                                               name=name,
                                               description=description,
                                               tenant=TEST_TENANT)
            exp_entry_def = core_defs.IcmpServiceEntryDef(
                service_id=mock.ANY,
                entry_id='entry',
                name='entry',
                version=4,
                icmp_type=icmp_type,
                tenant=TEST_TENANT)
            self.assert_called_with_defs(
                api_call, [exp_srv_def, exp_entry_def])
            self.assertIsNotNone(result)

    def test_delete(self):
        srv_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(srv_id, tenant=TEST_TENANT)
            expected_def = core_defs.ServiceDef(service_id=srv_id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        srv_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': srv_id}) as api_call:
            result = self.resourceApi.get(srv_id, tenant=TEST_TENANT)
            expected_def = core_defs.ServiceDef(service_id=srv_id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(srv_id, result['id'])

    def test_get_by_name(self):
        name = 's1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = core_defs.ServiceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = core_defs.ServiceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        srv_id = '111'
        name = 'new_name'
        description = 'new desc'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': 'entry',
                                             'protocol': 'ICMPv4'}),\
            mock.patch.object(self.policy_api,
                              "create_with_parent") as update_call:
            self.resourceApi.update(srv_id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)

            service_def = core_defs.ServiceDef(service_id=srv_id,
                                               name=name,
                                               description=description,
                                               tenant=TEST_TENANT)

            entry_def = core_defs.IcmpServiceEntryDef(
                service_id=srv_id,
                entry_id='entry',
                version=4,
                tenant=TEST_TENANT)

            self.assert_called_with_defs(update_call, [service_def, entry_def])

    def test_update_all(self):
        srv_id = '111'
        name = 'newName'
        description = 'new desc'
        version = 6
        icmp_type = 3
        icmp_code = 3

        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': 'entry'}),\
            mock.patch.object(self.policy_api,
                              "create_with_parent") as update_call:
            self.resourceApi.update(srv_id,
                                    name=name,
                                    description=description,
                                    version=version,
                                    icmp_type=icmp_type,
                                    icmp_code=icmp_code,
                                    tenant=TEST_TENANT)
            # get will be called for the entire service
            service_def = core_defs.ServiceDef(service_id=srv_id,
                                               name=name,
                                               description=description,
                                               tenant=TEST_TENANT)
            entry_def = core_defs.IcmpServiceEntryDef(
                service_id=srv_id,
                entry_id=mock.ANY,
                version=version,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
                tenant=TEST_TENANT)

            self.assert_called_with_defs(
                update_call, [service_def, entry_def])

    def test_icmp_type_and_code_in_obj_dict(self):
        icmp_type, icmp_code = 0, 0
        entry_def = core_defs.IcmpServiceEntryDef(
            icmp_type=icmp_type, icmp_code=icmp_code)
        body = entry_def.get_obj_dict()
        self.assertEqual(icmp_type, body["icmp_type"])
        self.assertEqual(icmp_code, body["icmp_code"])


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
            result = self.resourceApi.create_or_overwrite(
                name,
                description=description,
                protocol_number=protocol_number,
                tenant=TEST_TENANT)
            exp_srv_def = core_defs.ServiceDef(service_id=mock.ANY,
                                               name=name,
                                               description=description,
                                               tenant=TEST_TENANT)
            exp_entry_def = core_defs.IPProtocolServiceEntryDef(
                service_id=mock.ANY,
                entry_id='entry',
                name='entry',
                protocol_number=protocol_number,
                tenant=TEST_TENANT)
            self.assert_called_with_defs(
                api_call, [exp_srv_def, exp_entry_def])
            self.assertIsNotNone(result)

    def test_delete(self):
        srv_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(srv_id, tenant=TEST_TENANT)
            expected_def = core_defs.ServiceDef(service_id=srv_id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        srv_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': srv_id}) as api_call:
            result = self.resourceApi.get(srv_id, tenant=TEST_TENANT)
            expected_def = core_defs.ServiceDef(service_id=srv_id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(srv_id, result['id'])

    def test_get_by_name(self):
        name = 's1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = core_defs.ServiceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = core_defs.ServiceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        srv_id = '111'
        name = 'new_name'
        description = 'new desc'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': 'entry'}),\
            mock.patch.object(self.policy_api,
                              "create_with_parent") as update_call:
            self.resourceApi.update(srv_id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            service_def = core_defs.ServiceDef(service_id=srv_id,
                                               name=name,
                                               description=description,
                                               tenant=TEST_TENANT)

            entry_def = core_defs.IPProtocolServiceEntryDef(
                service_id=srv_id,
                entry_id='entry',
                tenant=TEST_TENANT)

            self.assert_called_with_defs(update_call, [service_def, entry_def])

    def test_update_all(self):
        srv_id = '111'
        name = 'newName'
        description = 'new desc'
        protocol_number = 3

        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': 'entry'}),\
            mock.patch.object(self.policy_api,
                              "create_with_parent") as service_update_call:
            self.resourceApi.update(srv_id,
                                    name=name,
                                    description=description,
                                    protocol_number=protocol_number,
                                    tenant=TEST_TENANT)

            service_def = core_defs.ServiceDef(service_id=srv_id,
                                               name=name,
                                               description=description,
                                               tenant=TEST_TENANT)
            entry_def = core_defs.IPProtocolServiceEntryDef(
                service_id=srv_id,
                entry_id='entry',
                protocol_number=protocol_number,
                tenant=TEST_TENANT)

            self.assert_called_with_defs(service_update_call,
                                         [service_def, entry_def])

    def test_protocol_number_in_obj_dict(self):
        protocol_number = 0
        entry_def = core_defs.IPProtocolServiceEntryDef(
            protocol_number=protocol_number)
        body = entry_def.get_obj_dict()
        self.assertEqual(protocol_number, body["protocol_number"])


class TestPolicyMixedService(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyMixedService, self).setUp()
        self.l4ServiceApi = self.policy_lib.service
        self.icmpServiceApi = self.policy_lib.icmp_service
        self.ipServiceApi = self.policy_lib.ip_protocol_service
        self.resourceApi = self.policy_lib.mixed_service

    def test_create_service_only(self):
        name = 's1'
        srv_id = '111'
        description = 'desc'
        tags = [{'scope': 'a', 'tag': 'b'}]
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                srv_id,
                description=description,
                tags=tags,
                tenant=TEST_TENANT)

            exp_srv_def = core_defs.ServiceDef(
                service_id=srv_id,
                name=name,
                description=description,
                tags=tags,
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, exp_srv_def)
            self.assertIsNotNone(result)

    def test_create_with_entries(self):
        name = 's1'
        srv_id = '111'
        description = 'desc'
        tags = [{'scope': 'a', 'tag': 'b'}]
        protocol = constants.TCP
        dest_ports = [81, 82]
        source_ports = [83, 84]
        icmp_type = 2
        protocol_number = 2

        l4_entry = self.l4ServiceApi.build_entry(
            'l4_entry', srv_id, 'l4_entry', protocol=protocol,
            dest_ports=dest_ports, source_ports=source_ports,
            tenant=TEST_TENANT)

        icmp_entry = self.icmpServiceApi.build_entry(
            'icmp_entry', srv_id, 'icmp_entry', icmp_type=icmp_type,
            tenant=TEST_TENANT)

        ip_entry = self.ipServiceApi.build_entry(
            'ip_entry', srv_id, 'ip_entry',
            protocol_number=protocol_number, tenant=TEST_TENANT)

        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                srv_id,
                description=description,
                entries=[l4_entry, icmp_entry, ip_entry],
                tags=tags,
                tenant=TEST_TENANT)

            service_def = core_defs.ServiceDef(
                service_id=srv_id,
                name=name,
                description=description,
                tags=tags,
                tenant=TEST_TENANT)

            self.assert_called_with_defs(
                api_call, [service_def, l4_entry, icmp_entry, ip_entry])
            self.assertIsNotNone(result)

    def test_delete(self):
        srv_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(srv_id, tenant=TEST_TENANT)
            expected_def = core_defs.ServiceDef(service_id=srv_id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        srv_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': srv_id}) as api_call:
            result = self.resourceApi.get(srv_id, tenant=TEST_TENANT)
            expected_def = core_defs.ServiceDef(service_id=srv_id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(srv_id, result['id'])

    def test_get_by_name(self):
        name = 's1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = core_defs.ServiceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = core_defs.ServiceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        name = 'newName'
        srv_id = '111'
        description = 'new desc'
        tags = [{'scope': 'c', 'tag': 'd'}]
        protocol = constants.UDP
        dest_ports = [91, 92]
        source_ports = [93, 94]
        icmp_type = 3
        protocol_number = 3

        l4_entry = self.l4ServiceApi.build_entry(
            'l4_entry', srv_id, 'l4_entry', protocol=protocol,
            dest_ports=dest_ports, source_ports=source_ports,
            tenant=TEST_TENANT)

        icmp_entry = self.icmpServiceApi.build_entry(
            'icmp_entry', srv_id, 'icmp_entry', icmp_type=icmp_type,
            tenant=TEST_TENANT)

        ip_entry = self.ipServiceApi.build_entry(
            'ip_entry', srv_id, 'ip_entry',
            protocol_number=protocol_number, tenant=TEST_TENANT)

        with mock.patch.object(self.policy_api, "get",
                               return_value={}),\
            mock.patch.object(self.policy_api,
                              "create_with_parent") as update_call:
            self.resourceApi.update(
                srv_id,
                name=name,
                description=description,
                entries=[l4_entry, icmp_entry, ip_entry],
                tags=tags,
                tenant=TEST_TENANT)

            service_def = core_defs.ServiceDef(
                service_id=srv_id,
                name=name,
                description=description,
                tags=tags,
                tenant=TEST_TENANT)

            self.assert_called_with_defs(
                update_call, [service_def, l4_entry, icmp_entry, ip_entry])


class TestPolicyCommunicationMap(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyCommunicationMap, self).setUp()
        self.resourceApi = self.policy_lib.comm_map
        self.mapDef = core_defs.CommunicationMapDef
        self.entryDef = core_defs.CommunicationMapEntryDef
        self.resource_type = 'SecurityPolicy'
        self.path_name = 'security-policies'

    def test_create_another(self):
        domain_id = '111'
        map_id = '222'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        seq_num = 7
        map_seq_num = 10
        service_id = 'c1'
        direction = nsx_constants.IN_OUT
        get_return_value = {'rules': [{'sequence_number': 1}]}
        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call,\
            mock.patch.object(self.policy_api, "get",
                              return_value=get_return_value):
            result = self.resourceApi.create_or_overwrite(
                name, domain_id,
                map_id=map_id,
                description=description,
                sequence_number=seq_num,
                service_ids=[service_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                direction=direction,
                logged=True,
                map_sequence_number=map_seq_num,
                tenant=TEST_TENANT)
            map_def = self.mapDef(
                domain_id=domain_id,
                map_id=map_id,
                name=name,
                description=description,
                category=constants.CATEGORY_APPLICATION,
                map_sequence_number=map_seq_num,
                tenant=TEST_TENANT)

            entry_def = self.entryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id='entry',
                name=name,
                action=constants.ACTION_ALLOW,
                description=description,
                sequence_number=seq_num,
                service_ids=[service_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                direction=direction,
                logged=True,
                tenant=TEST_TENANT)
            self.assert_called_with_defs(api_call, [map_def, entry_def])
            self.assertEqual(map_id, result)

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
            result = self.resourceApi.create_or_overwrite(
                name, domain_id,
                map_id=map_id,
                description=description,
                service_ids=[service_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                category=category,
                logged=False,
                tenant=TEST_TENANT)

            map_def = self.mapDef(
                domain_id=domain_id,
                map_id=map_id,
                name=name,
                description=description,
                category=category,
                tenant=TEST_TENANT)

            entry_def = self.entryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id='entry',
                name=name,
                action=constants.ACTION_ALLOW,
                direction=nsx_constants.IN_OUT,
                description=description,
                sequence_number=1,
                service_ids=[service_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                logged=False,
                tenant=TEST_TENANT)
            self.assert_called_with_defs(api_call, [map_def, entry_def])
            self.assertEqual(map_id, result)

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
            result = self.resourceApi.create_or_overwrite(
                name, domain_id,
                description=description,
                service_ids=[service1_id, service2_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                tenant=TEST_TENANT)

            expected_map_def = self.mapDef(
                domain_id=domain_id,
                map_id=mock.ANY,
                name=name,
                description=description,
                category=constants.CATEGORY_APPLICATION,
                tenant=TEST_TENANT)

            expected_entry_def = self.entryDef(
                domain_id=domain_id,
                map_id=mock.ANY,
                entry_id=mock.ANY,
                action=constants.ACTION_ALLOW,
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
            self.assertIsNotNone(result)

    def test_create_map_only(self):
        domain_id = '111'
        name = 'cm1'
        description = 'desc'
        map_seq_num = 10
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite_map_only(
                name, domain_id, description=description,
                map_sequence_number=map_seq_num, tenant=TEST_TENANT)

            expected_map_def = self.mapDef(
                domain_id=domain_id,
                map_id=mock.ANY,
                name=name,
                description=description,
                category=constants.CATEGORY_APPLICATION,
                map_sequence_number=map_seq_num,
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_map_def)
            self.assertIsNotNone(result)

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
            result = self.resourceApi.create_entry(
                name=name,
                domain_id=domain_id,
                map_id=map_id,
                description=description,
                service_ids=[service1_id, service2_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                sequence_number=1,
                direction=nsx_constants.IN,
                ip_protocol=nsx_constants.IPV4,
                tenant=TEST_TENANT)

            expected_entry_def = self.entryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id=mock.ANY,
                name=name,
                action=constants.ACTION_ALLOW,
                description=description,
                sequence_number=1,
                service_ids=[service1_id, service2_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                direction=nsx_constants.IN,
                ip_protocol=nsx_constants.IPV4,
                scope=None,
                logged=False,
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_entry_def)
            self.assertIsNotNone(result)

    def test_create_entry_no_service(self):
        domain_id = '111'
        map_id = '333'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_entry(
                name, domain_id, map_id,
                description=description,
                source_groups=[source_group],
                dest_groups=[dest_group],
                sequence_number=1,
                tenant=TEST_TENANT)

            expected_entry_def = self.entryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id=mock.ANY,
                name=name,
                action=constants.ACTION_ALLOW,
                direction=nsx_constants.IN_OUT,
                ip_protocol=nsx_constants.IPV4_IPV6,
                description=description,
                sequence_number=1,
                service_ids=None,
                source_groups=[source_group],
                dest_groups=[dest_group],
                scope=None,
                logged=False,
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_entry_def)
            self.assertIsNotNone(result)

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
            result = self.resourceApi.create_entry(
                name, domain_id, map_id,
                description=description,
                service_ids=[service1_id, service2_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                logged=False,
                tenant=TEST_TENANT)

            expected_entry_def = self.entryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id=mock.ANY,
                name=name,
                action=constants.ACTION_ALLOW,
                direction=nsx_constants.IN_OUT,
                ip_protocol=nsx_constants.IPV4_IPV6,
                description=description,
                service_ids=[service1_id, service2_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                sequence_number=seq_num + 1,
                scope=None,
                logged=False,
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_entry_def)
            self.assertIsNotNone(result)

    def test_create_with_entries(self):
        domain_id = '111'
        map_id = '222'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        service_id = 'c1'
        category = 'Emergency'
        ip_protocol = nsx_constants.IPV4
        map_seq_num = 10

        rule_id = 1
        entry1 = self.resourceApi.build_entry(
            'DHCP Reply', domain_id, map_id,
            rule_id, sequence_number=rule_id, service_ids=[service_id],
            action=constants.ACTION_DENY,
            source_groups=None,
            dest_groups=[dest_group],
            direction=nsx_constants.IN,
            ip_protocol=ip_protocol)
        rule_id += 1
        entry2 = self.resourceApi.build_entry(
            'DHCP Request', domain_id, map_id,
            rule_id, sequence_number=rule_id, service_ids=None,
            action=constants.ACTION_DENY,
            source_groups=[source_group],
            dest_groups=None,
            direction=nsx_constants.OUT, ip_protocol=ip_protocol)

        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call:
            result = self.resourceApi.create_with_entries(
                name, domain_id,
                map_id=map_id,
                description=description,
                entries=[entry1, entry2],
                category=category,
                map_sequence_number=map_seq_num,
                tenant=TEST_TENANT)

            expected_def = self.mapDef(
                domain_id=domain_id,
                map_id=map_id,
                name=name,
                description=description,
                category=category,
                map_sequence_number=map_seq_num,
                tenant=TEST_TENANT)

            self.assert_called_with_defs(api_call,
                                         [expected_def, entry1, entry2])
            self.assertEqual(map_id, result)

    def test_delete(self):
        domain_id = '111'
        map_id = '222'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(domain_id, map_id, tenant=TEST_TENANT)
            expected_def = self.mapDef(
                domain_id=domain_id,
                map_id=map_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_delete_entry(self):
        domain_id = '111'
        map_id = '222'
        entry_id = '333'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete_entry(domain_id, map_id, entry_id,
                                          tenant=TEST_TENANT)
            expected_def = self.entryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id=entry_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        domain_id = '111'
        map_id = '222'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': map_id}) as api_call:
            result = self.resourceApi.get(domain_id, map_id,
                                          tenant=TEST_TENANT)
            expected_def = self.mapDef(
                domain_id=domain_id,
                map_id=map_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(map_id, result['id'])

    def test_get_entry(self):
        domain_id = '111'
        map_id = '222'
        entry_id = '333'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': entry_id}) as api_call:
            result = self.resourceApi.get_entry(domain_id, map_id,
                                                entry_id, tenant=TEST_TENANT)
            expected_def = self.entryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id=entry_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(entry_id, result['id'])

    def test_get_by_name(self):
        domain_id = '111'
        name = 'cm1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(domain_id, name,
                                               tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = self.mapDef(
                domain_id=domain_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        domain_id = '111'
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(domain_id, tenant=TEST_TENANT)
            expected_def = self.mapDef(
                domain_id=domain_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        domain_id = '111'
        map_id = '222'
        name = 'new name'
        description = 'new desc'
        source_group = 'ng1'
        dest_group = 'ng2'
        service1_id = 'nc1'
        service2_id = 'nc2'
        category = constants.CATEGORY_EMERGENCY
        with mock.patch.object(self.policy_api, "get",
                               return_value={}),\
            mock.patch.object(self.resourceApi, "get",
                              return_value={'category': category}),\
            mock.patch.object(self.policy_api,
                              "create_with_parent") as update_call:
            self.resourceApi.update(domain_id, map_id,
                                    name=name,
                                    description=description,
                                    service_ids=[service1_id, service2_id],
                                    source_groups=[source_group],
                                    dest_groups=[dest_group],
                                    tenant=TEST_TENANT)
            map_def = self.mapDef(
                domain_id=domain_id,
                map_id=map_id,
                name=name,
                description=description,
                category=category,
                tenant=TEST_TENANT)

            entry_def = self.entryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id='entry',
                service_ids=[service1_id, service2_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                tenant=TEST_TENANT)

            self.assert_called_with_defs(update_call, [map_def, entry_def])

    def test_update_entry(self):
        domain_id = '111'
        map_id = '222'
        entry_id = 'entry'
        name = 'new name'
        description = 'new desc'
        source_group = 'ng1'
        dest_group = 'ng2'
        service1_id = 'nc1'
        service2_id = 'nc2'
        with mock.patch.object(self.policy_api, "get",
                               return_value={}),\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update_entry(
                domain_id, map_id, entry_id,
                name=name,
                description=description,
                service_ids=[service1_id, service2_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                tenant=TEST_TENANT)

            entry_def = self.entryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id=entry_id,
                name=name,
                description=description,
                service_ids=[service1_id, service2_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                tenant=TEST_TENANT)

            self.assert_called_with_def(update_call, entry_def)

    def test_update_entries(self):
        domain_id = '111'
        map_id = '222'
        entry1_id = 'entry1'
        entry2_id = 'entry2'
        entry3_id = 'entry3'
        entry1 = self.entryDef(
            domain_id=domain_id,
            map_id=map_id,
            entry_id=entry1_id,
            scope=['new_scope1'],
            tenant=TEST_TENANT)
        entry2 = self.entryDef(
            domain_id=domain_id,
            map_id=map_id,
            entry_id=entry2_id,
            scope=['scope2'],
            tenant=TEST_TENANT)
        original_map = {'rules': [
            {'id': entry1_id, 'resource_type': 'Rule',
             'dsiplay_name': 'name1', 'scope': ['scope1']},
            {'id': entry2_id, 'resource_type': 'Rule',
             'display_name': 'name2', 'scope': ['scope2']},
            {'id': entry3_id, 'resource_type': 'Rule',
             'display_name': 'name3', 'scope': ['scope3']}]}
        updated_map = {'rules': [
            {'id': entry1_id, 'resource_type': 'Rule',
             'dsiplay_name': 'name1', 'scope': ['new_scope1']},
            {'id': entry2_id, 'resource_type': 'Rule',
             'display_name': 'name2', 'scope': ['scope2']}]}
        map_def = self.mapDef(
            domain_id=domain_id,
            map_id=map_id,
            tenant=TEST_TENANT)
        with mock.patch.object(self.policy_api, "get",
                               return_value=original_map),\
            mock.patch.object(self.policy_api.client,
                              "update") as update_call:
            self.resourceApi.update_entries(
                domain_id, map_id, [entry1, entry2],
                tenant=TEST_TENANT)
            update_call.assert_called_once_with(
                map_def.get_resource_path(), updated_map)

    def test_unset(self):
        name = 'hello'
        domain_id = 'test'
        map_id = '111'
        dest_groups = ['/infra/stuff']
        category = constants.CATEGORY_EMERGENCY

        # Until policy PATCH is fixed to accept partial update, we
        # call get on child entry
        with mock.patch.object(
            self.policy_api, "get",
            return_value={'display_name': name,
                          'source_groups': ['/infra/other/stuff'],
                          'destination_groups': dest_groups}),\
            mock.patch.object(self.resourceApi, "get",
                              return_value={'category': category}):
            self.resourceApi.update(domain_id, map_id,
                                    description=None,
                                    source_groups=None,
                                    service_ids=None,
                                    tenant=TEST_TENANT)

        expected_body = {'id': map_id,
                         'description': None,
                         'category': category,
                         'resource_type': self.resource_type,
                         'rules': [{
                             'display_name': name,
                             'id': 'entry',
                             'resource_type': 'Rule',
                             'services': ["ANY"],
                             'source_groups': ["ANY"],
                             'destination_groups': dest_groups}]
                         }

        url = '%s/domains/%s/%s/%s' % (TEST_TENANT,
                                       domain_id,
                                       self.path_name,
                                       map_id)
        self.assert_json_call('PATCH', self.client, url, data=expected_body)

    def test_update_entries_logged(self):
        domain_id = '111'
        map_id = '222'
        dummy_map = {'rules': [{'logged': False}]}
        updated_map = {'rules': [{'logged': True}]}
        map_def = self.mapDef(
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
        result = [{'state': constants.STATE_REALIZED,
                   'entity_type': 'RealizedFirewallSection'}]
        with mock.patch.object(
            self.policy_api, "get_realized_entities",
            return_value=result) as api_get:
            state = self.resourceApi.get_realized_state(
                domain_id, map_id, tenant=TEST_TENANT)
            self.assertEqual(constants.STATE_REALIZED, state)
            path = "/%s/domains/%s/%s/%s" % (
                TEST_TENANT, domain_id, self.path_name, map_id)
            api_get.assert_called_once_with(path, silent=False)


class TestPolicyGatewayPolicy(TestPolicyCommunicationMap):

    def setUp(self, *args, **kwargs):
        super(TestPolicyGatewayPolicy, self).setUp()
        self.resourceApi = self.policy_lib.gateway_policy
        self.mapDef = core_defs.GatewayPolicyDef
        self.entryDef = core_defs.GatewayPolicyRuleDef
        self.resource_type = 'GatewayPolicy'
        self.path_name = 'gateway-policies'


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
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                ip_address=ip_address,
                thumbprint=thumbprint,
                username=username,
                password=password,
                edge_cluster_id=edge_cluster_id,
                transport_zone_id=transport_zone_id,
                tenant=TEST_TENANT)

            expected_def = core_defs.EnforcementPointDef(
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
            self.assertIsNotNone(result)

    def test_delete(self):
        ef_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(ef_id, tenant=TEST_TENANT)
            expected_def = core_defs.EnforcementPointDef(ep_id=ef_id,
                                                         tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        ef_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': ef_id}) as api_call:
            result = self.resourceApi.get(ef_id, tenant=TEST_TENANT)
            expected_def = core_defs.EnforcementPointDef(ep_id=ef_id,
                                                         tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(ef_id, result['id'])

    def test_get_by_name(self):
        name = 'ep1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = core_defs.EnforcementPointDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = core_defs.EnforcementPointDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        ef_id = '111'
        name = 'new name'
        username = 'admin'
        password = 'zzz'
        ip_address = '1.1.1.1'
        thumbprint = 'abc'
        edge_cluster_id = 'ec1'
        transport_zone_id = 'tz1'
        entry = {'id': ef_id,
                 'connection_info': {'thumbprint': thumbprint,
                                     'resource_type': 'NSXTConnectionInfo'}}

        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call,\
            mock.patch.object(self.policy_api, "get",
                              return_value=entry):
            self.resourceApi.update(ef_id,
                                    name=name,
                                    username=username,
                                    password=password,
                                    ip_address=ip_address,
                                    edge_cluster_id=edge_cluster_id,
                                    transport_zone_id=transport_zone_id,
                                    tenant=TEST_TENANT)
            expected_def = core_defs.EnforcementPointDef(
                ep_id=ef_id,
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
        result = [{'state': constants.STATE_REALIZED}]
        with mock.patch.object(
            self.policy_api, "get_realized_entities",
            return_value=result) as api_get:
            state = self.resourceApi.get_realized_state(
                ep_id, tenant=TEST_TENANT)
            self.assertEqual(constants.STATE_REALIZED, state)
            path = "/%s/sites/default/enforcement-points/%s" % (
                TEST_TENANT, ep_id)
            api_get.assert_called_once_with(path, silent=False)


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
            result = self.resourceApi.create_or_overwrite(
                name,
                description=description,
                ep_id=ep_id,
                domain_id=domain_id,
                tenant=TEST_TENANT)
            expected_def = core_defs.DeploymentMapDef(
                map_id=mock.ANY,
                name=name,
                description=description,
                ep_id=ep_id,
                domain_id=domain_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        domain_id = 'domain1'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, domain_id=domain_id,
                                    tenant=TEST_TENANT)
            expected_def = core_defs.DeploymentMapDef(map_id=obj_id,
                                                      domain_id=domain_id,
                                                      tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        domain_id = 'domain1'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, domain_id=domain_id,
                                          tenant=TEST_TENANT)
            expected_def = core_defs.DeploymentMapDef(map_id=obj_id,
                                                      domain_id=domain_id,
                                                      tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'ep1'
        domain_id = 'domain1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, domain_id=domain_id,
                                               tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = core_defs.DeploymentMapDef(domain_id=domain_id,
                                                      tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        domain_id = 'domain1'
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(domain_id=domain_id,
                                           tenant=TEST_TENANT)
            expected_def = core_defs.DeploymentMapDef(domain_id=domain_id,
                                                      tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        domain_id = 'domain2'
        ep_id = 'ep2'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    ep_id=ep_id,
                                    domain_id=domain_id,
                                    tenant=TEST_TENANT)
            expected_def = core_defs.DeploymentMapDef(
                map_id=obj_id,
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
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = core_defs.TransportZoneDef(tz_id=obj_id,
                                                      tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_with_cache(self):
        """Verify that cache is used for GET"""
        obj_id = '111'
        with mock.patch.object(self.policy_api.client, "get") as client_get:
            self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            self.assertEqual(1, client_get.call_count)

    def test_get_by_name(self):
        name = 'tz1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = core_defs.TransportZoneDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_tz_type(self):
        obj_id = '111'
        tz_type = self.resourceApi.TZ_TYPE_OVERLAY
        with mock.patch.object(self.policy_api, "get",
                               return_value={'tz_type': tz_type}) as api_call:
            actual_tz_type = self.resourceApi.get_tz_type(
                obj_id, tenant=TEST_TENANT)
            expected_def = core_defs.TransportZoneDef(tz_id=obj_id,
                                                      tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(tz_type, actual_tz_type)

    def test_get_transport_type(self):
        obj_id = '111'
        tz_type = self.resourceApi.TZ_TYPE_OVERLAY
        with mock.patch.object(self.policy_api, "get",
                               return_value={'tz_type': tz_type}) as api_call:
            actual_tz_type = self.resourceApi.get_transport_type(
                obj_id, tenant=TEST_TENANT)
            expected_def = core_defs.TransportZoneDef(tz_id=obj_id,
                                                      tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(nsx_constants.TRANSPORT_TYPE_OVERLAY,
                             actual_tz_type)

    def test_get_switch_mode(self):
        obj_id = '111'
        tz_type = self.resourceApi.TZ_TYPE_OVERLAY
        with mock.patch.object(self.policy_api, "get",
                               return_value={'tz_type': tz_type}) as api_call:
            actual_sm = self.resourceApi.get_host_switch_mode(
                obj_id, tenant=TEST_TENANT)
            expected_def = core_defs.TransportZoneDef(tz_id=obj_id,
                                                      tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(nsx_constants.HOST_SWITCH_MODE_STANDARD,
                             actual_sm)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = core_defs.TransportZoneDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)


class TestPolicyEdgeCluster(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyEdgeCluster, self).setUp()
        self.resourceApi = self.policy_lib.edge_cluster

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = core_defs.EdgeClusterDef(ec_id=obj_id,
                                                    tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'tz1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = core_defs.EdgeClusterDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = core_defs.EdgeClusterDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)


class TestPolicyTier1(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTier1, self).setUp(*args, **kwargs)
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
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tier0=tier0_id,
                force_whitelisting=True,
                route_advertisement=route_adv,
                tenant=TEST_TENANT)

            expected_def = core_defs.Tier1Def(
                tier1_id=mock.ANY,
                name=name,
                description=description,
                tier0=tier0_id,
                force_whitelisting=True,
                failover_mode=constants.NON_PREEMPTIVE,
                route_advertisement=route_adv,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = core_defs.Tier1Def(tier1_id=obj_id,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = core_defs.Tier1Def(tier1_id=obj_id,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_path(self):
        obj_id = '111'
        result = self.resourceApi.get_path(obj_id, tenant=TEST_TENANT)
        self.assertEqual('/%s/tier-1s/%s' % (TEST_TENANT, obj_id), result)

    def test_get_with_no_cache(self):
        """Make sure cache is not used for GET requests"""
        obj_id = '111'
        with mock.patch.object(self.policy_api.client, "get") as client_get:
            self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            self.assertEqual(2, client_get.call_count)

    def test_get_by_name(self):
        name = 'test'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = core_defs.Tier1Def(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = core_defs.Tier1Def(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        tier0 = 'tier0'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name, tier0=tier0,
                                    enable_standby_relocation=False,
                                    tenant=TEST_TENANT)
            expected_def = core_defs.Tier1Def(tier1_id=obj_id,
                                              name=name,
                                              tier0=tier0,
                                              enable_standby_relocation=False,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(
                update_call, expected_def)

    def test_update_ignore_tier0(self):
        obj_id = '111'
        name = 'new name'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    enable_standby_relocation=False,
                                    tenant=TEST_TENANT)
            expected_def = core_defs.Tier1Def(tier1_id=obj_id,
                                              name=name,
                                              enable_standby_relocation=False,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)
            # make sure tier0 is not in the body
            actual_def = update_call.call_args_list[0][0][0]
            self.assertNotIn('tier0_path', actual_def.get_obj_dict())

    def test_update_unset_tier0(self):
        obj_id = '111'
        name = 'new name'
        description = 'abc'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    tier0=None,
                                    enable_standby_relocation=False,
                                    tenant=TEST_TENANT)
            expected_def = core_defs.Tier1Def(tier1_id=obj_id,
                                              name=name,
                                              description=description,
                                              tier0=None,
                                              enable_standby_relocation=False,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)
            # make sure tier0 is in the body with value None
            actual_def = update_call.call_args_list[0][0][0]
            self.assertIn('tier0_path', actual_def.get_obj_dict())
            self.assertIsNone(actual_def.get_obj_dict()['tier0_path'])

    def test_update_route_adv(self):
        obj_id = '111'
        rtr_name = 'rtr111'
        get_result = {'id': obj_id,
                      'display_name': rtr_name,
                      'enable_standby_relocation': False,
                      'route_advertisement_types': ['TIER1_NAT',
                                                    'TIER1_LB_VIP']}
        with mock.patch.object(self.policy_api, "get",
                               return_value=get_result),\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update_route_advertisement(
                obj_id,
                static_routes=True,
                lb_vip=False,
                lb_snat=True,
                tenant=TEST_TENANT)

            new_adv = self.resourceApi.build_route_advertisement(
                nat=True, static_routes=True, lb_snat=True)

            expected_def = core_defs.Tier1Def(tier1_id=obj_id,
                                              name=rtr_name,
                                              enable_standby_relocation=False,
                                              route_advertisement=new_adv,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(
                update_call, expected_def)

    def test_set_enable_standby_relocation(self):
        obj_id = '111'
        name = 'new name'
        tier0 = 'tier0'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name, tier0=tier0,
                                    enable_standby_relocation=True,
                                    tenant=TEST_TENANT)
            expected_def = core_defs.Tier1Def(tier1_id=obj_id,
                                              name=name,
                                              tier0=tier0,
                                              enable_standby_relocation=True,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(
                update_call, expected_def)

    def test_wait_until_realized_fail(self):
        tier1_id = '111'
        logical_router_id = 'realized_111'
        info = {'state': constants.STATE_UNREALIZED,
                'realization_specific_identifier': logical_router_id,
                'entity_type': 'RealizedLogicalRouter'}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            self.assertRaises(nsxlib_exc.ManagerError,
                              self.resourceApi.wait_until_realized,
                              tier1_id, max_attempts=5, sleep=0.1,
                              tenant=TEST_TENANT)

    def test_wait_until_realized_succeed(self):
        tier1_id = '111'
        logical_router_id = 'realized_111'
        info = {'state': constants.STATE_REALIZED,
                'realization_specific_identifier': logical_router_id,
                'entity_type': 'RealizedLogicalRouter'}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            actual_info = self.resourceApi.wait_until_realized(
                tier1_id, max_attempts=5, sleep=0.1, tenant=TEST_TENANT)
            self.assertEqual(info, actual_info)

    def test_update_transport_zone(self):
        # Test the passthrough api
        tier1_id = '111'
        logical_router_id = 'realized_111'
        tz_uuid = 'dummy_tz'
        info = {'state': constants.STATE_REALIZED,
                'entity_type': 'RealizedLogicalRouter',
                'realization_specific_identifier': logical_router_id}
        passthrough_mock = self.resourceApi.nsx_api.logical_router.update
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info) as realization:
            self.resourceApi.update_transport_zone(tier1_id, tz_uuid,
                                                   tenant=TEST_TENANT)
            realization.assert_called_once()
            passthrough_mock.assert_called_once_with(
                logical_router_id, transport_zone_id=tz_uuid)

    def test_wait_until_realized(self):
        tier1_id = '111'
        logical_router_id = 'realized_111'
        info = {'state': constants.STATE_UNREALIZED,
                'realization_specific_identifier': logical_router_id}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            self.assertRaises(nsxlib_exc.ManagerError,
                              self.resourceApi.wait_until_realized,
                              tier1_id, tenant=TEST_TENANT,
                              max_attempts=5, sleep=0.1)

    def test_get_realized_downlink_port(self):
        tier1_id = '111'
        segment_id = '222'
        lrp_id = '333'
        info = {'state': constants.STATE_REALIZED,
                'realization_specific_identifier': lrp_id,
                'entity_type': 'RealizedLogicalRouterPort'}
        dummy_port = {'resource_type': nsx_constants.LROUTERPORT_DOWNLINK,
                      'id': lrp_id,
                      'display_name': 'test_%s' % segment_id}
        with mock.patch.object(self.resourceApi.policy_api,
                               "get_realized_entities",
                               return_value=[info]),\
            mock.patch.object(self.resourceApi.nsx_api.logical_router_port,
                              "get", return_value=dummy_port):
            actual_id = self.resourceApi._get_realized_downlink_port(
                tier1_id, segment_id)
            self.assertEqual(lrp_id, actual_id)

    def test_set_dhcp_relay(self):
        tier1_id = '111'
        segment_id = '222'
        lrp_id = '333'
        relay_id = '444'
        info = {'state': constants.STATE_REALIZED,
                'realization_specific_identifier': lrp_id,
                'entity_type': 'RealizedLogicalRouterPort'}
        dummy_port = {'resource_type': nsx_constants.LROUTERPORT_DOWNLINK,
                      'id': lrp_id,
                      'display_name': 'test_%s' % segment_id}
        with mock.patch.object(self.resourceApi.policy_api,
                               "get_realized_entities",
                               return_value=[info]),\
            mock.patch.object(self.resourceApi.nsx_api.logical_router_port,
                              "get", return_value=dummy_port),\
            mock.patch.object(self.resourceApi.nsx_api.logical_router_port,
                              "update") as nsx_lrp_update:
            self.resourceApi.set_dhcp_relay(tier1_id, segment_id, relay_id)
            nsx_lrp_update.assert_called_once_with(
                lrp_id, relay_service_uuid=relay_id)

    def test_get_edge_cluster(self):
        tier1_id = '111'
        path = 'dummy/path'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'edge_cluster_path': path}):
            result = self.resourceApi.get_edge_cluster_path(
                tier1_id, tenant=TEST_TENANT)
            self.assertEqual(path, result)

    def test_set_edge_cluster(self):
        tier1_id = '111'
        path = 'dummy/path'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.set_edge_cluster_path(
                tier1_id, path,
                tenant=TEST_TENANT)

            expected_def = core_defs.Tier1LocaleServiceDef(
                tier1_id=tier1_id,
                service_id=self.resourceApi._locale_service_id(tier1_id),
                edge_cluster_path=path,
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_def)

    def test_remove_edge_cluster(self):
        tier1_id = '111'
        with mock.patch.object(self.policy_api,
                               "delete") as api_call:
            self.resourceApi.remove_edge_cluster(
                tier1_id,
                tenant=TEST_TENANT)
            expected_def = core_defs.Tier1LocaleServiceDef(
                tier1_id=tier1_id,
                service_id=self.resourceApi._locale_service_id(tier1_id),
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_add_router_interface(self):
        tier1_id = '111'
        interface_id = 'seg-if'
        segment_id = 'seg'
        ip_addr = '1.1.1.1'
        prefix_len = '24'
        subnet = core_defs.InterfaceSubnet([ip_addr], prefix_len)
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.add_segment_interface(
                tier1_id, interface_id, segment_id,
                subnets=[subnet],
                tenant=TEST_TENANT)

            expected_def = core_defs.Tier1InterfaceDef(
                tier1_id=tier1_id,
                service_id=self.resourceApi._locale_service_id(tier1_id),
                interface_id=interface_id,
                segment_id=segment_id,
                subnets=[subnet],
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_def)

    def test_remove_router_interface(self):
        tier1_id = '111'
        interface_id = 'seg-if'
        with mock.patch.object(self.policy_api,
                               "delete") as api_call:
            self.resourceApi.remove_segment_interface(
                tier1_id, interface_id,
                tenant=TEST_TENANT)

            expected_def = core_defs.Tier1InterfaceDef(
                tier1_id=tier1_id,
                service_id=self.resourceApi._locale_service_id(tier1_id),
                interface_id=interface_id,
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_def)


class TestPolicyTier1NoPassthrough(TestPolicyTier1):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTier1NoPassthrough, self).setUp(
            allow_passthrough=False)

    def test_update_transport_zone(self):
        # Will not work without passthrough api
        tier1_id = '111'
        tz_uuid = 'dummy_tz'
        with mock.patch.object(self.resourceApi,
                               "_get_realization_info") as realization:
            self.resourceApi.update_transport_zone(tier1_id, tz_uuid,
                                                   tenant=TEST_TENANT)
            realization.assert_not_called()

    def test_get_realized_downlink_port(self):
        # Will not work without passthrough api
        tier1_id = '111'
        segment_id = '222'
        with mock.patch.object(self.resourceApi.policy_api,
                               "get_realized_entities") as realization:
            actual_id = self.resourceApi._get_realized_downlink_port(
                tier1_id, segment_id)
            self.assertIsNone(actual_id)
            realization.assert_not_called()

    def test_set_dhcp_relay(self):
        # Will not work without passthrough api
        tier1_id = '111'
        segment_id = '222'
        relay_id = '444'
        with mock.patch.object(self.resourceApi.policy_api,
                               "get_realized_entities") as realization:
            self.resourceApi.set_dhcp_relay(tier1_id, segment_id, relay_id)
            realization.assert_not_called()


class TestPolicyTier0NatRule(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTier0NatRule, self).setUp()
        self.resourceApi = self.policy_lib.tier0_nat_rule

    def test_create(self):
        name = 'test'
        description = 'desc'
        tier0_id = '111'
        nat_rule_id = 'rule1'
        action = constants.NAT_ACTION_SNAT
        cidr1 = '1.1.1.1/32'
        cidr2 = '2.2.2.0/24'
        enabled = True

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, tier0_id,
                nat_rule_id=nat_rule_id,
                description=description,
                action=action,
                translated_network=cidr1,
                source_network=cidr2,
                tenant=TEST_TENANT,
                enabled=enabled)
            expected_def = core_defs.Tier0NatRule(
                tier0_id=tier0_id,
                nat_rule_id=nat_rule_id,
                nat_id=self.resourceApi.DEFAULT_NAT_ID,
                name=name,
                description=description,
                action=action,
                translated_network=cidr1,
                source_network=cidr2,
                tenant=TEST_TENANT,
                enabled=enabled)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        tier0_id = '111'
        nat_rule_id = 'rule1'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(
                tier0_id,
                nat_rule_id,
                tenant=TEST_TENANT)
            expected_def = core_defs.Tier0NatRule(
                tier0_id=tier0_id,
                nat_rule_id=nat_rule_id,
                nat_id=self.resourceApi.DEFAULT_NAT_ID,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        tier0_id = '111'
        nat_rule_id = 'rule1'
        with mock.patch.object(self.policy_api, "get") as api_call:
            mock_t0_nat_rule = mock.Mock()
            api_call.return_value = mock_t0_nat_rule
            result = self.resourceApi.get(tier0_id, nat_rule_id,
                                          tenant=TEST_TENANT)
            expected_def = core_defs.Tier0NatRule(
                tier0_id=tier0_id,
                nat_rule_id=nat_rule_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(mock_t0_nat_rule, result)


class TestPolicyTier1NatRule(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTier1NatRule, self).setUp()
        self.resourceApi = self.policy_lib.tier1_nat_rule

    def test_create(self):
        name = 'test'
        description = 'desc'
        tier1_id = '111'
        nat_rule_id = 'rule1'
        action = constants.NAT_ACTION_SNAT
        cidr1 = '1.1.1.1/32'
        cidr2 = '2.2.2.0/24'
        enabled = True

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, tier1_id,
                nat_rule_id=nat_rule_id,
                description=description,
                action=action,
                translated_network=cidr1,
                source_network=cidr2,
                tenant=TEST_TENANT,
                enabled=enabled)

            expected_def = core_defs.Tier1NatRule(
                tier1_id=tier1_id,
                nat_rule_id=nat_rule_id,
                nat_id=self.resourceApi.DEFAULT_NAT_ID,
                name=name,
                description=description,
                action=action,
                translated_network=cidr1,
                source_network=cidr2,
                tenant=TEST_TENANT,
                enabled=enabled)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        tier1_id = '111'
        nat_rule_id = 'rule1'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(
                tier1_id,
                nat_rule_id,
                tenant=TEST_TENANT)
            expected_def = core_defs.Tier1NatRule(
                tier1_id=tier1_id,
                nat_rule_id=nat_rule_id,
                nat_id=self.resourceApi.DEFAULT_NAT_ID,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)


class TestPolicyTier1StaticRoute(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTier1StaticRoute, self).setUp()
        self.resourceApi = self.policy_lib.tier1_static_route

    def test_create(self):
        name = 'test'
        description = 'desc'
        tier1_id = '111'
        static_route_id = '222'
        network = '1.1.1.1/24'
        nexthop = '2.2.2.2'

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, tier1_id,
                static_route_id=static_route_id,
                description=description,
                network=network,
                next_hop=nexthop,
                tenant=TEST_TENANT)

            expected_def = core_defs.Tier1StaticRoute(
                tier1_id=tier1_id,
                static_route_id=static_route_id,
                name=name,
                description=description,
                network=network,
                next_hop=nexthop,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        tier1_id = '111'
        static_route_id = '222'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(
                tier1_id,
                static_route_id,
                tenant=TEST_TENANT)
            expected_def = core_defs.Tier1StaticRoute(
                tier1_id=tier1_id,
                static_route_id=static_route_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        tier1_id = '111'
        static_route_id = '222'
        with mock.patch.object(self.policy_api, "get") as api_call:
            mock_get = mock.Mock()
            api_call.return_value = mock_get
            result = self.resourceApi.get(
                tier1_id,
                static_route_id,
                tenant=TEST_TENANT)
            expected_def = core_defs.Tier1StaticRoute(
                tier1_id=tier1_id,
                static_route_id=static_route_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(mock_get, result)


class TestPolicyTier0(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTier0, self).setUp()
        self.resourceApi = self.policy_lib.tier0

    def test_create(self):
        name = 'test'
        description = 'desc'
        dhcp_config = '111'
        subnets = ["2.2.2.0/24"]
        ipv6_profile_id = '222'

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                dhcp_config=dhcp_config,
                force_whitelisting=True,
                default_rule_logging=True,
                transit_subnets=subnets,
                ipv6_ndra_profile_id=ipv6_profile_id,
                tenant=TEST_TENANT)

            expected_def = core_defs.Tier0Def(
                tier0_id=mock.ANY,
                name=name,
                description=description,
                dhcp_config=dhcp_config,
                default_rule_logging=True,
                force_whitelisting=True,
                ha_mode=constants.ACTIVE_ACTIVE,
                failover_mode=constants.NON_PREEMPTIVE,
                transit_subnets=subnets,
                ipv6_ndra_profile_id=ipv6_profile_id,
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = core_defs.Tier0Def(tier0_id=obj_id,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = core_defs.Tier0Def(tier0_id=obj_id,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_path(self):
        obj_id = '111'
        result = self.resourceApi.get_path(obj_id, tenant=TEST_TENANT)
        self.assertEqual('/%s/tier-0s/%s' % (TEST_TENANT, obj_id), result)

    def test_get_with_cache(self):
        """Make sure the cache is used for GET requests"""
        obj_id = '111'
        with mock.patch.object(self.policy_api.client, "get") as client_get:
            self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            self.assertEqual(1, client_get.call_count)

    def test_get_by_name(self):
        name = 'test'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = core_defs.Tier0Def(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = core_defs.Tier0Def(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    tenant=TEST_TENANT)
            expected_def = core_defs.Tier0Def(tier0_id=obj_id,
                                              name=name,
                                              tenant=TEST_TENANT)
            self.assert_called_with_def(
                update_call, expected_def)

    def test_get_overlay_transport_zone(self):
        # Test the passthrough api
        tier0_id = '111'
        logical_router_id = 'realized_111'
        info = {'state': constants.STATE_REALIZED,
                'entity_type': 'RealizedLogicalRouter',
                'realization_specific_identifier': logical_router_id}
        pt_mock = self.resourceApi.nsx_api.router.get_tier0_router_overlay_tz
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info) as realization:
            result = self.resourceApi.get_overlay_transport_zone(
                tier0_id, tenant=TEST_TENANT)
            realization.assert_called_once()
            pt_mock.assert_called_once_with(logical_router_id)
            self.assertIsNotNone(result)

    def test_wait_until_realized(self):
        tier1_id = '111'
        logical_router_id = 'realized_111'
        info = {'state': constants.STATE_UNREALIZED,
                'realization_specific_identifier': logical_router_id}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            self.assertRaises(nsxlib_exc.ManagerError,
                              self.resourceApi.wait_until_realized,
                              tier1_id, max_attempts=5, sleep=0.1,
                              tenant=TEST_TENANT)

    def test_get_uplink_ips(self):
        tier0_id = '111'
        ip_addr = '5.5.5.5'
        interface = {'id': '222', 'type': 'EXTERNAL',
                     'subnets': [{'ip_addresses': [ip_addr]}]}
        with mock.patch.object(self.resourceApi.policy_api, "list",
                               return_value={'results': [interface]}):
            uplink_ips = self.resourceApi.get_uplink_ips(
                tier0_id, tenant=TEST_TENANT)
            self.assertEqual([ip_addr], uplink_ips)

    def test_get_transport_zones(self):
        # Test the passthrough api
        tier0_id = '111'
        logical_router_id = 'realized_111'
        info = {'state': constants.STATE_REALIZED,
                'entity_type': 'RealizedLogicalRouter',
                'realization_specific_identifier': logical_router_id}
        pt_mock = self.resourceApi.nsx_api.router.get_tier0_router_tz
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info) as realization:
            result = self.resourceApi.get_transport_zones(
                tier0_id, tenant=TEST_TENANT)
            realization.assert_called_once()
            pt_mock.assert_called_once_with(logical_router_id)
            self.assertIsNotNone(result)


class TestPolicyTier1Segment(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTier1Segment, self).setUp()
        self.resourceApi = self.policy_lib.tier1_segment

    def test_create(self):
        name = 'test'
        description = 'desc'
        tier1_id = '111'
        ip_pool_id = 'external-ip-pool'

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tier1_id=tier1_id,
                ip_pool_id=ip_pool_id,
                tenant=TEST_TENANT)

            expected_def = core_defs.Tier1SegmentDef(
                segment_id=mock.ANY,
                name=name,
                description=description,
                tier1_id=tier1_id,
                ip_pool_id=ip_pool_id,
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        tier1_id = '111'
        segment_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(tier1_id, segment_id, tenant=TEST_TENANT)
            expected_def = core_defs.Tier1SegmentDef(
                tier1_id=tier1_id, segment_id=segment_id, tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        tier1_id = '111'
        segment_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': segment_id}) as api_call:
            result = self.resourceApi.get(tier1_id, segment_id,
                                          tenant=TEST_TENANT)
            expected_def = core_defs.Tier1SegmentDef(
                tier1_id=tier1_id, segment_id=segment_id, tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(segment_id, result['id'])

    def test_list(self):
        tier1_id = '111'
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tier1_id=tier1_id,
                                           tenant=TEST_TENANT)
            expected_def = core_defs.Tier1SegmentDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        tier1_id = '111'
        segment_id = '111'
        name = 'new name'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(segment_id=segment_id,
                                    tier1_id=tier1_id,
                                    name=name,
                                    tenant=TEST_TENANT)
            expected_def = core_defs.Tier1SegmentDef(
                tier1_id=tier1_id, segment_id=segment_id,
                name=name, tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)

    def test_build_subnet(self):
        gateway_address = "10.0.0.1/24"
        dhcp_ranges = None
        subnet = self.resourceApi.build_subnet(
            gateway_address=gateway_address, dhcp_ranges=dhcp_ranges)
        self.assertEqual(gateway_address, subnet.gateway_address)
        self.assertEqual(dhcp_ranges, subnet.dhcp_ranges)


class TestPolicySegment(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicySegment, self).setUp()
        self.resourceApi = self.policy_lib.segment

    def test_create(self):
        name = 'test'
        description = 'desc'
        tier1_id = '111'
        subnets = [core_defs.Subnet(gateway_address="2.2.2.0/24")]

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tier1_id=tier1_id,
                subnets=subnets,
                tenant=TEST_TENANT)

            expected_def = core_defs.SegmentDef(
                segment_id=mock.ANY,
                name=name,
                description=description,
                tier1_id=tier1_id,
                subnets=subnets,
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        segment_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(segment_id, tenant=TEST_TENANT)
            expected_def = core_defs.SegmentDef(segment_id=segment_id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        segment_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': segment_id}) as api_call:
            result = self.resourceApi.get(segment_id, tenant=TEST_TENANT)
            expected_def = core_defs.SegmentDef(segment_id=segment_id,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(segment_id, result['id'])

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = core_defs.SegmentDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        segment_id = '111'
        name = 'new name'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(segment_id,
                                    name=name,
                                    tenant=TEST_TENANT)
            expected_def = core_defs.SegmentDef(segment_id=segment_id,
                                                name=name,
                                                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)

    def test_remove_connectivity_and_subnets(self):
        segment_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': segment_id}) as api_get,\
            mock.patch.object(self.policy_api.client, "update") as api_put:
            self.resourceApi.remove_connectivity_and_subnets(
                segment_id, tenant=TEST_TENANT)
            api_get.assert_called_once()
            api_put.assert_called_once_with(
                '%s/segments/%s' % (TEST_TENANT, segment_id),
                {'id': segment_id, 'connectivity_path': None, 'subnets': None})

    def test_build_subnet(self):
        gateway_address = "10.0.0.1/24"
        dhcp_ranges = None
        subnet = self.resourceApi.build_subnet(
            gateway_address=gateway_address, dhcp_ranges=dhcp_ranges)
        self.assertEqual(gateway_address, subnet.gateway_address)
        self.assertEqual(dhcp_ranges, subnet.dhcp_ranges)


class TestPolicyIpPool(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyIpPool, self).setUp()
        self.resourceApi = self.policy_lib.ip_pool

    def test_create(self):
        name = 'test'
        description = 'desc'
        ip_pool_id = '111'

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, ip_pool_id, description=description,
                tenant=TEST_TENANT)

            expected_def = core_defs.IpPoolDef(
                ip_pool_id=ip_pool_id,
                name=name,
                description=description,
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(ip_pool_id, result)

    def test_delete(self):
        ip_pool_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(ip_pool_id, tenant=TEST_TENANT)
            expected_def = core_defs.IpPoolDef(ip_pool_id=ip_pool_id,
                                               tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        ip_pool_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': ip_pool_id}) as api_call:
            result = self.resourceApi.get(ip_pool_id, tenant=TEST_TENANT)
            expected_def = core_defs.IpPoolDef(ip_pool_id=ip_pool_id,
                                               tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(ip_pool_id, result['id'])

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = core_defs.IpPoolDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        ip_pool_id = '111'
        name = 'new name'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(ip_pool_id,
                                    name=name,
                                    tenant=TEST_TENANT)
            expected_def = core_defs.IpPoolDef(ip_pool_id=ip_pool_id,
                                               name=name,
                                               tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)

    def test_allocate_ip(self):
        ip_pool_id = '111'
        ip_allocation_id = 'alloc-id'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.allocate_ip(ip_pool_id,
                                         ip_allocation_id,
                                         tenant=TEST_TENANT)
            expected_def = core_defs.IpPoolAllocationDef(
                ip_pool_id=ip_pool_id,
                ip_allocation_id=ip_allocation_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(update_call, expected_def)

    def test_release_ip(self):
        ip_pool_id = '111'
        ip_allocation_id = 'alloc-id'
        with mock.patch.object(self.policy_api, "delete") as delete_call:
            self.resourceApi.release_ip(ip_pool_id,
                                        ip_allocation_id,
                                        tenant=TEST_TENANT)
            expected_def = core_defs.IpPoolAllocationDef(
                ip_pool_id=ip_pool_id,
                ip_allocation_id=ip_allocation_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(delete_call, expected_def)

    def test_allocate_block_subnet(self):
        ip_pool_id = '111'
        ip_block_id = 'block-id'
        size = 256
        ip_subnet_id = 'subnet-id'

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.allocate_block_subnet(
                ip_pool_id, ip_block_id, size, ip_subnet_id,
                tenant=TEST_TENANT)

            expected_def = core_defs.IpPoolBlockSubnetDef(
                ip_pool_id=ip_pool_id,
                ip_block_id=ip_block_id,
                ip_subnet_id=ip_subnet_id,
                size=size,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_release_block_subnet(self):
        ip_pool_id = '111'
        ip_subnet_id = 'subnet-id'
        with mock.patch.object(self.policy_api, "delete") as delete_call:
            self.resourceApi.release_block_subnet(ip_pool_id,
                                                  ip_subnet_id,
                                                  tenant=TEST_TENANT)
            expected_def = core_defs.IpPoolBlockSubnetDef(
                ip_pool_id=ip_pool_id,
                ip_subnet_id=ip_subnet_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(delete_call, expected_def)

    def test_list_block_subnets(self):
        ip_pool_id = 'ip-pool-id'
        api_results = {
            'results': [{'id': 'static_subnet_1',
                         'resource_type': 'IpAddressPoolStaticSubnet'},
                        {'id': 'block_subnet_2',
                         'resource_type': 'IpAddressPoolBlockSubnet'}]
        }
        with mock.patch.object(
            self.policy_api, "list", return_value=api_results) as api_call:
            result = self.resourceApi.list_block_subnets(
                ip_pool_id, tenant=TEST_TENANT)
            expected_def = core_defs.IpPoolBlockSubnetDef(
                ip_pool_id=ip_pool_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            expected_result = [{'id': 'block_subnet_2',
                                'resource_type': 'IpAddressPoolBlockSubnet'}]
            self.assertEqual(result, expected_result)

    def test_get_ip_subnet_realization_info(self):
        ip_pool_id = '111'
        ip_subnet_id = 'subnet-id'
        result = {'extended_attributes': [{'values': ['5.5.0.0/24'],
                                           'key': 'cidr'}]}
        with mock.patch.object(
            self.resourceApi, "_get_realization_info",
            return_value=result) as api_get:
            self.resourceApi.get_ip_subnet_realization_info(
                ip_pool_id, ip_subnet_id, tenant=TEST_TENANT)
            api_get.assert_called_once()
        # Test with wait set to True
        with mock.patch.object(
            self.resourceApi, "_wait_until_realized",
            return_value=result) as api_get:
            self.resourceApi.get_ip_subnet_realization_info(
                ip_pool_id, ip_subnet_id, tenant=TEST_TENANT,
                wait=True)
            api_get.assert_called_once()

    def test_get_ip_block_subnet_cidr(self):
        ip_pool_id = '111'
        ip_subnet_id = 'subnet-id'
        result = {'extended_attributes': [{'values': ['5.5.0.0/24'],
                                           'key': 'cidr'}]}
        with mock.patch.object(
            self.resourceApi, "_get_realization_info",
            return_value=result) as api_get:
            cidr = self.resourceApi.get_ip_block_subnet_cidr(
                ip_pool_id, ip_subnet_id, tenant=TEST_TENANT)
            self.assertEqual(['5.5.0.0/24'], cidr)
            api_get.assert_called_once()

    def test_get_ip_alloc_realization_info(self):
        ip_pool_id = '111'
        ip_allocation_id = 'alloc-id'
        result = {'extended_attributes': [{'values': ['5.5.0.8']}]}
        with mock.patch.object(
            self.resourceApi, "_get_realization_info",
            return_value=result) as api_get:
            self.resourceApi.get_ip_alloc_realization_info(
                ip_pool_id, ip_allocation_id, tenant=TEST_TENANT)
            api_get.assert_called_once()
        # Test with wait set to True
        with mock.patch.object(
            self.resourceApi, "_wait_until_realized",
            return_value=result) as api_get:
            self.resourceApi.get_ip_alloc_realization_info(
                ip_pool_id, ip_allocation_id, tenant=TEST_TENANT,
                wait=True)
            api_get.assert_called_once()

    def test_get_realized_allocated_ip(self):
        ip_pool_id = '111'
        ip_allocation_id = 'alloc-id'
        result = {'extended_attributes': [{'values': ['5.5.0.8']}]}
        with mock.patch.object(
            self.resourceApi, "_get_realization_info",
            return_value=result) as api_get:
            ip = self.resourceApi.get_realized_allocated_ip(
                ip_pool_id, ip_allocation_id, tenant=TEST_TENANT)
            self.assertEqual('5.5.0.8', ip)
            api_get.assert_called_once()

    def test_create_or_update_static_subnet(self):
        ip_pool_id = 'ip-pool-id'
        ip_subnet_id = 'static-subnet-id'
        cidr = '10.10.10.0/24'
        allocation_ranges = [{'start': '10.10.10.2', 'end': '10.10.10.250'}]

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_update_static_subnet(
                ip_pool_id, cidr, allocation_ranges, ip_subnet_id,
                tenant=TEST_TENANT)

            expected_def = core_defs.IpPoolStaticSubnetDef(
                ip_pool_id=ip_pool_id,
                cidr=cidr,
                allocation_ranges=allocation_ranges,
                ip_subnet_id=ip_subnet_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_release_static_subnet(self):
        ip_pool_id = 'ip-pool-id'
        ip_subnet_id = 'static-subnet-id'
        with mock.patch.object(self.policy_api, "delete") as delete_call:
            self.resourceApi.release_static_subnet(
                ip_pool_id, ip_subnet_id, tenant=TEST_TENANT)
            expected_def = core_defs.IpPoolStaticSubnetDef(
                ip_pool_id=ip_pool_id,
                ip_subnet_id=ip_subnet_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(delete_call, expected_def)

    def test_list_static_subnet(self):
        ip_pool_id = 'ip-pool-id'
        api_results = {
            'results': [{'id': 'static_subnet_1',
                         'resource_type': 'IpAddressPoolStaticSubnet'},
                        {'id': 'block_subnet_2',
                         'resource_type': 'IpAddressPoolBlockSubnet'}]
        }
        with mock.patch.object(
            self.policy_api, "list", return_value=api_results) as api_call:
            result = self.resourceApi.list_static_subnets(
                ip_pool_id, tenant=TEST_TENANT)
            expected_def = core_defs.IpPoolStaticSubnetDef(
                ip_pool_id=ip_pool_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            expected_result = [{'id': 'static_subnet_1',
                                'resource_type': 'IpAddressPoolStaticSubnet'}]
            self.assertEqual(result, expected_result)

    def test_get_static_subnet(self):
        ip_pool_id = 'ip-pool-id'
        ip_subnet_id = 'static-subnet-id'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get_static_subnet(
                ip_pool_id, ip_subnet_id, tenant=TEST_TENANT)
            expected_def = core_defs.IpPoolStaticSubnetDef(
                ip_pool_id=ip_pool_id,
                ip_subnet_id=ip_subnet_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_static_subnet_realization_info(self):
        ip_pool_id = 'ip-pool-id'
        ip_subnet_id = 'static-subnet-id'
        result = {'extended_attributes': [
            {'values': '10.10.10.0/24', 'key': 'cidr'},
            {'values': [{'value': '10.10.10.2', 'key': 'start'},
                        {'value': '10.10.10.250', 'key': 'end'}],
             'key': 'allocation_ranges'}]}
        with mock.patch.object(
            self.resourceApi, "_get_realization_info",
            return_value=result) as api_get:
            self.resourceApi.get_ip_subnet_realization_info(
                ip_pool_id, ip_subnet_id, tenant=TEST_TENANT,
                subnet_type=constants.IPPOOL_STATIC_SUBNET)
            api_get.assert_called_once()
        # Test with wait set to True
        with mock.patch.object(
            self.resourceApi, "_wait_until_realized",
            return_value=result) as api_get:
            self.resourceApi.get_ip_subnet_realization_info(
                ip_pool_id, ip_subnet_id, tenant=TEST_TENANT,
                wait=True, subnet_type=constants.IPPOOL_STATIC_SUBNET)
            api_get.assert_called_once()


class TestPolicySegmentPort(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicySegmentPort, self).setUp()
        self.resourceApi = self.policy_lib.segment_port

    def test_create(self):
        name = 'test'
        description = 'desc'
        segment_id = "segment"
        address_bindings = []
        attachment_type = "CHILD"
        vif_id = "vif"
        app_id = "app"
        context_id = "context"
        traffic_tag = 10
        allocate_addresses = "BOTH"
        tags = [{'scope': 'a', 'tag': 'b'}]

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, segment_id, description=description,
                address_bindings=address_bindings,
                attachment_type=attachment_type, vif_id=vif_id, app_id=app_id,
                context_id=context_id, traffic_tag=traffic_tag,
                allocate_addresses=allocate_addresses, tags=tags,
                tenant=TEST_TENANT)

            expected_def = core_defs.SegmentPortDef(
                segment_id=segment_id,
                port_id=mock.ANY,
                name=name,
                description=description,
                address_bindings=address_bindings,
                attachment_type=attachment_type,
                vif_id=vif_id,
                app_id=app_id,
                context_id=context_id,
                traffic_tag=traffic_tag,
                allocate_addresses=allocate_addresses,
                tags=tags,
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)


class TestPolicySegmentProfileBase(NsxPolicyLibTestCase):

    def setUp(self, resource_api_name='segment_security_profile',
              resource_def=core_defs.SegmentSecurityProfileDef):
        super(TestPolicySegmentProfileBase, self).setUp()
        self.resourceApi = getattr(self.policy_lib, resource_api_name)
        self.resourceDef = resource_def

    def test_create(self):
        name = 'test'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                tenant=TEST_TENANT)

            expected_def = self.resourceDef(
                profile_id=mock.ANY,
                name=name,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        profile_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(profile_id, tenant=TEST_TENANT)
            expected_def = self.resourceDef(profile_id=profile_id,
                                            tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        profile_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': profile_id}) as api_call:
            result = self.resourceApi.get(profile_id, tenant=TEST_TENANT)
            expected_def = self.resourceDef(profile_id=profile_id,
                                            tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(profile_id, result['id'])

    def test_get_by_name(self):
        name = 'test'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = self.resourceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = self.resourceDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        profile_id = '111'
        name = 'new name'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(profile_id,
                                    name=name,
                                    tenant=TEST_TENANT)
            expected_def = self.resourceDef(profile_id=profile_id,
                                            name=name,
                                            tenant=TEST_TENANT)
            self.assert_called_with_def(
                update_call, expected_def)


class TestPolicyQosProfile(TestPolicySegmentProfileBase):

    def setUp(self):
        super(TestPolicyQosProfile, self).setUp(
            resource_api_name='qos_profile',
            resource_def=core_defs.QosProfileDef)

    def test_create_with_params(self):
        name = 'test'
        description = 'desc'
        dscp = self.resourceApi.build_dscp(trusted=False, priority=7)
        limiter = self.resourceApi.build_ingress_rate_limiter(
            average_bandwidth=700,
            enabled=True)
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                description=description,
                dscp=dscp,
                shaper_configurations=[limiter],
                tenant=TEST_TENANT)

            expected_def = self.resourceDef(
                profile_id=mock.ANY,
                name=name,
                description=description,
                dscp=dscp,
                shaper_configurations=[limiter],
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)


class TestPolicySpoofguardProfile(TestPolicySegmentProfileBase):

    def setUp(self):
        super(TestPolicySpoofguardProfile, self).setUp(
            resource_api_name='spoofguard_profile',
            resource_def=core_defs.SpoofguardProfileDef)


class TestPolicyIpDiscoveryProfile(TestPolicySegmentProfileBase):

    def setUp(self):
        super(TestPolicyIpDiscoveryProfile, self).setUp(
            resource_api_name='ip_discovery_profile',
            resource_def=core_defs.IpDiscoveryProfileDef)


class TestPolicyMacDiscoveryProfile(TestPolicySegmentProfileBase):

    def setUp(self):
        super(TestPolicyMacDiscoveryProfile, self).setUp(
            resource_api_name='mac_discovery_profile',
            resource_def=core_defs.MacDiscoveryProfileDef)


class TestPolicyWAFProfile(TestPolicySegmentProfileBase):

    def setUp(self):
        super(TestPolicyWAFProfile, self).setUp(
            resource_api_name='waf_profile',
            resource_def=core_defs.WAFProfileDef)


class TestPolicySegmentSecurityProfile(TestPolicySegmentProfileBase):

    def test_create_with_params(self):
        name = 'test'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                bpdu_filter_enable=True,
                dhcp_client_block_enabled=False,
                dhcp_client_block_v6_enabled=True,
                dhcp_server_block_enabled=False,
                dhcp_server_block_v6_enabled=True,
                non_ip_traffic_block_enabled=False,
                ra_guard_enabled=True,
                rate_limits_enabled=False,
                tenant=TEST_TENANT)

            expected_def = self.resourceDef(
                profile_id=mock.ANY,
                name=name,
                bpdu_filter_enable=True,
                dhcp_client_block_enabled=False,
                dhcp_client_block_v6_enabled=True,
                dhcp_server_block_enabled=False,
                dhcp_server_block_v6_enabled=True,
                non_ip_traffic_block_enabled=False,
                ra_guard_enabled=True,
                rate_limits_enabled=False,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)


class TestPolicySegmentSecProfilesBinding(NsxPolicyLibTestCase):

    def setUp(self, resource_api_name='segment_port_security_profiles',
              resource_def=core_defs.SegmentPortSecProfilesBindingMapDef):
        super(TestPolicySegmentSecProfilesBinding, self).setUp()
        self.resourceApi = getattr(self.policy_lib, resource_api_name)
        self.resourceDef = resource_def

    def test_create(self):
        name = 'test'
        segment_id = 'seg1'
        port_id = 'port1'
        prf1 = '1'
        prf2 = '2'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, segment_id, port_id,
                segment_security_profile_id=prf1,
                spoofguard_profile_id=prf2,
                tenant=TEST_TENANT)

            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                map_id=core_resources.DEFAULT_MAP_ID,
                name=name,
                segment_security_profile_id=prf1,
                spoofguard_profile_id=prf2,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        segment_id = 'seg1'
        port_id = 'port1'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(segment_id, port_id, tenant=TEST_TENANT)
            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                map_id=core_resources.DEFAULT_MAP_ID,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        segment_id = 'seg1'
        port_id = 'port1'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': port_id}) as api_call:
            result = self.resourceApi.get(segment_id, port_id,
                                          tenant=TEST_TENANT)
            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                map_id=core_resources.DEFAULT_MAP_ID,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(port_id, result['id'])

    def test_list(self):
        segment_id = 'seg1'
        port_id = 'port1'
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(segment_id, port_id,
                                           tenant=TEST_TENANT)
            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        name = 'new name'
        segment_id = 'seg1'
        port_id = 'port1'
        prf1 = '1'
        prf2 = '2'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(
                segment_id=segment_id,
                port_id=port_id,
                name=name,
                segment_security_profile_id=prf1,
                spoofguard_profile_id=prf2,
                tenant=TEST_TENANT)
            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                map_id=core_resources.DEFAULT_MAP_ID,
                name=name,
                segment_security_profile_id=prf1,
                spoofguard_profile_id=prf2,
                tenant=TEST_TENANT)
            self.assert_called_with_def(
                update_call, expected_def)


class TestPolicySegmentDiscoveryProfilesBinding(NsxPolicyLibTestCase):

    def setUp(
        self, resource_api_name='segment_port_discovery_profiles',
        resource_def=core_defs.SegmentPortDiscoveryProfilesBindingMapDef):

        super(TestPolicySegmentDiscoveryProfilesBinding, self).setUp()
        self.resourceApi = getattr(self.policy_lib, resource_api_name)
        self.resourceDef = resource_def

    def test_create(self):
        name = 'test'
        segment_id = 'seg1'
        port_id = 'port1'
        prf1 = '1'
        prf2 = '2'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, segment_id, port_id,
                mac_discovery_profile_id=prf1,
                ip_discovery_profile_id=prf2,
                tenant=TEST_TENANT)

            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                map_id=core_resources.DEFAULT_MAP_ID,
                name=name,
                mac_discovery_profile_id=prf1,
                ip_discovery_profile_id=prf2,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        segment_id = 'seg1'
        port_id = 'port1'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(segment_id, port_id, tenant=TEST_TENANT)
            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                map_id=core_resources.DEFAULT_MAP_ID,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        segment_id = 'seg1'
        port_id = 'port1'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': port_id}) as api_call:
            result = self.resourceApi.get(segment_id, port_id,
                                          tenant=TEST_TENANT)
            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                map_id=core_resources.DEFAULT_MAP_ID,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(port_id, result['id'])

    def test_list(self):
        segment_id = 'seg1'
        port_id = 'port1'
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(segment_id, port_id,
                                           tenant=TEST_TENANT)
            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        name = 'new name'
        segment_id = 'seg1'
        port_id = 'port1'
        prf1 = '1'
        prf2 = '2'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(
                segment_id=segment_id,
                port_id=port_id,
                name=name,
                mac_discovery_profile_id=prf1,
                ip_discovery_profile_id=prf2,
                tenant=TEST_TENANT)
            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                map_id=core_resources.DEFAULT_MAP_ID,
                name=name,
                mac_discovery_profile_id=prf1,
                ip_discovery_profile_id=prf2,
                tenant=TEST_TENANT)
            self.assert_called_with_def(
                update_call, expected_def)


class TestPolicySegmentQosProfilesBinding(NsxPolicyLibTestCase):

    def setUp(
        self, resource_api_name='segment_port_qos_profiles',
        resource_def=core_defs.SegmentPortQoSProfilesBindingMapDef):

        super(TestPolicySegmentQosProfilesBinding, self).setUp()
        self.resourceApi = getattr(self.policy_lib, resource_api_name)
        self.resourceDef = resource_def

    def test_create(self):
        name = 'test'
        segment_id = 'seg1'
        port_id = 'port1'
        prf1 = '1'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, segment_id, port_id,
                qos_profile_id=prf1,
                tenant=TEST_TENANT)

            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                map_id=core_resources.DEFAULT_MAP_ID,
                name=name,
                qos_profile_id=prf1,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        segment_id = 'seg1'
        port_id = 'port1'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(segment_id, port_id, tenant=TEST_TENANT)
            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                map_id=core_resources.DEFAULT_MAP_ID,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        segment_id = 'seg1'
        port_id = 'port1'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': segment_id}) as api_call:
            result = self.resourceApi.get(segment_id, port_id,
                                          tenant=TEST_TENANT)
            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                map_id=core_resources.DEFAULT_MAP_ID,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(segment_id, result['id'])

    def test_list(self):
        segment_id = 'seg1'
        port_id = 'port1'
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(segment_id, port_id,
                                           tenant=TEST_TENANT)
            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        name = 'new name'
        segment_id = 'seg1'
        port_id = 'port1'
        prf1 = '1'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(
                segment_id=segment_id,
                port_id=port_id,
                name=name,
                qos_profile_id=prf1,
                tenant=TEST_TENANT)
            expected_def = self.resourceDef(
                segment_id=segment_id,
                port_id=port_id,
                map_id=core_resources.DEFAULT_MAP_ID,
                name=name,
                qos_profile_id=prf1,
                tenant=TEST_TENANT)
            self.assert_called_with_def(
                update_call, expected_def)


class TestPolicyTier1SegmentPort(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyTier1SegmentPort, self).setUp()
        self.resourceApi = self.policy_lib.tier1_segment_port

    def test_create(self):
        name = 'test'
        tier1_id = 'tier1'
        description = 'desc'
        segment_id = "segment"
        address_bindings = []
        attachment_type = "CHILD"
        vif_id = "vif"
        app_id = "app"
        context_id = "context"
        traffic_tag = 10
        allocate_addresses = "BOTH"
        tags = [{'scope': 'a', 'tag': 'b'}]

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, tier1_id, segment_id, description=description,
                address_bindings=address_bindings,
                attachment_type=attachment_type, vif_id=vif_id, app_id=app_id,
                context_id=context_id, traffic_tag=traffic_tag,
                allocate_addresses=allocate_addresses, tags=tags,
                tenant=TEST_TENANT)

            expected_def = core_defs.Tier1SegmentPortDef(
                segment_id=segment_id,
                tier1_id=tier1_id,
                port_id=mock.ANY,
                name=name,
                description=description,
                address_bindings=address_bindings,
                attachment_type=attachment_type,
                vif_id=vif_id,
                app_id=app_id,
                context_id=context_id,
                traffic_tag=traffic_tag,
                allocate_addresses=allocate_addresses,
                tags=tags,
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_wait_until_realized_fail(self):
        tier1_id = '111'
        port_id = 'port-111'
        segment_id = 'seg-111'
        logical_port_id = 'realized_port_111'
        info = {'state': constants.STATE_UNREALIZED,
                'realization_specific_identifier': logical_port_id,
                'entity_type': 'RealizedLogicalPort'}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            self.assertRaises(nsxlib_exc.ManagerError,
                              self.resourceApi.wait_until_realized,
                              tier1_id, segment_id, port_id, max_attempts=5,
                              sleep=0.1, tenant=TEST_TENANT)

    def test_wait_until_realized_succeed(self):
        tier1_id = '111'
        port_id = 'port-111'
        segment_id = 'seg-111'
        logical_port_id = 'realized_port_111'
        info = {'state': constants.STATE_REALIZED,
                'realization_specific_identifier': logical_port_id,
                'entity_type': 'RealizedLogicalPort'}
        with mock.patch.object(self.resourceApi, "_get_realization_info",
                               return_value=info):
            actual_info = self.resourceApi.wait_until_realized(
                tier1_id, segment_id, port_id, max_attempts=5, sleep=0.1,
                tenant=TEST_TENANT)
            self.assertEqual(info, actual_info)


class TestPolicyDhcpRelayConfig(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyDhcpRelayConfig, self).setUp()
        self.resourceApi = self.policy_lib.dhcp_relay_config

    def test_create(self):
        name = 'test'
        description = 'desc'
        server_addr = '1.1.1.1'

        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                server_addresses=[server_addr],
                tenant=TEST_TENANT)

            expected_def = core_defs.DhcpRelayConfigDef(
                config_id=mock.ANY,
                name=name,
                description=description,
                server_addresses=[server_addr],
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        config_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(config_id, tenant=TEST_TENANT)
            expected_def = core_defs.DhcpRelayConfigDef(config_id=config_id,
                                                        tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        config_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': config_id}) as api_call:
            result = self.resourceApi.get(config_id, tenant=TEST_TENANT)
            expected_def = core_defs.DhcpRelayConfigDef(config_id=config_id,
                                                        tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(config_id, result['id'])

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = core_defs.DhcpRelayConfigDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)


class TestPolicyCertificate(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyCertificate, self).setUp()
        self.resourceApi = self.policy_lib.certificate

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        obj_id = '111'
        pem_encoded = 'pem_encoded'
        private_key = 'private_key'
        passphrase = 'passphrase'
        key_algo = 'algo'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name,
                certificate_id=obj_id,
                description=description,
                pem_encoded=pem_encoded,
                private_key=private_key,
                passphrase=passphrase,
                key_algo=key_algo,
                tenant=TEST_TENANT)
            expected_def = (
                core_defs.CertificateDef(
                    certificate_id=obj_id,
                    name=name,
                    description=description,
                    pem_encoded=pem_encoded,
                    private_key=private_key,
                    passphrase=passphrase,
                    key_algo=key_algo,
                    tenant=TEST_TENANT))
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        pem_encoded = 'pem_encoded'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            result = self.resourceApi.create_or_overwrite(
                name, description=description,
                tenant=TEST_TENANT,
                pem_encoded=pem_encoded)
            expected_def = (
                core_defs.CertificateDef(certificate_id=mock.ANY,
                                         name=name,
                                         description=description,
                                         tenant=TEST_TENANT,
                                         pem_encoded=pem_encoded))
            self.assert_called_with_def(api_call, expected_def)
            self.assertIsNotNone(result)

    def test_delete(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(obj_id, tenant=TEST_TENANT)
            expected_def = core_defs.CertificateDef(
                certificate_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        obj_id = '111'
        with mock.patch.object(self.policy_api, "get",
                               return_value={'id': obj_id}) as api_call:
            result = self.resourceApi.get(obj_id, tenant=TEST_TENANT)
            expected_def = core_defs.CertificateDef(
                certificate_id=obj_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual(obj_id, result['id'])

    def test_get_by_name(self):
        name = 'd1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = core_defs.CertificateDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list",
                               return_value={'results': []}) as api_call:
            result = self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = core_defs.CertificateDef(tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            self.assertEqual([], result)

    def test_update(self):
        obj_id = '111'
        name = 'new name'
        description = 'new desc'
        pem_encoded = 'pem_encoded'
        private_key = 'private_key'
        passphrase = '12'
        key_algo = 'new_algo'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(obj_id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT,
                                    pem_encoded=pem_encoded,
                                    private_key=private_key,
                                    passphrase=passphrase,
                                    key_algo=key_algo)
            expected_def = core_defs.CertificateDef(
                certificate_id=obj_id,
                name=name,
                description=description,
                tenant=TEST_TENANT,
                pem_encoded=pem_encoded,
                private_key=private_key,
                passphrase=passphrase,
                key_algo=key_algo
            )
            self.assert_called_with_def(update_call, expected_def)


class TestPolicyExcludeList(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyExcludeList, self).setUp()
        self.resourceApi = self.policy_lib.exclude_list

    def test_create_or_overwrite(self):
        members = ["/infra/domains/default/groups/adit1"]
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite(
                members=members, tenant=TEST_TENANT)
            expected_def = core_defs.ExcludeListDef(
                members=members, tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_delete(self):
        self.skipTest("The action is not supported by this resource")

    def test_get(self):
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(tenant=TEST_TENANT)
            expected_def = core_defs.ExcludeListDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        self.skipTest("The action is not supported by this resource")

    def test_update(self):
        self.skipTest("The action is not supported by this resource")
