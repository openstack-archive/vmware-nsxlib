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
import unittest

import mock

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib import v3
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import policy_constants
from vmware_nsxlib.v3 import policy_defs

TEST_TENANT = 'test'


class NsxPolicyLibTestCase(unittest.TestCase):

    def setUp(self, *args, **kwargs):
        super(NsxPolicyLibTestCase, self).setUp()

        nsxlib_config = nsxlib_testcase.get_default_nsxlib_config()
        self.policy_lib = v3.NsxPolicyLib(nsxlib_config)
        self.policy_api = self.policy_lib.policy_api

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
        actual_def = mock_api.call_args_list[call_num][0][1]
        expected_def = expected_defs[1]
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
                                                 tenant=TEST_TENANT)
            expected_dict = {'display_name': name,
                             'description': description}
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)


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
                                                tenant=TEST_TENANT)
            expected_dict = {'display_name': name,
                             'description': description}
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

    def test_get_realized(self):
        domain_id = 'd1'
        id = 'g1'
        ep_id = 'ef1'
        result = {'state': policy_constants.STATE_REALIZED}
        with mock.patch.object(
            self.policy_api, "get_by_path",
            return_value=result) as api_get:
            state = self.resourceApi.get_realized_state(
                domain_id, id, ep_id, tenant=TEST_TENANT)
            self.assertEqual(policy_constants.STATE_REALIZED, state)
            expected_path = policy_defs.REALIZED_STATE_GROUP % (
                TEST_TENANT, ep_id, domain_id, id)
            api_get.assert_called_once_with(expected_path)


class TestPolicyService(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyService, self).setUp()
        self.resourceApi = self.policy_lib.service

    def test_create(self):
        name = 's1'
        description = 'desc'
        protocol = policy_constants.TCP
        dest_ports = [81, 82]
        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call:
            self.resourceApi.create_or_overwrite(name,
                                                 description=description,
                                                 protocol=protocol,
                                                 dest_ports=dest_ports,
                                                 tenant=TEST_TENANT)
            exp_srv_def = policy_defs.ServiceDef(service_id=mock.ANY,
                                                 name=name,
                                                 description=description,
                                                 tenant=TEST_TENANT)
            exp_entry_def = policy_defs.L4ServiceEntryDef(
                service_id=mock.ANY,
                name=name,
                description=description,
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
        with mock.patch.object(self.policy_api, "get",
                               return_value={}) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            expected_dict = {'display_name': name,
                             'description': description}
            self.assert_called_with_def(get_call, expected_def)
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

    def test_update_all(self):
        id = '111'
        name = 'newName'
        description = 'new desc'
        protocol = 'udp'
        dest_ports = [555]
        service_entry_id = '222'
        service_entry = {'id': service_entry_id}

        with mock.patch.object(
            self.policy_api, "get",
            return_value={'service_entries': [service_entry]}) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call,\
            mock.patch.object(self.policy_api, "list",
                              return_value={'results': []}):
            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    protocol=protocol,
                                    dest_ports=dest_ports,
                                    tenant=TEST_TENANT)
            # get will be called for the entire service
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            self.assert_called_with_def(get_call, expected_def)

            expected_dict = {'display_name': name,
                             'description': description,
                             'service_entries': [{
                                 'id': service_entry_id,
                                 'display_name': name,
                                 'description': description,
                                 'l4_protocol': protocol.upper(),
                                 'destination_ports': dest_ports}]}
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)


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
                name=name,
                description=description,
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
                               return_value={}) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            expected_dict = {'display_name': name,
                             'description': description}
            self.assert_called_with_def(get_call, expected_def)
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

    def test_update_all(self):
        id = '111'
        name = 'newName'
        description = 'new desc'
        version = 6
        icmp_type = 3
        icmp_code = 3
        service_entry_id = '222'
        service_entry = {'id': service_entry_id}

        with mock.patch.object(
            self.policy_api, "get",
            return_value={'service_entries': [service_entry]}) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call,\
            mock.patch.object(self.policy_api, "list",
                              return_value={'results': []}):
            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    version=version,
                                    icmp_type=icmp_type,
                                    icmp_code=icmp_code,
                                    tenant=TEST_TENANT)
            # get will be called for the entire service
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            self.assert_called_with_def(get_call, expected_def)

            expected_dict = {'display_name': name,
                             'description': description,
                             'service_entries': [{
                                 'id': service_entry_id,
                                 'display_name': name,
                                 'description': description,
                                 'protocol': 'ICMPv6',
                                 'icmp_type': icmp_type,
                                 'icmp_code': icmp_code}]}
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)


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
                name=name,
                description=description,
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
                               return_value={}) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            expected_dict = {'display_name': name,
                             'description': description}
            self.assert_called_with_def(get_call, expected_def)
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

    def test_update_all(self):
        id = '111'
        name = 'newName'
        description = 'new desc'
        protocol_number = 3
        service_entry_id = '222'
        service_entry = {'id': service_entry_id}

        with mock.patch.object(
            self.policy_api, "get",
            return_value={'service_entries': [service_entry]}) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call,\
            mock.patch.object(self.policy_api, "list",
                              return_value={'results': []}):
            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    protocol_number=protocol_number,
                                    tenant=TEST_TENANT)
            # get will be called for the entire service
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            self.assert_called_with_def(get_call, expected_def)

            expected_dict = {'display_name': name,
                             'description': description,
                             'service_entries': [{
                                 'id': service_entry_id,
                                 'display_name': name,
                                 'description': description,
                                 'protocol_number': protocol_number}]}
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)


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
        get_return_value = {'communication_entries': [{'sequence_number': 1}]}
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call,\
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
            expected_def = policy_defs.CommunicationMapDef(
                domain_id=domain_id,
                map_id=map_id,
                name=name,
                description=description,
                category=policy_constants.CATEGORY_APPLICATION,
                precedence=0,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

            expected_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id=map_id,
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
            self.assert_called_with_def(api_call, expected_def, call_num=1)

    def test_create_first_seqnum(self):
        domain_id = '111'
        map_id = '222'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        service_id = 'c1'
        category = 'Emergency'
        get_return_value = {'communication_entries': []}
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call, \
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

            expected_def = policy_defs.CommunicationMapDef(
                domain_id=domain_id,
                map_id=map_id,
                name=name,
                description=description,
                category=category,
                precedence=0,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

            expected_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=map_id,
                entry_id=map_id,
                name=name,
                action=policy_constants.ACTION_ALLOW,
                description=description,
                sequence_number=1,
                service_ids=[service_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                logged=False,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def, call_num=1)

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
                precedence=0,
                tenant=TEST_TENANT)

            expected_entry_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=mock.ANY,
                entry_id=mock.ANY,
                action=policy_constants.ACTION_ALLOW,
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
                precedence=0,
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
                description=description,
                sequence_number=1,
                service_ids=None,
                source_groups=[source_group],
                dest_groups=[dest_group],
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
        ret_comm = {'communication_entries': [{'sequence_number': seq_num}]}
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
                description=description,
                service_ids=[service1_id, service2_id],
                source_groups=[source_group],
                dest_groups=[dest_group],
                sequence_number=seq_num + 1,
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
                               "create_or_update") as api_call:
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
                precedence=0,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)
            actual_def = api_call.call_args_list[0][0][0]
            self.assertEqual([entry1.get_obj_dict(), entry2.get_obj_dict()],
                             actual_def.body['communication_entries'])

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
                               return_value={}) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update(domain_id, map_id,
                                    name=name,
                                    description=description,
                                    service_ids=[service1_id, service2_id],
                                    source_groups=[source_group],
                                    dest_groups=[dest_group],
                                    tenant=TEST_TENANT)
            expected_map_def = policy_defs.CommunicationMapDef(
                domain_id=domain_id,
                map_id=map_id,
                tenant=TEST_TENANT)
            expected_map_dict = {'display_name': name,
                                 'description': description}
            self.assert_called_with_def(get_call, expected_map_def)
            self.assert_called_with_def_and_dict(
                update_call, expected_map_def, expected_map_dict)

    def test_update_entries_logged(self):
        domain_id = '111'
        map_id = '222'
        dummy_map = {'communication_entries': [{'logged': False}]}
        updated_map = {'communication_entries': [{'logged': True}]}
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
        ep_id = 'ef1'
        result = {'state': policy_constants.STATE_REALIZED}
        with mock.patch.object(
            self.policy_api, "get_by_path",
            return_value=result) as api_get:
            state = self.resourceApi.get_realized_state(
                domain_id, map_id, ep_id, tenant=TEST_TENANT)
            self.assertEqual(policy_constants.STATE_REALIZED, state)
            expected_path = policy_defs.REALIZED_STATE_COMM_MAP % (
                TEST_TENANT, ep_id, domain_id, map_id)
            api_get.assert_called_once_with(expected_path)


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
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call,\
            mock.patch.object(self.policy_api, "get", return_value={'id': id}):
            self.resourceApi.update(id,
                                    name=name,
                                    username=username,
                                    password=password,
                                    ip_address=ip_address,
                                    thumbprint=thumbprint,
                                    edge_cluster_id=edge_cluster_id,
                                    transport_zone_id=transport_zone_id,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.EnforcementPointDef(ep_id=id,
                                                           tenant=TEST_TENANT)
            expected_dict = {'id': id,
                             'display_name': name,
                             'resource_type': 'EnforcementPoint',
                             'connection_info': {
                                 'username': username,
                                 'password': password,
                                 'thumbprint': thumbprint,
                                 'enforcement_point_address': ip_address,
                                 'edge_cluster_ids': [edge_cluster_id],
                                 'transport_zone_ids': [transport_zone_id],
                                 'resource_type': 'NSXTConnectionInfo'}}
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

    def test_get_realized(self):
        ep_id = 'ef1'
        result = {'state': policy_constants.STATE_REALIZED}
        with mock.patch.object(
            self.policy_api, "get_by_path",
            return_value=result) as api_get:
            state = self.resourceApi.get_realized_state(
                ep_id, tenant=TEST_TENANT)
            self.assertEqual(policy_constants.STATE_REALIZED, state)
            expected_path = policy_defs.REALIZED_STATE_EF % (
                TEST_TENANT, ep_id)
            api_get.assert_called_once_with(expected_path)


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
            expected_def = policy_defs.DeploymentMapDef(map_id=id,
                                                        tenant=TEST_TENANT)
            domain_path = "/%s/domains/%s" % (TEST_TENANT, domain_id)
            ep_path = ("/%s/sites/default/"
                       "enforcement-points/%s" % (TEST_TENANT, ep_id))
            expected_dict = {'display_name': name,
                             'enforcement_point_path': ep_path,
                             'parent_path': domain_path}
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)
