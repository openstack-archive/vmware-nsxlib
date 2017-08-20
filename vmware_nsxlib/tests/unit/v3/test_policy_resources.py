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
        self.assertEqual(expected_def.tenant, actual_def.tenant)
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
            expected_def = policy_defs.GroupDef(domain_id, tenant=TEST_TENANT)
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

    def test_update_condition(self):
        domain_id = '111'
        id = '222'
        cond_val = '123'
        with mock.patch.object(self.policy_api, "get",
                               return_value={}) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update_condition(domain_id, id,
                                              cond_val=cond_val,
                                              tenant=TEST_TENANT)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=id,
                                                tenant=TEST_TENANT)
            exp_cond = {'resource_type': 'Condition',
                        'member_type': policy_constants.CONDITION_MEMBER_PORT,
                        'key': policy_constants.CONDITION_KEY_TAG,
                        'value': cond_val,
                        'operator': policy_constants.CONDITION_OP_EQUALS}
            expected_dict = {'expression': [exp_cond]}
            self.assert_called_with_def(get_call, expected_def)
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

    def test_remove_condition(self):
        domain_id = '111'
        id = '222'
        old_cond = {'resource_type': 'Condition',
                    'member_type': policy_constants.CONDITION_MEMBER_PORT,
                    'key': policy_constants.CONDITION_KEY_TAG,
                    'value': 'abc',
                    'operator': policy_constants.CONDITION_OP_EQUALS}
        with mock.patch.object(self.policy_api, "get",
                               return_value={'expression': [old_cond]}) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update_condition(domain_id, id,
                                              cond_val=None,
                                              tenant=TEST_TENANT)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=id,
                                                tenant=TEST_TENANT)
            expected_dict = {'expression': []}
            self.assert_called_with_def(get_call, expected_def)
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
        with mock.patch.object(self.policy_api, "delete") as api_call,\
            mock.patch.object(self.policy_api, "get") as get_call:
            self.resourceApi.delete(id, tenant=TEST_TENANT)
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            self.assert_called_with_def(get_call, expected_def)
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
        name = 'new name'
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
                             'description': description,
                             'service_entries': []}
            self.assert_called_with_def(get_call, expected_def)
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

    def test_update_entry(self):
        id = '111'
        protocol = 'udp'
        dest_ports = [555]
        service_entry_id = '222'
        service_entry = {'id': service_entry_id}

        with mock.patch.object(
            self.policy_api, "get",
            return_value={'service_entries': [service_entry]}) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    protocol=protocol,
                                    dest_ports=dest_ports,
                                    tenant=TEST_TENANT)
            # get will be called for the entire service
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            self.assert_called_with_def(get_call, expected_def)

            # update will be called for the service entry only
            expected_entry_def = policy_defs.L4ServiceEntryDef(
                service_id=id,
                service_entry_id=service_entry_id,
                tenant=TEST_TENANT)
            expected_entry_dict = {'id': service_entry_id,
                                   'l4_protocol': protocol.upper(),
                                   'destination_ports': dest_ports}
            self.assert_called_with_def_and_dict(
                update_call, expected_entry_def, expected_entry_dict)

    def test_update_all(self):
        id = '111'
        name = 'new name'
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

            # update will be called for the service and entry (2 calls)
            expected_dict = {'display_name': name,
                             'description': description,
                             'service_entries': []}
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

            expected_entry_def = policy_defs.L4ServiceEntryDef(
                service_id=id,
                service_entry_id=service_entry_id,
                tenant=TEST_TENANT)
            expected_entry_dict = {'id': service_entry_id,
                                   'display_name': name,
                                   'description': description,
                                   'l4_protocol': protocol.upper(),
                                   'destination_ports': dest_ports}
            self.assert_called_with_def_and_dict(
                update_call, expected_entry_def, expected_entry_dict,
                call_num=1)


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
        with mock.patch.object(self.policy_api, "delete") as api_call,\
            mock.patch.object(self.policy_api, "get") as get_call:
            self.resourceApi.delete(id, tenant=TEST_TENANT)
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            self.assert_called_with_def(get_call, expected_def)
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
        name = 'new name'
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
                             'description': description,
                             'service_entries': []}
            self.assert_called_with_def(get_call, expected_def)
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

    def test_update_entry(self):
        id = '111'
        icmp_code = 12
        service_entry_id = '222'
        service_entry = {'id': service_entry_id}

        with mock.patch.object(
            self.policy_api, "get",
            return_value={'service_entries': [service_entry]}) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    icmp_code=icmp_code,
                                    tenant=TEST_TENANT)
            # get will be called for the entire service
            expected_def = policy_defs.ServiceDef(service_id=id,
                                                  tenant=TEST_TENANT)
            self.assert_called_with_def(get_call, expected_def)

            # update will be called for the service entry only
            expected_entry_def = policy_defs.IcmpServiceEntryDef(
                service_id=id,
                service_entry_id=service_entry_id,
                tenant=TEST_TENANT)
            expected_entry_dict = {'id': service_entry_id,
                                   'icmp_code': icmp_code}
            self.assert_called_with_def_and_dict(
                update_call, expected_entry_def, expected_entry_dict)

    def test_update_all(self):
        id = '111'
        name = 'new name'
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

            # update will be called for the service and entry (2 calls)
            expected_dict = {'display_name': name,
                             'description': description,
                             'service_entries': []}
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

            expected_entry_def = policy_defs.IcmpServiceEntryDef(
                service_id=id,
                service_entry_id=service_entry_id,
                tenant=TEST_TENANT)
            expected_entry_dict = {'id': service_entry_id,
                                   'display_name': name,
                                   'description': description,
                                   'protocol': 'ICMPv6',
                                   'icmp_type': icmp_type,
                                   'icmp_code': icmp_code}
            self.assert_called_with_def_and_dict(
                update_call, expected_entry_def, expected_entry_dict,
                call_num=1)


class TestPolicyCommunicationProfile(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyCommunicationProfile, self).setUp()
        self.resourceApi = self.policy_lib.comm_profile

    def test_create(self):
        name = 'c1'
        description = 'desc'
        service_id = '333'
        action = 'DENY'
        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call:
            self.resourceApi.create_or_overwrite(name, description=description,
                                                 services=[service_id],
                                                 action=action,
                                                 tenant=TEST_TENANT)
            exp_srv_def = policy_defs.CommunicationProfileDef(
                profile_id=mock.ANY,
                name=name,
                description=description,
                tenant=TEST_TENANT)
            exp_entry_def = policy_defs.CommunicationProfileEntryDef(
                profile_id=mock.ANY,
                name=name,
                description=description,
                services=[service_id],
                action=action,
                tenant=TEST_TENANT)
            self.assert_called_with_defs(
                api_call, [exp_srv_def, exp_entry_def])

    def test_delete(self):
        id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call,\
            mock.patch.object(self.policy_api, "get") as get_call:
            self.resourceApi.delete(id, tenant=TEST_TENANT)
            expected_def = policy_defs.CommunicationProfileDef(
                profile_id=id, tenant=TEST_TENANT)
            self.assert_called_with_def(get_call, expected_def)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        id = '111'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(id, tenant=TEST_TENANT)
            expected_def = policy_defs.CommunicationProfileDef(
                profile_id=id, tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get_by_name(self):
        name = 'c1'
        with mock.patch.object(
            self.policy_api, "list",
            return_value={'results': [{'display_name': name}]}) as api_call:
            obj = self.resourceApi.get_by_name(name, tenant=TEST_TENANT)
            self.assertIsNotNone(obj)
            expected_def = policy_defs.CommunicationProfileDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(tenant=TEST_TENANT)
            expected_def = policy_defs.CommunicationProfileDef(
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        id = '111'
        name = 'new name'
        description = 'new desc'
        with mock.patch.object(self.policy_api, "get",
                               return_value={}) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.CommunicationProfileDef(
                profile_id=id, tenant=TEST_TENANT)
            expected_dict = {'display_name': name,
                             'description': description,
                             'communication_profile_entries': []}
            self.assert_called_with_def(get_call, expected_def)
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

    def test_update_entry(self):
        id = '111'
        service_id = '333'
        action = 'deny'
        entry_id = '222'
        profile_entry = {'id': entry_id}
        entries_dict = {'communication_profile_entries': [profile_entry]}

        with mock.patch.object(
            self.policy_api, "get", return_value=entries_dict) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    services=[service_id],
                                    action=action,
                                    tenant=TEST_TENANT)
            # get will be called for the entire service
            expected_def = policy_defs.CommunicationProfileDef(
                profile_id=id, tenant=TEST_TENANT)
            self.assert_called_with_def(get_call, expected_def)

            # update will be called for the service entry only
            expected_entry_def = policy_defs.CommunicationProfileEntryDef(
                profile_id=id,
                profile_entry_id=entry_id,
                tenant=TEST_TENANT)
            expected_entry_dict = {'id': entry_id,
                                   'action': action.upper(),
                                   'services': [service_id]}
            self.assert_called_with_def_and_dict(
                update_call, expected_entry_def, expected_entry_dict)

    def test_update_all(self):
        id = '111'
        name = 'new name'
        description = 'new desc'
        service_id = '333'
        action = 'deny'
        entry_id = '222'
        profile_entry = {'id': entry_id}
        entries_dict = {'communication_profile_entries': [profile_entry]}

        with mock.patch.object(
            self.policy_api, "get", return_value=entries_dict) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    description=description,
                                    services=[service_id],
                                    action=action,
                                    tenant=TEST_TENANT)
            # get will be called for the entire service
            expected_def = policy_defs.CommunicationProfileDef(
                profile_id=id, tenant=TEST_TENANT)
            self.assert_called_with_def(get_call, expected_def)

            # update will be called for the service and entry (2 calls)
            expected_dict = {'display_name': name,
                             'description': description,
                             'communication_profile_entries': []}
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

            expected_entry_def = policy_defs.CommunicationProfileEntryDef(
                profile_id=id,
                profile_entry_id=entry_id,
                tenant=TEST_TENANT)
            expected_entry_dict = {'id': entry_id,
                                   'display_name': name,
                                   'description': description,
                                   'action': action.upper(),
                                   'services': [service_id]}
            self.assert_called_with_def_and_dict(
                update_call, expected_entry_def, expected_entry_dict,
                call_num=1)


class TestPolicyCommunicationMap(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyCommunicationMap, self).setUp()
        self.resourceApi = self.policy_lib.comm_map

    def test_create(self):
        domain_id = '111'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        seq_num = 7
        profile_id = 'c1'
        list_return_value = {'results': [{'sequence_number': 1}]}
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call,\
            mock.patch.object(self.policy_api, "list",
                              return_value=list_return_value):
            self.resourceApi.create_or_overwrite(name, domain_id,
                                                 description=description,
                                                 sequence_number=seq_num,
                                                 profile_id=profile_id,
                                                 source_groups=[source_group],
                                                 dest_groups=[dest_group],
                                                 tenant=TEST_TENANT)
            expected_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=mock.ANY,
                name=name,
                description=description,
                sequence_number=seq_num,
                profile_id=profile_id,
                source_groups=[source_group],
                dest_groups=[dest_group],
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_create_first_seqnum(self):
        domain_id = '111'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        profile_id = 'c1'
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call, \
            mock.patch.object(self.resourceApi, "list", return_value=[]):
            self.resourceApi.create_or_overwrite(name, domain_id,
                                                 description=description,
                                                 profile_id=profile_id,
                                                 source_groups=[source_group],
                                                 dest_groups=[dest_group],
                                                 tenant=TEST_TENANT)

            expected_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=mock.ANY,
                name=name,
                description=description,
                sequence_number=1,
                profile_id=profile_id,
                source_groups=[source_group],
                dest_groups=[dest_group],
                tenant=TEST_TENANT)

            self.assert_called_with_def(api_call, expected_def)

    def test_create_without_seqnum(self):
        domain_id = '111'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        profile_id = 'c1'
        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call, \
            mock.patch.object(self.resourceApi, "_get_last_seq_num",
                              return_value=-1):
            self.resourceApi.create_or_overwrite(name, domain_id,
                                                 description=description,
                                                 profile_id=profile_id,
                                                 source_groups=[source_group],
                                                 dest_groups=[dest_group],
                                                 tenant=TEST_TENANT)

            expected_map_def = policy_defs.CommunicationMapDef(
                domain_id=domain_id,
                tenant=TEST_TENANT)

            expected_entry_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=mock.ANY,
                name=name,
                description=description,
                sequence_number=1,
                profile_id=profile_id,
                source_groups=[source_group],
                dest_groups=[dest_group],
                tenant=TEST_TENANT)

            self.assert_called_with_defs(
                api_call,
                [expected_map_def, expected_entry_def])

    def test_delete(self):
        domain_id = '111'
        id = '222'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(domain_id, id, tenant=TEST_TENANT)
            expected_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        domain_id = '111'
        id = '222'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(domain_id, id, tenant=TEST_TENANT)
            expected_def = policy_defs.CommunicationMapEntryDef(
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
            expected_def = policy_defs.CommunicationMapEntryDef(
                domain_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        domain_id = '111'
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(domain_id, tenant=TEST_TENANT)
            expected_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                tenant=TEST_TENANT)
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        domain_id = '111'
        id = '222'
        name = 'new name'
        description = 'new desc'
        source_group = 'ng1'
        dest_group = 'ng2'
        profile_id = 'nc1'
        with mock.patch.object(self.policy_api, "get",
                               return_value={}) as get_call,\
            mock.patch.object(self.policy_api,
                              "create_or_update") as update_call:
            self.resourceApi.update(domain_id, id,
                                    name=name,
                                    description=description,
                                    profile_id=profile_id,
                                    source_groups=[source_group],
                                    dest_groups=[dest_group],
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.CommunicationMapEntryDef(
                domain_id=domain_id,
                map_id=id,
                tenant=TEST_TENANT)
            sgroup_path = "/%s/domains/%s/groups/%s" % (
                TEST_TENANT, domain_id, source_group)
            dgroup_path = "/%s/domains/%s/groups/%s" % (
                TEST_TENANT, domain_id, dest_group)
            profile_path = "/%s/communication-profiles/%s" % (
                TEST_TENANT, profile_id)
            expected_dict = {'display_name': name,
                             'description': description,
                             'communication_profile_path': profile_path,
                             'source_groups': [sgroup_path],
                             'destination_groups': [dgroup_path]}
            self.assert_called_with_def(get_call, expected_def)
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

    def test_get_realized(self):
        domain_id = 'd1'
        ep_id = 'ef1'
        result = {'state': policy_constants.STATE_REALIZED}
        with mock.patch.object(
            self.policy_api, "get_by_path",
            return_value=result) as api_get:
            state = self.resourceApi.get_realized_state(
                domain_id, ep_id, tenant=TEST_TENANT)
            self.assertEqual(policy_constants.STATE_REALIZED, state)
            expected_path = policy_defs.REALIZED_STATE_COMM_MAP % (
                TEST_TENANT, ep_id, domain_id)
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
        with mock.patch.object(self.policy_api,
                               "create_or_update") as api_call:
            self.resourceApi.create_or_overwrite(
                name, description=description,
                ip_address=ip_address,
                username=username,
                password=password,
                tenant=TEST_TENANT)

            expected_def = policy_defs.EnforcementPointDef(
                ep_id=mock.ANY,
                name=name,
                description=description,
                ip_address=ip_address,
                username=username,
                password=password,
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
        with mock.patch.object(self.policy_api,
                               "create_or_update") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    username=username,
                                    password=password,
                                    tenant=TEST_TENANT)
            expected_def = policy_defs.EnforcementPointDef(ep_id=id,
                                                           tenant=TEST_TENANT)
            expected_dict = {'display_name': name,
                             'username': username,
                             'password': password}
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
            ep_path = ("/%s/deployment-zones/default/"
                       "enforcement-points/%s" % (TEST_TENANT, ep_id))
            expected_dict = {'display_name': name,
                             'enforcement_point_paths': [ep_path],
                             'domain_path': domain_path}
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)
