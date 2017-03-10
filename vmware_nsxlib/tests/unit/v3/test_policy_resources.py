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
import unittest

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib import v3
from vmware_nsxlib.v3 import policy_constants
from vmware_nsxlib.v3 import policy_defs

BASE_POLICY_URI = "https://1.2.3.4/api/v1/"


class NsxPolicyLibTestCase(unittest.TestCase):

    def setUp(self, *args, **kwargs):
        super(NsxPolicyLibTestCase, self).setUp()

        nsxlib_config = nsxlib_testcase.get_default_nsxlib_config()
        self.policy_lib = v3.NsxPolicyLib(nsxlib_config)
        self.policy_api = self.policy_lib.policy_api

        self.maxDiff = None

    def assert_called_with_def(self, mock_api, expected_def):
        # verify the api was called
        mock_api.assert_called_once()
        actual_def = mock_api.call_args[0][0]
        # verify the resource definition class
        self.assertEqual(expected_def.__class__, actual_def.__class__)
        # verify the resource definition values
        self.assertEqual(expected_def.get_obj_dict(),
                         actual_def.get_obj_dict())

    def assert_called_with_defs(self, mock_api, expected_defs):
        # verify the api & first resource definition
        self.assert_called_with_def(mock_api, expected_defs[0])
        # compare the 2nd resource definition class & values
        actual_def = mock_api.call_args[0][1]
        expected_def = expected_defs[1]
        self.assertEqual(expected_def.__class__, actual_def.__class__)
        self.assertEqual(expected_def.get_obj_dict(),
                         actual_def.get_obj_dict())

    def assert_called_with_def_and_dict(self, mock_api,
                                        expected_def, expected_dict):
        # verify the api & resource definition
        self.assert_called_with_def(mock_api, expected_def)
        # compare the 2nd api parameter which is a dictionary
        actual_dict = mock_api.call_args[0][1]
        self.assertEqual(expected_dict, actual_dict)


class TestPolicyDomain(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyDomain, self).setUp()
        self.resourceApi = self.policy_lib.domain

    def test_create_with_id(self):
        name = 'd1'
        description = 'desc'
        id = '111'
        with mock.patch.object(self.policy_api, "create") as api_call:
            self.resourceApi.create(name,
                                    domain_id=id,
                                    description=description)
            expected_def = policy_defs.DomainDef(domain_id=id,
                                                 name=name,
                                                 description=description)
            self.assert_called_with_def(api_call, expected_def)

    def test_create_without_id(self):
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api, "create") as api_call:
            self.resourceApi.create(name, description=description)
            expected_def = policy_defs.DomainDef(domain_id=mock.ANY,
                                                 name=name,
                                                 description=description)
            self.assert_called_with_def(api_call, expected_def)

    def test_delete(self):
        id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(id)
            expected_def = policy_defs.DomainDef(domain_id=id)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        id = '111'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(id)
            expected_def = policy_defs.DomainDef(domain_id=id)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list()
            expected_def = policy_defs.DomainDef()
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        id = '111'
        name = 'new name'
        description = 'new desc'
        with mock.patch.object(self.policy_api, "get",
                               return_value={}) as get_call,\
            mock.patch.object(self.policy_api, "update") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    description=description)
            expected_def = policy_defs.DomainDef(domain_id=id)
            expected_dict = {'display_name': name,
                             'description': description}
            self.assert_called_with_def(get_call, expected_def)
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
        with mock.patch.object(self.policy_api, "create") as api_call:
            self.resourceApi.create(name,
                                    domain_id,
                                    group_id=id,
                                    description=description)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=id,
                                                name=name,
                                                description=description)
            self.assert_called_with_def(api_call, expected_def)

    def test_create_without_id(self):
        domain_id = '111'
        name = 'd1'
        description = 'desc'
        with mock.patch.object(self.policy_api, "create") as api_call:
            self.resourceApi.create(name, domain_id, description=description,
                                    conditions=[])
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=mock.ANY,
                                                name=name,
                                                description=description)
            self.assert_called_with_def(api_call, expected_def)

    def test_create_with_condition(self):
        # TODO(asarfaty) not yet
        pass

    def test_delete(self):
        domain_id = '111'
        id = '222'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(domain_id, id)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=id)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        domain_id = '111'
        id = '222'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(domain_id, id)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=id)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        domain_id = '111'
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(domain_id)
            expected_def = policy_defs.GroupDef(domain_id=domain_id)
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        domain_id = '111'
        id = '222'
        name = 'new name'
        description = 'new desc'
        with mock.patch.object(self.policy_api, "get",
                               return_value={}) as get_call,\
            mock.patch.object(self.policy_api, "update") as update_call:
            self.resourceApi.update(domain_id, id,
                                    name=name,
                                    description=description)
            expected_def = policy_defs.GroupDef(domain_id=domain_id,
                                                group_id=id)
            expected_dict = {'display_name': name,
                             'description': description}
            self.assert_called_with_def(get_call, expected_def)
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

    def test_update_with_condition(self):
        # TODO(asarfaty) not yet
        pass


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
            self.resourceApi.create(name, description=description,
                                    protocol=protocol, dest_ports=dest_ports)
            exp_srv_def = policy_defs.ServiceDef(service_id=mock.ANY,
                                                 name=name,
                                                 description=description)
            exp_entry_def = policy_defs.L4ServiceEntryDef(
                service_id=mock.ANY,
                name=name,
                description=description,
                protocol=protocol,
                dest_ports=dest_ports)
            self.assert_called_with_defs(
                api_call, [exp_srv_def, exp_entry_def])

    def test_delete(self):
        id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(id)
            expected_def = policy_defs.ServiceDef(service_id=id)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        id = '111'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(id)
            expected_def = policy_defs.ServiceDef(service_id=id)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list()
            expected_def = policy_defs.ServiceDef()
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        id = '111'
        name = 'new name'
        description = 'new desc'
        with mock.patch.object(self.policy_api, "get",
                               return_value={}) as get_call,\
            mock.patch.object(self.policy_api, "update") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    description=description)
            expected_def = policy_defs.ServiceDef(service_id=id)
            expected_dict = {'display_name': name,
                             'description': description,
                             'service_entries': []}
            self.assert_called_with_def(get_call, expected_def)
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

    def test_update_with_entry(self):
        # TODO(asarfaty) not yet
        pass


class TestPolicyContract(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyContract, self).setUp()
        self.resourceApi = self.policy_lib.contract

    def test_create(self):
        name = 'c1'
        description = 'desc'
        service_id = '333'
        action = policy_constants.CONTRACT_DENY
        with mock.patch.object(self.policy_api,
                               "create_with_parent") as api_call:
            self.resourceApi.create(name, description=description,
                                    services=[service_id], action=action)
            exp_srv_def = policy_defs.ContractDef(contract_id=mock.ANY,
                                                  name=name,
                                                  description=description)
            exp_entry_def = policy_defs.ContractEntryDef(
                contract_id=mock.ANY,
                name=name,
                description=description,
                services=[service_id],
                action=action)
            self.assert_called_with_defs(
                api_call, [exp_srv_def, exp_entry_def])

    def test_delete(self):
        id = '111'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(id)
            expected_def = policy_defs.ContractDef(contract_id=id)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        id = '111'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(id)
            expected_def = policy_defs.ContractDef(contract_id=id)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list()
            expected_def = policy_defs.ContractDef()
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        id = '111'
        name = 'new name'
        description = 'new desc'
        with mock.patch.object(self.policy_api, "get",
                               return_value={}) as get_call,\
            mock.patch.object(self.policy_api, "update") as update_call:
            self.resourceApi.update(id,
                                    name=name,
                                    description=description)
            expected_def = policy_defs.ContractDef(contract_id=id)
            expected_dict = {'display_name': name,
                             'description': description,
                             'contract_entries': []}
            self.assert_called_with_def(get_call, expected_def)
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)

    def test_update_with_entry(self):
        # TODO(asarfaty) not yet
        pass


class TestPolicyContractMap(NsxPolicyLibTestCase):

    def setUp(self, *args, **kwargs):
        super(TestPolicyContractMap, self).setUp()
        self.resourceApi = self.policy_lib.contractmap

    def test_create(self):
        domain_id = '111'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        seq_num = 7
        contract_id = 'c1'
        with mock.patch.object(self.policy_api, "create") as api_call:
            self.resourceApi.create(name, domain_id, description=description,
                                    sequence_number=seq_num,
                                    contract_id=contract_id,
                                    source_groups=[source_group],
                                    dest_groups=[dest_group])
            expected_def = policy_defs.ContractMapDef(
                domain_id=domain_id,
                contractmap_id=mock.ANY,
                name=name,
                description=description,
                sequence_number=seq_num,
                contract_id=contract_id,
                source_groups=[source_group],
                dest_groups=[dest_group])
            self.assert_called_with_def(api_call, expected_def)

    def test_create_without_seqnum(self):
        domain_id = '111'
        name = 'cm1'
        description = 'desc'
        source_group = 'g1'
        dest_group = 'g2'
        contract_id = 'c1'
        with mock.patch.object(self.policy_api, "create") as api_call, \
            mock.patch.object(self.resourceApi, "list", return_value=[]):
            self.resourceApi.create(name, domain_id, description=description,
                                    contract_id=contract_id,
                                    source_groups=[source_group],
                                    dest_groups=[dest_group])
            expected_def = policy_defs.ContractMapDef(
                domain_id=domain_id,
                contractmap_id=mock.ANY,
                name=name,
                description=description,
                sequence_number=0,
                contract_id=contract_id,
                source_groups=[source_group],
                dest_groups=[dest_group])
            self.assert_called_with_def(api_call, expected_def)

    def test_delete(self):
        domain_id = '111'
        id = '222'
        with mock.patch.object(self.policy_api, "delete") as api_call:
            self.resourceApi.delete(domain_id, id)
            expected_def = policy_defs.ContractMapDef(domain_id=domain_id,
                                                      contractmap_id=id)
            self.assert_called_with_def(api_call, expected_def)

    def test_get(self):
        domain_id = '111'
        id = '222'
        with mock.patch.object(self.policy_api, "get") as api_call:
            self.resourceApi.get(domain_id, id)
            expected_def = policy_defs.ContractMapDef(domain_id=domain_id,
                                                      contractmap_id=id)
            self.assert_called_with_def(api_call, expected_def)

    def test_list(self):
        domain_id = '111'
        with mock.patch.object(self.policy_api, "list") as api_call:
            self.resourceApi.list(domain_id)
            expected_def = policy_defs.ContractMapDef(domain_id=domain_id)
            self.assert_called_with_def(api_call, expected_def)

    def test_update(self):
        domain_id = '111'
        id = '222'
        name = 'new name'
        description = 'new desc'
        source_group = 'ng1'
        dest_group = 'ng2'
        contract_id = 'nc1'
        with mock.patch.object(self.policy_api, "get",
                               return_value={}) as get_call,\
            mock.patch.object(self.policy_api, "update") as update_call:
            self.resourceApi.update(domain_id, id,
                                    name=name,
                                    description=description,
                                    contract_id=contract_id,
                                    source_groups=[source_group],
                                    dest_groups=[dest_group])
            expected_def = policy_defs.ContractMapDef(domain_id=domain_id,
                                                      contractmap_id=id)
            sgroup_path = "/tenants/infra/domains/%s/groups/%s" % (
                domain_id, source_group)
            dgroup_path = "/tenants/infra/domains/%s/groups/%s" % (
                domain_id, dest_group)
            contract_path = "/tenants/infra/contracts/%s" % contract_id
            expected_dict = {'display_name': name,
                             'description': description,
                             'contract_path': contract_path,
                             'source_groups': [sgroup_path],
                             'destination_groups': [dgroup_path]}
            self.assert_called_with_def(get_call, expected_def)
            self.assert_called_with_def_and_dict(
                update_call, expected_def, expected_dict)
