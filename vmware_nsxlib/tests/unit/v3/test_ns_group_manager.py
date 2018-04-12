# Copyright (c) 2015 VMware, Inc.
# All Rights Reserved.
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
import mock

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import ns_group_manager
from vmware_nsxlib.v3 import nsx_constants as consts


# Pool of fake ns-groups uuids
NSG_IDS = ['11111111-1111-1111-1111-111111111111',
           '22222222-2222-2222-2222-222222222222',
           '33333333-3333-3333-3333-333333333333',
           '44444444-4444-4444-4444-444444444444',
           '55555555-5555-5555-5555-555555555555']


def _mock_create_and_list_nsgroups(test_method):
    nsgroups = []

    def _create_nsgroup_mock(name, desc, tags, membership_criteria=None):
        nsgroup = {'id': NSG_IDS[len(nsgroups)],
                   'display_name': name,
                   'description': desc,
                   'tags': tags}
        nsgroups.append(nsgroup)
        return nsgroup

    def wrap(*args, **kwargs):
        with mock.patch(
            'vmware_nsxlib.v3.security.NsxLibNsGroup.create'
        ) as create_nsgroup_mock:
            create_nsgroup_mock.side_effect = _create_nsgroup_mock
            with mock.patch(
                "vmware_nsxlib.v3.security.NsxLibNsGroup.list"
            ) as list_nsgroups_mock:
                list_nsgroups_mock.side_effect = lambda: nsgroups
                test_method(*args, **kwargs)
    return wrap


class TestNSGroupManager(nsxlib_testcase.NsxLibTestCase):
    """Tests for vmware_nsxlib.v3.ns_group_manager.NSGroupManager."""

    @_mock_create_and_list_nsgroups
    def test_first_initialization(self):
        size = 5
        cont_manager = ns_group_manager.NSGroupManager(self.nsxlib, size)
        nested_groups = cont_manager.nested_groups
        self.assertEqual({i: NSG_IDS[i] for i in range(size)},
                         nested_groups)

    @_mock_create_and_list_nsgroups
    def test_reconfigure_number_of_nested_groups(self):
        # We need to test that when changing the number of nested groups then
        # the NSGroupManager picks the ones which were previously created
        # and create the ones which are missing, which also verifies that it
        # also recognizes existing nested groups.

        size = 2
        # Creates 2 nested groups.
        ns_group_manager.NSGroupManager(self.nsxlib, size)

        size = 5
        # Creates another 3 nested groups.
        nested_groups = ns_group_manager.NSGroupManager(
            self.nsxlib, size).nested_groups
        self.assertEqual({i: NSG_IDS[i] for i in range(size)},
                         nested_groups)

    @_mock_create_and_list_nsgroups
    @mock.patch('vmware_nsxlib.v3.security.NsxLibNsGroup.remove_member')
    @mock.patch('vmware_nsxlib.v3.security.NsxLibNsGroup.add_members')
    def test_add_and_remove_nsgroups(self,
                                     add_member_mock,
                                     remove_member_mock):
        # We verify that when adding a new nsgroup the properly placed
        # according to its id and the number of nested groups.

        size = 5
        cont_manager = ns_group_manager.NSGroupManager(self.nsxlib, size)
        nsgroup_id = 'nsgroup_id'

        with mock.patch.object(cont_manager, '_hash_uuid', return_value=7):
            cont_manager.add_nsgroup(nsgroup_id)
            cont_manager.remove_nsgroup(nsgroup_id)

        # There are 5 nested groups, the hash function will return 7, therefore
        # we expect that the nsgroup will be placed in the 3rd group.
        add_member_mock.assert_called_once_with(
            NSG_IDS[2], consts.NSGROUP, [nsgroup_id])
        remove_member_mock.assert_called_once_with(
            NSG_IDS[2], consts.NSGROUP, nsgroup_id,
            verify=True)

    @_mock_create_and_list_nsgroups
    @mock.patch('vmware_nsxlib.v3.security.NsxLibNsGroup.remove_member')
    @mock.patch('vmware_nsxlib.v3.security.NsxLibNsGroup.add_members')
    def test_when_nested_group_is_full(self,
                                       add_member_mock,
                                       remove_member_mock):

        def _add_member_mock(nsgroup, target_type, target_id):
            if nsgroup == NSG_IDS[2]:
                raise nsxlib_exc.NSGroupIsFull(nsgroup_id=nsgroup)

        def _remove_member_mock(nsgroup, target_type, target_id, verify=False):
            if nsgroup == NSG_IDS[2]:
                raise nsxlib_exc.NSGroupMemberNotFound(nsgroup_id=nsgroup,
                                                       member_id=target_id)

        add_member_mock.side_effect = _add_member_mock
        remove_member_mock.side_effect = _remove_member_mock

        size = 5
        cont_manager = ns_group_manager.NSGroupManager(self.nsxlib, size)
        nsgroup_id = 'nsgroup_id'

        with mock.patch.object(cont_manager, '_hash_uuid', return_value=7):
            cont_manager.add_nsgroup(nsgroup_id)
            cont_manager.remove_nsgroup(nsgroup_id)

        # Trying to add nsgroup to the nested group at index 2 will raise
        # NSGroupIsFull exception, we expect that the nsgroup will be added to
        # the nested group at index 3.
        calls = [mock.call(NSG_IDS[2],
                           consts.NSGROUP, [nsgroup_id]),
                 mock.call(NSG_IDS[3],
                           consts.NSGROUP, [nsgroup_id])]
        add_member_mock.assert_has_calls(calls)

        # Since the nsgroup was added to the nested group at index 3, it will
        # fail to remove it from the group at index 2, and then will try to
        # remove it from the group at index 3.
        calls = [
            mock.call(
                NSG_IDS[2], consts.NSGROUP,
                nsgroup_id, verify=True),
            mock.call(
                NSG_IDS[3], consts.NSGROUP,
                nsgroup_id, verify=True)]
        remove_member_mock.assert_has_calls(calls)

    @_mock_create_and_list_nsgroups
    @mock.patch('vmware_nsxlib.v3.security.NsxLibNsGroup.remove_member')
    @mock.patch('vmware_nsxlib.v3.security.NsxLibNsGroup.add_members')
    def test_initialize_with_absent_nested_groups(self,
                                                  add_member_mock,
                                                  remove_member_mock):
        size = 3
        cont_manager = ns_group_manager.NSGroupManager(self.nsxlib, size)
        # list_nsgroups will return nested group 1 and 3, but not group 2.
        nsgroups = cont_manager.nsxlib_nsgroup.list()
        with mock.patch("vmware_nsxlib.v3.security.NsxLibNsGroup.list",
                        side_effect=lambda: nsgroups[::2]):
            # invoking the initialization process again, it should process
            # groups 1 and 3 and create group 2.
            cont_manager = ns_group_manager.NSGroupManager(self.nsxlib, size)
            self.assertEqual({0: NSG_IDS[0],
                              1: NSG_IDS[3],
                              2: NSG_IDS[2]},
                             cont_manager.nested_groups)

    @_mock_create_and_list_nsgroups
    def test_suggest_nested_group(self):
        size = 5
        cont_manager = ns_group_manager.NSGroupManager(self.nsxlib, size)
        # We expect that the first suggested index is 2
        expected_suggested_groups = NSG_IDS[2:5] + NSG_IDS[:2]
        with mock.patch.object(cont_manager, '_hash_uuid', return_value=7):
            for i, suggested in enumerate(
                cont_manager._suggest_nested_group('fake-id')):
                self.assertEqual(expected_suggested_groups[i], suggested)
