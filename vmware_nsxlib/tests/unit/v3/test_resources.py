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
import copy

import eventlet
import mock

from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from vmware_nsxlib.tests.unit.v3 import mocks
from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.tests.unit.v3 import test_client
from vmware_nsxlib.tests.unit.v3 import test_constants
from vmware_nsxlib.v3 import core_resources
from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import resources
from vmware_nsxlib.v3 import utils


class BaseTestResource(nsxlib_testcase.NsxClientTestCase):
    """Base class for resources tests

    Contains tests for the simple get/list/delete apis
    and an api to get the mocked resource
    """
    def setUp(self, resource=None):
        self.resource = resource
        super(BaseTestResource, self).setUp()

    def get_mocked_resource(self, mock_validate=True, response=None,
                            response_repeat=1):
        session_response = None
        if response:
            session_response = mocks.MockRequestsResponse(
                200, jsonutils.dumps(response))
            if response_repeat > 1:
                session_response = [session_response] * response_repeat

        return self.mocked_resource(
            self.resource, mock_validate=mock_validate,
            session_response=session_response)

    def test_get_resource(self):
        if not self.resource:
            return
        mocked_resource = self.get_mocked_resource()
        fake_uuid = uuidutils.generate_uuid()
        mocked_resource.get(fake_uuid)
        test_client.assert_json_call(
            'get', mocked_resource,
            'https://1.2.3.4/api/v1/%s/%s' % (mocked_resource.uri_segment,
                                              fake_uuid),
            headers=self.default_headers())

    def test_list_all(self):
        if not self.resource:
            return
        mocked_resource = self.get_mocked_resource()
        mocked_resource.list()
        test_client.assert_json_call(
            'get', mocked_resource,
            'https://1.2.3.4/api/v1/%s' % mocked_resource.uri_segment,
            headers=self.default_headers())

    def test_delete_resource(self, extra_params=None):
        if not self.resource:
            return
        mocked_resource = self.get_mocked_resource()
        fake_uuid = uuidutils.generate_uuid()
        mocked_resource.delete(fake_uuid)
        uri = 'https://1.2.3.4/api/v1/%s/%s' % (mocked_resource.uri_segment,
                                                fake_uuid)
        if extra_params:
            uri = uri + '?' + extra_params
        test_client.assert_json_call(
            'delete', mocked_resource, uri,
            headers=self.default_headers())


class TestSwitchingProfileTestCase(BaseTestResource):

    def setUp(self):
        self.types = resources.SwitchingProfileTypes
        super(TestSwitchingProfileTestCase, self).setUp(
            resources.SwitchingProfile)

    def test_switching_profile_create(self):
        mocked_resource = self.get_mocked_resource()

        mocked_resource.create(self.types.PORT_MIRRORING,
                               'pm-profile', 'port mirror prof')

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps({
                'resource_type': self.types.PORT_MIRRORING,
                'display_name': 'pm-profile',
                'description': 'port mirror prof'
            }, sort_keys=True),
            headers=self.default_headers())

    def test_switching_profile_update(self):

        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]

        mocked_resource = self.get_mocked_resource()
        fake_uuid = uuidutils.generate_uuid()

        mocked_resource.update(
            fake_uuid, self.types.PORT_MIRRORING, tags=tags)

        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles/%s' % fake_uuid,
            data=jsonutils.dumps({
                'resource_type': self.types.PORT_MIRRORING,
                'tags': tags
            }, sort_keys=True),
            headers=self.default_headers())

    def test_spoofgaurd_profile_create(self):

        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]

        mocked_resource = self.get_mocked_resource()

        mocked_resource.create_spoofguard_profile(
            'plugin-spoof', 'spoofguard-for-plugin',
            whitelist_ports=True, tags=tags)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps({
                'resource_type': self.types.SPOOF_GUARD,
                'display_name': 'plugin-spoof',
                'description': 'spoofguard-for-plugin',
                'white_list_providers': ['LPORT_BINDINGS'],
                'tags': tags
            }, sort_keys=True),
            headers=self.default_headers())

    def test_create_dhcp_profile(self):

        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]

        mocked_resource = self.get_mocked_resource()

        mocked_resource.create_dhcp_profile(
            'plugin-dhcp', 'dhcp-for-plugin',
            tags=tags)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps({
                'bpdu_filter': {
                    'enabled': True,
                    'white_list': []
                },
                'resource_type': self.types.SWITCH_SECURITY,
                'display_name': 'plugin-dhcp',
                'description': 'dhcp-for-plugin',
                'tags': tags,
                'dhcp_filter': {
                    'client_block_enabled': True,
                    'server_block_enabled': False
                },
                'rate_limits': {
                    'enabled': False,
                    'rx_broadcast': 0,
                    'tx_broadcast': 0,
                    'rx_multicast': 0,
                    'tx_multicast': 0
                },
                'block_non_ip_traffic': True
            }, sort_keys=True),
            headers=self.default_headers())

    def test_create_mac_learning_profile(self):

        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]

        mocked_resource = self.get_mocked_resource()

        mocked_resource.create_mac_learning_profile(
            'plugin-mac-learning', 'mac-learning-for-plugin',
            tags=tags)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps({
                'mac_learning': {
                    'enabled': True,
                },
                'resource_type': self.types.MAC_LEARNING,
                'display_name': 'plugin-mac-learning',
                'description': 'mac-learning-for-plugin',
                'tags': tags,
                'mac_change_allowed': True,
            }, sort_keys=True),
            headers=self.default_headers())

    def test_find_by_display_name(self):
        resp_resources = {
            'results': [
                {'display_name': 'resource-1'},
                {'display_name': 'resource-2'},
                {'display_name': 'resource-3'}
            ]
        }
        mocked_resource = self.get_mocked_resource(response=resp_resources,
                                                   response_repeat=3)

        self.assertEqual([{'display_name': 'resource-1'}],
                         mocked_resource.find_by_display_name('resource-1'))
        self.assertEqual([{'display_name': 'resource-2'}],
                         mocked_resource.find_by_display_name('resource-2'))
        self.assertEqual([{'display_name': 'resource-3'}],
                         mocked_resource.find_by_display_name('resource-3'))

        resp_resources = {
            'results': [
                {'display_name': 'resource-1'},
                {'display_name': 'resource-1'},
                {'display_name': 'resource-1'}
            ]
        }
        mocked_resource = self.get_mocked_resource(response=resp_resources)
        self.assertEqual(resp_resources['results'],
                         mocked_resource.find_by_display_name('resource-1'))

    def test_list_all(self):
        mocked_resource = self.get_mocked_resource()
        mocked_resource.list()
        test_client.assert_json_call(
            'get', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles/'
            '?include_system_owned=True',
            data=None,
            headers=self.default_headers())


class LogicalPortTestCase(BaseTestResource):

    def setUp(self):
        super(LogicalPortTestCase, self).setUp(resources.LogicalPort)

    def _get_profile_dicts(self, fake_port):
        fake_profile_dicts = []
        for profile_id in fake_port['switching_profile_ids']:
            fake_profile_dicts.append({'resource_type': profile_id['key'],
                                       'id': profile_id['value']})
        return fake_profile_dicts

    def _get_pktcls_bindings(self):
        fake_pkt_classifiers = []
        fake_binding_repr = []
        for i in range(0, 3):
            ip = "9.10.11.%s" % i
            mac = "00:0c:29:35:4a:%sc" % i
            fake_pkt_classifiers.append(resources.PacketAddressClassifier(
                ip, mac, None))
            fake_binding_repr.append({
                'ip_address': ip,
                'mac_address': mac
            })
        return fake_pkt_classifiers, fake_binding_repr

    def test_create_logical_port(self):
        """Test creating a port.

        returns the correct response and 200 status
        """
        fake_port = test_constants.FAKE_PORT.copy()

        profile_dicts = self._get_profile_dicts(fake_port)

        pkt_classifiers, binding_repr = self._get_pktcls_bindings()

        mocked_resource = self.get_mocked_resource()
        description = 'dummy'
        switch_profile = resources.SwitchingProfile
        mocked_resource.create(
            fake_port['logical_switch_id'],
            fake_port['attachment']['id'],
            address_bindings=pkt_classifiers,
            switch_profile_ids=switch_profile.build_switch_profile_ids(
                mock.Mock(), *profile_dicts),
            description=description)

        resp_body = {
            'logical_switch_id': fake_port['logical_switch_id'],
            'switching_profile_ids': fake_port['switching_profile_ids'],
            'attachment': {
                'attachment_type': 'VIF',
                'id': fake_port['attachment']['id']
            },
            'admin_state': 'UP',
            'address_bindings': binding_repr,
            'description': description
        }

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/logical-ports',
            data=jsonutils.dumps(resp_body, sort_keys=True),
            headers=self.default_headers())

    def test_create_logical_port_with_attachtype_cif(self):
        """Test creating a port returns the correct response and 200 status

        """
        fake_port = copy.deepcopy(test_constants.FAKE_CONTAINER_PORT)

        profile_dicts = self._get_profile_dicts(fake_port)

        pkt_classifiers, binding_repr = self._get_pktcls_bindings()

        fake_port['address_bindings'] = binding_repr

        mocked_resource = self.get_mocked_resource()
        switch_profile = resources.SwitchingProfile
        fake_port_ctx = fake_port['attachment']['context']

        fake_container_host_vif_id = fake_port_ctx['container_host_vif_id']

        mocked_resource.create(
            fake_port['logical_switch_id'],
            fake_port['attachment']['id'],
            parent_vif_id=fake_container_host_vif_id,
            traffic_tag=fake_port_ctx['vlan_tag'],
            address_bindings=pkt_classifiers,
            switch_profile_ids=switch_profile.build_switch_profile_ids(
                mock.Mock(), *profile_dicts),
            vif_type=fake_port_ctx['vif_type'], app_id=fake_port_ctx['app_id'],
            allocate_addresses=fake_port_ctx['allocate_addresses'])

        resp_body = {
            'logical_switch_id': fake_port['logical_switch_id'],
            'switching_profile_ids': fake_port['switching_profile_ids'],
            'attachment': {
                'attachment_type': 'VIF',
                'id': fake_port['attachment']['id'],
                'context': {
                    'resource_type': 'VifAttachmentContext',
                    'allocate_addresses': 'Both',
                    'parent_vif_id': fake_container_host_vif_id,
                    'traffic_tag': fake_port_ctx['vlan_tag'],
                    'app_id': fake_port_ctx['app_id'],
                    'vif_type': 'CHILD',
                }
            },
            'admin_state': 'UP',
            'address_bindings': fake_port['address_bindings']
        }

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/logical-ports',
            data=jsonutils.dumps(resp_body, sort_keys=True),
            headers=self.default_headers())

    def test_create_logical_port_admin_down(self):
        """Test creating port with admin_state down."""
        fake_port = test_constants.FAKE_PORT
        fake_port['admin_state'] = "DOWN"
        mocked_resource = self.get_mocked_resource(response=fake_port)

        result = mocked_resource.create(
            test_constants.FAKE_PORT['logical_switch_id'],
            test_constants.FAKE_PORT['attachment']['id'],
            tags={}, admin_state=False)

        self.assertEqual(fake_port, result)

    def test_create_logical_port_with_tn_uuid(self):
        """Test creating port with transport_node_uuid."""
        fake_port = copy.deepcopy(test_constants.FAKE_CONTAINER_PORT)
        fake_port['parent_vif_id'] = None
        fake_port_ctx = fake_port['attachment']['context']
        fake_port_ctx['vif_type'] = 'INDEPENDENT'
        fake_port_ctx['transport_node_uuid'] = test_constants.FAKE_TN_UUID

        profile_dicts = self._get_profile_dicts(fake_port)
        pkt_classifiers, binding_repr = self._get_pktcls_bindings()
        fake_port['address_bindings'] = binding_repr

        mocked_resource = self.get_mocked_resource()
        switch_profile = resources.SwitchingProfile

        mocked_resource.create(
            fake_port['logical_switch_id'],
            fake_port['attachment']['id'],
            traffic_tag=fake_port_ctx['vlan_tag'],
            address_bindings=pkt_classifiers,
            switch_profile_ids=switch_profile.build_switch_profile_ids(
                mock.Mock(), *profile_dicts),
            vif_type=fake_port_ctx['vif_type'], app_id=fake_port_ctx['app_id'],
            allocate_addresses=fake_port_ctx['allocate_addresses'],
            tn_uuid=fake_port_ctx['transport_node_uuid'])

        resp_body = {
            'logical_switch_id': fake_port['logical_switch_id'],
            'switching_profile_ids': fake_port['switching_profile_ids'],
            'attachment': {
                'attachment_type': 'VIF',
                'id': fake_port['attachment']['id'],
                'context': {
                    'resource_type': 'VifAttachmentContext',
                    'allocate_addresses': 'Both',
                    'app_id': fake_port_ctx['app_id'],
                    'vif_type': 'INDEPENDENT',
                    'transport_node_uuid': test_constants.FAKE_TN_UUID,
                }
            },
            'admin_state': 'UP',
            'address_bindings': fake_port['address_bindings']
        }

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/logical-ports',
            data=jsonutils.dumps(resp_body, sort_keys=True),
            headers=self.default_headers())

    def test_delete_resource(self):
        """Test deleting port."""
        super(LogicalPortTestCase, self).test_delete_resource(
            extra_params='detach=true')

    def test_get_logical_port_by_attachment(self):
        """Test deleting port."""
        mocked_resource = self.get_mocked_resource()
        attachment_type = nsx_constants.ATTACHMENT_DHCP
        attachment_id = '1234'
        mocked_resource.get_by_attachment(attachment_type, attachment_id)
        test_client.assert_json_call(
            'get', mocked_resource,
            "https://1.2.3.4/api/v1/logical-ports/?attachment_type=%s"
            "&attachment_id=%s" % (attachment_type, attachment_id),
            headers=self.default_headers())

    def test_clear_port_bindings(self):
        fake_port = copy.copy(test_constants.FAKE_PORT)
        fake_port['address_bindings'] = ['a', 'b']
        mocked_resource = self.get_mocked_resource()

        def get_fake_port(*args, **kwargs):
            return copy.copy(fake_port)

        mocked_resource.client.get = get_fake_port
        mocked_resource.update(
            fake_port['id'], fake_port['attachment']['id'],
            address_bindings=[])

        fake_port['address_bindings'] = []
        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/logical-ports/%s' % fake_port['id'],
            data=jsonutils.dumps(fake_port, sort_keys=True),
            headers=self.default_headers())

    def test_create_logical_port_fail(self):
        """Test the failure of port creation."""
        fake_port = test_constants.FAKE_PORT.copy()
        profile_dicts = self._get_profile_dicts(fake_port)
        pkt_classifiers, binding_repr = self._get_pktcls_bindings()
        fake_port['address_bindings'] = binding_repr
        mocked_resource = self.get_mocked_resource(mock_validate=False)
        switch_profile = resources.SwitchingProfile
        try:
            mocked_resource.create(
                fake_port['logical_switch_id'],
                fake_port['attachment']['id'],
                address_bindings=pkt_classifiers,
                switch_profile_ids=switch_profile.build_switch_profile_ids(
                    mock.Mock(), *profile_dicts))
        except exceptions.ManagerError as e:
            self.assertIn(nsxlib_testcase.NSX_MANAGER, e.msg)

    def test_update_logical_port_no_addr_binding(self):
        fake_port = copy.deepcopy(test_constants.FAKE_CONTAINER_PORT)
        mocked_resource = self.get_mocked_resource()
        new_name = 'updated_port'
        new_desc = 'updated'
        fake_port_ctx = fake_port['attachment']['context']
        fake_container_host_vif_id = fake_port_ctx['container_host_vif_id']

        def get_fake_port(*args, **kwargs):
            return copy.copy(fake_port)

        mocked_resource.client.get = get_fake_port

        mocked_resource.update(
            fake_port['id'],
            fake_port['attachment']['id'],
            name=new_name,
            description=new_desc,
            parent_vif_id=fake_container_host_vif_id,
            traffic_tag=fake_port_ctx['vlan_tag'],
            vif_type=fake_port_ctx['vif_type'],
            app_id=fake_port_ctx['app_id'],
            allocate_addresses=fake_port_ctx['allocate_addresses'])

        fake_port['display_name'] = new_name
        fake_port['description'] = new_desc
        fake_port['attachment'] = {
            'attachment_type': 'VIF',
            'id': fake_port['attachment']['id'],
            'context': {
                'resource_type': 'VifAttachmentContext',
                'allocate_addresses': 'Both',
                'parent_vif_id': fake_container_host_vif_id,
                'traffic_tag': fake_port_ctx['vlan_tag'],
                'app_id': fake_port_ctx['app_id'],
                'vif_type': 'CHILD',
            }
        }

        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/logical-ports/%s' % fake_port['id'],
            data=jsonutils.dumps(fake_port, sort_keys=True),
            headers=self.default_headers())

    def test_update_logical_port_with_addr_binding(self):
        fake_port = copy.deepcopy(test_constants.FAKE_CONTAINER_PORT)
        mocked_resource = self.get_mocked_resource()
        new_name = 'updated_port'
        new_desc = 'updated'
        fake_port_ctx = fake_port['attachment']['context']
        fake_container_host_vif_id = fake_port_ctx['container_host_vif_id']
        pkt_classifiers, binding_repr = self._get_pktcls_bindings()

        def get_fake_port(*args, **kwargs):
            return copy.copy(fake_port)

        mocked_resource.client.get = get_fake_port

        mocked_resource.update(
            fake_port['id'],
            fake_port['attachment']['id'],
            name=new_name,
            description=new_desc,
            parent_vif_id=fake_container_host_vif_id,
            traffic_tag=fake_port_ctx['vlan_tag'],
            vif_type=fake_port_ctx['vif_type'],
            app_id=fake_port_ctx['app_id'],
            allocate_addresses=fake_port_ctx['allocate_addresses'],
            address_bindings=pkt_classifiers)

        fake_port['display_name'] = new_name
        fake_port['description'] = new_desc
        fake_port['attachment'] = {
            'attachment_type': 'VIF',
            'id': fake_port['attachment']['id'],
            'context': {
                'resource_type': 'VifAttachmentContext',
                'allocate_addresses': 'Both',
                'parent_vif_id': fake_container_host_vif_id,
                'traffic_tag': fake_port_ctx['vlan_tag'],
                'app_id': fake_port_ctx['app_id'],
                'vif_type': 'CHILD',
            }
        }
        fake_port['address_bindings'] = binding_repr
        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/logical-ports/%s' % fake_port['id'],
            data=jsonutils.dumps(fake_port, sort_keys=True),
            headers=self.default_headers())


class LogicalRouterTestCase(BaseTestResource):

    def setUp(self):
        super(LogicalRouterTestCase, self).setUp(
            core_resources.NsxLibLogicalRouter)

    def test_create_logical_router(self):
        """Test creating a router returns the correct response and 201 status.

        """
        fake_router = test_constants.FAKE_ROUTER.copy()
        router = self.get_mocked_resource()
        tier0_router = True
        description = 'dummy'
        tz_id = 'tz_id'
        allocation_pool = {
            'allocation_pool_type': 'LoadBalancerAllocationPool',
            'allocation_size': 'SMALL'
        }
        router.create(fake_router['display_name'], None, None, tier0_router,
                      description=description, transport_zone_id=tz_id,
                      allocation_pool=allocation_pool)

        data = {
            'display_name': fake_router['display_name'],
            'router_type': 'TIER0' if tier0_router else 'TIER1',
            'tags': None,
            'description': description,
            'advanced_config': {'transport_zone_id': tz_id},
            'allocation_profile': {
                'allocation_pool': allocation_pool
            }
        }

        test_client.assert_json_call(
            'post', router,
            'https://1.2.3.4/api/v1/logical-routers',
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_update_logical_router(self):
        fake_router = test_constants.FAKE_ROUTER.copy()
        router = self.get_mocked_resource()
        uuid = fake_router['id']

        name = 'dummy'
        description = 'dummy'
        edge_cluster_id = 'ec_id'
        tz_id = 'tz_id'
        with mock.patch.object(router.client, 'get',
                               return_value=fake_router),\
            mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                       return_value='2.2.0'):
            router.update(uuid, display_name=name, description=description,
                          edge_cluster_id=edge_cluster_id,
                          transport_zone_id=tz_id)

        fake_router["display_name"] = name
        fake_router["description"] = description
        fake_router["edge_cluster_id"] = edge_cluster_id
        fake_router["advanced_config"]['transport_zone_id'] = tz_id
        test_client.assert_json_call(
            'put', router,
            'https://1.2.3.4/api/v1/logical-routers/%s' % uuid,
            data=jsonutils.dumps(fake_router, sort_keys=True),
            headers=self.default_headers())

    def test_force_delete_logical_router(self):
        """Test force deleting router"""
        router = self.get_mocked_resource()
        uuid = test_constants.FAKE_ROUTER['id']
        router.delete(uuid, True)
        test_client.assert_json_call(
            'delete', router,
            'https://1.2.3.4/api/v1/logical-routers/%s?force=True' % uuid,
            headers=self.default_headers())

    def test_list_logical_router_by_type(self):
        router = self.get_mocked_resource()
        router_type = 'TIER0'
        router.list(router_type=router_type)
        test_client.assert_json_call(
            'get', router,
            'https://1.2.3.4/api/v1/logical-routers?router_type=%s' %
            router_type)

    def test_get_logical_router_fw_section(self):
        fake_router = test_constants.FAKE_ROUTER.copy()
        router = self.get_mocked_resource()
        section_id = router.get_firewall_section_id(
            test_constants.FAKE_ROUTER_UUID, router_body=fake_router)
        self.assertEqual(test_constants.FAKE_ROUTER_FW_SEC_UUID, section_id)

    def _test_nat_rule_create(self, nsx_version, add_bypas_arg=True,
                              action='SNAT', expect_failure=False):
        router = self.get_mocked_resource()
        translated_net = '1.1.1.1'
        priority = 10
        display_name = 'fake_name'

        data = {
            'action': action,
            'display_name': display_name,
            'enabled': True,
            'translated_network': translated_net,
            'rule_priority': priority
        }
        if add_bypas_arg:
            # Expect nat_pass to be sent to the backend
            data['nat_pass'] = False

        # Ignoring 'bypass_firewall' with version 1.1
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value=nsx_version):
            try:
                router.add_nat_rule(test_constants.FAKE_ROUTER_UUID,
                                    action=action,
                                    translated_network=translated_net,
                                    rule_priority=priority,
                                    bypass_firewall=False,
                                    display_name=display_name)
            except exceptions.InvalidInput as e:
                if expect_failure:
                    return
                else:
                    self.fail("Failed to create NAT rule: %s", e)

            test_client.assert_json_call(
                'post', router,
                ('https://1.2.3.4/api/v1/logical-routers/%s/nat/rules' %
                    test_constants.FAKE_ROUTER_UUID),
                data=jsonutils.dumps(data, sort_keys=True),
                headers=self.default_headers())

    def test_nat_rule_create_v1(self):
        # Ignoring 'bypass_firewall' with version 1.1
        self._test_nat_rule_create('1.1.0', add_bypas_arg=False)

    def test_nat_rule_create_v2(self):
        # Sending 'bypass_firewall' with version 1.1
        self._test_nat_rule_create('2.0.0')

    def test_nat_rule_create_v22_NO_DNAT(self):
        # NO_DNAT is supported from 2.2 & up
        self._test_nat_rule_create('2.2.0', action='NO_DNAT')

    def test_nat_rule_create_v2_NO_DNAT(self):
        # NO_DNAT is supported from 2.2 & up
        self._test_nat_rule_create('2.0.0', action='NO_DNAT',
                                   expect_failure=True)

    def test_nat_rule_create_invalid(self):
        # NO_DNAT is supported from 2.2 & up
        self._test_nat_rule_create('2.0.0', action='INVALID',
                                   expect_failure=True)

    def test_nat_rule_list(self):
        router = self.get_mocked_resource()
        router.list_nat_rules(test_constants.FAKE_ROUTER_UUID)
        test_client.assert_json_call(
            'get', router,
            ('https://1.2.3.4/api/v1/logical-routers/%s/nat/rules' %
                test_constants.FAKE_ROUTER_UUID),
            headers=self.default_headers())

    def test_nat_rule_update(self):
        router = self.get_mocked_resource()
        rule_id = '123'
        with mock.patch.object(router.client, 'get',
                               return_value={'id': rule_id}):
            router.update_nat_rule(test_constants.FAKE_ROUTER_UUID,
                                   rule_id, nat_pass=False)
            data = {'id': rule_id, 'nat_pass': False}
            test_client.assert_json_call(
                'put', router,
                ('https://1.2.3.4/api/v1/logical-routers/%s/nat/rules/%s' %
                    (test_constants.FAKE_ROUTER_UUID, rule_id)),
                data=jsonutils.dumps(data, sort_keys=True),
                headers=self.default_headers())

    def test_delete_nat_rule_by_gw(self):
        router = self.get_mocked_resource()
        rule_id = '123'
        router_id = test_constants.FAKE_ROUTER_UUID
        gw_ip = '3.3.3.3'
        existing_rules = [{
            'translated_network': gw_ip,
            'logical_router_id': router_id,
            'id': rule_id,
            'action': 'SNAT',
            'resource_type': 'NatRule'}]
        with mock.patch.object(router.client, 'list',
                               return_value={'results': existing_rules}):
            router.delete_nat_rule_by_values(router_id,
                                             translated_network=gw_ip)
            test_client.assert_json_call(
                'delete', router,
                ('https://1.2.3.4/api/v1/logical-routers/%s/nat/rules/%s' %
                    (router_id, rule_id)),
                headers=self.default_headers())

    def test_delete_nat_rule_by_gw_and_source(self):
        router = self.get_mocked_resource()
        rule_id = '123'
        router_id = test_constants.FAKE_ROUTER_UUID
        gw_ip = '3.3.3.3'
        source_net = '4.4.4.4'
        existing_rules = [{
            'translated_network': gw_ip,
            'logical_router_id': router_id,
            'id': rule_id,
            'match_source_network': source_net,
            'action': 'SNAT',
            'resource_type': 'NatRule'}]
        with mock.patch.object(router.client, 'list',
                               return_value={'results': existing_rules}):
            router.delete_nat_rule_by_values(router_id,
                                             translated_network=gw_ip,
                                             match_source_network=source_net)
            test_client.assert_json_call(
                'delete', router,
                ('https://1.2.3.4/api/v1/logical-routers/%s/nat/rules/%s' %
                    (router_id, rule_id)),
                headers=self.default_headers())

    def test_update_advertisement(self):
        router = self.get_mocked_resource()
        router_id = test_constants.FAKE_ROUTER_UUID
        data = {'advertise_nat_routes': 'a',
                'advertise_nsx_connected_routes': 'b',
                'advertise_static_routes': False,
                'enabled': True,
                'advertise_lb_vip': False,
                'advertise_lb_snat_ip': False}
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value='2.1.0'), \
            mock.patch.object(router.client, 'get',
                              return_value={}):
            router.update_advertisement(
                router_id, **data)
            test_client.assert_json_call(
                'put', router,
                ('https://1.2.3.4/api/v1/logical-routers/%s/routing/'
                 'advertisement' % router_id),
                data=jsonutils.dumps(data, sort_keys=True),
                headers=self.default_headers())

    def test_update_advertisement_no_lb(self):
        router = self.get_mocked_resource()
        router_id = test_constants.FAKE_ROUTER_UUID
        data = {'advertise_nat_routes': 'a',
                'advertise_nsx_connected_routes': 'b',
                'advertise_static_routes': False,
                'enabled': True}
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value='1.1.0'), \
            mock.patch.object(router.client, 'get',
                              return_value={}):
            # lb args will be ignored on this nsx version
            router.update_advertisement(
                router_id,
                advertise_lb_vip=False,
                advertise_lb_snat_ip=False,
                **data)
            test_client.assert_json_call(
                'put', router,
                ('https://1.2.3.4/api/v1/logical-routers/%s/routing/'
                 'advertisement' % router_id),
                data=jsonutils.dumps(data, sort_keys=True),
                headers=self.default_headers())

    def test_update_advertisement_rules(self):
        router = self.get_mocked_resource()
        router_id = test_constants.FAKE_ROUTER_UUID
        rules = [{"action": "ALLOW",
                  "networks": ["44.0.0.0/20"],
                  "display_name": "rule1"},
                 {"action": "ALLOW",
                  "networks": ["6.60.0.0/20"],
                  "display_name": "rule2"}]
        with mock.patch.object(router.client, 'get',
                               return_value={}):
            router.update_advertisement_rules(router_id, rules)
            test_client.assert_json_call(
                'put', router,
                ('https://1.2.3.4/api/v1/logical-routers/%s/routing/'
                 'advertisement/rules' % router_id),
                data=jsonutils.dumps({'rules': rules}, sort_keys=True),
                headers=self.default_headers())

    def test_get_advertisement_rules(self):
        router = self.get_mocked_resource()
        router_id = test_constants.FAKE_ROUTER_UUID
        router.get_advertisement_rules(router_id)
        test_client.assert_json_call(
            'get', router,
            ('https://1.2.3.4/api/v1/logical-routers/%s/routing/'
             'advertisement/rules' % router_id),
            headers=self.default_headers())

    def test_get_debug_info(self):
        router = self.get_mocked_resource()
        router_id = test_constants.FAKE_ROUTER_UUID
        router.get_debug_info(router_id)
        test_client.assert_json_call(
            'get', router,
            ('https://1.2.3.4/api/v1/logical-routers/%s/'
             'debug-info?format=text' % router_id),
            headers=self.default_headers())

    def test_get_transportzone_id_empty(self):
        # Tier0 router may fail to provide TZ id if it
        # is not yet connected with any Tier1 router
        router = self.get_mocked_resource()
        router_id = test_constants.FAKE_ROUTER_UUID
        faked_responds = {
            'componentInfo': [{
                'componentType': nsx_constants.ROUTER_TYPE_TIER0_DR,
                'transportZoneId': None
            }]
        }
        with mock.patch.object(router.client, 'get',
                               return_value=faked_responds):
            res = router.get_transportzone_id(router_id)
            self.assertIsNone(res)

    def test_get_transportzone_id(self):
        router = self.get_mocked_resource()
        router_id = test_constants.FAKE_ROUTER_UUID
        faked_responds = {
            'componentInfo': [{
                'componentType': nsx_constants.ROUTER_TYPE_TIER0_DR,
                'transportZoneId': ['faked_id']
            }]
        }
        with mock.patch.object(router.client, 'get',
                               return_value=faked_responds):
            res = router.get_transportzone_id(router_id)
            self.assertEqual('faked_id', res)


class LogicalRouterPortTestCase(BaseTestResource):

    def setUp(self):
        super(LogicalRouterPortTestCase, self).setUp(
            resources.LogicalRouterPort)

    def test_create_logical_router_port(self):
        """Test creating a router port.

        returns the correct response and 201 status
        """
        fake_router_port = test_constants.FAKE_ROUTER_PORT.copy()
        fake_relay_uuid = uuidutils.generate_uuid()
        lrport = self.get_mocked_resource()

        data = {
            'display_name': fake_router_port['display_name'],
            'logical_router_id': fake_router_port['logical_router_id'],
            'resource_type': fake_router_port['resource_type'],
            'tags': [],
            'service_bindings': [{'service_id': {
                'target_type': 'LogicalService',
                'target_id': fake_relay_uuid}}],
            'linked_logical_switch_port_id': {'target_id': None}
        }

        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value='2.0.0'):
            lrport.create(fake_router_port['logical_router_id'],
                          fake_router_port['display_name'],
                          None,
                          fake_router_port['resource_type'],
                          None, None, None,
                          relay_service_uuid=fake_relay_uuid)

            test_client.assert_json_call(
                'post', lrport,
                'https://1.2.3.4/api/v1/logical-router-ports',
                data=jsonutils.dumps(data, sort_keys=True),
                headers=self.default_headers())

    def test_logical_router_port_max_attempts(self):
        """Test a router port api has the configured retries."""
        lrport = self.get_mocked_resource()

        self.assertEqual(nsxlib_testcase.NSX_MAX_ATTEMPTS,
                         lrport.client.max_attempts)

    def test_update_logical_router_port(self):
        fake_router_port = test_constants.FAKE_ROUTER_PORT.copy()
        uuid = fake_router_port['id']
        fake_relay_uuid = uuidutils.generate_uuid()
        lrport = self.get_mocked_resource()
        with mock.patch.object(lrport.client, 'get',
                               return_value=fake_router_port),\
            mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                       return_value='2.0.0'):
            lrport.update(uuid, relay_service_uuid=fake_relay_uuid)
            fake_router_port['service_bindings'] = [{'service_id': {
                'target_type': 'LogicalService',
                'target_id': fake_relay_uuid}}]

            test_client.assert_json_call(
                'put', lrport,
                'https://1.2.3.4/api/v1/logical-router-ports/%s' % uuid,
                data=jsonutils.dumps(fake_router_port, sort_keys=True),
                headers=self.default_headers())

    def test_get_logical_router_port_by_router_id(self):
        """Test getting a router port by router id."""
        fake_router_port = test_constants.FAKE_ROUTER_PORT.copy()
        resp_resources = {'results': [fake_router_port]}
        lrport = self.get_mocked_resource(response=resp_resources)

        router_id = fake_router_port['logical_router_id']
        result = lrport.get_by_router_id(router_id)
        self.assertEqual(fake_router_port, result[0])
        test_client.assert_json_call(
            'get', lrport,
            'https://1.2.3.4/api/v1/logical-router-ports/?'
            'logical_router_id=%s' % router_id,
            headers=self.default_headers())

    def test_get_logical_router_port_by_switch_id(self):
        """Test getting a router port by switch id."""
        fake_router_port = test_constants.FAKE_ROUTER_PORT.copy()
        resp_resources = {
            'result_count': 1,
            'results': [fake_router_port]
        }
        lrport = self.get_mocked_resource(response=resp_resources)

        switch_id = test_constants.FAKE_SWITCH_UUID
        lrport.get_by_lswitch_id(switch_id)
        test_client.assert_json_call(
            'get', lrport,
            'https://1.2.3.4/api/v1/logical-router-ports/?'
            'logical_switch_id=%s' % switch_id,
            headers=self.default_headers())

    def test_get_tier1_link_port(self):
        """Test getting a Tier0 router uplink port by router id."""
        router_id = test_constants.FAKE_ROUTER_PORT['logical_router_id']

        # No ports found - raise an exception
        lrport = self.get_mocked_resource(response={'results': []})
        self.assertRaises(exceptions.ResourceNotFound,
                          lrport.get_tier1_link_port,
                          router_id)

        # Non uplink ports found - raise an exception
        lrport = self.get_mocked_resource(response={'results': [
            test_constants.FAKE_ROUTER_PORT]})
        self.assertRaises(exceptions.ResourceNotFound,
                          lrport.get_tier1_link_port,
                          router_id)

        # uplink port exists
        lrport = self.get_mocked_resource(response={'results': [
            test_constants.FAKE_ROUTER_LINKT1_PORT]})
        result = lrport.get_tier1_link_port(router_id)
        self.assertEqual(test_constants.FAKE_ROUTER_LINKT1_PORT, result)

    def test_get_tier0_uplink_port(self):
        """Test getting a Tier0 router uplink port by router id."""
        router_id = test_constants.FAKE_ROUTER_PORT['logical_router_id']

        # No ports found - return None
        lrport = self.get_mocked_resource(response={'results': []})
        result = lrport.get_tier0_uplink_port(router_id)
        self.assertIsNone(result)

        # Non uplink ports found - return None
        lrport = self.get_mocked_resource(response={'results': [
            test_constants.FAKE_ROUTER_LINKT1_PORT]})
        result = lrport.get_tier0_uplink_port(router_id)
        self.assertIsNone(result)

        # uplink port exists
        lrport = self.get_mocked_resource(response={'results': [
            test_constants.FAKE_ROUTER_PORT]})
        result = lrport.get_tier0_uplink_port(router_id)
        self.assertEqual(test_constants.FAKE_ROUTER_PORT, result)

    def test_get_tier0_uplink_port_ips(self):
        """Test getting a Tier0 router uplink port by router id."""
        router_id = test_constants.FAKE_ROUTER_PORT['logical_router_id']

        # No ports found - return empty list
        lrport = self.get_mocked_resource(response={'results': []})
        result = lrport.get_tier0_uplink_ips(router_id)
        self.assertEqual(0, len(result))

        # uplink port exists, return ips
        lrport = self.get_mocked_resource(response={'results': [
            test_constants.FAKE_ROUTER_PORT]})
        result = lrport.get_tier0_uplink_ips(router_id)
        self.assertEqual(1, len(result))
        self.assertEqual('172.20.1.60', result[0])


class IpPoolTestCase(BaseTestResource):

    def setUp(self):
        super(IpPoolTestCase, self).setUp(resources.IpPool)

    def test_create_ip_pool_all_args(self):
        """Test creating an IP pool

        returns the correct response and 201 status
        """
        pool = self.get_mocked_resource()

        display_name = 'dummy'
        gateway_ip = '1.1.1.1'
        ranges = [{'start': '2.2.2.0', 'end': '2.2.2.255'},
                  {'start': '3.2.2.0', 'end': '3.2.2.255'}]
        cidr = '2.2.2.0/24'
        description = 'desc'
        dns_nameserver = '7.7.7.7'
        pool.create(cidr, allocation_ranges=ranges,
                    display_name=display_name,
                    gateway_ip=gateway_ip,
                    description=description,
                    dns_nameservers=[dns_nameserver])

        data = {
            'display_name': display_name,
            'description': description,
            'subnets': [{
                'gateway_ip': gateway_ip,
                'allocation_ranges': ranges,
                'cidr': cidr,
                'dns_nameservers': [dns_nameserver]
            }]
        }

        test_client.assert_json_call(
            'post', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools',
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_create_ip_pool_minimal_args(self):
        pool = self.get_mocked_resource()

        ranges = [{'start': '2.2.2.0', 'end': '2.2.2.255'},
                  {'start': '3.2.2.0', 'end': '3.2.2.255'}]
        cidr = '2.2.2.0/24'
        pool.create(cidr, allocation_ranges=ranges)

        data = {
            'subnets': [{
                'allocation_ranges': ranges,
                'cidr': cidr,
            }]
        }

        test_client.assert_json_call(
            'post', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools',
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_create_ip_pool_no_ranges_with_gateway(self):
        pool = self.get_mocked_resource()
        cidr = '2.2.2.0/30'
        gateway_ip = '2.2.2.1'
        pool.create(cidr, allocation_ranges=None, gateway_ip=gateway_ip)
        exp_ranges = [{'start': '2.2.2.0', 'end': '2.2.2.0'},
                      {'start': '2.2.2.2', 'end': '2.2.2.3'}]

        data = {
            'subnets': [{
                'gateway_ip': gateway_ip,
                'allocation_ranges': exp_ranges,
                'cidr': cidr,
            }]
        }

        test_client.assert_json_call(
            'post', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools',
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_create_ip_pool_no_ranges_no_gateway(self):
        pool = self.get_mocked_resource()
        cidr = '2.2.2.0/30'
        pool.create(cidr, allocation_ranges=None)
        exp_ranges = [{'start': '2.2.2.0', 'end': '2.2.2.3'}]

        data = {
            'subnets': [{
                'allocation_ranges': exp_ranges,
                'cidr': cidr,
            }]
        }

        test_client.assert_json_call(
            'post', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools',
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_create_ip_pool_no_cidr(self):
        pool = self.get_mocked_resource()
        gateway_ip = '1.1.1.1'
        ranges = [{'start': '2.2.2.0', 'end': '2.2.2.255'},
                  {'start': '3.2.2.0', 'end': '3.2.2.255'}]
        cidr = None

        try:
            pool.create(cidr, allocation_ranges=ranges,
                        gateway_ip=gateway_ip)
        except exceptions.InvalidInput:
            # This call should fail
            pass
        else:
            self.fail("shouldn't happen")

    def test_delete_ip_pool(self):
        fake_ip_pool = test_constants.FAKE_IP_POOL.copy()
        pool = self.get_mocked_resource(response=fake_ip_pool)
        uuid = fake_ip_pool['id']
        pool.delete(uuid)
        test_client.assert_json_call(
            'delete', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s' % uuid,
            headers=self.default_headers())

    def test_force_delete_ip_pool(self):
        fake_ip_pool = test_constants.FAKE_IP_POOL.copy()
        pool = self.get_mocked_resource(response=fake_ip_pool)
        uuid = fake_ip_pool['id']
        pool.delete(uuid, force=True)
        test_client.assert_json_call(
            'delete', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s?force=True' % uuid,
            headers=self.default_headers())

    def test_update_ip_pool_name(self):
        fake_ip_pool = test_constants.FAKE_IP_POOL.copy()
        pool = self.get_mocked_resource(response=fake_ip_pool)

        uuid = fake_ip_pool['id']
        new_name = 'new_name'
        pool.update(uuid, display_name=new_name)
        fake_ip_pool['display_name'] = new_name
        test_client.assert_json_call(
            'put', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s' % uuid,
            data=jsonutils.dumps(fake_ip_pool, sort_keys=True),
            headers=self.default_headers())

    def test_update_ip_pool_gateway(self):
        fake_ip_pool = test_constants.FAKE_IP_POOL.copy()
        pool = self.get_mocked_resource(response=fake_ip_pool)

        uuid = fake_ip_pool['id']
        new_gateway = '1.0.0.1'
        pool.update(uuid, gateway_ip=new_gateway)
        fake_ip_pool["subnets"][0]['gateway_ip'] = new_gateway
        test_client.assert_json_call(
            'put', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s' % uuid,
            data=jsonutils.dumps(fake_ip_pool, sort_keys=True),
            headers=self.default_headers())

    def test_update_ip_pool_delete_gateway(self):
        fake_ip_pool = test_constants.FAKE_IP_POOL.copy()
        pool = self.get_mocked_resource(response=fake_ip_pool)

        uuid = fake_ip_pool['id']
        pool.update(uuid, gateway_ip=None)
        del fake_ip_pool["subnets"][0]['gateway_ip']
        test_client.assert_json_call(
            'put', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s' % uuid,
            data=jsonutils.dumps(fake_ip_pool, sort_keys=True),
            headers=self.default_headers())

    def test_allocate_ip_from_pool(self):
        pool = self.get_mocked_resource()

        uuid = test_constants.FAKE_IP_POOL['id']
        addr = '1.1.1.1'
        pool.allocate(uuid, ip_addr=addr)

        data = {'allocation_id': addr}
        test_client.assert_json_call(
            'post', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s?action=ALLOCATE' % uuid,
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_release_ip_to_pool(self):
        pool = self.get_mocked_resource()

        uuid = test_constants.FAKE_IP_POOL['id']
        addr = '1.1.1.1'
        pool.release(uuid, addr)

        data = {'allocation_id': addr}
        test_client.assert_json_call(
            'post', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s?action=RELEASE' % uuid,
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_get_ip_pool_allocations(self):
        """Test getting a router port by router id"""
        fake_ip_pool = test_constants.FAKE_IP_POOL.copy()
        pool = self.get_mocked_resource(response=fake_ip_pool)

        uuid = fake_ip_pool['id']
        result = pool.get_allocations(uuid)
        self.assertEqual(fake_ip_pool, result)
        test_client.assert_json_call(
            'get', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s/allocations' % uuid,
            headers=self.default_headers())


class TestNsxSearch(nsxlib_testcase.NsxClientTestCase):

    def test_nsx_search_tags(self):
        """Test search of resources with the specified tag."""
        with mock.patch.object(self.nsxlib.client, 'url_get') as search:
            user_tags = [{'scope': 'user', 'tag': 'k8s'}]
            query = self.nsxlib._build_query(tags=user_tags)
            self.nsxlib.search_by_tags(tags=user_tags)
            search.assert_called_with('search?query=%s' % query)

    def test_nsx_search_tags_scope_only(self):
        """Test search of resources with the specified tag."""
        with mock.patch.object(self.nsxlib.client, 'url_get') as search:
            user_tags = [{'scope': 'user'}]
            query = self.nsxlib._build_query(tags=user_tags)
            self.nsxlib.search_by_tags(tags=user_tags)
            search.assert_called_with('search?query=%s' % query)

    def test_nsx_search_tags_tag_only(self):
        """Test search of resources with the specified tag."""
        with mock.patch.object(self.nsxlib.client, 'url_get') as search:
            user_tags = [{'tag': 'k8s'}]
            query = self.nsxlib._build_query(tags=user_tags)
            self.nsxlib.search_by_tags(tags=user_tags)
            search.assert_called_with('search?query=%s' % query)

    def test_nsx_search_tags_tag_and_scope(self):
        """Test search of resources with the specified tag."""
        with mock.patch.object(self.nsxlib.client, 'url_get') as search:
            user_tags = [{'tag': 'k8s'}, {'scope': 'user'}]
            query = self.nsxlib._build_query(tags=user_tags)
            self.nsxlib.search_by_tags(tags=user_tags)
            search.assert_called_with('search?query=%s' % query)

    def test_nsx_search_tags_and_resource_type(self):
        """Test search of specified resource with the specified tag."""
        with mock.patch.object(self.nsxlib.client, 'url_get') as search:
            user_tags = [{'scope': 'user', 'tag': 'k8s'}]
            res_type = 'LogicalPort'
            query = self.nsxlib._build_query(tags=user_tags)
            # Add resource_type to the query
            query = "resource_type:%s AND %s" % (res_type, query)
            self.nsxlib.search_by_tags(tags=user_tags, resource_type=res_type)
            search.assert_called_with('search?query=%s' % query)

    def test_nsx_search_tags_and_cursor(self):
        """Test search of resources with the specified tag and cursor."""
        with mock.patch.object(self.nsxlib.client, 'url_get') as search:
            user_tags = [{'scope': 'user', 'tag': 'k8s'}]
            query = self.nsxlib._build_query(tags=user_tags)
            self.nsxlib.search_by_tags(tags=user_tags, cursor=50)
            search.assert_called_with('search?query=%s&cursor=50' % query)

    def test_nsx_search_tags_and_page_size(self):
        """Test search of resources with the specified tag and page size."""
        with mock.patch.object(self.nsxlib.client, 'url_get') as search:
            user_tags = [{'scope': 'user', 'tag': 'k8s'}]
            query = self.nsxlib._build_query(tags=user_tags)
            self.nsxlib.search_by_tags(tags=user_tags, page_size=100)
            search.assert_called_with('search?query=%s&page_size=100' % query)

    def test_nsx_search_invalid_query_fail(self):
        """Test search query failure for missing tag argument."""
        self.assertRaises(exceptions.NsxSearchInvalidQuery,
                          self.nsxlib.search_by_tags,
                          tags=None, resource_type=None)

    def test_nsx_search_invalid_tags_fail(self):
        """Test search of resources with the invalid tag."""
        user_tags = [{'scope': 'user', 'invalid_tag_key': 'k8s'}]
        self.assertRaises(exceptions.NsxSearchInvalidQuery,
                          self.nsxlib._build_query,
                          tags=user_tags)

    def test_nsx_search_all_by_tags(self):
        """Test search all of resources with the specified tag."""
        with mock.patch.object(self.nsxlib.client, 'url_get') as search:
            search.side_effect = [
                {"cursor": "2",
                 "result_count": 3,
                 "results": [{"id": "s1"},
                             {"id": "s2"}]},
                {"cursor": "3",
                 "result_count": 3,
                 "results": [{"id": "s3"}]}]
            user_tags = [{'scope': 'user', 'tag': 'k8s'}]
            query = self.nsxlib._build_query(tags=user_tags)
            results = self.nsxlib.search_all_by_tags(tags=user_tags)
            search.assert_has_calls([
                mock.call('search?query=%s' % query),
                mock.call('search?query=%s&cursor=2' % query)])
            self.assertEqual(3, len(results))

    def test_get_id_by_resource_and_tag(self):
        id = 'test'
        scope = 'user'
        tag = 'k8s'
        res_type = 'LogicalPort'
        results = {'result_count': 1, 'results': [{'id': id}]}
        with mock.patch.object(self.nsxlib.client, 'url_get',
                               return_value=results):
            actual_id = self.nsxlib.get_id_by_resource_and_tag(
                res_type, scope, tag)
            self.assertEqual(id, actual_id)

    def test_get_id_by_resource_and_tag_not_found(self):
        scope = 'user'
        tag = 'k8s'
        res_type = 'LogicalPort'
        results = {'result_count': 0, 'results': []}
        with mock.patch.object(self.nsxlib.client, 'url_get',
                               return_value=results):
            self.assertRaises(exceptions.ResourceNotFound,
                              self.nsxlib.get_id_by_resource_and_tag,
                              res_type, scope, tag, alert_not_found=True)

    def test_get_id_by_resource_and_tag_multiple(self):
        scope = 'user'
        tag = 'k8s'
        res_type = 'LogicalPort'
        results = {'result_count': 2, 'results': [{'id': '1'}, {'id': '2'}]}
        with mock.patch.object(self.nsxlib.client, 'url_get',
                               return_value=results):
            self.assertRaises(exceptions.ManagerError,
                              self.nsxlib.get_id_by_resource_and_tag,
                              res_type, scope, tag, alert_multiple=True)


class TransportZone(BaseTestResource):

    def setUp(self):
        super(TransportZone, self).setUp(core_resources.NsxLibTransportZone)

    def test_get_transport_zone_type(self):
        fake_tz = test_constants.FAKE_TZ.copy()
        tz = self.get_mocked_resource()
        with mock.patch.object(tz.client, 'url_get', return_value=fake_tz):
            tz_type = tz.get_transport_type(fake_tz['id'])
            self.assertEqual(tz.TRANSPORT_TYPE_OVERLAY, tz_type)

            # call it again to test it when cached
            tz_type = tz.get_transport_type(fake_tz['id'])
            self.assertEqual(tz.TRANSPORT_TYPE_OVERLAY, tz_type)

    def test_get_host_switch_mode(self):
        fake_tz = test_constants.FAKE_TZ.copy()
        tz = self.get_mocked_resource()
        with mock.patch.object(tz.client, 'url_get', return_value=fake_tz):
            tz_mode = tz.get_host_switch_mode(fake_tz['id'])
            self.assertEqual(tz.HOST_SWITCH_MODE_STANDARD, tz_mode)


class TransportNode(BaseTestResource):

    def setUp(self):
        super(TransportNode, self).setUp(core_resources.NsxLibTransportNode)

    def test_get_transport_zones(self):
        fake_tn = test_constants.FAKE_TN.copy()
        tn = self.get_mocked_resource()
        with mock.patch.object(tn.client, 'url_get', return_value=fake_tn):
            tzs = tn.get_transport_zones(fake_tn['id'])
            self.assertEqual([test_constants.FAKE_TZ_UUID], tzs)


class MetadataProxy(BaseTestResource):

    def setUp(self):
        super(MetadataProxy, self).setUp(core_resources.NsxLibMetadataProxy)

    def test_update_metadata_proxy(self):
        fake_md = test_constants.FAKE_MD.copy()
        md = self.get_mocked_resource()
        new_url = "http://2.2.2.20:3500/xyz"
        new_secret = 'abc'
        new_edge = uuidutils.generate_uuid()
        with mock.patch.object(md.client, 'url_get', return_value=fake_md):
            md.update(fake_md['id'], server_url=new_url, secret=new_secret,
                      edge_cluster_id=new_edge)
            fake_md.update({'metadata_server_url': new_url,
                            'secret': new_secret,
                            'edge_cluster_id': new_edge})
            test_client.assert_json_call(
                'put', md,
                'https://1.2.3.4/api/v1/md-proxies/%s' % fake_md['id'],
                data=jsonutils.dumps(fake_md, sort_keys=True),
                headers=self.default_headers())

    def test_get_md_proxy_status(self):
        """Test getting proxy_status."""
        mocked_resource = self.get_mocked_resource()
        attachment_id = 'd84ba3b8-9201-4591-8264-aad289e762ee'
        logical_switch_id = 'e11803a2-2d3e-452b-a834-aeb94940d272'
        mocked_resource.get_md_proxy_status(attachment_id, logical_switch_id)
        test_client.assert_json_call(
            'get', mocked_resource,
            "https://1.2.3.4/api/v1/md-proxies/%s/%s/status" %
            (attachment_id, logical_switch_id),
            headers=self.default_headers())


class NsxLibSwitchTestCase(BaseTestResource):

    def setUp(self):
        super(NsxLibSwitchTestCase, self).setUp(
            core_resources.NsxLibLogicalSwitch)
        self._tz_id = uuidutils.generate_uuid()

    def _create_body(self, display_name="fake_name",
                     admin_state=nsx_constants.ADMIN_STATE_UP,
                     vlan_id=None, description=None, trunk_vlan=None):
        body = {
            "transport_zone_id": self._tz_id,
            "replication_mode": "MTEP",
            "display_name": display_name,
            "tags": [],
            "admin_state": admin_state
        }
        if vlan_id:
            body['vlan'] = vlan_id
        if description is not None:
            body['description'] = description
        if trunk_vlan:
            body['vlan_trunk_spec'] = {
                'vlan_ranges': [{'start': trunk_vlan[0],
                                 'end': trunk_vlan[1]}]}
        return body

    def test_create_logical_switch(self):
        """Test creating a switch returns the correct response and 200 status

        """
        desc = 'dummy'
        ls = self.get_mocked_resource()
        ls.create(mocks.FAKE_NAME, self._tz_id, [],
                  description=desc)
        data = self._create_body(description=desc)
        test_client.assert_json_call(
            'post', ls,
            'https://1.2.3.4/api/v1/logical-switches',
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_create_logical_switch_admin_down(self):
        """Test creating switch with admin_state down"""
        ls = self.get_mocked_resource()
        ls.create(mocks.FAKE_NAME, self._tz_id, [],
                  admin_state=False)
        data = self._create_body(admin_state=nsx_constants.ADMIN_STATE_DOWN)
        test_client.assert_json_call(
            'post', ls,
            'https://1.2.3.4/api/v1/logical-switches',
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_create_logical_switch_vlan(self):
        """Test creating switch with provider:network_type VLAN"""
        ls = self.get_mocked_resource()
        vlan_id = '123'
        ls.create(mocks.FAKE_NAME, self._tz_id, [],
                  vlan_id=vlan_id)
        data = self._create_body(vlan_id=vlan_id)
        test_client.assert_json_call(
            'post', ls,
            'https://1.2.3.4/api/v1/logical-switches',
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_create_logical_switch_trunk(self):
        """Test creating switch with trunk vlan"""
        ls = self.get_mocked_resource()
        trunk_vlan = [10, 20]
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value='2.2.0'):
            ls.create(mocks.FAKE_NAME, self._tz_id, [],
                      trunk_vlan_range=trunk_vlan)
            data = self._create_body(trunk_vlan=trunk_vlan)
            test_client.assert_json_call(
                'post', ls,
                'https://1.2.3.4/api/v1/logical-switches',
                data=jsonutils.dumps(data, sort_keys=True),
                headers=self.default_headers())

    def test_create_logical_switch_trunk_not_supported(self):
        """Test creating switch with trunk vlan without the support"""
        ls = self.get_mocked_resource()
        trunk_vlan = [10, 20]
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value='2.0.0'):
            self.assertRaises(exceptions.InvalidInput,
                              ls.create,
                              mocks.FAKE_NAME, self._tz_id, [],
                              trunk_vlan_range=trunk_vlan)

    def test_create_logical_switch_trunk_with_vlan(self):
        """Test creating switch with trunk vlan and vlan tag"""
        ls = self.get_mocked_resource()
        trunk_vlan = [10, 20]
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value='2.2.0'):
            self.assertRaises(exceptions.InvalidInput,
                              ls.create,
                              mocks.FAKE_NAME, self._tz_id, [],
                              trunk_vlan_range=trunk_vlan,
                              vlan_id='111')

    def test_create_logical_switch_illegal_trunk(self):
        """Test creating switch with illegal trunk vlan"""
        ls = self.get_mocked_resource()
        trunk_vlan = [10]
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value='2.2.0'):
            self.assertRaises(exceptions.InvalidInput,
                              ls.create,
                              mocks.FAKE_NAME, self._tz_id, [],
                              trunk_vlan_range=trunk_vlan)

    def test_create_logical_switch_illegal_name(self):
        """Test creating switch with illegal name that will be escaped"""
        ls = self.get_mocked_resource()
        ls.create(mocks.FAKE_NAME + ';|=,~@', self._tz_id, [])
        data = self._create_body(display_name=mocks.FAKE_NAME + '......')
        test_client.assert_json_call(
            'post', ls,
            'https://1.2.3.4/api/v1/logical-switches',
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_delete_resource(self):
        """Test deleting switch"""
        super(NsxLibSwitchTestCase, self).test_delete_resource(
            extra_params='detach=true&cascade=true')


class NsxLibPortMirrorTestCase(BaseTestResource):

    def setUp(self):
        super(NsxLibPortMirrorTestCase, self).setUp(
            core_resources.NsxLibPortMirror)


class NsxLibBridgeEndpointTestCase(BaseTestResource):

    def setUp(self):
        super(NsxLibBridgeEndpointTestCase, self).setUp(
            core_resources.NsxLibBridgeEndpoint)


class NsxLibEdgeClusterTestCase(BaseTestResource):

    def setUp(self):
        super(NsxLibEdgeClusterTestCase, self).setUp(
            core_resources.NsxLibEdgeCluster)


class NsxLibDhcpProfileTestCase(BaseTestResource):

    def setUp(self):
        super(NsxLibDhcpProfileTestCase, self).setUp(
            core_resources.NsxLibDhcpProfile)


class NsxLibDhcpRelayServiceTestCase(BaseTestResource):

    def setUp(self):
        super(NsxLibDhcpRelayServiceTestCase, self).setUp(
            core_resources.NsxLibDhcpRelayService)

    def test_server_ips(self):
        fake_srv = test_constants.FAKE_RELAY_SERVICE.copy()
        relay_service = self.get_mocked_resource()
        with mock.patch.object(relay_service.client, 'url_get',
                               return_value=fake_srv), \
            mock.patch.object(self.nsxlib.client, 'url_get',
                              return_value=test_constants.FAKE_RELAY_PROFILE):
            server_ips = relay_service.get_server_ips(fake_srv['id'])
            self.assertEqual(1, len(server_ips))
            self.assertEqual(test_constants.FAKE_RELAY_SERVER,
                             server_ips[0])


class NsxLibDhcpRelayProfileTestCase(BaseTestResource):

    def setUp(self):
        super(NsxLibDhcpRelayProfileTestCase, self).setUp(
            core_resources.NsxLibDhcpRelayProfile)

    def test_server_ips(self):
        fake_prf = test_constants.FAKE_RELAY_PROFILE.copy()
        relay_profile = self.get_mocked_resource()
        with mock.patch.object(relay_profile.client, 'url_get',
                               return_value=fake_prf):
            server_ips = relay_profile.get_server_ips(fake_prf['id'])
            self.assertEqual(1, len(server_ips))
            self.assertEqual(test_constants.FAKE_RELAY_SERVER,
                             server_ips[0])


class NsxLibBridgeClusterTestCase(BaseTestResource):

    def setUp(self):
        super(NsxLibBridgeClusterTestCase, self).setUp(
            core_resources.NsxLibBridgeCluster)


class NsxLibIpBlockSubnetTestCase(BaseTestResource):

    def setUp(self):
        super(NsxLibIpBlockSubnetTestCase, self).setUp(
            core_resources.NsxLibIpBlockSubnet)

    def test_list_all(self):
        if not self.resource:
            return
        mocked_resource = self.get_mocked_resource()
        block_id = '7'
        mocked_resource.list(block_id)
        test_client.assert_json_call(
            'get', mocked_resource,
            'https://1.2.3.4/api/v1/%s?block_id=%s' %
            (mocked_resource.uri_segment, block_id),
            headers=self.default_headers())


class NsxLibIpBlockTestCase(BaseTestResource):

    def setUp(self):
        super(NsxLibIpBlockTestCase, self).setUp(
            core_resources.NsxLibIpBlock)


class NsxLibFabricVirtualInterfaceTestCase(BaseTestResource):

    def setUp(self):
        super(NsxLibFabricVirtualInterfaceTestCase, self).setUp(
            core_resources.NsxLibFabricVirtualInterface)

    def test_get_by_owner_vm_id(self):
        mocked_resource = self.get_mocked_resource()
        vm_id = uuidutils.generate_uuid()
        mocked_resource.get_by_owner_vm_id(vm_id)
        test_client.assert_json_call(
            'get', mocked_resource,
            'https://1.2.3.4/api/v1/%s?owner_vm_id=%s' %
            (mocked_resource.uri_segment, vm_id),
            headers=self.default_headers())


class NsxLibFabricVirtualMachineTestCase(BaseTestResource):

    def setUp(self):
        super(NsxLibFabricVirtualMachineTestCase, self).setUp(
            core_resources.NsxLibFabricVirtualMachine)

    def test_get_by_display_name(self):
        mocked_resource = self.get_mocked_resource()
        display_name = 'some-vm-name'
        mocked_resource.get_by_display_name(display_name)
        test_client.assert_json_call(
            'get', mocked_resource,
            'https://1.2.3.4/api/v1/%s?display_name=%s' %
            (mocked_resource.uri_segment, display_name),
            headers=self.default_headers())


class LogicalDhcpServerTestCase(BaseTestResource):

    def setUp(self):
        super(LogicalDhcpServerTestCase, self).setUp(
            resources.LogicalDhcpServer)

    def test_update_empty_dhcp_server(self):
        mocked_resource = self.get_mocked_resource()
        server_uuid = 'server-uuid'
        ip = '1.1.1.1'

        with mock.patch.object(mocked_resource.client, "get", return_value={}):
            mocked_resource.update(server_uuid, server_ip=ip)
        body = {'ipv4_dhcp_server': {'dhcp_server_ip': ip}}

        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/%s/%s' %
            (mocked_resource.uri_segment, server_uuid),
            data=jsonutils.dumps(body, sort_keys=True),
            headers=self.default_headers())

    def test_update_dhcp_server_new_val(self):
        mocked_resource = self.get_mocked_resource()
        server_uuid = 'server-uuid'
        ip = '1.1.1.1'
        domain_name = 'dummy'
        existing_server = {'ipv4_dhcp_server': {'domain_name': domain_name}}

        # add the server ip
        with mock.patch.object(mocked_resource.client, "get",
                               return_value=existing_server):
            mocked_resource.update(server_uuid, server_ip=ip)

        existing_server['ipv4_dhcp_server']['dhcp_server_ip'] = ip
        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/%s/%s' %
            (mocked_resource.uri_segment, server_uuid),
            data=jsonutils.dumps(existing_server, sort_keys=True),
            headers=self.default_headers())

    def test_update_dhcp_server_replace_val(self):
        mocked_resource = self.get_mocked_resource()
        server_uuid = 'server-uuid'
        ip = '1.1.1.1'
        domain_name = 'dummy'
        existing_server = {'ipv4_dhcp_server': {'domain_name': domain_name,
                                                'dhcp_server_ip': ip}}

        # replace the server ip
        new_ip = '2.2.2.2'
        with mock.patch.object(mocked_resource.client, "get",
                               return_value=existing_server):
            mocked_resource.update(server_uuid, server_ip=new_ip)

        existing_server['ipv4_dhcp_server']['dhcp_server_ip'] = new_ip
        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/%s/%s' %
            (mocked_resource.uri_segment, server_uuid),
            data=jsonutils.dumps(existing_server, sort_keys=True),
            headers=self.default_headers())

    def test_create_binding(self):
        mocked_resource = self.get_mocked_resource()
        server_uuid = 'server-uuid'
        mac = 'aa:bb:cc:dd:ee:ff'
        ip = '1.1.1.1'
        host = 'host'
        mocked_resource.create_binding(server_uuid, mac, ip, hostname=host)
        body = {
            'mac_address': mac,
            'ip_address': ip,
            'host_name': host,
        }
        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/%s/%s/static-bindings' %
            (mocked_resource.uri_segment, server_uuid),
            data=jsonutils.dumps(body, sort_keys=True),
            headers=self.default_headers())

    def test_get_binding(self):
        mocked_resource = self.get_mocked_resource()
        server_uuid = 'server-uuid'
        binding_uuid = 'binding-uuid'
        mocked_resource.get_binding(server_uuid, binding_uuid)
        test_client.assert_json_call(
            'get', mocked_resource,
            'https://1.2.3.4/api/v1/%s/%s/static-bindings/%s' %
            (mocked_resource.uri_segment, server_uuid, binding_uuid),
            headers=self.default_headers())

    def test_update_binding(self):
        mocked_resource = self.get_mocked_resource()
        server_uuid = 'server-uuid'
        binding_uuid = 'binding-uuid'
        mac = 'aa:bb:cc:dd:ee:ff'
        new_mac = 'dd:bb:cc:dd:ee:ff'
        ip = '1.1.1.1'
        host = 'host'
        body = {
            'mac_address': mac,
            'ip_address': ip,
            'host_name': host,
        }
        with mock.patch.object(mocked_resource.client, "get",
                               return_value=body):
            mocked_resource.update_binding(server_uuid,
                                           binding_uuid,
                                           mac_address=new_mac)
        body['mac_address'] = new_mac
        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/%s/%s/static-bindings/%s' %
            (mocked_resource.uri_segment, server_uuid, binding_uuid),
            data=jsonutils.dumps(body, sort_keys=True),
            headers=self.default_headers())


class NodeHttpServicePropertiesTestCase(BaseTestResource):

    def setUp(self):
        super(NodeHttpServicePropertiesTestCase, self).setUp(
            resources.NodeHttpServiceProperties)

    def test_get_resource(self):
        self.skipTest("The action is not supported by this resource")

    def test_list_all(self):
        self.skipTest("The action is not supported by this resource")

    def test_delete_resource(self):
        self.skipTest("The action is not supported by this resource")

    def test_get_rate_limit(self):
        mocked_resource = self.get_mocked_resource()
        rate_limit = 40
        body = {'service_properties': {'client_api_rate_limit': rate_limit}}
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value='2.2.0'),\
            mock.patch.object(mocked_resource.client, "url_get",
                              return_value=body):
            result = mocked_resource.get_rate_limit()
            self.assertEqual(rate_limit, result)

    def test_update_rate_limit(self):
        mocked_resource = self.get_mocked_resource()
        old_rate_limit = 40
        new_rate_limit = 50
        body = {'service_properties': {
                'client_api_rate_limit': old_rate_limit}}
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value='2.2.0'),\
            mock.patch.object(mocked_resource.client, "url_get",
                              return_value=body):
            mocked_resource.update_rate_limit(new_rate_limit)
            body['service_properties'][
                'client_api_rate_limit'] = new_rate_limit
            test_client.assert_json_call(
                'put', mocked_resource,
                'https://1.2.3.4/api/v1/node/services/http',
                data=jsonutils.dumps(body, sort_keys=True),
                headers=self.default_headers())
            test_client.assert_json_call(
                'post', mocked_resource,
                'https://1.2.3.4/api/v1/node/services/http?action=restart',
                headers=self.default_headers())


class TestNsxlibClusterNodesConfigTestCase(BaseTestResource):
    def setUp(self):
        super(TestNsxlibClusterNodesConfigTestCase, self).setUp(
            resources.NsxlibClusterNodesConfig)

    def test_delete_resource(self):
        self.skipTest("The action is not supported by this resource")

    def test_get_managers_ips(self):
        mocked_resource = self.get_mocked_resource()
        body = {'results': test_constants.FAKE_CLUSTER_NODES_CONFIG}
        with mock.patch.object(mocked_resource.client, "url_get",
                               return_value=body):
            result = mocked_resource.get_managers_ips()
            self.assertEqual([test_constants.FAKE_MANAGER_IP1,
                              test_constants.FAKE_MANAGER_IP2], result)


class DummyCachedResource(utils.NsxLibApiBase):

    @property
    def uri_segment(self):
        return 'XXX'

    @property
    def resource_type(self):
        return 'xxx'

    @property
    def use_cache_for_get(self):
        return True

    @property
    def cache_timeout(self):
        return 2


class ResourceCache(BaseTestResource):

    def setUp(self):
        super(ResourceCache, self).setUp(DummyCachedResource)

    def test_get_with_cache(self):
        mocked_resource = self.get_mocked_resource()
        fake_uuid = uuidutils.generate_uuid()
        # first call -> goes to the client
        mocked_resource.get(fake_uuid)
        self.assertEqual(1, test_client.mock_calls_count(
            'get', mocked_resource))

        # second call -> goes to cache
        mocked_resource.get(fake_uuid)
        self.assertEqual(1, test_client.mock_calls_count(
            'get', mocked_resource))

        # a different call -> goes to the client
        fake_uuid2 = uuidutils.generate_uuid()
        mocked_resource.get(fake_uuid2)
        self.assertEqual(2, test_client.mock_calls_count(
            'get', mocked_resource))

        # third call -> still goes to cache
        mocked_resource.get(fake_uuid)
        self.assertEqual(2, test_client.mock_calls_count(
            'get', mocked_resource))

        # after timeout -> goes to the client
        eventlet.sleep(2)
        mocked_resource.get(fake_uuid)
        self.assertEqual(3, test_client.mock_calls_count(
            'get', mocked_resource))

        # after delete -> goes to the client
        mocked_resource.delete(fake_uuid)
        mocked_resource.get(fake_uuid)
        self.assertEqual(4, test_client.mock_calls_count(
            'get', mocked_resource))

        # And from cache again
        mocked_resource.get(fake_uuid)
        self.assertEqual(4, test_client.mock_calls_count(
            'get', mocked_resource))

        # Update the entry. The get inside the update is from
        # the client too, because it must be current)
        mocked_resource._update_with_retry(fake_uuid, {})
        self.assertEqual(5, test_client.mock_calls_count(
            'get', mocked_resource))

        # after update -> goes to client
        mocked_resource.get(fake_uuid)
        self.assertEqual(6, test_client.mock_calls_count(
            'get', mocked_resource))
