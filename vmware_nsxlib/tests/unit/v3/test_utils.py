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

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import utils


class TestNsxV3Utils(nsxlib_testcase.NsxClientTestCase):

    def test_build_v3_tags_payload(self):
        result = self.nsxlib.build_v3_tags_payload(
            {'id': 'fake_id',
             'project_id': 'fake_proj_id'},
            resource_type='os-net-id',
            project_name='fake_proj_name')
        expected = [{'scope': 'os-net-id', 'tag': 'fake_id'},
                    {'scope': 'os-project-id', 'tag': 'fake_proj_id'},
                    {'scope': 'os-project-name', 'tag': 'fake_proj_name'},
                    {'scope': 'os-api-version',
                     'tag': nsxlib_testcase.PLUGIN_VER}]
        self.assertEqual(expected, result)

    def test_build_v3_tags_payload_internal(self):
        result = self.nsxlib.build_v3_tags_payload(
            {'id': 'fake_id',
             'project_id': 'fake_proj_id'},
            resource_type='os-net-id',
            project_name=None)
        expected = [{'scope': 'os-net-id', 'tag': 'fake_id'},
                    {'scope': 'os-project-id', 'tag': 'fake_proj_id'},
                    {'scope': 'os-project-name',
                     'tag': nsxlib_testcase.PLUGIN_TAG},
                    {'scope': 'os-api-version',
                     'tag': nsxlib_testcase.PLUGIN_VER}]
        self.assertEqual(expected, result)

    def test_build_v3_tags_payload_invalid_length(self):
        self.assertRaises(exceptions.NsxLibInvalidInput,
                          self.nsxlib.build_v3_tags_payload,
                          {'id': 'fake_id',
                           'project_id': 'fake_proj_id'},
                          resource_type='os-longer-maldini-rocks-id',
                          project_name='fake')

    def test_build_v3_api_version_tag(self):
        result = self.nsxlib.build_v3_api_version_tag()
        expected = [{'scope': nsxlib_testcase.PLUGIN_SCOPE,
                     'tag': nsxlib_testcase.PLUGIN_TAG},
                    {'scope': 'os-api-version',
                     'tag': nsxlib_testcase.PLUGIN_VER}]
        self.assertEqual(expected, result)

    def test_is_internal_resource(self):
        project_tag = self.nsxlib.build_v3_tags_payload(
            {'id': 'fake_id',
             'project_id': 'fake_proj_id'},
            resource_type='os-net-id',
            project_name=None)
        internal_tag = self.nsxlib.build_v3_api_version_tag()

        expect_false = self.nsxlib.is_internal_resource({'tags': project_tag})
        self.assertFalse(expect_false)

        expect_true = self.nsxlib.is_internal_resource({'tags': internal_tag})
        self.assertTrue(expect_true)

    def test_get_name_and_uuid(self):
        uuid = 'afc40f8a-4967-477e-a17a-9d560d1786c7'
        suffix = '_afc40...786c7'
        expected = 'maldini%s' % suffix
        short_name = utils.get_name_and_uuid('maldini', uuid)
        self.assertEqual(expected, short_name)

        name = 'X' * 255
        expected = '%s%s' % ('X' * (80 - len(suffix)), suffix)
        short_name = utils.get_name_and_uuid(name, uuid)
        self.assertEqual(expected, short_name)

    def test_build_v3_tags_max_length_payload(self):
        result = self.nsxlib.build_v3_tags_payload(
            {'id': 'X' * 255,
             'project_id': 'X' * 255},
            resource_type='os-net-id',
            project_name='X' * 255)
        expected = [{'scope': 'os-net-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-name', 'tag': 'X' * 40},
                    {'scope': 'os-api-version',
                     'tag': nsxlib_testcase.PLUGIN_VER}]
        self.assertEqual(expected, result)

    def test_add_v3_tag(self):
        result = utils.add_v3_tag([], 'fake-scope', 'fake-tag')
        expected = [{'scope': 'fake-scope', 'tag': 'fake-tag'}]
        self.assertEqual(expected, result)

    def test_add_v3_tag_max_length_payload(self):
        result = utils.add_v3_tag([], 'fake-scope', 'X' * 255)
        expected = [{'scope': 'fake-scope', 'tag': 'X' * 40}]
        self.assertEqual(expected, result)

    def test_add_v3_tag_invalid_scope_length(self):
        self.assertRaises(exceptions.NsxLibInvalidInput,
                          utils.add_v3_tag,
                          [],
                          'fake-scope-name-is-far-too-long',
                          'fake-tag')

    def test_update_v3_tags_addition(self):
        tags = [{'scope': 'os-net-id', 'tag': 'X' * 40},
                {'scope': 'os-project-id', 'tag': 'Y' * 40},
                {'scope': 'os-project-name', 'tag': 'Z' * 40},
                {'scope': 'os-api-version',
                 'tag': nsxlib_testcase.PLUGIN_VER}]
        resources = [{'scope': 'os-instance-uuid',
                      'tag': 'A' * 40}]
        tags = utils.update_v3_tags(tags, resources)
        expected = [{'scope': 'os-net-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-id', 'tag': 'Y' * 40},
                    {'scope': 'os-project-name', 'tag': 'Z' * 40},
                    {'scope': 'os-api-version',
                     'tag': nsxlib_testcase.PLUGIN_VER},
                    {'scope': 'os-instance-uuid',
                     'tag': 'A' * 40}]
        self.assertEqual(sorted(expected, key=lambda x: x.get('tag')),
                         sorted(tags, key=lambda x: x.get('tag')))

    def test_update_v3_tags_removal(self):
        tags = [{'scope': 'os-net-id', 'tag': 'X' * 40},
                {'scope': 'os-project-id', 'tag': 'Y' * 40},
                {'scope': 'os-project-name', 'tag': 'Z' * 40},
                {'scope': 'os-api-version',
                 'tag': nsxlib_testcase.PLUGIN_VER}]
        resources = [{'scope': 'os-net-id',
                      'tag': ''}]
        tags = utils.update_v3_tags(tags, resources)
        expected = [{'scope': 'os-project-id', 'tag': 'Y' * 40},
                    {'scope': 'os-project-name', 'tag': 'Z' * 40},
                    {'scope': 'os-api-version',
                     'tag': nsxlib_testcase.PLUGIN_VER}]
        self.assertEqual(sorted(expected, key=lambda x: x.get('tag')),
                         sorted(tags, key=lambda x: x.get('tag')))

    def test_update_v3_tags_update(self):
        tags = [{'scope': 'os-net-id', 'tag': 'X' * 40},
                {'scope': 'os-project-id', 'tag': 'Y' * 40},
                {'scope': 'os-project-name', 'tag': 'Z' * 40},
                {'scope': 'os-api-version',
                 'tag': nsxlib_testcase.PLUGIN_VER}]
        resources = [{'scope': 'os-project-id',
                      'tag': 'A' * 40}]
        tags = utils.update_v3_tags(tags, resources)
        expected = [{'scope': 'os-net-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-id', 'tag': 'A' * 40},
                    {'scope': 'os-project-name', 'tag': 'Z' * 40},
                    {'scope': 'os-api-version',
                     'tag': nsxlib_testcase.PLUGIN_VER}]
        self.assertEqual(sorted(expected, key=lambda x: x.get('tag')),
                         sorted(tags, key=lambda x: x.get('tag')))

    def test_update_v3_tags_repetitive_scopes(self):
        tags = [{'scope': 'os-net-id', 'tag': 'X' * 40},
                {'scope': 'os-project-id', 'tag': 'Y' * 40},
                {'scope': 'os-project-name', 'tag': 'Z' * 40},
                {'scope': 'os-security-group', 'tag': 'SG1'},
                {'scope': 'os-security-group', 'tag': 'SG2'}]
        tags_update = [{'scope': 'os-security-group', 'tag': 'SG3'},
                       {'scope': 'os-security-group', 'tag': 'SG4'}]
        tags = utils.update_v3_tags(tags, tags_update)
        expected = [{'scope': 'os-net-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-id', 'tag': 'Y' * 40},
                    {'scope': 'os-project-name', 'tag': 'Z' * 40},
                    {'scope': 'os-security-group', 'tag': 'SG3'},
                    {'scope': 'os-security-group', 'tag': 'SG4'}]
        self.assertEqual(sorted(expected, key=lambda x: x.get('tag')),
                         sorted(tags, key=lambda x: x.get('tag')))

    def test_update_v3_tags_repetitive_scopes_remove(self):
        tags = [{'scope': 'os-net-id', 'tag': 'X' * 40},
                {'scope': 'os-project-id', 'tag': 'Y' * 40},
                {'scope': 'os-project-name', 'tag': 'Z' * 40},
                {'scope': 'os-security-group', 'tag': 'SG1'},
                {'scope': 'os-security-group', 'tag': 'SG2'}]
        tags_update = [{'scope': 'os-security-group', 'tag': None}]
        tags = utils.update_v3_tags(tags, tags_update)
        expected = [{'scope': 'os-net-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-id', 'tag': 'Y' * 40},
                    {'scope': 'os-project-name', 'tag': 'Z' * 40}]
        self.assertEqual(sorted(expected, key=lambda x: x.get('tag')),
                         sorted(tags, key=lambda x: x.get('tag')))

    def test_build_extra_args_positive(self):
        extra_args = ['fall_count', 'interval', 'monitor_port',
                      'request_body', 'request_method', 'request_url',
                      'request_version', 'response_body',
                      'response_status', 'rise_count', 'timeout']
        body = {'display_name': 'httpmonitor1',
                'description': 'my http monitor'}
        expected = {'display_name': 'httpmonitor1',
                    'description': 'my http monitor',
                    'interval': 5,
                    'rise_count': 3,
                    'fall_count': 3}
        resp = utils.build_extra_args(body, extra_args, interval=5,
                                      rise_count=3, fall_count=3)
        self.assertEqual(resp, expected)

    def test_build_extra_args_negative(self):
        extra_args = ['cookie_domain', 'cookie_fallback', 'cookie_garble',
                      'cookie_mode', 'cookie_name', 'cookie_path',
                      'cookie_time']
        body = {'display_name': 'persistenceprofile1',
                'description': 'my persistence profile',
                'resource_type': 'LoadBalancerCookiePersistenceProfile'}
        expected = {'display_name': 'persistenceprofile1',
                    'description': 'my persistence profile',
                    'resource_type': 'LoadBalancerCookiePersistenceProfile',
                    'cookie_mode': 'INSERT',
                    'cookie_name': 'ABC',
                    'cookie_fallback': True}
        resp = utils.build_extra_args(body, extra_args, cookie_mode='INSERT',
                                      cookie_name='ABC', cookie_fallback=True,
                                      bogus='bogus')
        self.assertEqual(resp, expected)

    def test_retry(self):
        max_retries = 5
        total_count = {'val': 0}

        @utils.retry_upon_exception(exceptions.NsxLibInvalidInput,
                                    max_attempts=max_retries)
        def func_to_fail(x):
            total_count['val'] = total_count['val'] + 1
            raise exceptions.NsxLibInvalidInput(error_message='foo')

        self.assertRaises(exceptions.NsxLibInvalidInput, func_to_fail, 99)
        self.assertEqual(max_retries, total_count['val'])

    def test_retry_random(self):
        max_retries = 5
        total_count = {'val': 0}

        @utils.retry_random_upon_exception(exceptions.NsxLibInvalidInput,
                                           max_attempts=max_retries)
        def func_to_fail(x):
            total_count['val'] = total_count['val'] + 1
            raise exceptions.NsxLibInvalidInput(error_message='foo')

        self.assertRaises(exceptions.NsxLibInvalidInput, func_to_fail, 99)
        self.assertEqual(max_retries, total_count['val'])

    @mock.patch.object(utils, '_update_max_nsgroups_criteria_tags')
    @mock.patch.object(utils, '_update_max_tags')
    @mock.patch.object(utils, '_update_tag_length')
    @mock.patch.object(utils, '_update_resource_length')
    def test_update_limits(self, _update_resource_length,
                           _update_tag_length, _update_max_tags,
                           _update_msx_nsg_criteria):
        limits = utils.TagLimits(1, 2, 3)
        utils.update_tag_limits(limits)
        _update_resource_length.assert_called_with(1)
        _update_tag_length.assert_called_with(2)
        _update_max_tags.assert_called_with(3)
        _update_msx_nsg_criteria.assert_called_with(3)


class NsxFeaturesTestCase(nsxlib_testcase.NsxLibTestCase):

    def test_v2_features(self, current_version='2.0.0'):
        self.nsxlib.nsx_version = current_version
        self.assertTrue(self.nsxlib.feature_supported(
            nsx_constants.FEATURE_ROUTER_FIREWALL))
        self.assertTrue(self.nsxlib.feature_supported(
            nsx_constants.FEATURE_EXCLUDE_PORT_BY_TAG))

    def test_v2_features_plus(self):
        self.test_v2_features(current_version='2.0.1')

    def test_v2_features_minus(self):
        self.nsxlib.nsx_version = '1.9.9'
        self.assertFalse(self.nsxlib.feature_supported(
            nsx_constants.FEATURE_ROUTER_FIREWALL))
        self.assertFalse(self.nsxlib.feature_supported(
            nsx_constants.FEATURE_EXCLUDE_PORT_BY_TAG))
        self.assertTrue(self.nsxlib.feature_supported(
            nsx_constants.FEATURE_MAC_LEARNING))
