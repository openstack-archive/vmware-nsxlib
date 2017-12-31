# Copyright (c) 2015 VMware, Inc.
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
#
import copy

import mock
from oslo_log import log

from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.tests.unit.v3 import test_constants
from vmware_nsxlib.v3 import nsx_constants

LOG = log.getLogger(__name__)


class NsxLibQosTestCase(nsxlib_testcase.NsxClientTestCase):

    def _body(self, qos_marking=None, dscp=None,
              description=test_constants.FAKE_NAME):
        body = {
            "resource_type": "QosSwitchingProfile",
            "tags": []
        }
        if qos_marking:
            body = self.nsxlib.qos_switching_profile._update_dscp_in_args(
                body, qos_marking, dscp)

        body["display_name"] = test_constants.FAKE_NAME
        body["description"] = description

        return body

    def _body_with_shaping(self, shaping_enabled=False,
                           burst_size=None,
                           peak_bandwidth=None,
                           average_bandwidth=None,
                           description=test_constants.FAKE_NAME,
                           qos_marking=None,
                           dscp=0, direction=nsx_constants.EGRESS,
                           body=None):
        if body is None:
            body = copy.deepcopy(test_constants.FAKE_QOS_PROFILE)
        body["display_name"] = test_constants.FAKE_NAME
        body["description"] = description

        resource_type = (nsx_constants.EGRESS_SHAPING
                         if direction == nsx_constants.EGRESS
                         else nsx_constants.INGRESS_SHAPING)
        for shaper in body["shaper_configuration"]:
            if shaper["resource_type"] == resource_type:
                shaper["enabled"] = shaping_enabled
                if burst_size:
                    shaper["burst_size_bytes"] = burst_size
                if peak_bandwidth:
                    shaper["peak_bandwidth_mbps"] = peak_bandwidth
                if average_bandwidth:
                    shaper["average_bandwidth_mbps"] = average_bandwidth
                break

        if qos_marking:
            body = self.nsxlib.qos_switching_profile._update_dscp_in_args(
                body, qos_marking, dscp)

        return body

    def test_create_qos_switching_profile(self):
        """Test creating a qos-switching profile

        returns the correct response
        """
        with mock.patch.object(self.nsxlib.client, 'create') as create:
            self.nsxlib.qos_switching_profile.create(
                tags=[],
                name=test_constants.FAKE_NAME,
                description=test_constants.FAKE_NAME)
            create.assert_called_with(
                'switching-profiles', self._body())

    def test_update_qos_switching_profile(self):
        """Test updating a qos-switching profile

        returns the correct response
        """
        original_profile = self._body()
        new_description = "Test"
        with mock.patch.object(self.nsxlib.client, 'get',
                               return_value=original_profile):
            with mock.patch.object(self.nsxlib.client, 'update') as update:

                # update the description of the profile
                self.nsxlib.qos_switching_profile.update(
                    test_constants.FAKE_QOS_PROFILE['id'],
                    tags=[],
                    description=new_description)
                update.assert_called_with(
                    'switching-profiles/%s'
                    % test_constants.FAKE_QOS_PROFILE['id'],
                    self._body(description=new_description),
                    headers=None)

    def _enable_qos_switching_profile_shaping(
        self, direction=nsx_constants.EGRESS, new_burst_size=100):
        """Test updating a qos-switching profile

        returns the correct response
        """
        original_burst = 10
        original_profile = self._body_with_shaping(direction=direction,
                                                   burst_size=original_burst)
        peak_bandwidth = 200
        average_bandwidth = 300
        qos_marking = "untrusted"
        dscp = 10

        with mock.patch.object(self.nsxlib.client, 'get',
                               return_value=original_profile):
            with mock.patch.object(self.nsxlib.client, 'update') as update:
                # update the bw shaping of the profile
                self.nsxlib.qos_switching_profile.update_shaping(
                    test_constants.FAKE_QOS_PROFILE['id'],
                    shaping_enabled=True,
                    burst_size=new_burst_size,
                    peak_bandwidth=peak_bandwidth,
                    average_bandwidth=average_bandwidth,
                    qos_marking=qos_marking,
                    dscp=dscp, direction=direction)

                actual_body = copy.deepcopy(update.call_args[0][1])
                actual_path = update.call_args[0][0]
                expected_path = ('switching-profiles/%s' %
                                 test_constants.FAKE_QOS_PROFILE['id'])
                expected_burst = (new_burst_size if new_burst_size is not None
                                  else original_burst)
                expected_body = self._body_with_shaping(
                    shaping_enabled=True,
                    burst_size=expected_burst,
                    peak_bandwidth=peak_bandwidth,
                    average_bandwidth=average_bandwidth,
                    qos_marking="untrusted", dscp=10,
                    direction=direction)
                self.assertEqual(expected_path, actual_path)
                self.assertEqual(expected_body, actual_body)

    def test_enable_qos_switching_profile_egress_shaping(self):
        self._enable_qos_switching_profile_shaping(
            direction=nsx_constants.EGRESS)

    def test_enable_qos_switching_profile_ingress_shaping(self):
        self._enable_qos_switching_profile_shaping(
            direction=nsx_constants.INGRESS)

    def test_update_qos_switching_profile_with_burst_size(self):
        self._enable_qos_switching_profile_shaping(
            direction=nsx_constants.EGRESS, new_burst_size=101)

    def test_update_qos_switching_profile_without_burst_size(self):
        self._enable_qos_switching_profile_shaping(
            direction=nsx_constants.EGRESS, new_burst_size=None)

    def test_update_qos_switching_profile_zero_burst_size(self):
        self._enable_qos_switching_profile_shaping(
            direction=nsx_constants.EGRESS, new_burst_size=0)

    def _disable_qos_switching_profile_shaping(
        self, direction=nsx_constants.EGRESS):
        """Test updating a qos-switching profile.

        Returns the correct response
        """
        burst_size = 100
        peak_bandwidth = 200
        average_bandwidth = 300
        original_profile = self._body_with_shaping(
            shaping_enabled=True,
            burst_size=burst_size,
            peak_bandwidth=peak_bandwidth,
            average_bandwidth=average_bandwidth,
            qos_marking="untrusted",
            dscp=10, direction=direction)

        with mock.patch.object(self.nsxlib.client, 'get',
                               return_value=original_profile):
            with mock.patch.object(self.nsxlib.client, 'update') as update:
                # update the bw shaping of the profile
                self.nsxlib.qos_switching_profile.update_shaping(
                    test_constants.FAKE_QOS_PROFILE['id'],
                    shaping_enabled=False, qos_marking="trusted",
                    direction=direction)

                actual_body = copy.deepcopy(update.call_args[0][1])
                actual_path = update.call_args[0][0]
                expected_path = ('switching-profiles/%s' %
                                 test_constants.FAKE_QOS_PROFILE['id'])
                expected_body = self._body_with_shaping(qos_marking="trusted",
                                                        direction=direction)
                self.assertEqual(expected_path, actual_path)
                self.assertEqual(expected_body, actual_body)

    def test_disable_qos_switching_profile_egress_shaping(self):
        self._disable_qos_switching_profile_shaping(
            direction=nsx_constants.EGRESS)

    def test_disable_qos_switching_profile_ingress_shaping(self):
        self._disable_qos_switching_profile_shaping(
            direction=nsx_constants.INGRESS)

    def test_delete_qos_switching_profile(self):
        """Test deleting qos-switching-profile"""
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            self.nsxlib.qos_switching_profile.delete(
                test_constants.FAKE_QOS_PROFILE['id'])
            delete.assert_called_with(
                'switching-profiles/%s'
                % test_constants.FAKE_QOS_PROFILE['id'])

    def test_qos_switching_profile_set_shaping(self):
        """Test updating a qos-switching profile

        returns the correct response
        """
        egress_peak_bandwidth = 200
        egress_average_bandwidth = 300
        egress_burst_size = 500
        ingress_peak_bandwidth = 100
        ingress_average_bandwidth = 400
        ingress_burst_size = 600
        qos_marking = "untrusted"
        dscp = 10

        original_profile = self._body_with_shaping()
        with mock.patch.object(self.nsxlib.client, 'get',
                               return_value=original_profile):
            with mock.patch.object(self.nsxlib.client, 'update') as update:
                # update the bw shaping of the profile
                self.nsxlib.qos_switching_profile.set_profile_shaping(
                    test_constants.FAKE_QOS_PROFILE['id'],
                    ingress_bw_enabled=True,
                    ingress_burst_size=ingress_burst_size,
                    ingress_peak_bandwidth=ingress_peak_bandwidth,
                    ingress_average_bandwidth=ingress_average_bandwidth,
                    egress_bw_enabled=True,
                    egress_burst_size=egress_burst_size,
                    egress_peak_bandwidth=egress_peak_bandwidth,
                    egress_average_bandwidth=egress_average_bandwidth,
                    qos_marking=qos_marking,
                    dscp=dscp)

                actual_body = copy.deepcopy(update.call_args[0][1])
                actual_path = update.call_args[0][0]
                expected_path = ('switching-profiles/%s' %
                                 test_constants.FAKE_QOS_PROFILE['id'])
                expected_body = self._body_with_shaping(
                    shaping_enabled=True,
                    burst_size=egress_burst_size,
                    peak_bandwidth=egress_peak_bandwidth,
                    average_bandwidth=egress_average_bandwidth,
                    qos_marking="untrusted", dscp=10,
                    direction=nsx_constants.EGRESS)
                # Add the other direction to the body
                expected_body = self._body_with_shaping(
                    shaping_enabled=True,
                    burst_size=ingress_burst_size,
                    peak_bandwidth=ingress_peak_bandwidth,
                    average_bandwidth=ingress_average_bandwidth,
                    direction=nsx_constants.INGRESS,
                    body=expected_body)

                self.assertEqual(expected_path, actual_path)
                self.assertEqual(expected_body, actual_body)
