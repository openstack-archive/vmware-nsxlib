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

from oslo_log import log as logging

from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)
VPN_IPSEC_PATH = 'vpn/ipsec/'


class IkeVersionTypes(object):
    # Supported IKE versions (NSX default is V2)
    IKE_VERSION_V1 = "IKE-V1"
    IKE_VERSION_V2 = "IKE-V2"
    IKE_VERSION_Flex = "IKE-Flex"


class IkeEncryptionAlgorithmTypes(object):
    # Supported encryption algorithms (NSX default is GCM)
    ENCRYPTION_ALGORITHM_128 = "AES128"
    ENCRYPTION_ALGORITHM_256 = "AES256"
    ENCRYPTION_ALGORITHM_GCM = "AESGCM"


class IkeDigestAlgorithmTypes(object):
    # Supported digest (auth) algorithms (NSX default is None)
    DIGEST_ALGORITHM_SHA1 = "sha1"
    DIGEST_ALGORITHM_SHA2 = "sha2"


class IkeDHGroupTypes(object):
    # Supported DH groups for Perfect Forward Secrecy
    DH_GROUP_2 = "GROUP-2"
    DH_GROUP_5 = "GROUP-5"
    DH_GROUP_14 = "GROUP-14"
    DH_GROUP_15 = "GROUP-15"
    DH_GROUP_16 = "GROUP-16"


class IkeProfile(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        # TODO(asarfaty) wait for backend
        return 'IkeProfile'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'ike-profiles'

    def create(self, name, description=None,
               encription_algorithm=None,
               digest_algorithm=None,
               ike_version=None,
               pfs=None,
               dh_group=None,
               sa_life_time=None):

        body = {'display_name': name,
                'encription_algorithm': encription_algorithm,
                'ike_version': ike_version}
        if description:
            body['description'] = description
        if encription_algorithm:
            body['encription_algorithm'] = encription_algorithm
        if digest_algorithm:
            body['digest_algorithm'] = digest_algorithm
        if ike_version:
            body['ike_version'] = ike_version
        if sa_life_time:
            body['sa_life_time'] = sa_life_time
        if pfs is not None:
            body['enable_prefect_forward_secrecy'] = pfs
        if dh_group:
            # TODO(asarfaty): string or list?
            body['dh_group'] = dh_group
        return self.client.create(self.get_path(), body=body)


class TunnelProfile(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        # TODO(asarfaty) wait for backend
        return 'TunnelProfile'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'tunnel-profiles'


class PeerEndpoint(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        # TODO(asarfaty) wait for backend
        return 'PeerEndpoint'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'peer-endpoints'


class LocalEndpoint(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        # TODO(asarfaty) wait for backend
        return 'LocalEndpoint'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'local-endpoints'


class Session(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        # TODO(asarfaty) wait for backend
        return 'Session'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'sessions'


class Service(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        # TODO(asarfaty) wait for backend
        return 'Service'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'services'


class VpnIpSec(object):
    """This is the class that have all vpn ipsec resource clients"""

    def __init__(self, client, nsxlib_config, nsxlib=None):
        self.ike_profile = IkeProfile(client, nsxlib_config, nsxlib=nsxlib)
        self.tunnel_profile = TunnelProfile(client, nsxlib_config,
                                            nsxlib=nsxlib)
        self.peer_profile = PeerEndpoint(client, nsxlib_config, nsxlib=nsxlib)
        self.local_profile = LocalEndpoint(client, nsxlib_config,
                                           nsxlib=nsxlib)
        self.session = Session(client, nsxlib_config, nsxlib=nsxlib)
        self.service = Service(client, nsxlib_config, nsxlib=nsxlib)
