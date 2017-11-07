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

# TODO(asarfaty) Do those objects have tags??


class IkeVersionTypes(object):
    """Supported IKE versions (NSX default is V2)"""
    IKE_VERSION_V1 = "IKE_V1"
    IKE_VERSION_V2 = "IKE_V2"
    IKE_VERSION_Flex = "IKE_FLEX"


class EncryptionAlgorithmTypes(object):
    """Supported encryption algorithms (NSX default is GCM)"""
    ENCRYPTION_ALGORITHM_128 = "AES128"
    ENCRYPTION_ALGORITHM_256 = "AES256"
    ENCRYPTION_ALGORITHM_GCM = "AESGCM"


class DigestAlgorithmTypes(object):
    """Supported digest (auth) algorithms (NSX default is None)"""
    DIGEST_ALGORITHM_SHA1 = "SHA1"
    DIGEST_ALGORITHM_SHA256 = "SHA256"
    DIGEST_ALGORITHM_GMAC_128 = "GMAC_128"
    DIGEST_ALGORITHM_GMAC_256 = "GMAC_256"


class DHGroupTypes(object):
    """Supported DH groups for Perfect Forward Secrecy"""
    DH_GROUP_2 = "GROUP2"
    DH_GROUP_5 = "GROUP5"
    DH_GROUP_14 = "GROUP14"
    DH_GROUP_15 = "GROUP15"
    DH_GROUP_16 = "GROUP16"


class EncapsulationModeTypes(object):
    """Supported encapsulation modes for ipsec tunnel profile"""
    ENCAPSULATION_MODE_TUNNEL = "TUNNEL_MODE"


class TransformProtocolTypes(object):
    """Supported transform protocols for ipsec tunnel profile"""
    TRANSFORM_PROTOCOL_ESP = "ESP"


class AuthenticationModeTypes(object):
    """Supported authentication modes for ipsec peer endpoint (default PSK)"""
    AUTH_MODE_PSK = "PSK"
    AUTH_MODE_CERT = "CERTIFICATE"


class DpdProfileActionTypes(object):
    """Supported DPD profile actions"""
    DPD_PROFILE_ACTION_HOLD = "HOLD"


class DpdProfileTimeoutLimits(object):
    """Supported DPD timeout range"""
    DPD_TIMEOUT_MIN = 10
    DPD_TIMEOUT_MAX = 3600


class SALifetimeLimits(object):
    """Limits to the allowed SA lifetime in seconds"""
    SA_LIFETIME_MIN = 90
    SA_LIFETIME_MAX = 365 * 24 * 3600


class ConnectionInitiationModeTypes(object):
    """Supported connection initiation mode type"""
    INITIATION_MODE_INITIATOR = "INITIATOR"
    INITIATION_MODE_RESPOND_ONLY = "RESPOND_ONLY"


class IkeLogLevelTypes(object):
    """Supported service IKE log levels (default ERROR)"""
    LOG_LEVEL_DEBUG = "DEBUG"
    LOG_LEVEL_INFO = "INFO"
    LOG_LEVEL_WARN = "WARN"
    LOG_LEVEL_ERROR = "ERROR"


class IkeProfile(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        return 'IPSecVPNIKEProfile'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'ike-profiles'

    def create(self, name, description=None,
               encryption_algorithm=None,
               digest_algorithm=None,
               ike_version=None,
               pfs=None,
               dh_group=None,
               sa_life_time=None):

        # mandatory parameters
        body = {'display_name': name}
        # optional parameters
        if description:
            body['description'] = description
        if encryption_algorithm:
            body['encryption_algorithms'] = [encryption_algorithm]
        if digest_algorithm:
            body['digest_algorithms'] = [digest_algorithm]
        if ike_version:
            body['ike_version'] = ike_version
        if sa_life_time:
            body['sa_life_time'] = {'unit': 'SEC', 'value': sa_life_time}
        if dh_group:
            body['dh_groups'] = [dh_group]
        # Boolean parameters
        if pfs is not None:
            body['enable_perfect_forward_secrecy'] = pfs
        LOG.debug("Create ike profile %s", body)
        return self.client.create(self.get_path(), body=body)


class IPSecTunnelProfile(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        return 'IPSecVPNTunnelProfile'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'tunnel-profiles'

    def create(self, name, description=None,
               encryption_algorithm=None,
               digest_algorithm=None,
               pfs=None,
               dh_group=None,
               sa_life_time=None):

        # mandatory parameters
        body = {'display_name': name}
        # optional parameters
        if description:
            body['description'] = description
        if encryption_algorithm:
            body['encryption_algorithms'] = [encryption_algorithm]
        if digest_algorithm:
            body['digest_algorithms'] = [digest_algorithm]
        if sa_life_time:
            body['sa_life_time'] = {'unit': 'SEC', 'value': sa_life_time}
        if dh_group:
            body['dh_groups'] = [dh_group]
        # Boolean parameters
        if pfs is not None:
            body['enable_perfect_forward_secrecy'] = pfs
        LOG.debug("Create ipsec profile %s", body)
        return self.client.create(self.get_path(), body=body)


class IPSecDpdProfile(utils.NsxLibApiBase):
    @property
    def resource_type(self):
        return 'IPSecVPNDPDProfile'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'dpd-profiles'

    def create(self, name, description=None,
               enabled=None,
               timeout=None):

        # mandatory parameters
        body = {'display_name': name}
        # optional parameters
        if description:
            body['description'] = description
        if timeout:
            body['timeout'] = timeout
        # Boolean parameters
        if enabled is not None:
            body['enabled'] = enabled
        LOG.debug("Create DPD profile %s", body)
        return self.client.create(self.get_path(), body=body)

    def update(self, profile_id, enabled=None,
               timeout=None):

        body = self.get(profile_id)
        if timeout:
            body['timeout'] = timeout
        if enabled is not None:
            body['enabled'] = enabled
        return self.client.update(self.get_path(profile_id), body=body)


class IPSecPeerEndpoint(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        return 'IPSecVPNPeerEndpoint'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'peer-endpoints'

    def create(self, name, peer_address, peer_id,
               description=None,
               authentication_mode=None,
               dpd_profile_id=None,
               ike_profile_id=None,
               ipsec_tunnel_profile_id=None,
               connection_initiation_mode=None,
               psk=None):

        # mandatory parameters
        body = {'display_name': name,
                'peer_address': peer_address,
                'peer_id': peer_id}
        # optional parameters
        if description:
            body['description'] = description
        if authentication_mode:
            body['authentication_mode'] = authentication_mode
        if dpd_profile_id:
            body['dpd_profile_id'] = dpd_profile_id
        if ike_profile_id:
            body['ike_profile_id'] = ike_profile_id
        if ipsec_tunnel_profile_id:
            body['ipsec_tunnel_profile_id'] = ipsec_tunnel_profile_id
        if psk:
            body['psk'] = psk
        if connection_initiation_mode:
            body['connection_initiation_mode'] = connection_initiation_mode
        LOG.debug("Create peer endpoint %s", body)
        return self.client.create(self.get_path(), body=body)

    def update(self, uuid, name=None, description=None, peer_address=None,
               peer_id=None, connection_initiation_mode=None, psk=None):
        body = self.get(uuid)
        if description:
            body['description'] = description
        if name:
            body['display_name'] = name
        if psk:
            body['psk'] = psk
        if connection_initiation_mode:
            body['connection_initiation_mode'] = connection_initiation_mode
        if peer_address:
            body['peer_address'] = peer_address
        if peer_id:
            body['peer_id'] = peer_id
        return self.client.update(self.get_path(uuid), body=body)


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

    def create(self, name, logical_router_id,
               enabled=True, ike_log_level="ERROR"):

        # mandatory parameters
        body = {'display_name': name,
                'logical_router_id': {'target_id': logical_router_id}}
        # optional parameters
        if ike_log_level:
            body['ike_log_level'] = ike_log_level
        if enabled is not None:
            body['enabled'] = enabled
        return self.client.create(self.get_path(), body=body)


class VpnIpSec(object):
    """This is the class that have all vpn ipsec resource clients"""

    def __init__(self, client, nsxlib_config, nsxlib=None):
        self.ike_profile = IkeProfile(client, nsxlib_config, nsxlib=nsxlib)
        self.tunnel_profile = IPSecTunnelProfile(client, nsxlib_config,
                                                 nsxlib=nsxlib)
        self.dpd_profile = IPSecDpdProfile(client, nsxlib_config,
                                           nsxlib=nsxlib)
        self.peer_endpoint = IPSecPeerEndpoint(client, nsxlib_config,
                                               nsxlib=nsxlib)
        self.local_endpoint = LocalEndpoint(client, nsxlib_config,
                                            nsxlib=nsxlib)
        self.session = Session(client, nsxlib_config, nsxlib=nsxlib)
        self.service = Service(client, nsxlib_config, nsxlib=nsxlib)
