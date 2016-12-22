# Copyright 2016 VMware, Inc.
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

import datetime
from OpenSSL import crypto
from time import time

from neutron_lib import exceptions
from oslo_log import log

from vmware_nsxlib._i18n import _, _LE
from vmware_nsxlib.v3 import exceptions as nsxlib_exceptions

LOG = log.getLogger(__name__)

NSX_ERROR_IDENTITY_EXISTS = 2027


def validate_cert_params(key_size, valid_for_days,
                         signature_alg, subject):
    """Validate parameters for certificate"""

    expected_key_sizes = (2048, 4096)
    if key_size not in expected_key_sizes:
        raise exceptions.InvalidInput(
            error_message=_('Invalid key size %(value)d'
                          '(must be one of %(list)s)') %
                          {'value': key_size,
                          'list': expected_key_sizes})

    expected_signature_algs = ('sha224', 'sha256')
    if signature_alg not in expected_signature_algs:
        raise exceptions.InvalidInput(
            error_message=_('Invalid signature algorithm %(value)s'
                          '(must be one of %(list)s)') %
                          {'value': signature_alg,
                          'list': expected_signature_algs})


def generate_self_signed_cert_pair(key_size, valid_for_days,
                                   signature_alg, subject):
    """Generate self signed certificate and key pair"""

    validate_cert_params(key_size, valid_for_days,
                         signature_alg, subject)

    # generate key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, key_size)

    # generate certificate
    cert = crypto.X509()
    cert.get_subject().C = subject.get('country', 'US')
    cert.get_subject().ST = subject.get('state', 'California')
    cert.get_subject().O = subject.get('organization', 'MyOrg')
    cert.get_subject().OU = subject.get('unit', 'MyUnit')
    cert.get_subject().CN = subject.get('hostname', 'myorg.com')
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(valid_for_days * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.set_serial_number(int(time()))
    cert.sign(key, signature_alg)

    return cert, key


class ClientCertificateManager(object):
    """Manage Client Certificate for backend authentication

    There should be single client certificate associated
    with certain principal identity. Certificate and PK storage
    is pluggable. Storage API (similar to neutron-lbaas barbican API):
        store_cert(project_id, certificate, private_key)
        get_cert(project_id)
        delete_cert(project_id)
    """

    def __init__(self, identity, nsx_trust_management, storage_driver):
        self._cert = None
        self._key = None
        self._storage_driver = storage_driver
        self._identity = identity

        self._nsx_trust_management = nsx_trust_management

        self._load_cert_and_key()

    def generate(self, subject, key_size=2048, valid_for_days=365,
            signature_alg='sha256'):
        """Generate new certificate and register it in the system

        Generate certificate with RSA key based on arguments provided,
        register and associate it to principal identity on backend,
        and store it in storage. If certificate already exists, fail.
        """
        self._validate_empty()

        self._cert, self._key = generate_self_signed_cert_pair(key_size,
                                                               valid_for_days,
                                                               signature_alg,
                                                               subject)

        self._register_cert()
        self._store_cert_and_key()

        LOG.debug("Client certificate generated successfully")

    def delete(self):
        """Delete existing certificate from storage and backend"""

        if not self.exists():
            return

        ok = True
        try:
            # delete certificate and principal identity from backend
            details = self._nsx_trust_management.get_identity_details(
                    self._identity)

            self._nsx_trust_management.delete_identity(details['id'])
            if details['certificate_id']:
                self._nsx_trust_management.delete_cert(
                        details['certificate_id'])

        except exceptions.ManagerError as e:
            LOG.error(_LE("Failed to clear certificate on backend: %s"), e)
            ok = False

        try:
            self._storage_driver.delete_cert(self._identity)
        except Exception as e:
            LOG.error(_LE("Failed to clear certificate on storage: %s"), e)
            ok = False

        self._cert = None
        self._key = None

        if ok:
            LOG.debug("Client certificate removed successfully")

    def exists(self):
        """Check if certificate was created"""

        return self._cert is not None

    def get_pem(self):
        """Returns certificate and key pair in PEM format"""
        self._validate_exists()

        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, self._cert)
        key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, self._key)

        return (cert_pem, key_pem)

    def export_pem(self, filename):
        """Exports certificate and key pair to file"""
        if not self.exists():
            LOG.error(_LE("No certificate present - nothing to export"))
            return

        cert_pem, key_pem = self.get_pem()
        with open(filename, 'w') as f:
            f.write(cert_pem)
            f.write(key_pem)

    def expires_on(self):
        """Returns certificate expiration timestamp"""
        self._validate_exists()

        converted = datetime.datetime.strptime(
                self._cert.get_notAfter().decode(),
                "%Y%m%d%H%M%SZ")
        return converted

    def expires_in_days(self):
        """Returns in how many days the certificate expires"""
        delta = self.expires_on() - datetime.datetime.utcnow()
        return delta.days

    def _validate_empty(self):
        if self.exists():
            raise nsxlib_exceptions.ObjectAlreadyExists(
                object_type='Client Certificate')

    def _validate_exists(self):
        if not self.exists():
            raise nsxlib_exceptions.ObjectNotGenerated(
                object_type='Client Certificate')

    def _load_cert_and_key(self):
        self._validate_empty()

        cert_pem, key_pem = self._storage_driver.get_cert(self._identity)

        if cert_pem is not None:
            self._cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
            self._key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)

    def _store_cert_and_key(self):
        self._validate_exists()

        cert_pem, key_pem = self.get_pem()
        self._storage_driver.store_cert(self._identity, cert_pem, key_pem)

    def _register_cert(self):
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, self._cert)
        nsx_cert_id = self._nsx_trust_management.create_cert(cert_pem)
        try:
            self._nsx_trust_management.create_identity(self._identity,
                                                       nsx_cert_id)
        except nsxlib_exceptions.BadRequest as e:
            if e.error_code != NSX_ERROR_IDENTITY_EXISTS:
                raise e

            # principal identity already exists - this can happen
            # due to temporary error on deletion. Worth retrying.
            details = self._nsx_trust_management.get_identity_details(
                    self._identity)
            self._nsx_trust_management.delete_identity(details['id'])
            self._nsx_trust_management.create_identity(self._identity,
                                                       nsx_cert_id)
