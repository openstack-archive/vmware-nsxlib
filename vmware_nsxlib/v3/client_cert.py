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
from time import time

from OpenSSL import crypto
from oslo_log import log
from oslo_utils import uuidutils

from vmware_nsxlib._i18n import _
from vmware_nsxlib.v3 import exceptions as nsxlib_exceptions

LOG = log.getLogger(__name__)

CERT_SUBJECT_COUNTRY = 'country'
CERT_SUBJECT_STATE = 'state'
CERT_SUBJECT_ORG = 'organization'
CERT_SUBJECT_UNIT = 'unit'
CERT_SUBJECT_HOST = 'hostname'


def validate_cert_params(key_size, valid_for_days,
                         signature_alg, subject):
    """Validate parameters for certificate"""

    expected_key_sizes = (2048, 4096)
    if key_size not in expected_key_sizes:
        raise nsxlib_exceptions.NsxLibInvalidInput(
            error_message=_('Invalid key size %(value)d'
                            '(must be one of %(list)s)') %
            {'value': key_size,
             'list': expected_key_sizes})

    expected_signature_algs = ('sha256')
    if signature_alg not in expected_signature_algs:
        raise nsxlib_exceptions.NsxLibInvalidInput(
            error_message=_('Invalid signature algorithm %(value)s'
                            '(must be one of %(list)s)') %
            {'value': signature_alg,
             'list': expected_signature_algs})

    if (CERT_SUBJECT_COUNTRY in subject and
       (len(subject[CERT_SUBJECT_COUNTRY]) != 2)):
        raise nsxlib_exceptions.NsxLibInvalidInput(
            error_message=_('Invalid country %s: '
                            'must be exactly 2 characters') %
            subject[CERT_SUBJECT_COUNTRY])

    # values defined in rfc5280
    max_len_constraints = {CERT_SUBJECT_STATE: 128,
                           CERT_SUBJECT_ORG: 64,
                           CERT_SUBJECT_UNIT: 64,
                           CERT_SUBJECT_HOST: 64}

    for field, max_len in max_len_constraints.items():
        if field in subject and (len(subject[field]) > max_len):
            raise nsxlib_exceptions.NsxLibInvalidInput(
                error_message=_('Invalid %(field)s [%(value)s]: '
                                'must not exceed %(max)d characters') %
                {'field': field,
                 'value': subject[field],
                 'max': max_len})


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
    cert.get_subject().C = subject.get(CERT_SUBJECT_COUNTRY, 'US')
    cert.get_subject().ST = subject.get(CERT_SUBJECT_STATE, 'California')
    cert.get_subject().O = subject.get(CERT_SUBJECT_ORG, 'MyOrg')
    cert.get_subject().OU = subject.get(CERT_SUBJECT_UNIT, 'MyUnit')
    cert.get_subject().CN = subject.get(CERT_SUBJECT_HOST, 'myorg.com')
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
        store_cert(purpose, certificate, private_key)
        get_cert(purpose)
        delete_cert(purpose)
    """

    def __init__(self, identity, nsx_trust_management, storage_driver):
        self._cert = None
        self._key = None
        self._storage_driver = storage_driver
        self._identity = identity

        self._nsx_trust_management = nsx_trust_management

    def __enter__(self):
        """Load cert from storage

        This is an optimization to avoid repeated storage access.
        Usage example:
            with cert_manager as c:
                if c.exists():
                    date = c.expires_on()
                    days = c.exires_in_days()
        """

        self._cert, self._key = self.get_cert_and_key()
        return self

    def __exit__(self, type, value, traceback):
        self._cert = None
        self._key = None

    def generate(self, subject, key_size=2048, valid_for_days=3650,
                 signature_alg='sha256', node_id=None):
        """Generate new certificate and register it in the system

        Generate certificate with RSA key based on arguments provided,
        register and associate it to principal identity on backend,
        and store it in storage. If certificate already exists, fail.
        """
        self._validate_empty()

        cert, key = generate_self_signed_cert_pair(key_size,
                                                   valid_for_days,
                                                   signature_alg,
                                                   subject)

        # register on backend
        self._register_cert(cert, node_id or uuidutils.generate_uuid())

        # save in storage
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        self._storage_driver.store_cert(self._identity, cert_pem, key_pem)

        LOG.debug("Client certificate generated successfully")

    def delete(self):
        """Delete existing certificate from storage and backend"""
        cert_pem, key_pem = self.get_pem()
        if not cert_pem:
            return

        ok = True
        try:
            self._nsx_trust_management.delete_cert_and_identity(
                self._identity, cert_pem)
        except nsxlib_exceptions.ManagerError as e:
            LOG.error("Failed to clear certificate on backend: %s", e)
            ok = False

        try:
            self._storage_driver.delete_cert(self._identity)
        except Exception:
            LOG.error("Failed to clear certificate in storage: %s", e)
            ok = False

        self._cert = None
        self._key = None

        if ok:
            LOG.debug("Client certificate removed successfully")

    def exists(self):
        """Check if certificate was created for given identity"""
        if self._cert:
            return True

        cert_pem, key_pem = self._storage_driver.get_cert(self._identity)
        return cert_pem is not None

    def _get_cert_from_file(self, filename):
        with open(filename, 'r') as f:
            cert_pem = f.read()

        if not cert_pem:
            raise nsxlib_exceptions.CertificateError(
                msg=_("Failed to read certificate from %s") % filename)

        # validate correct crypto
        try:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        except crypto.Error:
            raise nsxlib_exceptions.CertificateError(
                msg=_("Failed to import client certificate"))

        return cert

    def import_pem(self, filename, node_id=None):
        """Import and register existing certificate in PEM format"""

        # TODO(annak): support PK import as well
        self._validate_empty()

        cert = self._get_cert_from_file(filename)
        # register on backend
        self._register_cert(cert, node_id or uuidutils.generate_uuid())

        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        self._storage_driver.store_cert(self._identity, cert_pem, None)

        LOG.debug("Client certificate imported successfully")

    def delete_pem(self, filename):
        """Delete specified client certificate without storage verification"""
        # This file may contain private key
        # passing the pem through crypto will perform validation and
        # strip off the key
        cert = self._get_cert_from_file(filename)
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

        self._nsx_trust_management.delete_cert_and_identity(self._identity,
                                                            cert_pem)
        self._storage_driver.delete_cert(self._identity)

    def _load_from_storage(self):
        """Returns certificate and key pair in PEM format"""

        cert_pem, key_pem = self._storage_driver.get_cert(self._identity)
        if cert_pem is None:
            return None, None

        return (cert_pem, key_pem)

    def get_pem(self):
        return self._load_from_storage()

    def export_pem(self, filename):
        """Exports certificate and key pair to file"""
        self._validate_exists()

        cert_pem, key_pem = self._load_from_storage()

        with open(filename, 'w') as f:
            f.write(cert_pem)
            f.write(key_pem)

    def expires_on(self):
        """Returns certificate expiration timestamp"""
        self._validate_exists()

        cert, key = self.get_cert_and_key()
        converted = datetime.datetime.strptime(
            cert.get_notAfter().decode(),
            "%Y%m%d%H%M%SZ")
        return converted

    def expires_in_days(self):
        """Returns in how many days the certificate expires"""
        delta = self.expires_on() - datetime.datetime.utcnow()
        return delta.days

    def get_subject(self):
        self._validate_exists()

        cert, key = self.get_cert_and_key()
        return {CERT_SUBJECT_COUNTRY: cert.get_subject().C,
                CERT_SUBJECT_STATE: cert.get_subject().ST,
                CERT_SUBJECT_ORG: cert.get_subject().O,
                CERT_SUBJECT_UNIT: cert.get_subject().OU,
                CERT_SUBJECT_HOST: cert.get_subject().CN}

    def get_signature_alg(self):
        self._validate_exists()

        cert, key = self.get_cert_and_key()
        return cert.get_signature_algorithm()

    def get_key_size(self):
        self._validate_exists()

        cert, key = self.get_cert_and_key()
        return key.bits()

    def _validate_empty(self):
        if self.exists():
            raise nsxlib_exceptions.ObjectAlreadyExists(
                object_type='Client Certificate')

    def _validate_exists(self):
        if not self.exists():
            raise nsxlib_exceptions.ObjectNotGenerated(
                object_type='Client Certificate')

    def get_cert_and_key(self):
        """Load cert and key from storage"""
        if self._cert and self._key:
            return self._cert, self._key

        cert_pem, key_pem = self._load_from_storage()

        if cert_pem is None:
            return None, None

        try:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)
        except crypto.Error:
            raise nsxlib_exceptions.CertificateError(
                msg="Failed to load client certificate")

        return cert, key

    def _register_cert(self, cert, node_id):
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

        self._nsx_trust_management.create_cert_and_identity(self._identity,
                                                            cert_pem,
                                                            node_id)


class ClientCertProvider(object):
    """Basic implementation for client certificate provider

       Responsible for preparing, providing and disposing client certificate
       file. Basic implementation assumes the file exists in the file system
       and does not take responsibility of deleting this sensitive information
       after use.
       Inheriting objects should make use of __enter__ and __exit__ APIs to
       prepare and dispose the certificate file data.
    """
    def __init__(self, filename):
        self._filename = filename

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass

    def filename(self):
        return self._filename
