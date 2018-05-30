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
import re
import time

from oslo_log import log
from oslo_serialization import jsonutils
import requests
import six.moves.urllib.parse as urlparse
from vmware_nsxlib._i18n import _
from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import utils

LOG = log.getLogger(__name__)

NULL_CURSOR_PREFIX = '0000'


def http_error_to_exception(status_code, error_code):
    errors = {
        requests.codes.NOT_FOUND:
            {'202': exceptions.BackendResourceNotFound,
             'default': exceptions.ResourceNotFound},
        requests.codes.BAD_REQUEST:
            {'60508': exceptions.NsxIndexingInProgress,
             '500045': exceptions.NsxPendingDelete},
        requests.codes.CONFLICT: exceptions.StaleRevision,
        requests.codes.PRECONDITION_FAILED: exceptions.StaleRevision,
        requests.codes.INTERNAL_SERVER_ERROR:
            {'99': exceptions.ClientCertificateNotTrusted},
        requests.codes.FORBIDDEN:
            {'98': exceptions.BadXSRFToken},
        requests.codes.TOO_MANY_REQUESTS: exceptions.TooManyRequests,
        requests.codes.SERVICE_UNAVAILABLE: exceptions.ServiceUnavailable}

    if status_code in errors:
        if isinstance(errors[status_code], dict):
            # choose based on error code
            if error_code and str(error_code) in errors[status_code]:
                return errors[status_code][str(error_code)]
            elif 'default' in errors[status_code]:
                return errors[status_code]['default']
        else:
            return errors[status_code]

    # default exception
    return exceptions.ManagerError


class RESTClient(object):

    _VERB_RESP_CODES = {
        'get': [requests.codes.ok],
        'post': [requests.codes.created, requests.codes.ok],
        'put': [requests.codes.created, requests.codes.ok],
        'patch': [requests.codes.created, requests.codes.ok],
        'delete': [requests.codes.ok]
    }

    def __init__(self, connection, url_prefix=None,
                 default_headers=None,
                 client_obj=None):
        self._conn = connection
        self._url_prefix = url_prefix or ""
        self._default_headers = default_headers or {}

    def new_client_for(self, *uri_segments):
        uri = self._build_url('/'.join(uri_segments))

        return self.__class__(
            self._conn,
            url_prefix=uri,
            default_headers=self._default_headers,
            client_obj=self)

    def list(self, resource='', headers=None, silent=False):
        return self.url_list(resource, headers=headers, silent=silent)

    def get(self, uuid, headers=None, silent=False):
        return self.url_get(uuid, headers=headers, silent=silent)

    def delete(self, uuid, headers=None, expected_results=None):
        return self.url_delete(uuid, headers=headers,
                               expected_results=expected_results)

    def update(self, uuid, body=None, headers=None, expected_results=None):
        return self.url_put(uuid, body, headers=headers,
                            expected_results=expected_results)

    def create(self, resource='', body=None, headers=None,
               expected_results=None):
        return self.url_post(resource, body, headers=headers,
                             expected_results=expected_results)

    def patch(self, resource='', body=None, headers=None):
        return self.url_patch(resource, body, headers=headers)

    def url_list(self, url, headers=None, silent=False):
        concatenate_response = self.url_get(url, headers=headers)
        cursor = concatenate_response.get('cursor', NULL_CURSOR_PREFIX)
        op = '&' if urlparse.urlparse(url).query else '?'
        url += op + 'cursor='

        while cursor and not cursor.startswith(NULL_CURSOR_PREFIX):
            page = self.url_get(url + cursor, headers=headers, silent=silent)
            concatenate_response['results'].extend(page.get('results', []))
            cursor = page.get('cursor', NULL_CURSOR_PREFIX)
        return concatenate_response

    def url_get(self, url, headers=None, silent=False):
        return self._rest_call(url, method='GET', headers=headers,
                               silent=silent)

    def url_delete(self, url, headers=None, expected_results=None):
        return self._rest_call(url, method='DELETE', headers=headers,
                               expected_results=expected_results)

    def url_put(self, url, body, headers=None, expected_results=None):
        return self._rest_call(url, method='PUT', body=body, headers=headers,
                               expected_results=expected_results)

    def url_post(self, url, body, headers=None, expected_results=None):
        return self._rest_call(url, method='POST', body=body, headers=headers,
                               expected_results=expected_results)

    def url_patch(self, url, body, headers=None):
        return self._rest_call(url, method='PATCH', body=body, headers=headers)

    def _raise_error(self, status_code, operation, result_msg,
                     error_code=None):
        error = http_error_to_exception(status_code, error_code)
        raise error(manager='', operation=operation, details=result_msg,
                    error_code=error_code)

    def _validate_result(self, result, expected, operation, silent=False):
        if result.status_code not in expected:
            result_msg = result.json() if result.content else ''
            if not silent:
                LOG.warning("The HTTP request returned error code "
                            "%(result)s, whereas %(expected)s response "
                            "codes were expected. Response body %(body)s",
                            {'result': result.status_code,
                             'expected': '/'.join([str(code)
                                                   for code in expected]),
                             'body': result_msg})

            error_code = None
            if isinstance(result_msg, dict) and 'error_message' in result_msg:
                error_code = result_msg.get('error_code')
                related_errors = [error['error_message'] for error in
                                  result_msg.get('related_errors', [])]
                result_msg = result_msg['error_message']
                if related_errors:
                    result_msg += " relatedErrors: %s" % ' '.join(
                        related_errors)
            self._raise_error(result.status_code, operation, result_msg,
                              error_code=error_code)

    @classmethod
    def merge_headers(cls, *headers):
        merged = {}
        for header in headers:
            if header:
                merged.update(header)
        return merged

    def _build_url(self, uri):
        prefix = urlparse.urlparse(self._url_prefix)
        uri = ("/%s/%s" % (prefix.path, uri)).replace('//', '/').strip('/')
        if prefix.netloc:
            uri = "%s/%s" % (prefix.netloc, uri)
        if prefix.scheme:
            uri = "%s://%s" % (prefix.scheme, uri)
        return uri

    def _mask_password(self, json):
        '''Mask password value in json format'''
        if not json:
            return json

        pattern = r'\"password\": [^,}]*'
        return re.sub(pattern, '"password": "********"', json)

    def _rest_call(self, url, method='GET', body=None, headers=None,
                   silent=False, expected_results=None):
        request_headers = headers.copy() if headers else {}
        request_headers.update(self._default_headers)
        if utils.INJECT_HEADERS_CALLBACK:
            inject_headers = utils.INJECT_HEADERS_CALLBACK()
            request_headers.update(inject_headers)

        request_url = self._build_url(url)

        do_request = getattr(self._conn, method.lower())
        if not silent:

            LOG.debug("REST call: %s %s. Headers: %s. Body: %s",
                      method, request_url, request_headers,
                      self._mask_password(body))

        ts = time.time()
        result = do_request(
            request_url,
            data=body,
            headers=request_headers)
        te = time.time()

        if not silent:
            LOG.debug("REST call: %s %s. Response: %s. Took %2.4f",
                      method, request_url,
                      result.json() if result.content else '',
                      te - ts)

        if not expected_results:
            expected_results = RESTClient._VERB_RESP_CODES[method.lower()]
        self._validate_result(
            result, expected_results,
            _("%(verb)s %(url)s") % {'verb': method, 'url': request_url},
            silent=silent)
        return result


class JSONRESTClient(RESTClient):

    _DEFAULT_HEADERS = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    def __init__(self, connection, url_prefix=None,
                 default_headers=None,
                 client_obj=None):

        super(JSONRESTClient, self).__init__(
            connection,
            url_prefix=url_prefix,
            default_headers=RESTClient.merge_headers(
                JSONRESTClient._DEFAULT_HEADERS, default_headers),
            client_obj=None)

    def _rest_call(self, *args, **kwargs):
        if kwargs.get('body') is not None:
            kwargs['body'] = jsonutils.dumps(kwargs['body'], sort_keys=True)
        result = super(JSONRESTClient, self)._rest_call(*args, **kwargs)
        return result.json() if result.content else result


class NSX3Client(JSONRESTClient):

    NSX_V1_API_PREFIX = 'api/v1/'
    NSX_POLICY_V1_API_PREFIX = 'policy/api/v1/'

    def __init__(self, connection, url_prefix=None,
                 default_headers=None,
                 nsx_api_managers=None,
                 max_attempts=utils.DEFAULT_MAX_ATTEMPTS,
                 rate_limit_retry=True,
                 client_obj=None,
                 url_path_base=NSX_V1_API_PREFIX):

        # If the client obj is defined - copy configuration from it
        if client_obj:
            self.nsx_api_managers = client_obj.nsx_api_managers or []
            self.max_attempts = client_obj.max_attempts
            self.rate_limit_retry = client_obj.rate_limit_retry
        else:
            self.nsx_api_managers = nsx_api_managers or []
            self.max_attempts = max_attempts
            self.rate_limit_retry = rate_limit_retry

        url_prefix = url_prefix or url_path_base
        if url_prefix and url_path_base not in url_prefix:
            if url_prefix.startswith('http'):
                url_prefix += '/' + url_path_base
            else:
                url_prefix = "%s/%s" % (url_path_base,
                                        url_prefix or '')
        self.max_attempts = max_attempts

        super(NSX3Client, self).__init__(
            connection, url_prefix=url_prefix,
            default_headers=default_headers,
            client_obj=client_obj)

    def _raise_error(self, status_code, operation, result_msg,
                     error_code=None):
        """Override the Rest client errors to add the manager IPs"""
        error = http_error_to_exception(status_code, error_code)
        raise error(manager=self.nsx_api_managers,
                    operation=operation,
                    details=result_msg,
                    error_code=error_code)

    def _rest_call(self, url, **kwargs):
        if self.rate_limit_retry:
            # If too many requests are handled by the nsx at the same time,
            # error "429: Too Many Requests" or "503: Server Unavailable"
            # will be returned.
            # the client is expected to retry after a random 400-600 milli,
            # and later exponentially until 5 seconds wait
            @utils.retry_random_upon_exception(
                exceptions.ServerBusy,
                max_attempts=self.max_attempts)
            def _rest_call_with_retry(self, url, **kwargs):
                return super(NSX3Client, self)._rest_call(url, **kwargs)
            return _rest_call_with_retry(self, url, **kwargs)
        else:
            return super(NSX3Client, self)._rest_call(url, **kwargs)
