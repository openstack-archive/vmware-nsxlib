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
import abc
import contextlib
import copy
import datetime
import inspect
import itertools
import logging
import re

import eventlet
from eventlet import greenpool
from eventlet import pools
import OpenSSL
from oslo_log import log
from oslo_service import loopingcall
import requests
from requests import adapters
from requests import exceptions as requests_exceptions
import six
import six.moves.urllib.parse as urlparse
import tenacity

from vmware_nsxlib._i18n import _
from vmware_nsxlib.v3 import client as nsx_client
from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import utils


LOG = log.getLogger(__name__)

# disable warning message for each HTTP retry
logging.getLogger(
    "requests.packages.urllib3.connectionpool").setLevel(logging.ERROR)


@six.add_metaclass(abc.ABCMeta)
class AbstractHTTPProvider(object):
    """Interface for providers of HTTP connections.

    which are responsible for creating and validating connections
    for their underlying HTTP support.
    """
    @property
    def default_scheme(self):
        return 'https'

    @abc.abstractproperty
    def provider_id(self):
        """A unique string name for this provider."""
        pass

    @abc.abstractmethod
    def validate_connection(self, cluster_api, endpoint, conn):
        """Validate the said connection for the given endpoint and cluster."""
        pass

    @abc.abstractmethod
    def new_connection(self, cluster_api, provider):
        """Create a new http connection.

        Create a new http connection for the said cluster and
        cluster provider. The actual connection should duck type
        requests.Session http methods (get(), put(), etc.).
        """
        pass

    @abc.abstractmethod
    def is_connection_exception(self, exception):
        """Determine if the given exception is related to connection failure.

        Return True if it's a connection exception and False otherwise.
        """


class TimeoutSession(requests.Session):
    """Extends requests.Session to support timeout at the session level."""

    def __init__(self, timeout, read_timeout):
        self.timeout = timeout
        self.read_timeout = read_timeout
        self.cert_provider = None
        super(TimeoutSession, self).__init__()

    @property
    def cert_provider(self):
        return self._cert_provider

    @cert_provider.setter
    def cert_provider(self, value):
        self._cert_provider = value

    # wrapper timeouts at the session level
    # see: https://goo.gl/xNk7aM
    def request(self, *args, **kwargs):
        def request_with_retry_on_ssl_error(*args, **kwargs):
            try:
                return super(TimeoutSession, self).request(*args, **kwargs)
            except (IOError, OpenSSL.SSL.Error):
                # This can happen when connection tries to access certificate
                # file it was opened with (renegotiation?)
                # Proper way to solve this would be to pass in-memory cert
                # to ssl C code.
                # Retrying here works around the problem
                return super(TimeoutSession, self).request(*args, **kwargs)

        def get_cert_provider():
            if inspect.isclass(self._cert_provider):
                # If client provided certificate provider as a class,
                # we spawn an instance here
                return self._cert_provider()
            return self._cert_provider

        if 'timeout' not in kwargs:
            kwargs['timeout'] = (self.timeout, self.read_timeout)
        if not self.cert_provider:
            # No client certificate needed
            return super(TimeoutSession, self).request(*args, **kwargs)

        if self.cert is not None:
            # Recursive call - shouldn't happen
            return request_with_retry_on_ssl_error(*args, **kwargs)

        # The following with statement allows for preparing certificate and
        # private key file and dispose it at the end of request
        # (since PK is sensitive information, immediate disposal is
        # important).
        # It would be optimal to populate certificate once per connection,
        # per request. Unfortunately requests library verifies cert file
        # existence regardless of whether certificate is going to be used
        # for this request.
        # Optimal solution for this would be to expose certificate as variable
        # and not as a file to the SSL library
        with get_cert_provider() as provider:
            self.cert = provider.filename()
            try:
                ret = request_with_retry_on_ssl_error(*args, **kwargs)
            except Exception as e:
                self.cert = None
                raise e

            self.cert = None

        return ret


class NSXRequestsHTTPProvider(AbstractHTTPProvider):
    """Concrete implementation of AbstractHTTPProvider.

    using requests.Session() as the underlying connection.
    """

    SESSION_CREATE_URL = '/api/session/create'
    COOKIE_FIELD = 'Cookie'
    SET_COOKIE_FIELD = 'Set-Cookie'
    XSRF_TOKEN = 'X-XSRF-TOKEN'
    JSESSIONID = 'JSESSIONID'

    @property
    def provider_id(self):
        return "%s-%s" % (requests.__title__, requests.__version__)

    def validate_connection(self, cluster_api, endpoint, conn):
        client = nsx_client.NSX3Client(
            conn, url_prefix=endpoint.provider.url,
            url_path_base=cluster_api.nsxlib_config.url_base,
            default_headers=conn.default_headers)
        keepalive_section = cluster_api.nsxlib_config.keepalive_section
        result = client.get(keepalive_section, silent=True)
        # If keeplive section returns a list, it is assumed to be non-empty
        if not result or result.get('result_count', 1) <= 0:
            msg = _("No %(section)s found "
                    "for '%(url)s'") % {'section': keepalive_section,
                                        'url': endpoint.provider.url}
            LOG.warning(msg)
            raise exceptions.ResourceNotFound(
                manager=endpoint.provider.url, operation=msg)

    def new_connection(self, cluster_api, provider):
        config = cluster_api.nsxlib_config
        session = TimeoutSession(config.http_timeout,
                                 config.http_read_timeout)
        if config.client_cert_provider:
            session.cert_provider = config.client_cert_provider
        else:
            session.auth = (provider.username, provider.password)

        # NSX v3 doesn't use redirects
        session.max_redirects = 0

        session.verify = not config.insecure
        if session.verify and provider.ca_file:
            # verify using the said ca bundle path
            session.verify = provider.ca_file

        # we are pooling with eventlet in the cluster class
        adapter = adapters.HTTPAdapter(
            pool_connections=1, pool_maxsize=1,
            max_retries=config.retries,
            pool_block=False)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        self.get_default_headers(session, provider,
                                 config.allow_overwrite_header)

        return session

    def is_connection_exception(self, exception):
        return isinstance(exception, requests_exceptions.ConnectionError)

    def is_conn_open_exception(self, exception):
        return isinstance(exception, requests_exceptions.ConnectTimeout)

    def get_default_headers(self, session, provider, allow_overwrite_header):
        """Get the default headers that should be added to future requests"""
        session.default_headers = {}

        # Perform the initial session create and get the relevant jsessionid &
        # X-XSRF-TOKEN for future requests
        req_data = ''
        if not session.cert_provider:
            # With client certificate authentication, username and password
            # may not be provided.
            # If provided, backend treats these credentials as authentication
            # and ignores client cert as principal identity indication.
            req_data = 'j_username=%s&j_password=%s' % (provider.username,
                                                        provider.password)
        req_headers = {'Accept': 'application/json',
                       'Content-Type': 'application/x-www-form-urlencoded'}
        # Cannot use the certificate at this stage, because it is used for
        # the certificate generation
        resp = session.request('post', provider.url + self.SESSION_CREATE_URL,
                               data=req_data, headers=req_headers)
        if resp.status_code != 200:
            LOG.error("Session create failed for endpoint %s", provider.url)
            # this will later cause the endpoint to be Down
        else:
            for header_name in resp.headers:
                if self.SET_COOKIE_FIELD.lower() == header_name.lower():
                    m = re.match('%s=.*?\;' % self.JSESSIONID,
                                 resp.headers[header_name])
                    if m:
                        session.default_headers[self.COOKIE_FIELD] = m.group()
                if self.XSRF_TOKEN.lower() == header_name.lower():
                    session.default_headers[self.XSRF_TOKEN] = resp.headers[
                        header_name]
            LOG.info("Session create succeeded for endpoint %(url)s with "
                     "headers %(hdr)s",
                     {'url': provider.url, 'hdr': session.default_headers})

        # Add allow-overwrite if configured
        if allow_overwrite_header:
            session.default_headers['X-Allow-Overwrite'] = 'true'


class ClusterHealth(object):
    """Indicator of overall cluster health.

    with respect to the connectivity of the clusters managed endpoints.
    """
    # all endpoints are UP
    GREEN = 'GREEN'
    # at least 1 endpoint is UP, but 1 or more are DOWN
    ORANGE = 'ORANGE'
    # all endpoints are DOWN
    RED = 'RED'


class EndpointState(object):
    """Tracks the connectivity state for a said endpoint."""
    # no UP or DOWN state recorded yet
    INITIALIZED = 'INITIALIZED'
    # endpoint has been validate and is good
    UP = 'UP'
    # endpoint can't be reached or validated
    DOWN = 'DOWN'


class Provider(object):
    """Data holder for a provider

    Which has a unique id a connection URL, and the credential details.
    """

    def __init__(self, provider_id, provider_url, username, password, ca_file):
        self.id = provider_id
        self.url = provider_url
        self.username = username
        self.password = password
        self.ca_file = ca_file

    def __str__(self):
        return str(self.url)


class Endpoint(object):
    """A single NSX manager endpoint (host).

    A single NSX manager endpoint (host) which includes
    related information such as the endpoint's provider,
    state, etc.. A pool is used to hold connections to the
    endpoint which are doled out when proxying HTTP methods
    to the underlying connections.
    """

    def __init__(self, provider, pool):
        self.provider = provider
        self.pool = pool
        self._state = EndpointState.INITIALIZED
        self._last_updated = datetime.datetime.now()

    def regenerate_pool(self):
        self.pool = pools.Pool(min_size=self.pool.min_size,
                               max_size=self.pool.max_size,
                               order_as_stack=True,
                               create=self.pool.create)

    @property
    def last_updated(self):
        return self._last_updated

    @property
    def state(self):
        return self._state

    def set_state(self, state):
        if self.state != state:
            LOG.info("Endpoint '%(ep)s' changing from state"
                     " '%(old)s' to '%(new)s'",
                     {'ep': self.provider,
                      'old': self.state,
                      'new': state})
        old_state = self._state
        self._state = state

        self._last_updated = datetime.datetime.now()

        return old_state

    def __str__(self):
        return "[%s] %s" % (self.state, self.provider)


class EndpointConnection(object):
    """Simple data holder

    Which contains an endpoint and a connection for that endpoint.
    """

    def __init__(self, endpoint, connection):
        self.endpoint = endpoint
        self.connection = connection


class ClusteredAPI(object):
    """Duck types the major HTTP based methods of a requests.Session

    Such as get(), put(), post(), etc.
    and transparently proxies those calls to one of
    its managed NSX manager endpoints.
    """
    _HTTP_VERBS = ['get', 'delete', 'head', 'put', 'post', 'patch', 'create']

    def __init__(self, providers,
                 http_provider,
                 min_conns_per_pool=0,
                 max_conns_per_pool=20,
                 keepalive_interval=33):

        self._http_provider = http_provider
        self._keepalive_interval = keepalive_interval

        def _init_cluster(*args, **kwargs):
            self._init_endpoints(providers,
                                 min_conns_per_pool, max_conns_per_pool)

        _init_cluster()

        # keep this internal method for reinitialize upon fork
        # for api workers to ensure each process has its own keepalive
        # loops + state
        self._reinit_cluster = _init_cluster

    def _init_endpoints(self, providers,
                        min_conns_per_pool, max_conns_per_pool):
        LOG.debug("Initializing API endpoints")

        def _create_conn(p):
            def _conn():
                return self._http_provider.new_connection(self, p)

            return _conn

        self._endpoints = {}
        for provider in providers:
            pool = pools.Pool(
                min_size=min_conns_per_pool,
                max_size=max_conns_per_pool,
                order_as_stack=True,
                create=_create_conn(provider))

            endpoint = Endpoint(provider, pool)
            self._endpoints[provider.id] = endpoint

        # service requests using round robin
        self._endpoint_schedule = itertools.cycle(self._endpoints.values())

        # duck type to proxy http invocations
        for method in ClusteredAPI._HTTP_VERBS:
            setattr(self, method, self._proxy_stub(method))

        conns = greenpool.GreenPool()
        for endpoint in self._endpoints.values():
            conns.spawn(self._validate, endpoint)
        eventlet.sleep(0)
        while conns.running():
            if (self.health == ClusterHealth.GREEN or
                self.health == ClusterHealth.ORANGE):
                # only wait for 1 or more endpoints to reduce init time
                break
            eventlet.sleep(0.5)

        for endpoint in self._endpoints.values():
            # dynamic loop for each endpoint to ensure connectivity
            loop = loopingcall.DynamicLoopingCall(
                self._endpoint_keepalive, endpoint)
            loop.start(initial_delay=self._keepalive_interval,
                       periodic_interval_max=self._keepalive_interval,
                       stop_on_exception=False)

        LOG.debug("Done initializing API endpoint(s). "
                  "API cluster health: %s", self.health)

    def _endpoint_keepalive(self, endpoint):
        delta = datetime.datetime.now() - endpoint.last_updated
        if delta.seconds >= self._keepalive_interval:
            # TODO(boden): backoff on validation failure
            self._validate(endpoint)
            return self._keepalive_interval
        return self._keepalive_interval - delta.seconds

    @property
    def providers(self):
        return [ep.provider for ep in self._endpoints.values()]

    @property
    def endpoints(self):
        return copy.copy(self._endpoints)

    @property
    def http_provider(self):
        return self._http_provider

    @property
    def health(self):
        down = 0
        up = 0
        for endpoint in self._endpoints.values():
            if endpoint.state != EndpointState.UP:
                down += 1
            else:
                up += 1

        if down == len(self._endpoints):
            return ClusterHealth.RED
        return (ClusterHealth.GREEN
                if up == len(self._endpoints)
                else ClusterHealth.ORANGE)

    def _validate(self, endpoint):
        try:
            with endpoint.pool.item() as conn:
                self._http_provider.validate_connection(self, endpoint, conn)
                endpoint.set_state(EndpointState.UP)
        except exceptions.ClientCertificateNotTrusted:
            LOG.warning("Failed to validate API cluster endpoint "
                        "'%(ep)s' due to untrusted client certificate",
                        {'ep': endpoint})
            # regenerate connection pool based on new certificate
            endpoint.regenerate_pool()
        except exceptions.BadXSRFToken:
            LOG.warning("Failed to validate API cluster endpoint "
                        "'%(ep)s' due to expired XSRF token",
                        {'ep': endpoint})
            # regenerate connection pool based on token
            endpoint.regenerate_pool()
        except Exception as e:
            endpoint.set_state(EndpointState.DOWN)
            LOG.warning("Failed to validate API cluster endpoint "
                        "'%(ep)s' due to: %(err)s",
                        {'ep': endpoint, 'err': e})

    def _select_endpoint(self):
        """Return an endpoint in UP state.

        Go over all endpoint and return the next one which is UP
        If all endpoints are currently DOWN, depending on the configuration
        retry it until one is UP (or max retries exceeded)
        """
        def _select_endpoint_internal(refresh=False):
            # check for UP state until exhausting all endpoints
            seen, total = 0, len(self._endpoints.values())
            while seen < total:
                endpoint = next(self._endpoint_schedule)
                if refresh:
                    self._validate(endpoint)
                if endpoint.state == EndpointState.UP:
                    return endpoint
                seen += 1

        @utils.retry_upon_none_result(self.nsxlib_config.max_attempts)
        def _select_endpoint_internal_with_retry():
            # redo endpoint selection with refreshing states
            return _select_endpoint_internal(refresh=True)

        # First attempt to get an UP endpoint
        endpoint = _select_endpoint_internal()
        if endpoint or not self.nsxlib_config.cluster_unavailable_retry:
            return endpoint

        # Retry the selection while refreshing the endpoints state
        try:
            return _select_endpoint_internal_with_retry()
        except tenacity.RetryError:
            # exhausted number of retries
            return None

    def endpoint_for_connection(self, conn):
        # check all endpoint pools
        for endpoint in self._endpoints.values():
            if (conn in endpoint.pool.channel.queue or
                    conn in endpoint.pool.free_items):
                return endpoint

    @property
    def cluster_id(self):
        return ','.join([str(ep.provider.url)
                         for ep in self._endpoints.values()])

    @contextlib.contextmanager
    def connection(self):
        with self.endpoint_connection() as conn_data:
            yield conn_data.connection

    @contextlib.contextmanager
    def endpoint_connection(self):
        endpoint = self._select_endpoint()
        if not endpoint:
            LOG.debug("All endpoints down for: %s" %
                      [str(ep) for ep in self._endpoints.values()])
            # all endpoints are DOWN and will have their next
            # state updated as per _endpoint_keepalive()
            raise exceptions.ServiceClusterUnavailable(
                cluster_id=self.cluster_id)

        if endpoint.pool.free() == 0:
            LOG.info("API endpoint %(ep)s at connection "
                     "capacity %(max)s and has %(waiting)s waiting",
                     {'ep': endpoint,
                      'max': endpoint.pool.max_size,
                      'waiting': endpoint.pool.waiting()})
        # pool.item() will wait if pool has 0 free
        with endpoint.pool.item() as conn:
            yield EndpointConnection(endpoint, conn)

    def _proxy_stub(self, proxy_for):
        def _call_proxy(url, *args, **kwargs):
            return self._proxy(proxy_for, url, *args, **kwargs)
        return _call_proxy

    def _proxy(self, proxy_for, uri, *args, **kwargs):
        # proxy http request call to an avail endpoint
        with self.endpoint_connection() as conn_data:
            conn = conn_data.connection
            endpoint = conn_data.endpoint

            # http conn must support requests style interface
            do_request = getattr(conn, proxy_for)

            if not uri.startswith('/'):
                uri = "/%s" % uri
            url = "%s%s" % (endpoint.provider.url, uri)
            try:
                LOG.debug("API cluster proxy %s %s to %s",
                          proxy_for.upper(), uri, url)
                # Add the connection default headers
                if conn.default_headers:
                    kwargs['headers'] = kwargs.get('headers', {})
                    kwargs['headers'].update(conn.default_headers)

                # call the actual connection method to do the
                # http request/response over the wire
                response = do_request(url, *args, **kwargs)
                endpoint.set_state(EndpointState.UP)

                return response
            except Exception as e:
                LOG.warning("Request failed due to: %s", e)
                if not self._http_provider.is_connection_exception(e):
                    # only trap and retry connection errors
                    raise e
                if self._http_provider.is_conn_open_exception(e):
                    # unable to establish new connection - endpoint is
                    # inaccessible
                    endpoint.set_state(EndpointState.DOWN)

                LOG.debug("Connection to %s failed, checking additional "
                          "connections and endpoints" % url)
                # this might be a result of server closing connection
                # retry until exhausting connections and endpoints
                return self._proxy(proxy_for, uri, *args, **kwargs)


class NSXClusteredAPI(ClusteredAPI):
    """Extends ClusteredAPI to get conf values and setup the NSXv3 cluster."""

    def __init__(self, nsxlib_config):
        self.nsxlib_config = nsxlib_config

        self._http_provider = (nsxlib_config.http_provider or
                               NSXRequestsHTTPProvider())

        super(NSXClusteredAPI, self).__init__(
            self._build_conf_providers(),
            self._http_provider,
            max_conns_per_pool=self.nsxlib_config.concurrent_connections,
            keepalive_interval=self.nsxlib_config.conn_idle_timeout)

        LOG.debug("Created NSX clustered API with '%s' "
                  "provider", self._http_provider.provider_id)

    def _build_conf_providers(self):

        def _schemed_url(uri):
            uri = uri.strip('/')
            return urlparse.urlparse(
                uri if uri.startswith('http') else
                "%s://%s" % (self._http_provider.default_scheme, uri))

        conf_urls = self.nsxlib_config.nsx_api_managers[:]
        urls = []
        providers = []
        provider_index = -1
        for conf_url in conf_urls:
            provider_index += 1
            conf_url = _schemed_url(conf_url)
            if conf_url in urls:
                LOG.warning("'%s' already defined in configuration file. "
                            "Skipping.", urlparse.urlunparse(conf_url))
                continue
            urls.append(conf_url)
            providers.append(
                Provider(
                    conf_url.netloc,
                    urlparse.urlunparse(conf_url),
                    self.nsxlib_config.username(provider_index),
                    self.nsxlib_config.password(provider_index),
                    self.nsxlib_config.ca_file(provider_index)))
        return providers
