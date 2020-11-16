# -*- coding: utf-8 -*-

# Copyright 2018 Spanish National Research Council (CSIC)
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import time

import flask
import jwkest
from keystone.auth.plugins import mapped as ks_mapped
import keystone.conf
from keystone import exception
from keystone.i18n import _
import oic.exception
import oic.oic
import oic.oic.message
from oic.utils.authn import client as utils_client
from oic.utils import jwt
from oslo_config import cfg
from oslo_log import log
from six.moves.urllib import parse as urlparse

from keystone_oidc_auth_plugin import configuration

LOG = log.getLogger(__name__)

CONF = keystone.conf.CONF

opts = [
    cfg.StrOpt(
        "issuer",
        help="OpenID connect issuer URL. We will use this to build all the "
             "required options asking the discovery url (i.e. querying the "
             "$issuer/.well-known/openid-configuration endpoint. This has "
             "to correspond to the 'remote-id' parameter that is set in the "
             "federated identity provider configuration that is configured "
             "in Keystone."),
    cfg.StrOpt(
        "client_id",
        help="Client identifier used in calls to the OpenID Connect Provider"),
    cfg.StrOpt(
        "authorization_endpoint",
        help="OpenID connect issuer URL. We will use this to build all the "
             "in Keystone."),
    cfg.StrOpt(
        "client_secret",
        help="Client identifier only known by the application and Identity "
             "provider client"),
    cfg.StrOpt(
        "scope",
        help="Supported OpenID scopes in the Identity provider"),
    cfg.StrOpt(
        "token_endpoint",
        help="OpenID connect URL to get identity and access tokens"),
    cfg.StrOpt(
        "userinfo_method",
        help="Allowed HTTP method for userinfo request. Optional"),
]

global_opts = [
    cfg.StrOpt(
        "claim_prefix",
        default="OIDC_",
        help="The prefix to use when setting claims in the HTTP "
             "headers/environment variables."),
    cfg.StrOpt(
        'remote_id_attribute',
        default="OIDC_iss",
        help="Value to be used to obtain the entity ID of the Identity "
             "Provider from the environment. Defaults to OIDC_iss."),
    cfg.IntOpt(
        "jws_refresh_interval",
        default=3600,
        help="Default duration in seconds after which retrieved JWS should "
             "be refreshed."),
]

CONF.register_opts(global_opts, group="openid")


class InvalidOauthToken(exception.ValidationError):
    message_format = _('No valid OAuth 2.0 token has been found in headers.')


class OpenIDConnect(ks_mapped.Mapped):
    """Provide OpenID Connect authentication.

    This plugin subclasses ``mapped.Mapped``, and may be specified in
    keystone.conf::

        [auth]
        methods = external,password,token,openid
        openid = ifca
    """

    def __init__(self, *args, **kwargs):
        super(OpenIDConnect, self).__init__(*args, **kwargs)

        # Dictionary to store the clients, we will store here a tuple for each
        # of the clients, with the first element being the timestamp when the
        # client was created, the second the client itself.
        self._clients = {}

    def get_oidc_client(self, idp):
        conf = configuration.Configuration(opts, "openid_%s" % idp)

        created_at, oidc_client = self._clients.get(idp, (0, None))

        now = int(time.time())
        refresh_interval = CONF.openid.jws_refresh_interval

        # Create client if we do not have one
        if oidc_client is None:

            oidc_client = oic.oic.Client(
                client_authn_method=utils_client.CLIENT_AUTHN_METHOD
            )

            oidc_client.client_id = conf.client_id
            self._clients[idp] = (now, oidc_client)

        # Refresh the provider configuration if the interval has passed. This
        # will trigger an update of the keyjar
        if now - created_at >= refresh_interval:
            # FIXME(aloga): check here that the issuer and whatnot is set,
            # otherwise raise an error
            oidc_client.provider_config(conf.issuer)

        return oidc_client

    def _get_redirect_uri(self, conf):
        query = urlparse.parse_qs(flask.request.environ["QUERY_STRING"])
        if query.get("oscli"):
            return "http://localhost:8080"
        origin = flask.request.args.get('origin')
        origin = urlparse.quote_plus(origin)
        return flask.request.base_url + f"?origin={origin}"

    def _get_idp_from_payload(self, auth_payload):
        try:
            identity_provider = auth_payload['identity_provider']
        except KeyError:
            raise exception.ValidationError(
                "Identity provider not found in auth_payload")

        return identity_provider

    def authenticate(self, auth_payload):
        assertion = ks_mapped.extract_assertion_data()
        # Handle Bearer auth, this is not "pure" OpenID Connect but it is
        # required to work with the current keystoneauth1 code, that allows
        # users to register the OpenStack CLI as an OpenID Connect client,
        # therefore they will only present the Oauth 2.0 token. In order to
        # support this we need to use this token to get the user_info claims
        # from the IdP.
        if 'Bearer' in assertion.get("HTTP_AUTHORIZATION", ""):
            LOG.debug("Bearer token received, using OAuth token")

            bearer = utils_client.BearerHeader()
            try:
                # Beware: BearerHeader.verify() only verifies that the
                # assertion is there, but not its actual validity!
                access_token = bearer.verify(assertion)
            except oic.exception.AuthnFailure:
                raise InvalidOauthToken()

            self.handle_bearer(auth_payload, access_token)

            return super(OpenIDConnect, self).authenticate(auth_payload)
        # Get a new token based on config
        else:
            query = urlparse.parse_qs(flask.request.environ["QUERY_STRING"])
            if "code" in query:
                access_token = self.get_access_token(auth_payload, assertion)
                self.handle_bearer(auth_payload, access_token)
                return super(OpenIDConnect, self).authenticate(auth_payload)
            else:
                LOG.debug("Bearer token was not received, getting OAuth token")
                login_url = self.handle_access_token(auth_payload)
                raise exception.RedirectRequired(login_url)

    def handle_bearer(self, auth_payload, access_token):
        idp = self._get_idp_from_payload(auth_payload)
        conf = configuration.Configuration(opts, "openid_%s" % idp)
        client = self.get_oidc_client(idp)
        # Validate the JSON Web Token
        jwt_hdl = jwt.JWT(client.keyjar)
        try:
            token = jwt_hdl.unpack(access_token)
        except Exception as e:
            token = dict({"iss": client.issuer})

        method = conf.userinfo_method
        if method is None:
            try:
                claims = client.do_user_info_request(access_token=access_token,
                                                     method="POST")
            except oic.exception.RequestError:
                claims = client.do_user_info_request(access_token=access_token,
                                                     method="GET")

        else:
            claims = client.do_user_info_request(access_token=access_token,
                                                 method=method)

        claims["iss"] = token["iss"]

        # We set here the ENV variables that are needed for the assertion to be
        # consumed downstream, and we are done
        set_env_params_from_dict(claims)

    def handle_access_token(self, auth_payload):
        idp = self._get_idp_from_payload(auth_payload)
        conf = configuration.Configuration(opts, "openid_%s" % idp)
        client = self.get_oidc_client(idp)

        session = {"nonce": oic.rndstr(), "state": oic.rndstr()}
        args = {
            "response_type": 'code',
            "client_id": conf.client_id,
            "authorization_endpoint": conf.authorization_endpoint,
            "token_endpoint": conf.token_endpoint,
            "redirect_uri": self._get_redirect_uri(conf),
            "scope": conf.scope,
            "nonce": session["nonce"],
            "state": session["state"],
        }
        auth_req = client.construct_AuthorizationRequest(request_args=args)
        login_url = auth_req.request(client.authorization_endpoint)

        return login_url

    def get_access_token(self, auth_payload, assertion):
        idp = self._get_idp_from_payload(auth_payload)
        conf = configuration.Configuration(opts, "openid_%s" % idp)
        client = self.get_oidc_client(idp)

        LOG.debug("Lets assert response")
        response = flask.request.environ["QUERY_STRING"]

        LOG.debug('Create aresp')
        aresp = client.parse_response(oic.oic.message.AuthorizationResponse,
                                      info=response, sformat="urlencoded")
        code = aresp["code"]
        args = {
            "code": code,
            "client_id": conf.client_id,
            "authorization_endpoint": conf.authorization_endpoint,
            "client_secret": conf.client_secret,
            "token_endpoint": conf.token_endpoint,
            "redirect_uri": self._get_redirect_uri(conf),
            "scope": conf.scope
        }
        client.client_id = conf.client_id
        client.authorization_endpoint = conf.authorization_endpoint
        resp = client.do_access_token_request(state=aresp["state"],
                                              request_args=args,
                                              authn_method="client"
                                                           "_secret"
                                                           "_basic")
        access_token = resp['access_token']
        return access_token


def set_env_params_from_dict(d):
    prefix = CONF.openid.claim_prefix
    aux = {"%s%s" % (prefix, n): v for n, v in d.items()}
    flask.request.environ.update(aux)
