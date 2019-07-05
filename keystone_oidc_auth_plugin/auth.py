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

import flask
from keystone.auth.plugins import mapped as ks_mapped
import keystone.conf
from keystone import exception
from keystone.i18n import _
from oic import oic
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oslo_config import cfg
from oslo_log import log

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
]

CONF.register_opts(global_opts, group="openid")


class InvalidOauthToken(exception.ValidationError):
    message_format = _('No valid OAuth 2.0 token has been found.')


class OpenIDConnect(ks_mapped.Mapped):
    """Provide OpenID Connect authentication.

    This plugin subclasses ``mapped.Mapped``, and may be specified in
    keystone.conf::

        [auth]
        methods = external,password,token,openid
        openid = ifca
    """

    def get_oidc_client(self, conf):

        oidc_client = oic.Client(client_authn_method=CLIENT_AUTHN_METHOD)

        oidc_client.client_id = conf.client_id
        oidc_client.provider_config(conf.issuer)
        return oidc_client

    def _get_idp_from_payload(self, auth_payload):
        try:
            identity_provider = auth_payload['identity_provider']
        except KeyError:
            raise exception.ValidationError(
                attribute='identity_provider', target='mapped')

        return identity_provider

    def authenticate(self, auth_payload):
        assertion = ks_mapped.extract_assertion_data()

        # TODO(aguilarf) The first request won't have a Bearer. Testing
        if 'Bearer' in assertion.get("HTTP_AUTHORIZATION", ""):
            LOG.debug("Bearer token received, using OAuth token")

            access_token = assertion["HTTP_AUTHORIZATION"].split(":")[-1]
            if not access_token.startswith("Bearer "):
                raise InvalidOauthToken()
            access_token = access_token[7:]

            self.handle_bearer(auth_payload, access_token)
        else:
            pass

        return super(OpenIDConnect, self).authenticate(auth_payload)

    def handle_bearer(self, auth_payload, access_token):
        identity_provider = self._get_idp_from_payload(auth_payload)

        conf = configuration.Configuration(opts,
                                           "openid_%s" % identity_provider)
        oidc_client = self.get_oidc_client(conf)

        # TODO(aguilarf): validate token first!!
        claims = oidc_client.do_user_info_request(access_token=access_token)
        claims["iss"] = conf.issuer

        # We set here the ENV variables that are needed for the assertion to be
        # consumed downstream, and we are done
        set_env_params_from_dict(claims)


def set_env_params_from_dict(d):
    prefix = CONF.openid.claim_prefix
    aux = {"%s%s" % (prefix, n): v for n, v in d.items()}
    flask.request.environ.update(aux)
