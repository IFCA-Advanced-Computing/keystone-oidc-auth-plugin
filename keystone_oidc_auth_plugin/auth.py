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

LOG = log.getLogger(__name__)

CONF = keystone.conf.CONF

opts = [
    cfg.DictOpt(
        "iss",
        default={},
        help="OpenID connect issuer (identity_provider:iss)"),
    cfg.DictOpt(
        "client_id",
        default={},
        help="OpenID Connect client_id (identity_provider:client_id"),
    cfg.StrOpt(
        "claim_prefix",
        default="OIDC_",
        help="Prefix to use for our claims"),
]
CONF.register_opts(opts, group="openid")


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

    def get_oidc_client(self, identity_provider):
        oidc_client = oic.Client(client_authn_method=CLIENT_AUTHN_METHOD)

        oidc_client.client_id = CONF.openid.client_id[identity_provider]
        oidc_client.provider_config(CONF.openid.iss[identity_provider])
        return oidc_client

    def authenticate(self, auth_payload):
        assertion = ks_mapped.extract_assertion_data()

        # TODO(aguilarf) The first request won't have a Bearer. Testing
        if 'Bearer' in assertion["HTTP_AUTHORIZATION"]:
            LOG.debug("Bearer token received, using OAuth token")

            self.handle_bearer(auth_payload, assertion)
        else:
            pass
        return super(OpenIDConnect, self).authenticate(auth_payload)

    def handle_bearer(self, auth_payload, assertion):
        try:
            identity_provider = auth_payload['identity_provider']
        except KeyError:
            raise exception.ValidationError(
                attribute='identity_provider', target='mapped')

        oidc_client = self.get_oidc_client(identity_provider)

        access_token = assertion["HTTP_AUTHORIZATION"].split(":")[-1]
        if not access_token.startswith("Bearer "):
            raise InvalidOauthToken()
        access_token = access_token[7:]

        # TODO(aguilarf): validate token first!!
        claims = oidc_client.do_user_info_request(access_token=access_token)
        claims["iss"] = CONF.openid.iss[identity_provider]

        # We set here the ENV variables that are needed for the assertion to be
        # consumed downstream, and we are done
        set_env_params_from_dict(claims)


def set_env_params_from_dict(d):
    prefix = CONF.openid.claim_prefix
    aux = {"%s%s" % (prefix, n): v for n, v in d.items()}
    flask.request.environ.update(aux)
