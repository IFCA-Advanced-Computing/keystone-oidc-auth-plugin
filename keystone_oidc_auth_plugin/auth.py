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

from keystone.auth.plugins import mapped as ks_mapped
from keystone.auth.plugins import mapped as ks_mapped
from keystone.auth.plugins import base
from keystone.common import provider_api
from keystone import exception
from keystone.federation import constants as federation_constants
from keystone.federation import utils

from oslo_log import log
from oic.oic import Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.http_util import Redirect
from oic import rndstr
from oic.oic.message import AuthorizationResponse
from oic.oic.message import ProviderConfigurationResponse
import requests


class OpenIDConnect(ks_mapped.Mapped):
    """Provide OpenID Connect authentication.

    This plugin subclasses ``mapped.Mapped``, and may be specified in
    keystone.conf::

        [auth]
        methods = external,password,token,oidc
        oidc = keystone_oidc_auth_plugin.auth.OpenIDConnect
    """
    def authenticate(self, request, auth_payload):
        LOG.debug("Request")
        LOG.debug(request)
        LOG.debug("Auth_payload")
        LOG.debug(auth_payload)

        LOG.debug("Estoy en authenticate debuggeando")
        #TODO Copied from mapped
        if 'id' in auth_payload:
            LOG.debug("Estoy en id in auth_payload")
            token_ref = self._get_token_ref(auth_payload)
            response_data = handle_scoped_token(request,
                                                token_ref,
                                                PROVIDERS.federation_api,
                                                PROVIDERS.identity_api)
        #TODO We need to change this. The first request won't have a Bearer, but this is for testing
        elif 'Bearer' in str(request):
            LOG.debug("Authorization Bearer received")
            client = Client(client_authn_method=CLIENT_AUTHN_METHOD, verify_ssl=False)
            #TODO provider should be provided by keystone config
            op_info = ProviderConfigurationResponse(
                      version="1.0", issuer="https://sso.ifca.es",
                      authorization_endpoint="https://sso.ifca.es/auth/realms/master/protocol/openid-connect/auth")
            provider_info = op_info
            #provider_info = client.provider_config("https://sso.ifca.es/auth/realms/master")
            session = {"nonce": rndstr(), "state": rndstr()}
            #TODO some parameters should be provided by keystone config
            args = {
                "response_type": "code",
                "client_id": "lifewatch-iam",
                "authorization_endpoint": "https://sso.ifca.es/auth/realms/master/protocol/openid-connect/auth",
                #    "client_secret": "hF_Cw596zGO_fs15ERl09-dM",
                "redirect_uri": "http://vm009.pub.cloud.ifca.es:5000/v3/OS-FEDERATION/identity_providers/ifca-sso/protocols/oidc/auth",
                "scope": ["openid", "profile", "email"],
                "nonce": session["nonce"],
                "state": session["state"],
            }
             LOG.debug("Request params: %s" % session["state"])
            auth_req = client.construct_AuthorizationRequest(request_args=args)
            client.client_id=args["client_id"]
            LOG.debug("Client_id: %s" % client.client_id)
            login_url = auth_req.request(client.authorization_endpoint)
            LOG.debug(client)
            LOG.debug("LOGIN URL %s" %login_url) #TODO esto se supone que hay que devolverselo al cliente de alguna manera

            response_data={'URL'}
         else:
            #TODO This should handle the flow after the IdP returns the first answer. Maybe the method should be different.
            LOG.debug("NO Estoy en id in auth_payload")
            response_data = handle_unscoped_token(request,
                                                  auth_payload,
                                                  PROVIDERS.resource_api,
                                                  PROVIDERS.federation_api,
                                                  PROVIDERS.identity_api,
                                                  PROVIDERS.assignment_api,
                                                  PROVIDERS.role_api)
            LOG.debug("Estoy response_data: %s", response_data)
            return base.AuthiHandlerResponse(status=True, response_body=None,response_data=response_data)
def handle_unscoped_token(request, auth_payload, resource_api, federation_api,
                          identity_api, assignment_api, role_api):
    assertion = extract_assertion_data(request)
    LOG.debug("Estoy despues de extract_assertion_data con assertion: %s", assertion)

    #Target mapped????
    try:
        identity_provider = auth_payload['identity_provider']
        LOG.debug("Estoy en Identity provider: %s",identity_provider)
    except KeyError:
        raise exception.ValidationError(
            attribute='identity_provider', target='mapped')
    try:
        protocol = auth_payload['protocol']
        LOG.debug("Estoy en protocolr: %s",protocol)
    except KeyError:
        raise exception.ValidationError(
            attribute='protocol', target='mapped')

    utils.assert_enabled_identity_provider(federation_api, identity_provider)
    group_ids = None
    # NOTE(topol): The user is coming in from an IdP with a SAML assertion
    # instead of from a token, so we set token_id to None
    token_id = None
    # NOTE(marek-denis): This variable is set to None and there is a
    # possibility that it will be used in the CADF notification. This means
    # operation will not be mapped to any user (even ephemeral).
    user_id = None

    #TODO we need a way to get the state, that is provided in the URL itself
    #TODO if there is no state, then error
    req = str(request)
    if 'state' in req:
        #TODO change this forma cutre de obtener state
        state = req[req.find('state='):len(req)]
        state = state[len('state='):state.find('&')]
        client = Client(client_authn_method=CLIENT_AUTHN_METHOD, verify_ssl=False)
        provider_info = client.provider_config("https://sso.ifca.es/auth/realms/master")
        #TODO otra nhapa
        if 'code' in req:
            code = req[req.find('code='):len(req)]
            code = code[len('code='):code.find('\'')]

            args = {
                "response_type": "code",
                "client_id": "lifewatch-iam",
                "authorization_endpoint": "https://sso.ifca.es/auth/realms/master/protocol/openid-connect/auth",
                #    "client_secret": "hF_Cw596zGO_fs15ERl09-dM",
                "redirect_uri": "http://vm009.pub.cloud.ifca.es:5000/v3/OS-FEDERATION/identity_providers/ifca-sso/protocols/oidc/auth",
                "scope": ["openid", "profile", "email"],
                "state": state
              }

            client.construct_AuthorizationRequest(request_args=args)
            LOG.debug("GRAnt del client pyoidc: %s" % client.grant)
            args = {
                "code": code,
                #"redirect_uri": ["https://lifewatch-iam.ifca.es/google"],
                "client_id": "lifewatch-iam",
                "client_secret": "183b338e-38b4-4a66-b28c-3279240281fd",
                "scope": ["openid", "profile", "email"],
                "state": state
            }
            resp = client.do_access_token_request(state=state,request_args=args, authn_method="client_secret_basic")
            LOG.debug("After access token request:...............")
            for i in resp:
                LOG.debug("%s: %s" %(i, resp[i]))
                #    token_response = client.do_access_token_request(scope="openid", state=aresp["state"], request_args=args,  authn_method="client_secret_basic")
                #TODO introspection endpoint
                #resp = client.do_access_token_request(scope='openid',state=session["state"], request_args=args, authn_method="client_secret_basic")
                LOG.debug('##############################')
                LOG.debug('User info request')
                userinfo = client.do_user_info_request(schema="openid",state=aresp["state"],method="GET")
                LOG.debug(userinfo)

    else:

        return {'OS-FEDERATION:protocol': u'oidc', 'OS-FEDERATION:identity_provider': u'ifca-sso', 'group_ids': [u'6d540e81a3d54a46bae19df707a20574'], 'user_id': u'd5a8b27b3ca94b12a179017594b9102c'}
#this method has been copied from mapped.py
def extract_assertion_data(request):
    assertion = dict(utils.get_assertion_params_from_env(request))
    return assertion

def apply_mapping_filter(identity_provider, protocol, assertion,
                         resource_api, federation_api, identity_api):
    idp = federation_api.get_idp(identity_provider)
    utils.validate_idp(idp, protocol, assertion)

    LOG.debug("Estoy en apply_mapping_filter con identity_provider: %s, protocol: %s y assertion: %s", identity_provider,protocol,assertion)
    mapped_properties, mapping_id = federation_api.evaluate(
        identity_provider, protocol, assertion)
    # NOTE(marek-denis): We update group_ids only here to avoid fetching
    # groups identified by name/domain twice.
    # NOTE(marek-denis): Groups are translated from name/domain to their
    # corresponding ids in the auth plugin, as we need information what
    # ``mapping_id`` was used as well as idenity_api and resource_api
    # objects.
    group_ids = mapped_properties['group_ids']
    LOG.debug("Estoy en apply_mapping_filter con group_ids", group_ids)
    utils.validate_mapped_group_ids(group_ids, mapping_id, identity_api)
    group_ids.extend(
        utils.transform_to_group_ids(
            mapped_properties['group_names'], mapping_id,
            identity_api, resource_api))
    mapped_properties['group_ids'] = list(set(group_ids))
    return mapped_properties, mapping_id
