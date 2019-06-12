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
from keystone.auth.plugins import base
from keystone.auth.plugins import mapped as ks_mapped
from keystone.common import provider_api
import keystone.conf
from keystone import exception
from keystone import notifications
from keystone.federation import constants as federation_constants
from keystone.federation import utils
from oic import oic
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oslo_config import cfg
from oslo_log import log
from pycadf import cadftaxonomy as taxonomy
import six

LOG = log.getLogger(__name__)

METHOD_NAME = 'oidc'

CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs

opts = [
    cfg.DictOpt(
        "iss",
        default={},
        help="OpenID connect issuer (identity_provider:iss)"),
    cfg.DictOpt(
        "client_id",
        default={},
        help="OpenID Connect client_id (identity_provider:client_id"),
]
CONF.register_opts(opts, group="oidc")


class OpenIDConnect(ks_mapped.Mapped):
    """Provide OpenID Connect authentication.

    This plugin subclasses ``mapped.Mapped``, and may be specified in
    keystone.conf::

        [auth]
        methods = external,password,token,oidc
        oidc = keystone_oidc_auth_plugin.auth.OpenIDConnect
    """
    def authenticate(self, request, auth_payload):
        assertion = ks_mapped.extract_assertion_data(request)

        # TODO(aguilarf) The first request won't have a Bearer. Testing
        if 'Bearer' in assertion["HTTP_AUTHORIZATION"]:
            LOG.debug("Bearer token received")
            response_data = self.handle_bearer(request, auth_payload)
        else:
            return super(OpenIDConnect, self).authenticate(auth_payload)

        return base.AuthHandlerResponse(status=True,
                                        response_body=None,
                                        response_data=response_data)

    def handle_bearer(self, request, auth_payload):
        assertion = ks_mapped.extract_assertion_data(request)
        try:
            identity_provider = auth_payload['identity_provider']
        except KeyError:
            raise exception.ValidationError(
                attribute='identity_provider', target='mapped')
        try:
            protocol = auth_payload['protocol']
        except KeyError:
            raise exception.ValidationError(
                attribute='protocol', target='mapped')
        group_ids = None
        token_id = None
        user_id = None
        resource_api = PROVIDERS.resource_api
        federation_api = PROVIDERS.federation_api
        identity_api = PROVIDERS.identity_api
        assignment_api = PROVIDERS.assignment_api
        role_api = PROVIDERS.role_api
        try:
            identity_provider = auth_payload['identity_provider']
        except KeyError:
            raise exception.ValidationError(
                attribute='identity_provider', target='mapped')

        oidc_client = oic.Client(client_authn_method=CLIENT_AUTHN_METHOD)

        oidc_client.client_id = CONF.oidc.client_id[identity_provider]
        oidc_client.provider_config(CONF.oidc.iss[identity_provider])

        access_token = assertion["HTTP_AUTHORIZATION"].split(":")[-1]
        access_token = access_token[7:]
        # TODO: validate token first!!
        userinfo = oidc_client.do_user_info_request(access_token=access_token)

        # We set here the ENV variables that are needed for the assertion to be
        # consumed downstream
        userinfo_vars = set_env_params_from_userinfo(userinfo)
        
        unique_id = userinfo_vars['sub']
        LOG.debug("UNIQUE ID: %s" % unique_id)
        display_name = userinfo_vars['name']
        LOG.debug("Display_name: %s" % display_name)
        assertion = userinfo
        try:
            try:
                mapped_properties, mapping_id = ks_mapped.apply_mapping_filter(
                    identity_provider, protocol, assertion, resource_api,
                    federation_api, identity_api)
                LOG.debug("Mapping filter: %s" % mapped_properties)
            except exception.ValidationError as e:
                # if mapping is either invalid or yield no valid identity,
                # it is considered a failed authentication
                raise exception.Unauthorized(e)

            if is_ephemeral_user(mapped_properties):
                # TODO(aguilarf) Way to get state needed. Provided in URL itself
                # TODO(aguilarf) if there is no state, then error
                user = identity_api.shadow_federated_user(identity_provider,
                                                          protocol, unique_id,
                                                          display_name)

                if 'projects' in mapped_properties:
                    idp_domain_id = federation_api.get_idp(
                        identity_provider
                    )['domain_id']
                    existing_roles = {
                        role['name']: role for role in role_api.list_roles()
                    }
                # NOTE(lbragstad): If we are dealing with a shadow mapping,
                    # then we need to make sure we validate all pieces of the
                    # mapping and what it's saying to create. If there is something
                    # wrong with how the mapping is, we should bail early before we
                    # create anything.
                    validate_shadow_mapping(
                        mapped_properties['projects'],
                        existing_roles,
                        idp_domain_id,
                        identity_provider
                    )
                    create_projects_from_mapping(
                        mapped_properties['projects'],
                        idp_domain_id,
                        existing_roles,
                        user,
                        assignment_api,
                        resource_api
                    )

                user_id = user['id']
                group_ids = mapped_properties['group_ids']
                response_data = build_ephemeral_user_context(
                    user, mapped_properties, identity_provider, protocol)
            else:
                response_data = ks_mapped.build_local_user_context(mapped_properties)
        except Exception:
            # NOTE(topol): Diaper defense to catch any exception, so we can
            # send off failed authentication notification, raise the exception
            # after sending the notification
            outcome = taxonomy.OUTCOME_FAILURE
            notifications.send_saml_audit_notification('authenticate',
                                                       request,
                                                       user_id, group_ids,
                                                       identity_provider,
                                                       protocol, token_id,
                                                       outcome)
            raise
        else:
            outcome = taxonomy.OUTCOME_SUCCESS
            notifications.send_saml_audit_notification('authenticate',
                                                       request,
                                                       user_id, group_ids,
                                                       identity_provider,
                                                       protocol, token_id,
                                                       outcome)

        return response_data

def validate_shadow_mapping(shadow_projects, existing_roles, idp_domain_id,
                                idp_id):
        # Validate that the roles in the shadow mapping actually exist. If
        # they don't we should bail early before creating anything.
        for shadow_project in shadow_projects:
            for shadow_role in shadow_project['roles']:
                # The role in the project mapping must exist in order for it to
                # be useful.
                if shadow_role['name'] not in existing_roles:
                    LOG.error(
                        'Role %s was specified in the mapping but does '
                        'not exist. All roles specified in a mapping must '
                        'exist before assignment.',
                        shadow_role['name']
                    )
                    # NOTE(lbragstad): The RoleNotFound exception usually
                    # expects a role_id as the parameter, but in this case we
                    # only have a name so we'll pass that instead.
                    raise exception.RoleNotFound(shadow_role['name'])
                role = existing_roles[shadow_role['name']]
                if (role['domain_id'] is not None and
                        role['domain_id'] != idp_domain_id):
                    LOG.error(
                        'Role %(role)s is a domain-specific role and '
                        'cannot be assigned within %(domain)s.',
                        {'role': shadow_role['name'], 'domain': idp_domain_id}
                    )
                    raise exception.DomainSpecificRoleNotWithinIdPDomain(
                        role_name=shadow_role['name'],
                        identity_provider=idp_id
                    )

def create_projects_from_mapping(shadow_projects, idp_domain_id,
                                 existing_roles, user, assignment_api,
                                 resource_api):
    for shadow_project in shadow_projects:
        try:
            # Check and see if the project already exists and if it
            # does not, try to create it.
            project = resource_api.get_project_by_name(
                shadow_project['name'], idp_domain_id
            )
        except exception.ProjectNotFound:
            LOG.info(
                'Project %(project_name)s does not exist. It will be '
                'automatically provisioning for user %(user_id)s.',
                {'project_name': shadow_project['name'],
                 'user_id': user['id']}
            )
            project_ref = {
                'id': user['id'],
                'name': shadow_project['name'],
                'domain_id': idp_domain_id
            }
            project = resource_api.create_project(
                project_ref['id'],
                project_ref
            )
 
        shadow_roles = shadow_project['roles']
        for shadow_role in shadow_roles:
            assignment_api.create_grant(
                existing_roles[shadow_role['name']]['id'],
                user_id=user['id'],
                project_id=project['id']
            )

            
def is_ephemeral_user(mapped_properties):
    return mapped_properties['user']['type'] == utils.UserType.EPHEMERAL


def build_ephemeral_user_context(user, mapped_properties,
                                     identity_provider, protocol):
    resp = {}
    resp['user_id'] = user['id']
    resp['group_ids'] = mapped_properties['group_ids']
    resp[federation_constants.IDENTITY_PROVIDER] = identity_provider
    resp[federation_constants.PROTOCOL] = protocol
    return resp


def build_local_user_context(mapped_properties):
    resp = {}
    user_info = auth_plugins.UserAuthInfo.create(mapped_properties,
                                                 METHOD_NAME)
    resp['user_id'] = user_info.user_id
    return resp


def set_env_params_from_userinfo(userinfo):
    LOG.debug('Userinfo response: %s', userinfo)
    prefix = CONF.federation.assertion_prefix
#    userinfo_vars = {"%s%s" % (prefix, n): v.split(';')
#                     for n, v in userinfo.items()
#                     if isinstance(v, six.string_types)}
    userinfo_vars = {n: v.split(';') for n, v in userinfo.items()
                     if isinstance(v, six.string_types)} 
    return userinfo_vars
