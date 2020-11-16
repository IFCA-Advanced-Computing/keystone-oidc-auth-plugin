# OpenID Connect plugin for Keystone authentication

This repository contains an OpenID Connect Implementation for the OpenStack
Identity service (Keystone).

## Installation

Install it via `pip`:

    pip install keystone_oidc_auth_plugin

## Configuration

In order to configure it you must enable it on the authentication methods in
`keystone.conf`, and then specify to use the `ifca` plugin, for instance:

    [auth]

    # Allowed authentication methods. Note: You should disable the `external` auth
    # method if you are currently using federation. External auth and federation
    # both use the REMOTE_USER variable. Since both the mapped and external plugin
    # are being invoked to validate attributes in the request environment, it can
    # cause conflicts. (list value)
    methods = password,token,openid

    openid = ifca

Then, you can configure the global OpenID Connect specific options as follows:

    [openid]

    # The prefix to use when setting claims in the HTTP headers/environment
    # variables. (string value)
    #claim_prefix = OIDC_

    # Value to be used to obtain the entity ID of the Identity Provider from the
    # environment. Defaults to OIDC_iss. (string value)
    #remote_id_attribute = OIDC_iss

    # Default duration in seconds after which retrieved JWS should be refreshed.
    # (integer value)
    #jws_refresh_interval = 3600

Finally, you need to add a section for each of the Identity Providers (IdP)
that you want to support. In order to do so, the plugin looks for IdP entries
that are prefixed by `openid_`. The IdP name that you use for each of these
entries must match the identity provider's name configured in Keystone,
therefore if you have defined an IdP named `idp-name`, you must add an entry as
follows:

    [openid_idp-name]

    # OpenID connect issuer URL. We will use this to build all the required options
    # asking the discovery url (i.e. querying the $issuer/.well-known/openid-
    # configuration endpoint. This has to correspond to the 'remote-id' parameter
    # that is set in the federated identity provider configuration that is
    # configured in Keystone. (string value)
    #issuer = <None>

    # Client identifier used in calls to the OpenID Connect Provider (string value)
    #client_id = <None>

    # OpenID connect issuer URL. We will use this to build all the in Keystone.
    # (string value)
    #authorization_endpoint = <None>

    # Client identifier only known by the application and Identity provider client
    # (string value)
    #client_secret = <None>

    # Supported OpenID scopes in the Identity provider (string value)
    #scope = <None>

    # OpenID connect URL to get identity and access tokens (string value)
    #token_endpoint = <None>

    # Allowed HTTP method for userinfo request. Optional.
    #userinfo_method = POST
