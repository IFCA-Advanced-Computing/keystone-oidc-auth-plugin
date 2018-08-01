2. Edit the ``/etc/keystone_oidc_auth_plugin/keystone_oidc_auth_plugin.conf`` file and complete the following
   actions:

   * In the ``[database]`` section, configure database access:

     .. code-block:: ini

        [database]
        ...
        connection = mysql+pymysql://keystone_oidc_auth_plugin:KEYSTONE_OIDC_AUTH_PLUGIN_DBPASS@controller/keystone_oidc_auth_plugin
