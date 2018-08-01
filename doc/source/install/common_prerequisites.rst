Prerequisites
-------------

Before you install and configure the NNAA service,
you must create a database, service credentials, and API endpoints.

#. To create the database, complete these steps:

   * Use the database access client to connect to the database
     server as the ``root`` user:

     .. code-block:: console

        $ mysql -u root -p

   * Create the ``keystone_oidc_auth_plugin`` database:

     .. code-block:: none

        CREATE DATABASE keystone_oidc_auth_plugin;

   * Grant proper access to the ``keystone_oidc_auth_plugin`` database:

     .. code-block:: none

        GRANT ALL PRIVILEGES ON keystone_oidc_auth_plugin.* TO 'keystone_oidc_auth_plugin'@'localhost' \
          IDENTIFIED BY 'KEYSTONE_OIDC_AUTH_PLUGIN_DBPASS';
        GRANT ALL PRIVILEGES ON keystone_oidc_auth_plugin.* TO 'keystone_oidc_auth_plugin'@'%' \
          IDENTIFIED BY 'KEYSTONE_OIDC_AUTH_PLUGIN_DBPASS';

     Replace ``KEYSTONE_OIDC_AUTH_PLUGIN_DBPASS`` with a suitable password.

   * Exit the database access client.

     .. code-block:: none

        exit;

#. Source the ``admin`` credentials to gain access to
   admin-only CLI commands:

   .. code-block:: console

      $ . admin-openrc

#. To create the service credentials, complete these steps:

   * Create the ``keystone_oidc_auth_plugin`` user:

     .. code-block:: console

        $ openstack user create --domain default --password-prompt keystone_oidc_auth_plugin

   * Add the ``admin`` role to the ``keystone_oidc_auth_plugin`` user:

     .. code-block:: console

        $ openstack role add --project service --user keystone_oidc_auth_plugin admin

   * Create the keystone_oidc_auth_plugin service entities:

     .. code-block:: console

        $ openstack service create --name keystone_oidc_auth_plugin --description "NNAA" nnaa

#. Create the NNAA service API endpoints:

   .. code-block:: console

      $ openstack endpoint create --region RegionOne \
        nnaa public http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        nnaa internal http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        nnaa admin http://controller:XXXX/vY/%\(tenant_id\)s
