# -*- coding: utf-8 -*-

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

"""
test_keystone_oidc_auth_plugin
----------------------------------

Tests for `keystone_oidc_auth_plugin` module.
"""

from unittest import mock
import uuid

from keystone.api._shared import authentication
from keystone import auth
from keystone.tests.unit.ksfixtures import auth_plugins
from keystone.tests.unit import test_auth_plugin as ks_test_auth_plugin

from keystone_oidc_auth_plugin import auth as auth_plugin


class TestKeystone_oidc_auth_plugin(ks_test_auth_plugin.TestMapped):

    def test_load_openid_ifca(self):
        method_name = "openid"

        with mock.patch.object(auth_plugin.OpenIDConnect,
                               'authenticate',
                               return_value=None) as authenticate:

            self.useFixture(auth_plugins.ConfigAuthPlugins(self.config_fixture,
                                                           [method_name],
                                                           openid="ifca"))
            self.useFixture(auth_plugins.LoadAuthPlugins(method_name))
            auth_data = {
                'identity': {
                    'methods': [method_name],
                    method_name: {'protocol': method_name},
                }
            }
            auth_info = auth.core.AuthInfo.create(auth_data)
            auth_context = auth.core.AuthContext(
                method_names=[],
                user_id=uuid.uuid4().hex)
            with self.make_request():
                authentication.authenticate(auth_info, auth_context)
            # make sure Mapped plugin got invoked with the correct payload
            ((auth_payload,), kwargs) = authenticate.call_args
            self.assertEqual(method_name, auth_payload['protocol'])
