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


from keystone.tests.unit.ksfixtures import auth_plugins
from keystone.tests.unit import test_auth_plugin as ks_test_auth_plugin


class TestKeystone_oidc_auth_plugin(ks_test_auth_plugin.TestMapped):

    def test_load_openid_ifca(self):
        self.useFixture(auth_plugins.ConfigAuthPlugins(self.config_fixture,
                                                       ["oidc"],
                                                       oidc="ifca"))
        self.useFixture(auth_plugins.LoadAuthPlugins("oidc"))
        self._test_mapped_invocation_with_method_name("oidc")
