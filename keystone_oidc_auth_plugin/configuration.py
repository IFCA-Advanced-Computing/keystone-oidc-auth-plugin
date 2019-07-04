# Copyright (c) 2012 Rackspace Hosting
# Copyright (c) 2019 Spanish National Research Council (CSIC)
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Configuration support for different providers.

This module allows support for setting configurations either from default
or from a particular FLAGS group, to be able to set multiple configurations
for a given set of values.

For instance, two openid configurations can be set by naming them in groups as

 [openid_1]
 issuer=foo
 ...

 [openid_2]
 issuer=bar
 ...

And the configuration group name will be passed in so that all calls to
configuration.issuer within that instance will be mapped to the proper
named group.

This class also ensures the implementation's configuration is grafted into the
option group. This is due to the way cfg works. All cfg options must be defined
and registered in the group in which they are used.
"""


from oslo_config import cfg

CONF = cfg.CONF


class Configuration(object):

    def __init__(self, opts, config_group):
        """Initialize configuration."""
        self.config_group = config_group

        # set the local conf so that __call__'s know what to use
        self._ensure_config_values(opts)
        self.backend_conf = CONF._get(self.config_group)

    def _safe_register(self, opt, group):
        try:
            CONF.register_opt(opt, group=group)
        except cfg.DuplicateOptError:
            pass  # If it's already registered ignore it

    def _ensure_config_values(self, opts):
        """Register the options in the shared group.

        When we go to get a config option we will try the backend specific
        group first and fall back to the shared group. We override the default
        from all the config options for the backend group so we can know if it
        was set or not.
        """
        for opt in opts:
            self._safe_register(opt, self.config_group)
            CONF.set_default(opt.name, None, group=self.config_group)

    def append_config_values(self, opts):
        self._ensure_config_values(opts)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def safe_get(self, value):
        try:
            return self.__getattr__(value)
        except cfg.NoSuchOptError:
            return None

    def __getattr__(self, opt_name):
        # Don't use self.X to avoid reentrant call to __getattr__()
        backend_conf = object.__getattribute__(self, 'backend_conf')
        opt_value = getattr(backend_conf, opt_name)
        return opt_value
