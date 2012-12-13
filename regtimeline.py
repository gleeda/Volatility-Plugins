# Volatility
# Copyright (C) 2008-2010 Volatile Systems
# Copyright (C) 2011 Jamie Levy (Gleeda) <jamie.levy@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       Jamie Levy (Gleeda)
@license:      GNU General Public License 2.0 or later
@contact:      jamie.levy@gmail.com
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import volatility.plugins.registry.registryapi as registryapi
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.debug as debug


class RegTimeline(common.AbstractWindowsCommand):
    """Outputs a registry timeline"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('HIVE', short_option = 'H',
                          help = 'Registry Hive', type = 'str')
        config.add_option('USER', short_option = 'U',
                          help = 'User Hive', type = 'str')
        config.add_option('TIMELINE', short_option = 'T',
                          help = 'Last N Modified keys or all regs/keys if -1', type = 'int')
        config.add_option('START', short_option = 'S',
                          help = 'Start date of timeline (optional) format: YYYY-MM-DD', type = 'str')
        config.add_option('END', short_option = 'E', 
                          help = 'End date of timeline (optional) format: YYYY-MM-DD', type = 'str')


    def calculate(self):
        addr_space = utils.load_as(self._config)

        if not self._config.TIMELINE:
            print "You must enter an option for this plugin (either last number of keys or -1 for all)"
            return

        regapi = registryapi.RegistryApi(self._config)
       
        if self._config.TIMELINE and self._config.TIMELINE != -1:
            if self._config.OUTPUT != "text":
                 debug.error("Last N keys only works with text output")
            data = regapi.reg_get_last_modified(self._config.HIVE, self._config.TIMELINE, self._config.USER, self._config.START, self._config.END, True)

            for t, reg, name in data:
                yield name, reg, t

        elif self._config.TIMELINE and self._config.TIMELINE == -1:
            data = regapi.reg_get_all_keys(self._config.HIVE, self._config.USER, self._config.START, self._config.END, True, True)
    
            for t, reg, name in data:
                yield name, reg, t

    def render_text(self, outfd, data):
        for item, reg, lwtime in data:
            item = item.replace("|", "%7c")
            outfd.write("{0:<20}|{1}|{2}\n".format(lwtime, reg, item))

    def render_body(self, outfd, data):
        for item, reg, lwtime in data:
            item = item.replace("|", "%7c")
            outfd.write("0|[REGISTRY] {1}/{2}|0|---------------|0|0|0|{0}|{0}|{0}|{0}\n".format(
            lwtime.v(), reg, item))
