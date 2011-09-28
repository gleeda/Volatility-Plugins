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

import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg
import volatility.debug as debug
import volatility.utils as utils
import volatility.commands as commands
import volatility.plugins.registry.hivelist as hl
from heapq import nlargest
import sys as sys


class RegistryAPI(hl.HiveList): 
    """A wrapper several highly used Registry functions and w/a Timeline component"""

    def __init__(self, config, *args):
        hl.HiveList.__init__(self, config, *args)  
        config.add_option('KEY', short_option = 'K',
                          help = 'Check if Registry Key Exists', type = 'str')
        config.add_option('HIVE', short_option = 'H',
                          help = 'Registry Hive', type = 'str')
        config.add_option('USER', short_option = 'U',
                          help = 'User Hive', type = 'str')
        config.add_option('VALUE', short_option = 'V',
                          help = 'Value', type = 'str')
        config.add_option('TIMELINE', short_option = 'T',
                          help = 'Last N Modified keys or all regs/keys if -1', type = 'int')
        config.add_option('START', short_option = 'S',
                          help = 'Start date of timeline (optional) format: YYYY-MM-DD', type = 'str')
        config.add_option('END', short_option = 'E', 
                          help = 'End date of timeline (optional) format: YYYY-MM-DD', type = 'str')
        self.all_offsets = {}
        self.current_offsets = {}


    def print_offsets(self):
        '''
        this is just in case we want to check our offsets and which hive(s) was/were chosen
        '''
        for item in self.all_offsets:
            print item, self.all_offsets[item]
        for item in self.current_offsets:
            print 'current', item, self.current_offsets[item]

    def populate_offsets(self):
        '''
        get all hive offsets so we don't have to scan again...
        '''
        hive_offsets = []
        hiveroot = hl.HiveList.calculate(self)
        
        for hive in hiveroot:
            if hive.obj_offset not in hive_offsets:
                hive_offsets.append(hive.obj_offset) 
                try:
                    name = hive.FileFullPath.v() or hive.FileUserName.v() or hive.HiveRootPath.v() or "[no name]"
                except:
                    name = "[no name]"
                self.all_offsets[hive.obj_offset] = name

    def set_current(self, hive_name = None, user = None):
        '''
        if we find a hive that fits the given criteria, save its offset 
        so we don't have to scan again.  this can be reset using reset_current
        if context changes
        '''
        for item in self.all_offsets:
            name = self.all_offsets[item] + " " 
            if user == None and hive_name == None:
                #no particular preference: all hives
                self.current_offsets[item] = name
            elif user != None and name.lower().find('\\' + user.lower() + '\\') != -1 and name.lower().find("\\" + "ntuser.dat ") != -1: 
                #user's NTUSER.DAT hive
                self.current_offsets[item] = name
            elif hive_name != None and hive_name.lower() == 'hklm' \
                and (name.lower().find("\\security ") != -1 or name.lower().find("\\system ") != -1 \
                or name.lower().find("\\software ") != -1 or name.lower().find("\\sam ") != -1):
                #any HKLM hive 
                self.current_offsets[item] = name
            elif hive_name != None and name.lower().find("\\" + hive_name.lower() + " ") != -1: 
                #a particular hive indicated by hive_name
                if hive_name.lower() == "system" and name.lower().find("\\syscache.hve ") == -1:
                    self.current_offsets[item] = name
                elif hive_name.lower() != "system":
                    self.current_offsets[item] = name

    def reset_current(self):
        '''
        this is in case we switch to a different hive/user/context
        '''
        self.current_offsets = {}

    def reg_get_key(self, hive_name, key, user = None, given_root = None):
        '''
        Returns a key from a requested hive; assumes this is from a single hive
        if more than one hive is specified, the hive/key found is returned
        '''
        addr_space = utils.load_as(self._config)
        if self.all_offsets == {}:
            self.populate_offsets()
        if self.current_offsets == {}:
            self.set_current(hive_name, user)
        if key:
            for offset in self.current_offsets:
                if given_root == None:
                    h = hivemod.HiveAddressSpace(addr_space, self._config, offset)
                    root = rawreg.get_root(h)
                else:
                    root = given_root
                if root != None:
                    k = rawreg.open_key(root, key.split('\\'))
                    if k:
                        return k
        return None

    def reg_yield_key(self, hive_name, key, user = None, given_root = None):
        ''' 
        Use this function if you are collecting keys from more than one hive
        '''
        addr_space = utils.load_as(self._config)
        if self.all_offsets == {}:
            self.populate_offsets()
        if self.current_offsets == {}:
            self.set_current(hive_name, user)
        if key:
            for offset in self.current_offsets:
                name = self.current_offsets[offset]
                if given_root == None:
                    h = hivemod.HiveAddressSpace(addr_space, self._config, offset)
                    root = rawreg.get_root(h)
                else:
                    root = given_root
                if root != None:
                    k = rawreg.open_key(root, key.split('\\'))
                    if k:
                        yield k, name

    def reg_enum_key(self, hive_name, key, user = None):
        '''
        This function enumerates the requested key
        '''
        addr_space = utils.load_as(self._config)
        k = self.reg_get_key(hive_name, key, user)
        if k:
            for s in rawreg.subkeys(k):
                if s.Name:
                    item = key +  '\\' + s.Name
                    yield item

    def reg_get_all_subkeys(self, hive_name, key, user = None, given_root = None):
        '''
        This function enumerates the subkeys of the requested key
        '''
        addr_space = utils.load_as(self._config)
        if given_root == None:
            k = self.reg_get_key(hive_name, key, user)
        else:
            k = given_root
        if k:
            for s in rawreg.subkeys(k):
                if s.Name:
                    yield s
 
    def reg_get_value(self, hive_name, key, value, data = None):
        '''
        This function returns the requested value of a registry key
        '''
        addr_space = utils.load_as(self._config)
        if key and value:
            h = self.reg_get_key(hive_name, key)
            if h != None:
                for v in rawreg.values(h):
                    if value == v.Name:
                        tp, dat = rawreg.value_data(v)
                        if tp == 'REG_BINARY':
                            return dat
                        else:
                            dat = str(dat)
                            dat = dat.strip()
                            temp = ''
                            dat = temp.join([x for x in dat if ord(x) != 0])  #get rid of funky nulls for string comparison
                        if data != None and data == dat:
                            return dat 
                        elif data == None:
                            return dat
        return None

    def reg_get_all_keys(self, hive_name, user=None, start = None, end = None, reg = False):
        '''
        This function enumerates all keys in specified hives and 
        collects lastwrite times.
        '''
        addr_space = utils.load_as(self._config)
        keys = []
        if self.all_offsets == {}:
            self.populate_offsets()
        if self.current_offsets == {}:
            self.set_current(hive_name, user)
        
        for offset in self.current_offsets:
            reg_name = self.current_offsets[offset]  
            h = hivemod.HiveAddressSpace(addr_space, self._config, offset)
            root = rawreg.get_root(h)
            if not root:
                pass
            else:
                time = "{0}".format(root.LastWriteTime)
                if reg:
                    yield (time, reg_name, root.Name)
                else:
                    yield (time, root.Name)
                for s in rawreg.subkeys(root):
                    if reg:
                        keys.append([s, reg_name, root.Name + "\\" + s.Name])
                    else:
                        keys.append([s, root.Name + "\\" + s.Name])

        for k, reg_name, name in keys:
            time = "{0}".format(k.LastWriteTime)
            if start and end and time >= start and time <= end:
                if reg:
                    yield (time, reg_name, name)
                else:
                    yield (time, name)
            elif start == None and end == None:
                if reg:
                    yield (time, reg_name, name)
                else:
                    yield (time, name)

            for s in rawreg.subkeys(k):
                if name and s.Name:
                    item = name +  '\\' + s.Name
                    if reg:
                        keys.append([s, reg_name, item])
                    else:
                        keys.append([s, item])
            

    def reg_get_last_modified(self, hive_name, count = 1, user = None, start = None, end = None, reg = False):
        '''
        Wrapper function using reg_get_all_keys. These functions can take a WHILE since all 
        subkeys have to be collected before you can compare lastwrite times.
        '''
        data = nlargest(count, self.reg_get_all_keys(hive_name, user, start, end, reg))
        for t, _, name in data:
            yield (t, name)


    def calculate(self):
        addr_space = utils.load_as(self._config)

        if self._config.TIMELINE or self._config.KEY:
            pass
        else:
            print 'You must enter an option for this plugin (TIMELINE or KEY or KEY and VALUE)'
            return
       
        if self._config.TIMELINE and self._config.TIMELINE != -1:
            if (self._config.START and not self._config.END) or (self._config.END and not self._config.START):
                print "You must specify both START and END if you set a time period"
                return

            data = self.reg_get_last_modified(self._config.HIVE, self._config.TIMELINE, self._config.USER, self._config.START, self._config.END, True)

            yield 'Key Name', 'Last Write'
            for t, name in data:
                yield name,  t

        elif self._config.TIMELINE and self._config.TIMELINE == -1:
            data = self.reg_get_all_keys(self._config.HIVE, self._config.USER, self._config.START, self._config.END, True)
    
            for t, reg, name in data:
                yield name, reg, t

        elif self._config.KEY and not self._config.VALUE:
            yield 'Key Name', 'Remark'
            if self._config.USER:
                key = self.reg_get_key(self._config.USER, self._config.KEY)
            else:
                key = self.reg_get_key(self._config.HIVE, self._config.KEY)
            if key:
                yield self._config.KEY, 'FOUND'
            else:
                yield self._config.KEY, 'NOT FOUND'

        elif self._config.VALUE and self._config.KEY:
            yield 'Reg Value', 'Remark'
            if self._config.USER:
                key = self.reg_get_value(self._config.USER, self._config.KEY, self._config.VALUE)
            else:
                key = self.reg_get_value(self._config.HIVE, self._config.KEY, self._config.VALUE)
            if key:
                yield self._config.VALUE, 'FOUND'
            else:
                yield self._config.VALUE, 'NOT FOUND'


    def render_text(self, outfd, data):
        if self._config.TIMELINE == -1:
            for item, reg, remark in data:
                item = item.replace("|", "%7c")
                outfd.write("{0:<20}|{1}|{2}\n".format(remark, reg, item))
        else:
            for item, remark in data:
                outfd.write("{0:<20} {1}\n".format(remark, item))

