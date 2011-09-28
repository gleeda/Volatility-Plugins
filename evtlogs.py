# Volatility
# Copyright (C) 2008-2011 Volatile Systems
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
@author:       Jamie Levy (gleeda)
@license:      GNU General Public License 2.0 or later
@contact:      jamie.levy@gmail.com
@organization: Volatile Systems
"""

import volatility.plugins.malware as malware
import volatility.plugins.getsids as getsids
import volatility.plugins.registryapi as registryapi
import volatility.plugins.getservicesids as getservicesids
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.addrspace as addrspace
import volatility.obj as obj
import os, subprocess
import datetime
import string

# for more information on Event Log structures see WFA 2E pg 260-263 by Harlan Carvey

event_types = {
    0x01:"Error",
    0x02:"Warning",
    0x04:"Info",
    0x08:"Success",
    0x10:"Failure",
} 

evt_log_types = {
    'evt_log_header' : [ 0x30, {
        'header_size' : [ 0x0, ['int']],
        'magic' : [ 0x4, ['int']],  #LfLe
        'offset_oldest' : [ 0x10, ['int']],  #offset of oldest record
        'offset_next_to_write' : [ 0x14, ['int']],  #offset of next record to be written
        'next_ID' : [ 0x18, ['int']],  #next event record ID
        'oldest_ID' : [ 0x1c, ['int']], #oldest event record ID
        'max_size' : [ 0x20, ['int']],  #maximum size of event record (from registry)
        'retention_time' : [ 0x28, ['int']], #retention time of records (from registry)
        'record_size' : [ 0x2c, ['int']],  #size of the record (repeat of DWORD at offset 0)
    } ],

    'evt_record_struct' : [ 0x38, {
        'record_length' : [ 0x0, ['int']],
        'magic' : [ 0x4, ['int']],  #LfLe
        'record_number' : [ 0x8, ['int']],
        'time_generated' : [ 0xc, ['unsigned int']], 
        'time_written' : [ 0x10, ['unsigned int']],
        'event_ID' : [ 0x14, ['unsigned short']], #specific to event source and uniquely identifies the event
        'event_type' : [ 0x18, ['unsigned short']], #described above in event_types
        'num_strings' : [ 0x1a, ['unsigned short']], #number of description strings in even message
        'event_category' : [ 0x1c, ['unsigned short']],
        'reserved_flags' : [ 0x1e, ['unsigned short']],
        'closing_record_num' : [ 0x20, ['int']],
        'string_offset' : [ 0x24, ['int']], #offset w/in record of description strings
        'sid_length' : [ 0x28, ['int']], #length of SID: if 0 no SID is present
        'sid_offset' : [ 0x2c, ['int']], #offset w/in record to start of SID (if present)
        'data_length' : [ 0x30, ['int']], #length of binary data of record
        'data_offset' : [ 0x34, ['int']], #offset of data w/in record
    } ],
}

def remove_unprintable(str):
    return ''.join([c for c in str if (ord(c) > 31 or ord(c) == 9) and ord(c) <= 126])

class EvtLogs(malware.LdrModules, getservicesids.GetServiceSids, registryapi.RegistryAPI):
    """Extract Windows Event Logs (XP/2K3 only)"""
    def __init__(self, config, *args):
        config.remove_option("HIVE-OFFSET")
        malware.LdrModules.__init__(self, config, *args)
        registryapi.RegistryAPI.__init__(self, config, *args)

        self.extrasids = {}

        config.add_option('VERBOSE', short_option = 'v', default = False,
                          help = 'Get Service SIDs and User SIDs from Registry',
                          action = "store_true")

    def calculate(self):
        addr_space = utils.load_as(self._config)
        addr_space.profile.add_types(evt_log_types)
        if addr_space.profile.metadata.get('major', 0) != 5:
            print "This plugin only works on XP and 2K3"
            return

        if self._config.VERBOSE:
            self.reset_current()
            self.set_current("SYSTEM")
            ssids = getservicesids.GetServiceSids.calculate(self)
            for sid, service in ssids:
                self.extrasids[sid] = " (Service: " + service + ")" 
        else:
            for sid in self.extrasids:
                self.extrasids[sid] = " (Service: " + self.extrasids[sid] + ")"

        self.reset_current()
        self.set_current("SOFTWARE")
        for k1 in self.reg_enum_key('SOFTWARE', 'Microsoft\\Windows NT\\CurrentVersion\\ProfileList'):
            val = self.reg_get_value('SOFTWARE',  k1, 'ProfileImagePath')
            sid = k1.split("\\")[-1]
            if val != None:
                self.extrasids[sid] = " (User: " + val.split("\\")[-1] + ")"

        for proc in tasks.pslist(addr_space):
            if str(proc.ImageFileName).lower() == "services.exe":
                map = self.list_mapped_files(proc, pe_only=False, get_data=True)
                for key, (name, buf) in map.items():
                    if name and buf:
                        name = str(name).lower()
                        if name.endswith(".evt"):
                            yield name, buf
    
    def time_stamp(self, unix_time):
        try:
            dt = datetime.datetime.utcfromtimestamp(unix_time)
        except ValueError, e:
            return None
        return dt

    def get_locs(self, buf):
        loc = buf.find("LfLe")
        locs = []
        if loc == -1:
            return locs
        locs.append(loc)
        while 1:
            loc = buf.find("LfLe", loc + 1)
            if loc == -1:
                return locs
            locs.append(loc)

    def render_dump(self, outfd, data):
        for name, buf in data:
            ofname = os.path.basename(name.replace('\\', '/'))
            fh = open(ofname, "wb")
            fh.write(buf)
            fh.close()
            outfd.write('Saved {0} bytes to {1}\n'.format(len(buf), ofname))

    def parse_evt_info(self, name, buf):
        ofname = os.path.basename(name.replace('\\', '/'))
        locs = self.get_locs(buf)
        lines = []
        for i in range(0, len(locs)):
            line = ""
            loc = locs[i]
            if loc == 4:
                #this is the header, ignore
                #or you can parse out the header info
                '''
                if buf != None:
                    bufferas = addrspace.BufferAddressSpace(self._config, data = buf)
                    evtlogheader = obj.Object("evt_log_header", offset = 0, vm = bufferas)
                if evtlogheader != None:
                    print "0x%x" % evtlogheader.magic
                '''
                continue
            if i == len(locs) - 1:
                next_loc = -1
            else:
                next_loc = locs[i+1]
            rec = buf[loc-4:]
            bufferas = addrspace.BufferAddressSpace(self._config, data = rec)
            evtlog = obj.Object("evt_record_struct", offset = 0, vm = bufferas)
            if next_loc == -1:
                raw_data = buf[loc-4:]
            else:
                raw_data = buf[loc-4:(next_loc - 1)]
            computer_name = ""
            source = ""
            sid_string = "N/A"
            if evtlog.sid_length == 0:
                end = evtlog.string_offset
            else:
                end = evtlog.sid_offset
                sid_name = ""
                s = rec[evtlog.sid_offset:evtlog.sid_offset + evtlog.sid_length]
                bufferas = addrspace.BufferAddressSpace(self._config, data = s)
                sid = obj.Object("_SID", offset = 0, vm = bufferas)
                for i in sid.IdentifierAuthority.Value:
                    id_auth = i 
                sid_string = "S-" + "-".join(str(i) for i in (sid.Revision, id_auth) + tuple(sid.SubAuthority))
                if sid_string in getsids.well_known_sids:
                    sid_name = " ({0})".format(getsids.well_known_sids[sid_string])
                else:
                    sid_name_re = getsids.find_sid_re(sid_string, getsids.well_known_sid_re)
                    if sid_name_re:
                        sid_name = " ({0})".format(sid_name_re)
                    else:
                        try:
                            sid_name = self.extrasids[sid_string]
                        except KeyError:
                            sid_name = ""
                sid_string += sid_name
            try:
                source = remove_unprintable(raw_data[56:end].split("\x00\x00")[0])
                computer_name = remove_unprintable(raw_data[56:end].split("\x00\x00")[1])
            except IndexError:
                pass
            stuff = raw_data[evtlog.string_offset:].split("\x00\x00", evtlog.num_strings)
            if evtlog.num_strings == 0:
                msg = "N/A"
            else:
                msg = None
                for i in range(0, evtlog.num_strings):
                    try:
                        item = remove_unprintable(stuff[i])
                    except IndexError:
                        item = ""
                    if msg != None: 
                        msg +=  ";" + item
                    else:
                        msg = item
            try:
                type = event_types[int(evtlog.event_type)]
            except KeyError:
                #not sure if there are other types, but in case:
                type = "UNKNOWN"

            ts = str(self.time_stamp(evtlog.time_written))
            if ts != None:
                msg = msg.replace("|", "%7c")
                line = '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}\n'.format(
                    ts,
                    ofname,
                    computer_name,
                    sid_string,
                    source,
                    str(evtlog.event_ID),
                    type,
                    msg)
                lines.append(line)
        return lines

    def render_text(self, outfd, data):
        for name, buf in data: 
            ofname = os.path.basename(name.replace('\\', '/'))
            ofname = ofname.replace(".evt", ".txt")
            lines = self.parse_evt_info(name, buf)
            fh = open(ofname, "wb")
            for line in lines:
                fh.write(line)    
            fh.close()
            outfd.write('Parsed data sent to {0}\n'.format( ofname))

