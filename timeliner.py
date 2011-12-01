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

import volatility.plugins.taskmods as taskmods
import volatility.plugins.filescan as filescan
import volatility.plugins.sockets as sockets
import volatility.plugins.sockscan as sockscan
import volatility.plugins.modscan as modscan
import volatility.plugins.procdump as  procdump
import volatility.plugins.dlldump as dlldump
import volatility.plugins.moddump as moddump
import volatility.plugins.netscan as netscan
import volatility.plugins.evtlogs as evtlogs
import volatility.plugins.registryapi as registryapi
import volatility.plugins.userassist as userassist
import volatility.plugins.imageinfo as imageinfo
import volatility.win32.rawreg as rawreg
import volatility.addrspace as addrspace
import volatility.plugins.overlays.windows.windows as windows
import volatility.utils as utils
import volatility.protos as protos
import os, sys
import struct
import volatility.debug as debug
import volatility.obj as obj 
import datetime

class TimeLiner(filescan.PSScan, sockets.Sockets, 
                sockscan.SockScan,
                modscan.ThrdScan, 
                dlldump.DLLDump,
                moddump.ModDump,
                procdump.ProcExeDump, 
                modscan.ModScan, 
                netscan.Netscan,
                evtlogs.EvtLogs,
                userassist.UserAssist,
                registryapi.RegistryAPI,
                imageinfo.ImageInfo):
    """ Creates a timeline from various artifacts in memory """

    def __init__(self, config, *args):  
        config.remove_option("HIVE-OFFSET")
        userassist.UserAssist.__init__(self, config, *args)
        config.remove_option("HIVE-OFFSET")
        registryapi.RegistryAPI.__init__(self, config, *args)
        config.remove_option("HIVE-OFFSET")
        filescan.PSScan.__init__(self, config, *args)
        sockscan.SockScan.__init__(self, config, *args)
        sockets.Sockets.__init__(self, config, *args)
        modscan.ThrdScan.__init__(self, config, *args)
        dlldump.DLLDump.__init__(self, config, *args)
        procdump.ProcExeDump.__init__(self, config, *args)
        modscan.ModScan.__init__(self, config, *args)
        moddump.ModDump.__init__(self, config, *args)
        netscan.Netscan.__init__(self, config, *args)
        evtlogs.EvtLogs.__init__(self, config, *args)
        imageinfo.ImageInfo.__init__(self, config, *args)
        config.add_option("UNSAFE", short_option = "u", default = False, action = 'store_true',
                          help = 'Bypasses certain sanity checks when creating image')
        config.remove_option("KEY")
        config.remove_option("START")
        config.remove_option("END")
        config.remove_option("VALUE")


    def render_text(self, outfd, data):
        for line in data:
            if line != None:
                outfd.write(line)

    def calculate(self):
        addr_space = utils.load_as(self._config)

        self._config.update('TIMELINE', -1)
        pids = {}     #dictionary of process IDs/ImageFileName
        offsets = []  #process offsets
        
        im = self.get_image_time(addr_space) 
        event = "{0}|[END LIVE RESPONSE]\n".format(im['ImageDatetime'])
        yield event
                

        # Get EPROCESS 
        psscan = filescan.PSScan.calculate(self)
        for eprocess in psscan:
            if eprocess.obj_offset not in offsets:
                offsets.append(eprocess.obj_offset)

            ts = eprocess.CreateTime or '-1'
            line = "{0}|{1}|{2}|{3}|{4}|{5}|0x{6:08x}||\n".format(
                    eprocess.CreateTime or '-1', 
                    "[PROCESS]",
                    eprocess.ImageFileName,
                    eprocess.UniqueProcessId,
                    eprocess.InheritedFromUniqueProcessId,
                    eprocess.ExitTime or '',
                    eprocess.obj_offset)
            pids[eprocess.UniqueProcessId.v()] = eprocess.ImageFileName
            yield line 

        # Get Sockets and Evtlogs XP/2k3 only
        if addr_space.profile.metadata.get('major', 0) == 5:
            socks = sockets.Sockets.calculate(self)
            #socks = sockscan.SockScan.calculate(self)   # you can use sockscan instead if you uncomment
            for sock in socks:
                la = "{0}:{1}".format(sock.LocalIpAddress, sock.LocalPort)
                line = "{0}|[SOCKET]|{1}|{2}|Protocol: {3} ({4})|{5:#010x}|||\n".format(
                        sock.CreateTime, 
                        sock.Pid, 
                        la,
                        sock.Protocol,
                        protos.protos.get(sock.Protocol.v(), "-"),
                        sock.obj_offset)
                yield line

            stuff = evtlogs.EvtLogs.calculate(self)
            for name, buf in stuff:
                lines = self.parse_evt_info(name, buf)
                for l in lines:
                    l = l.replace("\n","")
                    t = l.split("|")
                    line = '{0} |[EVT LOG]|{1}|{2}|{3}|{4}|{5}|{6}|{7}\n'.format(
                            t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7])
                    yield line
        else:
            # Vista+
            nets = netscan.Netscan.calculate(self)
            for offset, proto, laddr, lport, raddr, rport, state, p, ctime in nets:
                conn = "{0}:{1} -> {2}:{3}".format(laddr, lport, raddr, rport)
                line = "{0}|[NETWORK CONNECTION]|{1}|{2}|{3}|{4}|{5:<#10x}||\n".format(
                        ctime,
                        p.UniqueProcessId,
                        conn,
                        proto,
                        state,
                        offset)
                yield line

        # Get threads
        threads = modscan.ThrdScan.calculate(self)
        for thread in threads:
            try:
                image = pids[thread.Cid.UniqueProcess.v()]
            except:
                image = ""
            line = "{0}|{1}|{2}|{3}|{4}|{5}|||\n".format(
                    thread.CreateTime or '-1',
                    "[THREAD]",
                    image,
                    thread.Cid.UniqueProcess,
                    thread.Cid.UniqueThread,
                    thread.ExitTime or '',
                    )
            yield line

        # now we get to the PE part.  All PE's are dumped in case you want to inspect them later
    
        # Get module offsets by scanning
        mod_offsets = []
        data = modscan.ModScan.calculate(self)
        for module in data:
            base = "{0:#010x}".format(module.DllBase)
            mod_offsets.append(base)

        # and get PE timestamps for those modules
        for base in mod_offsets:
            self._config.update('OFFSET', int(base, 16))
            data = moddump.ModDump.calculate(self)

            for addr_space, procs, mod_base, mod_name in data:
                space = self.find_space(addr_space, procs, mod_base)
                if space != None:
                    try:
                        header = self.get_nt_header(space, mod_base)
                    except ValueError, ve: 
                        continue

                    try:
                        line = "{0}|{1}|{2}|{3}|{4:#010x}|||||\n".format(
                            self.time_stamp(header.FileHeader.TimeDateStamp) or '-1',
                            "[PE Timestamp (module)]",
                            mod_name,
                            "",
                            mod_base)
                    except:
                        line = "{0}|{1}|{2}|{3}|{4}|||||\n".format(
                            '-1',
                            "[PE Timestamp (module)]",
                            mod_name,
                            "",
                            mod_base)
                    yield line


        # get EPROCESS PE timestamps
        for o in offsets:
            self._config.update('OFFSET', o)
            data = self.filter_tasks(procdump.ProcExeDump.calculate(self))
            dllskip = False
            for task in data:
                if task.Peb == None or task.Peb.ImageBaseAddress == None:
                    dllskip = True
                    continue

                try:
                    header = self.get_nt_header(task.get_process_address_space(), task.Peb.ImageBaseAddress)
                except ValueError, ve:
                    dllskip = True
                    continue

                try:
                    line = "{0}|{1}|{2}|{3}|{4}|{5}|0x{6:08x}|||\n".format(
                            self.time_stamp(header.FileHeader.TimeDateStamp) or "-1",
                            "[PE Timestamp (exe)]",
                            task.ImageFileName,
                            task.UniqueProcessId,
                            task.InheritedFromUniqueProcessId,
                            task.Peb.ProcessParameters.CommandLine,
                            o)
                except:
                    line = "{0}|{1}|{2}|{3}|{4}|{5}|0x{6:08x}|||\n".format(
                            "-1",
                            "[PE Timestamp (exe)]",
                            task.ImageFileName,
                            task.UniqueProcessId,
                            task.InheritedFromUniqueProcessId,
                            task.Peb.ProcessParameters.CommandLine,
                            o)
                yield line

            # Get DLL PE timestamps
            if not dllskip:
                dlls = self.filter_tasks(dlldump.DLLDump.calculate(self))
            else:
                dllskip = False
                dlls = []
            for proc, ps_ad, mod in dlls:
                if ps_ad.is_valid_address(mod.DllBase):
                    if mod.FullDllName == task.ImageFileName:
                        continue
                    try:
                        header = self.get_nt_header(ps_ad, mod.DllBase)
                    except ValueError, ve: 
                        continue
                    try:
                        line = "{0}|{1}|{2}|{3}|{4}|{5}|EPROCESS Offset: 0x{6:08x}|DLL Base: {7:8x}||\n".format(
                            self.time_stamp(header.FileHeader.TimeDateStamp) or '-1',
                            "[PE Timestamp (dll)]",
                            task.ImageFileName,
                            task.UniqueProcessId,
                            task.InheritedFromUniqueProcessId,
                            mod.FullDllName,
                            o,
                            mod.DllBase)
                    except:
                        line = "{0}|{1}|{2}|{3}|{4}|{5}|EPROCESS Offset: 0x{6:08x}|DLL Base: {7:8x}||\n".format(
                            "-1",
                            "[PE Timestamp (dll)]",
                            task.ImageFileName,
                            task.UniqueProcessId,
                            task.InheritedFromUniqueProcessId,
                            mod.FullDllName,
                            o,
                            mod.DllBase)
                    yield line

        self.reset_current()
        uastuff = userassist.UserAssist.calculate(self)
        for win7, reg, key in uastuff:
            ts = "{0}".format(key.LastWriteTime)
            for v in rawreg.values(key):
                tp, dat = rawreg.value_data(v)
                subname = v.Name
                if tp == 'REG_BINARY':
                    dat_raw = dat
                    try:
                        subname = subname.encode('rot_13')
                    except:
                        pass
                    if win7:
                        guid = subname.split("\\")[0]
                        if guid in userassist.folder_guids:
                            subname = subname.replace(guid, userassist.folder_guids[guid])
                    bufferas = addrspace.BufferAddressSpace(self._config, data = dat_raw)
                    uadata = obj.Object("_VOLUSER_ASSIST_TYPES", offset = 0, vm = bufferas)
                    ID = "N/A"
                    count = "N/A"
                    fc = "N/A"
                    tf = "N/A"
                    lw = "N/A"
                    if len(dat_raw) < bufferas.profile.get_obj_size('_VOLUSER_ASSIST_TYPES') or uadata == None:
                        pass
                    else:
                        if hasattr(uadata, "ID"):
                            ID = "{0}".format(uadata.ID)
                        if hasattr(uadata, "Count"):
                            count = "{0}".format(uadata.Count)
                        else:
                            count = "{0}".format(uadata.CountStartingAtFive if uadata.CountStartingAtFive < 5 else uadata.CountStartingAtFive - 5)
                        if hasattr(uadata, "FocusCount"):
                            seconds = (uadata.FocusTime + 500) / 1000.0
                            time = datetime.timedelta(seconds = seconds) if seconds > 0 else uadata.FocusTime
                            fc = "{0}".format(uadata.FocusCount)
                            tf = "{0}".format(time)
                        lw = "{0}".format(uadata.LastUpdated)

                subname = subname.replace("|", "%7c")
                line = "{0}|[USER ASSIST]|{1}|{2}|{3}|{4}|{5}|{6}\n".format(lw, reg, subname, ID, count, fc, tf)
                yield line

        #self._config.update("HIVE", "system") #you could use this if you wanted to only look at one particular registry
        regs = registryapi.RegistryAPI.calculate(self)
        for item, reg, remark in regs:
            item = item.replace("|", "%7c")
            line = "{0}|[REGISTRY]|{1}|{2}|||||\n".format(remark, reg, item)
            yield line

