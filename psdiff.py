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

import volatility.plugins.taskmods as taskmods
import volatility.plugins.filescan as filescan
import volatility.utils as utils


# original how-to: http://gleeda.blogspot.com/2011/04/whats-difference-brief-volatility-14.html

class PSDiff(filescan.PSScan, taskmods.PSList):
    """ Prints a processes found by psscan, but not in pslist"""

    def __init__(self, config, *args):
        filescan.PSScan.__init__(self, config, *args)
        taskmods.PSList.__init__(self, config, *args)


    def calculate(self):
        addr_space = utils.load_as(self._config)
        pslist = taskmods.PSList.calculate(self)
        psscan = filescan.PSScan.calculate(self)

        '''
        # uncomment this to use pids instead

        pslist_pids = [p.UniqueProcessId for p in pslist]

        for p in psscan:
            if p.UniqueProcessId not in pslist_pids:
                yield p
        '''
        
        psoffsets = [p.obj_vm.vtop(p.obj_offset) for p in pslist]

        for p in psscan:
            if p.obj_offset not in psoffsets:
                yield p

    def render_text(self, outfd, data):
        self.table_header(outfd, [('Offset(P)', '[addrpad]'),
                                  ('Name', '16'),
                                  ('PID', '>6'),
                                  ('PPID', '>6'),
                                  ('PDB', '[addrpad]'),
                                  ('Time created', '20'),
                                  ('Time exited', '20')
                                  ])  

        for eprocess in data:
            self.table_row(outfd,
                eprocess.obj_offset,
                eprocess.ImageFileName,
                eprocess.UniqueProcessId,
                eprocess.InheritedFromUniqueProcessId,
                eprocess.Pcb.DirectoryTableBase,
                eprocess.CreateTime or '', 
                eprocess.ExitTime or '')


