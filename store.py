# -*- coding: utf-8 -*-
# copyright 2016 LOGILAB S.A. (Paris, FRANCE), all rights reserved.
# contact http://www.logilab.fr -- mailto:contact@logilab.fr
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 2.1 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
from collections import defaultdict

from cubes.fastimport.entities import reserve_eids, FlushController


class FastImportStore(object):
    eidbatchsize = 10
    disabled_regids = ('htmltidy',)

    def __init__(self, cnx):
        self.cnx = cnx
        self.fc = FlushController(cnx, self.disabled_regids)
        self.edicts_by_etype = defaultdict(list)
        self.subjobj_by_rtype = defaultdict(list)
        self.eidseq = reserve_eids(cnx, self.eidbatchsize)

    def _neweid(self):
        try:
            return self.eidseq.next()
        except StopIteration:
            self.eidseq = reserve_eids(self.cnx, self.eidbatchsize)
            return self._neweid()

    def prepare_insert_entity(self, etype, **kw):
        self.edicts_by_etype[etype].append((kw, None))
        eid = self._neweid()
        kw['eid'] = eid
        return eid

    def prepare_insert_relation(self, eidfrom, rtype, eidto):
        self.subjobj_by_rtype[rtype].append((eidfrom, eidto))

    def flush(self):
        # entities
        for etype, edicts in self.edicts_by_etype.iteritems():
            self.fc.insert_entities(etype, edicts, _store=True)

        # relations
        entity = self.cnx.entity_from_eid
        for rtype, subjobjs in self.subjobj_by_rtype.iteritems():
            self.fc.insert_relations(rtype,
                                     [(entity(subjeid), entity(objeid))
                                      for subjeid, objeid in subjobjs])

        # reset
        self.edicts_by_etype = defaultdict(list)
        self.subjobj_by_rtype = defaultdict(list)

    def commit(self):
        self.cnx.commit()
