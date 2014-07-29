# copyright 2011-2014 LOGILAB S.A. (Paris, FRANCE), all rights reserved.
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
# You should have received a copy of the GNU Lesser General Public License along
# with this program. If not, see <http://www.gnu.org/licenses/>.

from logilab.common.decorators import monkeypatch
from cubicweb.__pkginfo__ import numversion
from cubicweb.server.sources.native import NativeSQLSource


# sqlite: monkeypatching is not sufficient
# because the native source already does live patching
# create_eid at __init__ time (before _this module_ is
# even loaded).

if numversion[:2] < (3, 19):
    @monkeypatch(NativeSQLSource)
    def _create_eid_sqlite(self, session, count=1, eids=None):
        with self._eid_cnx_lock:
            eids = []
            for _x in xrange(count):
                for sql in self.dbhelper.sqls_increment_sequence('entities_id_seq'):
                    cursor = self.doexec(session, sql)
                eids.append(cursor.fetchone()[0])
            if count > 1:
                return eids
            return eids[0]

    # postgres / sqlserver

    @monkeypatch(NativeSQLSource)
    def create_eid(self, session, count=1):
        with self._eid_cnx_lock:
            return self._create_eid(count)

    @monkeypatch(NativeSQLSource)
    def _create_eid(self, count, eids=None):
        # internal function doing the eid creation without locking.
        # needed for the recursive handling of disconnections (otherwise we
        # deadlock on self._eid_cnx_lock
        if self._eid_creation_cnx is None:
            self._eid_creation_cnx = self.get_connection()
        cnx = self._eid_creation_cnx
        try:
            eids = eids or []
            cursor = cnx.cursor()
            for _x in xrange(count):
                for sql in self.dbhelper.sqls_increment_sequence('entities_id_seq'):
                    cursor.execute(sql)
                eids.append(cursor.fetchone()[0])
        except (self.OperationalError, self.InterfaceError):
            # FIXME: better detection of deconnection pb
            self.warning("trying to reconnect create eid connection")
            self._eid_creation_cnx = None
            return self._create_eid(count, eids)
        except self.DbapiError as exc:
            # We get this one with pyodbc and SQL Server when connection was reset
            if exc.args[0] == '08S01':
                self.warning("trying to reconnect create eid connection")
                self._eid_creation_cnx = None
                return self._create_eid(count, eids)
            else:
                raise
        except Exception:
            cnx.rollback()
            self._eid_creation_cnx = None
            self.exception('create eid failed in an unforeseen way on SQL statement %s', sql)
            raise
        else:
            cnx.commit()
            # one eid vs many
            # we must take a list because the postgres sequence does not
            # ensure a contiguous sequence
            if count > 1:
                return eids
            return eids[0]
