from cubicweb.__pkginfo__ import numversion
from cubicweb.devtools.testlib import CubicWebTC

class FastImportTC(CubicWebTC):

    def setUp(self):
        super(FastImportTC, self).setUp()
        if numversion[:2] < (3, 19):
            # utils monkeypatch had the time to fire
            patched_create_eid = self.session.repo.system_source._create_eid_sqlite
            self.session.repo.system_source.create_eid = patched_create_eid
