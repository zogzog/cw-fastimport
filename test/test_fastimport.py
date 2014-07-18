# copyright 2014 LOGILAB S.A. (Paris, FRANCE), all rights reserved.
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

"""cubicweb-fastimport automatic tests


uncomment code below if you want to activate automatic test for your cube:

.. sourcecode:: python

    from cubicweb.devtools.testlib import AutomaticWebTest

    class AutomaticWebTest(AutomaticWebTest):
        '''provides `to_test_etypes` and/or `list_startup_views` implementation
        to limit test scope
        '''

        def to_test_etypes(self):
            '''only test views for entities of the returned types'''
            return set(('My', 'Cube', 'Entity', 'Types'))

        def list_startup_views(self):
            '''only test startup views of the returned identifiers'''
            return ('some', 'startup', 'views')
"""

import os.path as osp
import csv
from functools import partial

from cubicweb.devtools import testlib
from cubes.fastimport.entities import FlushController as FC

class DefaultTC(testlib.CubicWebTC):

    def test_an_import(self):
        controller = FC(self.session, self.schema, ())

        cwgroups = []
        group_by_name = {}
        with open(osp.join(self.datadir, 'cwgroups.csv'), 'rb') as groupsfile:
            reader = csv.DictReader(groupsfile)
            for item in reader:
                cwgroups.append((item,))

        def newgroup_callback(entity, *args):
            group_by_name[entity.name] = entity
        controller.insert_entities('CWGroup', cwgroups, newgroup_callback)

        cwusers = []
        in_group = []
        with open(osp.join(self.datadir, 'cwusers.csv'), 'rb') as usersfile:
            reader = csv.DictReader(usersfile)
            for item in reader:
                item = dict((k, v.decode('utf-8'))
                            for k, v in item.iteritems())
                for name in item.pop('groups', '').split(','):
                    in_group.append((item['login'], name))
                cwusers.append((item,))

        user_by_login = {}
        def newcwuser_callback(entity, *args):
            user_by_login[entity.login] = entity
        controller.insert_entities('CWUser', cwusers, newcwuser_callback)

        getgroup = partial(self.session.execute, 'CWGroup G WHERE G name %(n)s')
        controller.insert_relations('in_group',
                                    [(user_by_login[login],
                                      group_by_name.get(name, getgroup({'n':name}).get_entity(0,0)))
                                     for login, name in in_group])
        self.commit()

        self.assertEqual([[u'anon', u'guests'],
                          [u'admin', u'managers'],
                          [u'auc', u'users'],
                          [u'dtomanos', u'users'],
                          [u'gadelmaleh', u'users'],
                          [u'bedos', u'users'],
                          [u'auc', u'staff'],
                          [u'dtomanos', u'staff'],
                          [u'gadelmaleh', u'humorists'],
                          [u'bedos', u'humorists']],
                         self.session.execute('Any UN,GN WHERE U in_group G, '
                                              'U login UN, G name GN').rows)

if __name__ == '__main__':
    from logilab.common.testlib import unittest_main
    unittest_main()
