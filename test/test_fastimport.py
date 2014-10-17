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

from cubes.worker.testutils import run_all_tasks

from cubes.fastimport.entities import FlushController as FC
from cubes.fastimport.testutils import FastImportTC

class DefaultTC(FastImportTC):

    def test_an_import(self):
        session = self.session
        controller = FC(session, disabled_regids=('disable_me_directly',))

        # collect & insert groups
        cwgroups = []
        group_by_name = {}
        with open(osp.join(self.datadir, 'cwgroups.csv'), 'rb') as groupsfile:
            reader = csv.DictReader(groupsfile)
            for item in reader:
                cwgroups.append((item,))

        def newgroup_callback(entity, *args):
            group_by_name[entity.name] = entity
        controller.insert_entities('CWGroup', cwgroups, newgroup_callback)

        # collect cwuser data, prepare emails and group relations
        cwusers = []
        in_group = []
        emails_by_address= {}
        with open(osp.join(self.datadir, 'cwusers.csv'), 'rb') as usersfile:
            reader = csv.DictReader(usersfile)
            for item in reader:
                item = dict((k, v.decode('utf-8'))
                            for k, v in item.iteritems())
                for name in item.pop('groups', '').split(','):
                    in_group.append((item['login'], name))
                email = item.pop('email')
                if email: # my_email is an inlined relation -> in a cwuser column
                    emails_by_address[email] = ({'address': email}, item['login'])
                item['my_email'] = None
                cwusers.append((item, email))

        # insert emails
        def newemail_callback(entity, *args):
            # remap address -> eid
            emails_by_address[entity.address] = entity.eid # address -> eid
        emails = controller.insert_entities('EmailAddress', emails_by_address.values(), newemail_callback)
        # now, resolve these 'my_email' relations for which
        # we've got a value
        for cwuser, emailaddress in cwusers:
            if emailaddress:
                cwuser['my_email'] = emails_by_address[emailaddress] # -> eid

        # insert users
        user_by_login = {}
        def newcwuser_callback(entity, *args):
            user_by_login[entity.login] = entity
        with session.allow_all_hooks_but('disable-me'):
            controller.insert_entities('CWUser', cwusers,
                                       processentity=newcwuser_callback)

        # insert user in_group group
        getgroup = partial(session.execute, 'CWGroup G WHERE G name %(n)s')
        controller.insert_relations('in_group',
                                    [(user_by_login[login],
                                      group_by_name.get(name, getgroup({'n':name}).get_entity(0,0)))
                                     for login, name in in_group])

        # run vectorized & collect deferred hooks
        errors = []
        controller.run_deferred_hooks(errors)
        self.assertEqual([], errors)
        session.commit()

        session = self.session
        self.assertEqual(0, session.execute('Any X WHERE X has_text "gmail"').rowcount)
        self.assertNone(self.session.data.get('BABAR_WAS_THERE'))
        self.assertNone(self.session.data.get('CELESTE_WAS_THERE'))

        # let the deferred-hooks task run
        run_all_tasks(self.session)
        session.commit()

        # we should be green
        session = self.session
        self.assertEqual(1, session.execute('Any X WHERE X has_text "gmail"').rowcount)

        # test: we must be robust against group_concat ordering, which changed between cw 3.17 and 3.18
        rows = self.session.execute('Any UN,E,group_concat(GN) GROUPBY UN,E '
                                    'WHERE U in_group G, U my_email XE,'
                                    'U login UN, G name GN, XE address E').rows

        self.assertEqual([[u'auc', u'aurelien.campeas@gmail.com', [u'staff', u'users']],
                          [u'bedos', u'guy@bed.os', [u'humorists', u'users']],
                          [u'dtomanos', u'dimitri@tomanos.info', [u'staff', u'users']],
                          [u'gadelmaleh', u'gad@elmaleh.com', [u'humorists', u'users']]],
                         [[login, mail, sorted(group.strip() for group in groups.split(','))]
                          for login, mail, groups in rows])

        self.assertEqual([[u'guests', 1], [u'managers', 1], [u'owners', 1],
                          [u'users', 1], [u'staff', 1], [u'humorists', 1]],
                         self.execute('Any N,S ORDERBY X WHERE X is CWGroup, X name N, X cw_source S?').rows)


if __name__ == '__main__':
    from logilab.common.testlib import unittest_main
    unittest_main()
