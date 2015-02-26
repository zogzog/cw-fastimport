# -*- coding: utf-8 -*-
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

"""cubicweb-fastimport entity's classes"""
from collections import defaultdict
from itertools import izip
from contextlib import contextmanager
from datetime import datetime
from logging import getLogger
from cPickle import dumps, loads

from cubicweb import neg_role, validation_error, Binary, ValidationError
from cubicweb.rset import ResultSet
from cubicweb.schema import RQLConstraint
from cubicweb import server
from cubicweb.server.edition import EditedEntity
from cubicweb.server.utils import eschema_eid
from cubicweb.server.session import Session
from cubicweb.hooks.integrity import DONT_CHECK_RTYPES_ON_ADD

from cubes.worker.entities import Performer

from cubes.fastimport.utils import nohook
from cubes.fastimport.hooks import HooksRunner


YAMS_TO_PY_TYPEMAP = defaultdict(
    lambda : lambda x:x,
    {
        'Float': float,
        'Int': int,
        'String': unicode
    })

def _insertmany(cnx, table, attributes, prefix=''):
    """ Low-level INSERT many entities of the same etype
    at once
    """
    # the low-level python-dbapi cursor
    cursor = cnx.cnxset.cu
    columns = sorted(attributes[0])
    cursor.executemany('INSERT INTO %s (%s) VALUES (%s)' % (
        prefix + table,                                    # table name
        ','.join(prefix + name for name in columns),       # column names
        ','.join('%%(%s)s' %  name for name in columns)),  # dbapi placeholders
                       attributes)

def _default_value(rdef, utcnow):
    """ compute the real default value of an rdef
    (because rdef.default is unreliable)
    """
    default = rdef.default
    # default values fixed in cw 3.18
    if rdef.object.type == 'Boolean':
        if isinstance(default, bool):
            return default
        return default != ''
    if default == 'TODAY':
        if rdef.object.type == 'Date':
            return utcnow.date()
        else:
            assert rdef.object.type == 'Datetime'
            return utcnow
    if default == 'NOW':
        assert rdef.object.type == 'Datetime'
        return utcnow
    if default is not None:
        default = YAMS_TO_PY_TYPEMAP[rdef.object.type](default)
    return default

def _iter_attr_default(eschema, utcnow):
    for rschema in eschema.subject_relations():
        if rschema.meta:
            continue
        if not (rschema.final or rschema.inlined):
            continue
        rdef = eschema.rdef(rschema.type)
        default = _default_value(rdef, utcnow) if rschema.final else None
        yield rschema.type, default

# variant of cnx._update_entity_rel_cache_add that gets
# the entities
def _update_entity_rel_cache_add(cnx, entity, rtype, role, targetentity, otherside=False):
    rcache = entity.cw_relation_cached(rtype, role)
    if rcache is None:
        rset = ResultSet([[targetentity.eid]], 'Any X WHERE X eid %s' % targetentity.eid,
                         description=[[targetentity.cw_etype]])
        rset.req = cnx
        entities = []
    else:
        rset, entities = rcache
        rset = rset.copy()
        entities = list(entities)
        rset.rows.append([targetentity.eid])
        if not isinstance(rset.description, list): # else description not set
            rset.description = list(rset.description)
        rset.description.append([targetentity.cw_etype])
    if targetentity.cw_rset is None:
        targetentity.cw_rset = rset
        targetentity.cw_row = rset.rowcount
        targetentity.cw_col = 0
    rset.rowcount += 1
    entities.append(targetentity)
    entity._cw_related_cache['%s_%s' % (rtype, role)] = (rset, tuple(entities))
    if not otherside:
        _update_entity_rel_cache_add(cnx, targetentity, rtype, neg_role(role), entity, True)


def reserve_eids(cnx, qty):
    source = cnx.repo.system_source
    if qty == 1:
        yield source.create_eid(cnx)
    lasteid = source.create_eid(cnx, count=qty)
    start = lasteid - qty + 1
    for eid in xrange(start, lasteid + 1):
        yield eid


class FlushController(object):
    hooksrunnerclass = HooksRunner
    loggername = 'cubicweb'
    # vectorized hooks are open-coded within the hooks runner
    vectorized_entity_hooks = ('checkcard_after_add_entity',
                               'setowner',
                               'metaattrsinit',
                               'checkattrconstraint',)
    deferred_entity_hooks = ('supervising',)
    vectorized_relation_hooks = ('checkconstraint',)
    deferred_relation_hooks = ('updateftirel',
                               'notifyrelationchange')

    # debatable option
    handle_cw_source_relation = True

    def __init__(self, cnx,
                 disabled_regids=(),
                 deferred_entity_hooks=(),
                 deferred_relation_hooks=()):
        self.cnx = cnx
        cnx.mode = 'write'
        self.schema = cnx.vreg.schema
        self.logger = getLogger(self.loggername)
        self.hooksrunner = self.hooksrunnerclass(self.logger,
                                                 cnx,
                                                 disabled_regids,
                                                 (deferred_entity_hooks +
                                                  self.vectorized_entity_hooks +
                                                  self.deferred_entity_hooks),
                                                 (deferred_relation_hooks +
                                                  self.vectorized_relation_hooks +
                                                  self.deferred_relation_hooks))

    def insert_relations(self, rtype, fromto, _update_relcache=True):
        cnx = self.cnx
        runhooks = not nohook(cnx)
        if runhooks:
            self.hooksrunner.call_rtype_hooks('before_add', rtype, fromto)

        _insertmany(cnx, rtype + '_relation',
                    [{'eid_from': fromentity.eid, 'eid_to': toentity.eid}
                     for fromentity, toentity in fromto])

        if runhooks:
            if _update_relcache:
                for subjentity, objentity in fromto:
                    _update_entity_rel_cache_add(cnx, subjentity, rtype, 'subject', objentity)

            self.hooksrunner.call_rtype_hooks('after_add', rtype, fromto)

    def insert_entities(self, etype, entitiesdicts,
                        processentity=None,
                        processattributes=None):

        eschema = self.schema[etype]
        etypeclass = self.cnx.vreg['etypes'].etype_class(etype)
        etypeid = eschema_eid(self.cnx, eschema)
        ancestorseid = [etypeid] + [eschema_eid(self.cnx, aschema)
                                    for aschema in eschema.ancestors()]

        allkeys = set()
        attributes = []
        binaries = []

        metadata = []
        isrelation = []
        isinstanceof = []
        cw_source = []

        system_source_eid = None
        if self.handle_cw_source_relation:
            system_source_eid = self.cnx.repo.system_source.eid

        entities = []
        bytesrtypes = set(rschema.type
                          for rschema in eschema.subject_relations()
                          if 'Bytes' in rschema.targets())

        utcnow = datetime.utcnow()

        eidsequence = reserve_eids(self.cnx, len(entitiesdicts))
        for attrs_and_callbackdata, eid in izip(entitiesdicts, eidsequence):

            insertattrs = attrs_and_callbackdata[0]

            # metaattrsinit hook
            insertattrs['creation_date'] = utcnow
            insertattrs['modification_date'] = utcnow
            if 'cwuri' not in insertattrs:
                insertattrs['cwuri'] = u''
            insertattrs['eid'] = eid

            if processattributes:
                processattributes(insertattrs, attrs_and_callbackdata[1])

            attributes.append(insertattrs)
            allkeys |= set(insertattrs)

            # prepare metadata tables
            meta = {'type': etype, 'eid': eid, 'asource': 'system'}
            metadata.append(meta)
            isrelation.append({'eid_from': eid, 'eid_to': etypeid})
            for ancestor in ancestorseid:
                isinstanceof.append({'eid_from': eid, 'eid_to': ancestor})

            if system_source_eid:
                cw_source.append({'eid_from': eid, 'eid_to': system_source_eid})

            # create an entity
            entity = etypeclass(self.cnx)
            entity.eid = eid
            entity.cw_attr_cache = insertattrs
            entity.cw_edited = EditedEntity(entity, **insertattrs)

            self.cnx.set_entity_cache(entity)

            entities.append(entity)

        # give a default value to unvalued attributes
        # after this, all attributes are well defined
        for rtype, default in _iter_attr_default(eschema, utcnow):
            for attr in attributes:
                if rtype not in attr:
                    attr[rtype] = default

        # update the repo.eid_type_source cache
        repo = self.cnx.repo
        for entity in entities:
            repo._type_source_cache[entity.eid] = entity.cw_etype, None, 'system'
        inlinedrtypes = set(rschema.type
                            for rschema in eschema.subject_relations()
                            if rschema.inlined)

        runhooks = not nohook(self.cnx)

        # we compute the smallest possible inlined rtypes set to minimize
        # the work done by the hook
        irtypes = inlinedrtypes.intersection(allkeys)
        if runhooks:
            self.hooksrunner.call_etype_hooks('before_add', etype, entities, irtypes)


        # Binary -> buffer thing
        if bytesrtypes:
            for insertattrs in attributes:
                binary = {}
                for rtype in bytesrtypes:
                    data = insertattrs[rtype]
                    binary[rtype] = data
                    insertattrs[rtype] = buffer(data.getvalue())
                    binaries.append(binary)

        # insert entities
        _insertmany(self.cnx, etype, attributes, prefix='cw_')
        # insert metadata
        _insertmany(self.cnx, 'entities', metadata)
        _insertmany(self.cnx, 'is_relation', isrelation)
        _insertmany(self.cnx, 'is_instance_of_relation', isinstanceof)
        if cw_source:
            _insertmany(self.cnx, 'cw_source_relation', cw_source)

        if bytesrtypes:
            # wipe the buffer, restore the Binary object
            for binary, insertattrs in izip(binaries, attributes):
                for rtype, data in binary.iteritems():
                    insertattrs[rtype] = data

        if processentity is not None:
            for entity, callbackdata in izip(entities, entitiesdicts):
                processentity(entity, *callbackdata)

        user = self.cnx.user
        if runhooks:
            self.hooksrunner.call_etype_hooks('after_add', etype, entities, irtypes)

            # setowner hook
            fromto = tuple((entity, user) for entity in entities)
            self.insert_relations('owned_by', fromto, _update_relcache=False)
            self.insert_relations('created_by', fromto, _update_relcache=False)

        # avoid an excessive memory consumption: the user is never cleared by
        # cnx.commit() or cnx.clear()
        user._cw_related_cache.clear()

        return entities

    def run_deferred_hooks(self, errors):
        """Run vectorized hooks and pass deferred hooks to a worker task.
        This must be called explicitly before the end of the transaction.
        """
        self.logger.info('running vectorized hooks')
        cnx = self.cnx
        if nohook(cnx):
            return
        schema = cnx.vreg.schema
        # we either run a 'vectorized' version of these or
        # we get a fresh session^Wtransaction to run this stuff
        # in the context of a worker task
        vectorized_regids = set(self.vectorized_relation_hooks) | set(self.vectorized_entity_hooks)
        deferred_entity_hooks = []
        deferred_relation_hooks = []

        # Handle vectorized hooks
        # entity hooks
        _ = self.cnx._
        for regid, entities_by_etype in self.hooksrunner.deferred_entity_hooks.iteritems():

            self.logger.info('checking inlined deferred hooks %s (for %s etypes)',
                             regid, len(entities_by_etype))

            def signalerror(etype, eid, rtype, role):
                msg = _('at least one relation %(rtype)s is required on %(etype)s (%(eid)s)')
                errors.append({etype: str(validation_error(eid, {(rtype, role): msg},
                                                           {'rtype': rtype,
                                                            'etype': etype,
                                                            'eid': eid},
                                                           ['rtype', 'etype']))})

            if regid == 'checkcard_after_add_entity':
                for etype, entities in entities_by_etype.iteritems():
                    done = 0
                    eschema = schema[etype]
                    for rschema, targetschemas, role in eschema.relation_definitions():
                        # skip automatically handled relations
                        if rschema.type in DONT_CHECK_RTYPES_ON_ADD:
                            continue
                        rtype = rschema.type
                        for teschema in targetschemas:
                            rdef = rschema.role_rdef(eschema, teschema, role)
                            if rdef.role_cardinality(role) in '1+':
                                done += len(entities)
                                for entity in entities:
                                    if rschema.inlined and role == 'subject':
                                        if not entity.cw_attr_cache[rtype]:
                                            signalerror(etype, entity.eid, rschema.type, role)
                                        continue
                                    rcache = entity.cw_relation_cached(rtype, role)
                                    if rcache:
                                        if not len(rcache[1]):
                                            signalerror(etype, entity.eid, rschema.type, role)
                                        continue
                                    else:
                                        if not entity.related(rschema.type, role, limit=1):
                                            signalerror(etype, entity.eid, rschema.type, role)
                    if done:
                        self.logger.info('%s: checked %s entities (for %s)', regid, done, etype)

            elif regid == 'checkattrconstraint':
                for etype, entities in entities_by_etype.iteritems():
                    done = 0
                    eschema = schema[etype]
                    insertattrs = set(entities[0].cw_attr_cache)
                    for rtype in insertattrs:
                        if schema[rtype].inlined:
                            continue
                        for constraint in eschema.rdef(rtype).constraints:
                            if isinstance(constraint, RQLConstraint):
                                if not check_attribute_repo_constraint(cnx, self.logger,
                                                                       entities, constraint):
                                    for entity in entities:
                                        signalerror(etype, entity.eid, rtype, 'subject')
                                done += 1
                                continue
                            for entity in entities:
                                value = entity.cw_attr_cache.get(rtype)
                                if value is not None:
                                    if not constraint.check(entity, rtype, value):
                                        signalerror(etype, entity.eid, rtype, 'subject')
                                    done += 1
                    if done:
                        self.logger.info('%s: checked %s entities (for %s)', regid, done, etype)
            else:
                if not entities_by_etype:
                    continue
                # we must transform things a bit to survive pickling
                by_etype = defaultdict(list)
                for etype, entities in entities_by_etype.iteritems():
                    for entity in entities:
                        by_etype[etype].append((entity.eid, entity.cw_attr_cache))
                if regid not in vectorized_regids:
                    deferred_entity_hooks.append((regid, by_etype))


        # relation hooks
        for regid, relations in self.hooksrunner.deferred_relation_hooks.iteritems():

            self.logger.info('checking inlined deferred hooks %s (for %s relations)',
                             regid, len(relations))

            known_rql_constraints = set(('O rcase_of C, S rcase_of C',))
            if regid == 'checkconstraint':
                for rtype, fromto in relations.iteritems():
                    done = 0
                    for eidfrom, eidto in fromto:
                        rdef = cnx.rtype_eids_rdef(rtype, eidfrom, eidto)
                        constraints = rdef.constraints
                        if constraints:
                            for constraint in constraints:
                                if constraint.expression in known_rql_constraints:
                                    continue
                                try:
                                    constraint.repo_check(cnx, eidfrom, rtype, eidto)
                                except ValidationError as err:
                                    errors.append({rtype: str(err)})
                                done += 1
                    if done:
                        self.logger.info('%s: checked %s constraints (for %s)', regid, done, rtype)
            else:
                if not relations:
                    continue
                if regid not in vectorized_regids:
                    deferred_relation_hooks.append((regid, relations))

        if deferred_entity_hooks or deferred_relation_hooks:
            self.logger.info('saving info for %s entity hooks', len(deferred_entity_hooks))
            self.logger.info('saving info for %s relation hooks', len(deferred_relation_hooks))
            with cnx.deny_all_hooks_but('metadata', 'workflow'):
                task = cnx.create_entity('CWWorkerTask',
                                         operation=u'run-deferred-hooks',
                                         deferred_hooks=Binary(dumps((deferred_entity_hooks,
                                                                      deferred_relation_hooks))))
                self.logger.info('scheduling task %s to run deferrd hooks', task.eid)
        self.logger.info('/running vectorized hooks')

def contiguousboundaries(intseq):
    """
    >>> r = [1, 2, 3, 4, 7, 55, 56, 57, 98, 99]
    >>> assert r == sorted(r)
    >>> list(contiguousboundaries(r))
    [(1, 4), (7, 7), (55, 57), (98, 99)]
    """
    intseq = iter(intseq)
    low = last = next(intseq)
    for num in intseq:
        if num - last != 1:
            yield low, last
            low = last = num
        else:
            last = num
    yield low, last

def check_attribute_repo_constraint(cnx, logger, entities, constraint):
    eidboundaries = contiguousboundaries([e.eid for e in entities])
    for mineid, maxeid in eidboundaries:
        if not _check_attribute_repo_constraint(cnx, logger, mineid, maxeid, constraint):
            return False
    return True

def _check_attribute_repo_constraint(cnx, logger, mineid, maxeid, constraint):
    expression = 'S eid > %(mineid)s, S eid < %(maxeid)s, ' + constraint.expression
    args = {'mineid': mineid - 1, 'maxeid': maxeid + 1}
    if 'U' in constraint.rqlst.defined_vars:
        expression = 'U eid %(u)s, ' + expression
        args['u'] = cnx.user.eid
    rql = 'Any %s WHERE %s' % (','.join(sorted(constraint.mainvars)), expression)
    if constraint.distinct_query:
        rql = 'DISTINCT ' + rql
    logger.info('constraint execution: %s (args: %s)', rql, args)
    rset = cnx.execute(rql, args, build_descr=False)
    return rset.rowcount == (maxeid - mineid) + 1




@contextmanager
def newsession(self, user):
    session = Session(user, self.repo)
    try:
        yield session
    finally:
        session.close()


class DeferredHooksRunner(Performer):
    __regid__ = 'run-deferred-hooks'

    def abort_task(self, cnx, task, error):
        pass

    def perform_task(self, cnx, task):
        user = task.created_by[0]
        with newsession(cnx, user) as session:
            with session.new_cnx() as cnx:
                entity_hooks, relation_hooks = loads(task.deferred_hooks.getvalue())
                try:
                    self.process_entities_hooks(entity_hooks)
                except ValidationError, verr:
                    cnx.exception(verr)
                    self.abort_task(cnx, task, verr)
                try:
                    self.process_relations_hooks(relation_hooks)
                except ValidationError, verr:
                    cnx.exception(verr)
                    self.abort_task(cnx, task, verr)
                cnx.commit()
                return cnx._('Success')

    def _fetch_hook(self, hookregid, hooktype=None):
        assert hooktype in ('entity', 'relation')
        hook = self._cw.vreg['%s_hooks' % hookregid.payload][hookregid.real][0]
        events = set(ev for ev in hook.events if hooktype in ev and 'add' in ev)
        assert hookregid.payload in events, hook
        return hook, events

    def process_entities_hooks(self, entity_hooks):
        cnx = self._cw
        source = cnx.repo.system_source

        for hookregid, stuff in entity_hooks:
            for etype, eid_plus_caches in stuff.iteritems():
                entities = []
                etypeclass = cnx.vreg['etypes'].etype_class(etype)

                for eid, cache in eid_plus_caches:
                    entity = etypeclass(cnx)
                    entity.eid = eid
                    entity.cw_attr_cache = cache
                    entity.cw_edited = EditedEntity(entity, **cache)

                    cnx.set_entity_cache(entity)
                    entities.append(entity)

                if hookregid == '__pseudo_entity_fti__':
                    if server.DEBUG & server.DBG_HOOKS:
                        print '%s: fti for %s entities' % (etype, len(eid_plus_caches))
                    for entity in entities:
                        entity.complete(entity.e_schema.indexable_attributes())
                        source.index_entity(cnx, entity=entity)
                    continue

                hookclass, events = self._fetch_hook(hookregid, 'entity')
                if server.DEBUG & server.DBG_HOOKS:
                    print 'entity hooks: %s %s (%s)' %(etype, hookregid, len(entities))
                for entity in entities:
                    assert entity.cw_etype == etype
                    with self._cw.security_enabled(read=False, write=False):
                        for event in events:
                            hook = hookclass(cnx, entity=entity, event=event)
                            hook()

    def process_relations_hooks(self, relation_hooks):
        session = self._cw

        for hookregid, fromto_by_rtype in relation_hooks:
            hookclass, events = self._fetch_hook(hookregid, 'relation')
            for rtype, fromto in fromto_by_rtype.iteritems():
                if server.DEBUG & server.DBG_HOOKS:
                    print 'relation hooks: %s %s (%s)' % (type, hookregid, len(fromto))
                with session.security_enabled(read=False, write=False):
                    for eidfrom, eidto in fromto:
                        for event in events:
                            hook = hookclass(session, event=event, rtype=rtype,
                                             eidfrom=eidfrom, eidto=eidto)
                            hook()
