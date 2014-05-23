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
import numpy
from collections import defaultdict
from itertools import izip
from contextlib import contextmanager
from datetime import datetime
from logging import getLogger
from cPickle import dumps, loads

from cubicweb import neg_role, validation_error, Binary, ValidationError
from cubicweb.rset import ResultSet
from cubicweb.predicates import is_instance
from cubicweb.schema import RQLConstraint
from cubicweb.server.edition import EditedEntity
from cubicweb.server.utils import eschema_eid
from cubicweb.server.session import Session
from cubicweb.hooks.integrity import DONT_CHECK_RTYPES_ON_ADD
from cubicweb.view import EntityAdapter

from cubes.fastimport.hooks import HooksRunner


YAMS_TO_PY_TYPEMAP = defaultdict(
    lambda : lambda x:x,
    {
        'Float': float,
        'Int': int,
        'String': unicode
    })

def _insertmany(session, table, attributes, prefix=''):
    """ Low-level INSERT many entities of the same etype
    at once
    """
    # the low-level python-dbapi cursor
    cursor = session.cnxset['system']
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

def iter_subjrdef_card_default(eschema, utcnow):
    for rschema in eschema.subject_relations():
        if rschema.meta:
            continue
        if not (rschema.final or rschema.inlined):
            continue
        rdef = eschema.rdef(rschema.type)
        default = _default_value(rdef, utcnow) if rschema.final else None
        yield (rschema.type,
               rdef.cardinality.startswith('1'),
               default)

# variant of session._update_entity_rel_cache_add that gets
# the entities
def _update_entity_rel_cache_add(session, entity, rtype, role, targetentity, otherside=False):
    rcache = entity.cw_relation_cached(rtype, role)
    if rcache is None:
        rset = ResultSet([[targetentity.eid]], 'Any X WHERE X eid %s' % targetentity.eid,
                         description=[[targetentity.cw_etype]])
        rset.req = session
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
        _update_entity_rel_cache_add(session, targetentity, rtype, neg_role(role), entity, True)


class FlushController(object):
    hooksrunnerclass = HooksRunner
    loggername = 'cubicweb'

    def __init__(self, session, schema, disabled_regids,
                 deferred_entity_hooks=(),
                 deferred_relation_hooks=()):
        self.session = session
        self.schema = schema
        self.logger = getLogger(self.loggername)
        self.hooksrunner = self.hooksrunnerclass(self.logger,
                                                 session,
                                                 disabled_regids,
                                                 deferred_entity_hooks,
                                                 deferred_relation_hooks)

    def insert_relations(self, rtype, fromto):
        session = self.session
        self.hooksrunner.call_rtype_hooks('before_add', rtype, fromto)

        _insertmany(session, rtype + '_relation',
                    [{'eid_from': fromentity.eid, 'eid_to': toentity.eid}
                     for fromentity, toentity in fromto])

        # is the timing of this thing right ? wouldn't earlier be better ?
        for subjentity, objentity in fromto:
            _update_entity_rel_cache_add(session, subjentity, rtype, 'subject', objentity)

        self.hooksrunner.call_rtype_hooks('after_add', rtype, fromto)

    def _reserve_eids(self, qty):
        """ not fast enough (yet) """
        assert qty > 0
        source = self.session.repo.system_source
        if qty == 1:
            return (source.create_eid(self.session),)
        return source.create_eid(self.session, count=qty)

    def insert_entities(self, etype, entitiesdicts,
                        postprocessentity=None):

        eschema = self.schema[etype]
        etypeclass = self.session.vreg['etypes'].etype_class(etype)
        etypeid = eschema_eid(self.session, eschema)
        ancestorseid = [etypeid] + [eschema_eid(self.session, aschema)
                                    for aschema in eschema.ancestors()]

        allkeys = set()
        attributes = []
        binaries = []
        metadata = []
        isrelation = []
        isinstanceof = []
        entities = []
        entitycallbacks = []
        bytesrtypes = set(rschema.type
                          for rschema in eschema.subject_relations()
                          if 'Bytes' in rschema.targets())

        utcnow = datetime.utcnow()

        for packedstuff, eid in izip(entitiesdicts,
                                     self._reserve_eids(len(entitiesdicts))):

            insertattrs = packedstuff[0]
            callbackdata = packedstuff[1:]

            # metaattrsinit hook
            insertattrs['creation_date'] = utcnow
            insertattrs['modification_date'] = utcnow
            insertattrs['cwuri'] = u''
            insertattrs['eid'] = eid

            attributes.append(insertattrs)
            allkeys |= set(insertattrs)

            # prepare metadata tables
            metadata.append({'type': etype, 'eid': eid,
                             'source': 'system', 'asource': 'system',
                             'mtime': utcnow})
            isrelation.append({'eid_from': eid, 'eid_to': etypeid})
            for ancestor in ancestorseid:
                isinstanceof.append({'eid_from': eid, 'eid_to': ancestor})

            # create an entity
            entity = etypeclass(self.session)
            entity.eid = eid
            entity.cw_attr_cache = insertattrs
            entity.cw_edited = EditedEntity(entity, **insertattrs)

            self.session.set_entity_cache(entity)

            entities.append(entity)
            entitycallbacks.append(packedstuff)

        # give a default value to unvalued attributes
        # after this, all attributes are well defined
        for rtype, required, default in iter_subjrdef_card_default(eschema, utcnow):
            for attr in attributes:
                if rtype not in attr:
                    attr[rtype] = default

        # update the repo.eid_type_source cache
        repo = self.session.repo
        for entity in entities:
            repo._type_source_cache[entity.eid] = entity.cw_etype, 'system', None, 'system'

        inlinedrtypes = set(rschema.type
                            for rschema in eschema.subject_relations()
                            if rschema.inlined)

        irtypes = inlinedrtypes.intersection(allkeys)
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
        _insertmany(self.session, etype, attributes, prefix='cw_')
        # insert metadata
        _insertmany(self.session, 'entities', metadata)
        _insertmany(self.session, 'is_relation', isrelation)
        _insertmany(self.session, 'is_instance_of_relation', isinstanceof)

        if bytesrtypes:
            # wipe the buffer, restore the Binary object
            for binary, insertattrs in izip(binaries, attributes):
                for rtype, data in binary.iteritems():
                    insertattrs[rtype] = data

        if postprocessentity is not None:
            for entity, callbackdata in izip(entities, entitycallbacks):
                postprocessentity(entity, *callbackdata)

        self.hooksrunner.call_etype_hooks('after_add', etype, entities, irtypes)

        # setowner hook
        user = self.session.user
        fromto = tuple((entity, user) for entity in entities)
        self.insert_relations('owned_by', fromto)
        self.insert_relations('created_by', fromto)

        return entities

    def run_deferred_hooks(self, errors, target):
        self.logger.info('running deferred hooks')
        session = self.session
        schema = session.vreg.schema
        # we either run a 'vectorized' version of these or
        # we get a fresh session^Wtransaction to run this stuff
        # in the context of a worker task
        deferred_entity_hooks = []
        deferred_relation_hooks = []

        # entity hooks
        _ = self.session._
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
                                if not check_attribute_repo_constraint(session, self.logger,
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
                        rdef = session.rtype_eids_rdef(rtype, eidfrom, eidto)
                        constraints = rdef.constraints
                        if constraints:
                            for constraint in constraints:
                                if constraint.expression in known_rql_constraints:
                                    continue
                                try:
                                    constraint.repo_check(session, eidfrom, rtype, eidto)
                                except ValidationError as err:
                                    errors.append({rtype: str(err)})
                                done += 1
                    if done:
                        self.logger.info('%s: checked %s constraints (for %s)', regid, done, rtype)
            else:
                if not relations:
                    continue
                deferred_relation_hooks.append((regid, relations))

        if deferred_entity_hooks or deferred_relation_hooks:
            self.logger.info('saving info for %s entity hooks', len(deferred_entity_hooks))
            self.logger.info('saving info for %s relation hooks', len(deferred_relation_hooks))
            session.create_entity('CWWorkerTask',
                                  operation=u'run-deferred-hooks',
                                  target=target,
                                  on_behalf=session.user,
                                  deferred_hooks=Binary(dumps((deferred_entity_hooks,
                                                               deferred_relation_hooks))))
        self.logger.info('/running deferred hooks')

def contiguousboundaries(eids):
    """
    >>> r = [1, 2, 3, 4, 7, 55, 56, 57, 98, 99]
    >>> assert r == sorted(r)
    >>> contiguousboundaries(r)
    [(1, 4), (7, 7), (55, 57), (98, 99)]
    """
    partitionindices = numpy.where(numpy.diff(eids) != 1)[0]
    boundaries = []
    i = 0
    for j in partitionindices:
        boundaries.append((eids[i], eids[j]))
        i = j+1
    boundaries.append((eids[i], eids[len(eids) - 1]))
    return boundaries

def check_attribute_repo_constraint(session, logger, entities, constraint):
    eids = [e.eid for e in entities]
    eidboundaries = contiguousboundaries(eids)
    for mineid, maxeid in eidboundaries:
        if not _check_attribute_repo_constraint(session, logger, mineid, maxeid, constraint):
            return False
    return True

def _check_attribute_repo_constraint(session, logger, mineid, maxeid, constraint):
    expression = 'S eid > %(mineid)s, S eid < %(maxeid)s, ' + constraint.expression
    args = {'mineid': mineid - 1, 'maxeid': maxeid + 1}
    if 'U' in constraint.rqlst.defined_vars:
        expression = 'U eid %(u)s, ' + expression
        args['u'] = session.user.eid
    rql = 'Any %s WHERE %s' % (','.join(sorted(constraint.mainvars)), expression)
    if constraint.distinct_query:
        rql = 'DISTINCT ' + rql
    logger.info('constraint execution: %s (args: %s)', rql, args)
    rset = session.execute(rql, args, build_descr=False)
    return rset.rowcount == (maxeid - mineid) + 1




@contextmanager
def newsession(self, user):
    session = Session(user, self.repo)
    session.set_cnxset()
    user = session.entity_from_eid(user.eid)
    try:
        yield session
    finally:
        session.close()

class DeferredHooksRunner(EntityAdapter):
    __regid__ = 'run-deferred-hooks'
    __select__ = is_instance('CWWorkerTask')

    def abort_task(self, session, task, error):
        pass

    def perform_task(self, session, task):
        user = task.on_behalf[0]
        with newsession(session, user) as session:
            entity_hooks, relation_hooks = loads(task.deferred_hooks.getvalue())
            try:
                self.process_entities_hooks(entity_hooks)
            except ValidationError, verr:
                self.exception(verr)
                self.abort_task(session, task, verr)
            try:
                self.process_relations_hooks(relation_hooks)
            except ValidationError, verr:
                self.exception(verr)
                self.abort_task(session, task, verr)
            session.commit()
            return session._('Success')

    def _fetch_hook(self, hookregid, hooktype=None):
        assert hooktype in ('entity', 'relation')
        hook = self._cw.vreg['%s_hooks' % hookregid.payload][hookregid.real][0]
        events = set(ev for ev in hook.events if hooktype in ev and 'add' in ev)
        assert hookregid.payload in events, hook
        return hook, events

    def process_entities_hooks(self, entity_hooks):
        session = self._cw
        source = session.repo.system_source

        for hookregid, stuff in entity_hooks:
            for etype, eid_plus_caches in stuff.iteritems():
                entities = []
                etypeclass = session.vreg['etypes'].etype_class(etype)

                for eid, cache in eid_plus_caches:
                    entity = etypeclass(session)
                    entity.eid = eid
                    entity.cw_attr_cache = cache
                    entity.cw_edited = EditedEntity(entity, **cache)

                    session.set_entity_cache(entity)
                    entities.append(entity)

                if hookregid == '__pseudo_entity_fti__':
                    self.info('%s: fti for %s entities', etype, len(eid_plus_caches))
                    for entity in entities:
                        entity.complete(entity.e_schema.indexable_attributes())
                        source.index_entity(session, entity=entity)
                    continue

                hookclass, events = self._fetch_hook(hookregid, 'entity')
                self.info('entity hooks: %s %s (%s)', etype, hookregid, len(entities))
                for entity in entities:
                    assert entity.cw_etype == etype
                    with self._cw.security_enabled(read=False, write=False):
                        for event in events:
                            hook = hookclass(session, entity=entity, event=event)
                            hook()

    def process_relations_hooks(self, relation_hooks):
        session = self._cw

        for hookregid, fromto_by_rtype in relation_hooks:
            hookclass, events = self._fetch_hook(hookregid, 'relation')
            for rtype, fromto in fromto_by_rtype.iteritems():
                self.info('relation hooks: %s %s (%s)', rtype, hookregid, len(fromto))
                with session.security_enabled(read=False, write=False):
                    for eidfrom, eidto in fromto:
                        for event in events:
                            hook = hookclass(session, event=event, rtype=rtype,
                                             eidfrom=eidfrom, eidto=eidto)
                            hook()


