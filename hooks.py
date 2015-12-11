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

"""cubicweb-fastimport specific hooks and operations"""

from collections import defaultdict
from contextlib import contextmanager
from cPickle import loads

from cubicweb import server, ValidationError
from cubicweb.server.session import Session
from cubicweb.server.hook import (ENTITIES_HOOKS as ENTITIES_EVENTS,
                                  RELATIONS_HOOKS as RELATIONS_EVENTS,
                                  enabled_category)
from cubicweb.server.session import HOOKS_ALLOW_ALL, HOOKS_DENY_ALL
from cubicweb.server.edition import EditedEntity

from cubes.worker.entities import Performer

from cubes.fastimport.utils import transactor, nohook


class key_data(object):
    """a two-parts object whose eq/hashability belong to the first `key`
    part, e.g.:

    key_data('Elephant', 'Babar') == key_data('Elephant', 'Celeste')

    This will allow to transport an hook regid allong with one of
    the registry entries which hosts it (e.g. the hook
    'mix-chocolate' in 'before_add_entity_hooks').
    """
    __slots__ = ('real', 'payload')

    def __init__(self, real, payload):
        self.real = real
        self.payload = payload

    def __hash__(self):
        return hash(self.real)

    def __eq__(self, other):
        return self.real == other

    def __getstate__(self):
        return (self.real, self.payload)

    def __setstate__(self, state):
        self.real = state[0]
        self.payload = state[1]

    def __str__(self):
        return '<%s with %s>' % (self.real, self.payload)
    __repr__ = __str__


class HooksRunner(object):

    def __init__(self, logger, cnx, disabled_regids=(),
                 deferred_entity_hooks=(), deferred_relation_hooks=()):
        self.logger = logger
        self.vreg = cnx.vreg
        self.cnx = cnx
        self.disabled_regids = frozenset(disabled_regids)

        self.deferred_entity_regids = set(deferred_entity_hooks)
        self.deferred_relation_regids = set(deferred_relation_hooks)

        self.deferred_entity_hooks = defaultdict(lambda: defaultdict(list))
        self.deferred_relation_hooks = defaultdict(lambda: defaultdict(list))

    def instance(self, hookclass, *args, **kwargs):
        selector = hookclass.__select__
        # let's not evaluate the enabled_category selector
        if isinstance(selector, enabled_category):
            # if we get there, this has actually been already evaluated
            return hookclass(*args, **kwargs)
        # unfortunately, the enabled_category embedded in the AndPredicate
        # cannot be skipped as easily
        if selector(hookclass, *args, **kwargs):
            return hookclass(*args, **kwargs)
        return None

    def _iterhooks(self, event):
        tx = transactor(self.cnx)
        if nohook(tx):
            return
        deny = tx.hooks_mode == HOOKS_DENY_ALL
        whitelist = tx.enabled_hook_cats
        allow = tx.hooks_mode == HOOKS_ALLOW_ALL
        blacklist = tx.disabled_hook_cats
        for hooks in self.vreg[event + '_hooks'].itervalues():
            for hook in hooks:
                if hook.__regid__ in self.disabled_regids:
                    continue
                if deny and hook.category not in whitelist:
                    continue
                if allow and hook.category in blacklist:
                    continue
                yield hook

    def iterentityhooks(self, event, entity):
        pruned = self.pruned_entity_hooks(event, entity)
        for hklass in self._iterhooks(event):
            if hklass in pruned:
                continue
            if hklass.__regid__ in self.deferred_entity_regids:
                key = key_data(hklass.__regid__, event)
                self.deferred_entity_hooks[key][entity.cw_etype].append(entity)
                continue
            hook = self.instance(hklass, self.cnx, event=event, entity=entity)
            if hook is not None:
                yield hook

    def iterentityrelationhooks(self, event, entity, rtype):
        if entity.cw_attr_cache.get(rtype) is None:
            # the rtype must be there for normalization reasons
            # however there might not be anyone over there
            return
        pruned = self.pruned_inlinedrtype_hooks(event, entity, rtype)
        for hklass in self._iterhooks(event):
            if hklass in pruned:
                continue
            if hklass.__regid__ in self.deferred_relation_regids:
                fromto = entity.eid, entity.cw_attr_cache[rtype]
                key = key_data(hklass.__regid__, event)
                self.deferred_relation_hooks[key][rtype].append(fromto)
                continue
            hook = self.instance(hklass, self.cnx,
                                 event=event,
                                 rtype=rtype,
                                 eidfrom=entity.eid,
                                 eidto=entity.cw_attr_cache[rtype])
            if hook is not None:
                yield hook

    def iterrelationhooks(self, event, rtype, relation):
        pruned = self.pruned_relations_hooks(event, rtype, relation)
        for hklass in self._iterhooks(event):
            if hklass in pruned:
                continue
            if hklass.__regid__ in self.deferred_relation_regids:
                fromto = relation[0].eid, relation[1].eid
                assert None not in fromto
                key = key_data(hklass.__regid__, event)
                self.deferred_relation_hooks[key][rtype].append(fromto)
                continue
            hook = self.instance(hklass, self.cnx,
                                 event=event,
                                 rtype=rtype,
                                 eidfrom=relation[0].eid,
                                 eidto=relation[1].eid)
            if hook is not None:
                yield hook

    def pruned_entity_hooks(self, event, entity):
        cache_key = (event, entity.cw_etype)
        pruned = self.cnx.pruned_hooks_cache.get(cache_key)
        if pruned is not None:
            return pruned

        pruned = set()
        for hook in self._iterhooks(event):
            _enabled_cat, main_predicate = hook.filterable_selectors()
            if main_predicate is not None:
                if not main_predicate(hook, self.cnx, entity=entity):
                    pruned.add(hook)

        self.cnx.pruned_hooks_cache[cache_key] = pruned
        return pruned

    def pruned_inlinedrtype_hooks(self, event, entity, rtype):
        cache_key = (event, entity.cw_etype, rtype)
        pruned = self.cnx.pruned_hooks_cache.get(cache_key)
        if pruned is not None:
            return pruned

        pruned = set()
        for hook in self._iterhooks(event):
            _enabled_cat, main_predicate = hook.filterable_selectors()
            if main_predicate is not None:
                if not main_predicate(hook, self.cnx,
                                      rtype=rtype,
                                      eidfrom=entity.eid,
                                      eidto=entity.cw_attr_cache[rtype]):
                    pruned.add(hook)

        self.cnx.pruned_hooks_cache[cache_key] = pruned
        return pruned

    def pruned_relations_hooks(self, event, rtype, relation):
        cache_key = (event, rtype)
        pruned = self.cnx.pruned_hooks_cache.get(cache_key)
        if pruned is not None:
            return pruned

        pruned = set()
        for hook in self._iterhooks(event):
            _enabled_cat, main_predicate = hook.filterable_selectors()
            if main_predicate is not None:
                if not main_predicate(hook, self.cnx,
                                      rtype=rtype,
                                      eidfrom=relation[0].eid,
                                      eidto=relation[1].eid):
                    pruned.add(hook)

        self.cnx.pruned_hooks_cache[cache_key] = pruned
        return pruned

    def call_rtype_hooks(self, event, rtype, relations):
        event = event + '_relation'
        assert event in RELATIONS_EVENTS
        shown = not server.DEBUG & server.DBG_HOOKS
        self.logger.info('call rtypes hooks %s', event)
        with self.cnx.security_enabled(read=False):
            for relation in relations:
                hooks = list(self.iterrelationhooks(event, rtype, relation))
                if not shown and hooks:
                    print ' hooks: ', [(hook.category, hook.__regid__)
                                       for hook in hooks]
                    shown = True
                if not hooks:
                    continue
                with self.cnx.security_enabled(write=False):
                    for hook in hooks:
                        hook()

    def call_etype_hooks(self, event, etype, entities, inlinedrtypes):
        """ execute selectable hooks for entities and inlined relations """
        with self.cnx.security_enabled(read=False):
            eevent = event + '_entity'
            assert eevent in ENTITIES_EVENTS
            self.logger.info('call entity hooks %s', eevent)
            shown = not server.DEBUG & server.DBG_HOOKS
            for entity in entities:
                assert entity.cw_etype == etype
                hooks = list(self.iterentityhooks(eevent, entity))
                if not shown and hooks:
                    print ' hooks: ', [(hook.category, hook.__regid__)
                                       for hook in hooks]
                    shown = True
                if not hooks:
                    continue
                with self.cnx.security_enabled(write=False):
                    for hook in hooks:
                        hook()

            revent = event + '_relation'
            assert revent in RELATIONS_EVENTS
            self.logger.info('call inlined relations hooks %s', revent)
            for rtype in inlinedrtypes:
                shown = not server.DEBUG & server.DBG_HOOKS
                for entity in entities:
                    hooks = list(self.iterentityrelationhooks(revent, entity, rtype))
                    if not shown and hooks:
                        print ' %s hooks: %s' % (rtype,
                                                 [(hook.category, hook.__regid__)
                                                  for hook in hooks])
                        shown = True
                    if not hooks:
                        continue
                    with self.cnx.security_enabled(write=False):
                        for hook in hooks:
                            hook()

            # entities fti is handled directly by the source
            # hence we cheat a bit by pretending it's the business of a pseudo-hook
            source = self.cnx.repo.system_source
            if source.do_fti and source.need_fti_indexation(etype):
                key = key_data('__pseudo_entity_fti__', event)
                for entity in entities:
                    self.deferred_entity_hooks[key][entity.cw_etype].append(entity)
                if server.DEBUG & server.DBG_HOOKS:
                    print '%s: preparing %s entities for fti' % (etype, len(entities))


@contextmanager
def newsession(self, user):
    session = Session(user, self.repo)
    try:
        yield session
    finally:
        session.close()

@contextmanager
def try_user_cnx(self, task):
    """ Try to yiel a Connection loged in as the task creator
    else default to internal connection.
    """
    try:
        user = task.created_by[0]
    except IndexError:
        with self.repo.internal_cnx() as cnx:
            yield cnx
    else:
        with newsession(self, user) as session:
            with session.new_cnx() as cnx:
                yield cnx


class DeferredHooksRunner(Performer):
    __regid__ = 'run-deferred-hooks'

    def abort_task(self, cnx, task, error):
        pass

    def perform_task(self, cnx, task):
        with try_user_cnx(cnx, task) as cnx:
            with cnx.ensure_cnx_set:
                entity_hooks, relation_hooks = loads(task.deferred_hooks.getvalue())
                try:
                    self.process_entities_hooks(cnx, entity_hooks)
                except ValidationError, verr:
                    cnx.rollback()
                    cnx.exception(verr)
                    self.abort_task(cnx, task, verr)
                try:
                    self.process_relations_hooks(cnx, relation_hooks)
                except ValidationError, verr:
                    cnx.rollback()
                    cnx.exception(verr)
                    self.abort_task(cnx, task, verr)
                cnx.commit()
                return cnx._('Success')

    def _fetch_hook(self, cnx, hookregid, hooktype=None):
        assert hooktype in ('entity', 'relation')
        hook = cnx.vreg['%s_hooks' % hookregid.payload][hookregid.real][0]
        events = set(ev for ev in hook.events if hooktype in ev and 'add' in ev)
        assert hookregid.payload in events, hook
        return hook, events

    def process_entities_hooks(self, cnx, entity_hooks):
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

                hookclass, events = self._fetch_hook(cnx, hookregid, 'entity')
                if server.DEBUG & server.DBG_HOOKS:
                    print 'entity hooks: %s %s (%s)' %(etype, hookregid, len(entities))
                for entity in entities:
                    assert entity.cw_etype == etype
                    with cnx.security_enabled(read=False, write=False):
                        for event in events:
                            hook = hookclass(cnx, entity=entity, event=event)
                            hook()

    def process_relations_hooks(self, cnx, relation_hooks):
        for hookregid, fromto_by_rtype in relation_hooks:
            hookclass, events = self._fetch_hook(cnx, hookregid, 'relation')
            for rtype, fromto in fromto_by_rtype.iteritems():
                if server.DEBUG & server.DBG_HOOKS:
                    print 'relation hooks: %s %s (%s)' % (type, hookregid, len(fromto))
                with cnx.security_enabled(read=False, write=False):
                    for eidfrom, eidto in fromto:
                        for event in events:
                            hook = hookclass(cnx, event=event, rtype=rtype,
                                             eidfrom=eidfrom, eidto=eidto)
                            hook()
