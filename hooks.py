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

from cubicweb.server.hook import (ENTITIES_HOOKS as ENTITIES_EVENTS,
                                  RELATIONS_HOOKS as RELATIONS_EVENTS)


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


class HooksRunner(object):

    def __init__(self, logger, session, disabled_regids=(),
                 deferred_entity_hooks=(), deferred_relation_hooks=()):
        self.logger = logger
        self.vreg = session.vreg
        self.session = session
        self.disabled_regids = frozenset(disabled_regids)

        self.deferred_entity_regids = set(deferred_entity_hooks)
        self.deferred_relation_regids = set(deferred_relation_hooks)

        self.deferred_entity_hooks = defaultdict(lambda: defaultdict(list))
        self.deferred_relation_hooks = defaultdict(lambda: defaultdict(list))

    def select_best(self, hooks, *args, **kwargs):
        # NOTE: later, shunt enabled_category
        score, winners = 0, []
        for hook in hooks:
            objectscore = hook.__select__(hook, *args, **kwargs)
            if objectscore > score:
                score, winners = objectscore, [hook]
            elif objectscore > 0 and objectscore == score:
                winners.append(hook)
        if winners is None:
            return None
        # return the result of calling the object
        if winners:
            assert len(winners) <= 1, winners
            return winners[0](*args, **kwargs)
        return None

    def _iterhooks(self, event):
        for hooks in self.vreg[event + '_hooks'].itervalues():
            for hook in hooks:
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
            hook = self.select_best([hklass], self.session, event=event, entity=entity)
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
            hook = self.select_best([hklass], self.session,
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
            hook = self.select_best([hklass], self.session,
                                    event=event,
                                    rtype=rtype,
                                    eidfrom=relation[0].eid,
                                    eidto=relation[1].eid)
            if hook is not None:
                yield hook

    def pruned_entity_hooks(self, event, entity):
        cache_key = (event, entity.cw_etype)
        pruned = self.session.pruned_hooks_cache.get(cache_key)
        if pruned is not None:
            return pruned

        pruned = set()
        for hook in self._iterhooks(event):
            if hook.__regid__ in self.disabled_regids:
                pruned.add(hook)
                continue
            enabled_cat, main_predicate = hook.filterable_selectors()
            if enabled_cat is not None:
                if not enabled_cat(hook, self.session):
                    pruned.add(hook)
                    continue
            if main_predicate is not None:
                if not main_predicate(hook, self.session, entity=entity):
                    pruned.add(hook)

        self.session.pruned_hooks_cache[cache_key] = pruned
        return pruned

    def pruned_inlinedrtype_hooks(self, event, entity, rtype):
        cache_key = (event, entity.cw_etype, rtype)
        pruned = self.session.pruned_hooks_cache.get(cache_key)
        if pruned is not None:
            return pruned

        pruned = set()
        for hook in self._iterhooks(event):
            if hook.__regid__ in self.disabled_regids:
                pruned.add(hook)
                continue
            enabled_cat, main_predicate = hook.filterable_selectors()
            if enabled_cat is not None:
                if not enabled_cat(hook, self.session):
                    pruned.add(hook)
                    continue
            if main_predicate is not None:
                if not main_predicate(hook, self.session,
                                      eidfrom=entity.eid,
                                      eidto=entity.cw_attr_cache[rtype]):
                    pruned.add(hook)

        self.session.pruned_hooks_cache[cache_key] = pruned
        return pruned

    def pruned_relations_hooks(self, event, rtype, relation):
        cache_key = (event, rtype)
        pruned = self.session.pruned_hooks_cache.get(cache_key)
        if pruned is not None:
            return pruned

        pruned = set()
        for hook in self._iterhooks(event):
            if hook.__regid__ in self.disabled_regids:
                pruned.add(hook)
                continue
            enabled_cat, main_predicate = hook.filterable_selectors()
            if enabled_cat is not None:
                if not enabled_cat(hook, self.session):
                    pruned.add(hook)
                    continue
            if main_predicate is not None:
                if not main_predicate(hook, self.session,
                                      eidfrom=relation[0].eid,
                                      eidto=relation[1].eid):
                    pruned.add(hook)

        self.session.pruned_hooks_cache[cache_key] = pruned
        return pruned

    def call_rtype_hooks(self, event, rtype, relations):
        event = event + '_relation'
        assert event in RELATIONS_EVENTS
        shown = False
        self.logger.info('call rtypes hooks %s', event)
        with self.session.security_enabled(read=False):
            for relation in relations:
                hooks = list(self.iterrelationhooks(event, rtype, relation))
                if not shown and hooks:
                    self.logger.info(' hooks: %s', [(hook.category, hook.__regid__)
                                                    for hook in hooks])
                    shown = True
                if not hooks:
                    continue
                with self.session.security_enabled(write=False):
                    for hook in hooks:
                        hook()

    def call_etype_hooks(self, event, etype, entities, inlinedrtypes):
        """ execute selectable hooks for entities and inlined relations """
        with self.session.security_enabled(read=False):
            eevent = event + '_entity'
            assert eevent in ENTITIES_EVENTS
            self.logger.info('call entity hooks %s', eevent)
            shown = False
            for entity in entities:
                assert entity.cw_etype == etype
                hooks = list(self.iterentityhooks(eevent, entity))
                if not shown and hooks:
                    self.logger.info(' hooks: %s', [(hook.category, hook.__regid__)
                                                    for hook in hooks])
                    shown = True
                if not hooks:
                    continue
                with self.session.security_enabled(write=False):
                    for hook in hooks:
                        hook()

            revent = event + '_relation'
            assert revent in RELATIONS_EVENTS
            self.logger.info('call inlined relations hooks %s', revent)
            for rtype in inlinedrtypes:
                shown = False
                for entity in entities:
                    hooks = list(self.iterentityrelationhooks(revent, entity, rtype))
                    if not shown and hooks:
                        self.logger.info(' %s hooks: %s', rtype,
                                         [(hook.category, hook.__regid__)
                                          for hook in hooks])
                        shown = True
                    if not hooks:
                        continue
                    with self.session.security_enabled(write=False):
                        for hook in hooks:
                            hook()

            # entities fti is handled directly by the source
            # hence we cheat a bit by pretending it's the business of a pseudo-hook
            source = self.session.repo.system_source
            if source.do_fti and source.need_fti_indexation(etype):
                key = key_data('__pseudo_entity_fti__', event)
                for entity in entities:
                    self.deferred_entity_hooks[key][entity.cw_etype].append(entity)
                self.logger.info('%s: preparing %s entities for fti', etype, len(entities))
