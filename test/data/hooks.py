from cubicweb.predicates import is_instance
from cubicweb.server.hook import Hook, match_rtype

class MyFancyHook(Hook):
    __regid__ = 'my_dummy_hook'
    __select__ = Hook.__select__ & is_instance('CWUser')
    events = ('after_add_entity',)
    category = 'disable-me'

    def __call__(self):
        self._cw.data['BABAR_WAS_THERE'] = True

class MyOtherFancyHook(Hook):
    __regid__ = 'disable_me_directly'
    __select__ = Hook.__select__ & is_instance('CWUser')
    events = ('after_add_entity',)
    category = 'category_which_doesnt_matter'

    def __call__(self):
        self._cw.data['CELESTE_WAS_THERE'] = True



class InGroupHook(Hook):
    # non-inlined relation
    __regid__ = 'in_group'
    __select__ = Hook.__select__ & match_rtype('in_group')
    events = ('after_add_relation',)

    def __call__(self):
        cnx = self._cw
        if not 'IN_GROUP' in cnx.data:
            cnx.data['IN_GROUP'] = []
        cnx.data['IN_GROUP'].append((cnx.entity_from_eid(self.eidfrom).login,
                                     cnx.entity_from_eid(self.eidto).name))

class MyEmailHook(Hook):
    # inlined relation
    __regid__ = 'my_email'
    __select__ = Hook.__select__ & match_rtype('my_email')
    events = ('after_add_relation',)

    def __call__(self):
        cnx = self._cw
        if not 'MY_EMAIL' in cnx.data:
            cnx.data['MY_EMAIL'] = []
        cnx.data['MY_EMAIL'].append((cnx.entity_from_eid(self.eidfrom).login,
                                     cnx.entity_from_eid(self.eidto).address))
