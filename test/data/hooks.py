from cubicweb.predicates import is_instance
from cubicweb.server.hook import Hook

class MyFancyHook(Hook):
    __regid__ = 'my_dummy_hook'
    __select__ = Hook.__select__ & is_instance('CWUser')
    events = ('after_add_entity',)
    category = 'disable-me'

    def __call__(self):
        self._cw.data['BABAR_WAS_THERE'] = True

