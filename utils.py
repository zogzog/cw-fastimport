from cubicweb.server.session import HOOKS_DENY_ALL

def transactor(cnx):
    try:
        # a 'client connection'
        return cnx._cnx
    except AttributeError:
        # a 'repo connection'
        return cnx

def nohook(tx):
    # no hooks & no whitelist
    return tx._hooks_mode == HOOKS_DENY_ALL and not tx._hooks_categories
