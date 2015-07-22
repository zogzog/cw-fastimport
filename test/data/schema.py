from yams.buildobjs import RelationDefinition, Bytes

class my_email(RelationDefinition):
    fulltext_container = 'subject'
    subject = 'CWUser'
    object = 'EmailAddress'
    cardinality = '??'
    inlined = True

class some_bytes(RelationDefinition):
    subject = 'CWUser'
    object = 'Bytes'
    cardinality = '?1'
