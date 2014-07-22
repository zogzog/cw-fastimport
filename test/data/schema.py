from yams.buildobjs import RelationDefinition

class my_email(RelationDefinition):
    fulltext_container = 'subject'
    subject = 'CWUser'
    object = 'EmailAddress'
    cardinality = '??'
    inlined = True
