def get_audit_attrs(data):
    # Split audit.log entry into dict
    data = data.replace("'", " ")
    data = data.replace('"', "")
    data = data.replace("\n", "")
    data = data.split(' ')

    attrs = dict((s.split('=')+[1])[:2] for s in data)

    # Clean some values
    attrs['AUID'] = attrs['AUID'].strip('\n')
    attrs['UID'] = attrs.pop('\x1dUID')
    
    return attrs
