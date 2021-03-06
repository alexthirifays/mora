#
# Copyright (c) 2017, Magenta ApS
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

from .. import lora
from .. import util


def list_organisations():
    orgs = lora.organisation(uuid=lora.organisation(bvn='%'))

    def convert(org):
        rootid = lora.organisationenhed(overordnet=org['id'])[0]
        orgunit = lora.organisationenhed.get(rootid)
        unitattrs = orgunit['attributter']['organisationenhedegenskaber'][0]
        unit_validity = orgunit['tilstande']['organisationenhedgyldighed'][0]

        reg = org['registreringer'][-1]

        return wrap_in_org(org['id'], {
            'name': unitattrs['enhedsnavn'],
            'user-key': unitattrs['brugervendtnoegle'],
            'uuid': rootid,
            'valid-from': util.to_frontend_time(
                unit_validity['virkning']['from'],
            ),
            'valid-to': util.to_frontend_time(
                unit_validity['virkning']['to'],
            ),
            'hasChildren': True,
            'children': [],
            'org': org['id'],
        }, reg)

    return list(map(convert, orgs))


def full_hierarchies(orgid: str, parentid: str,
                     include_children=True,
                     include_parents=False,
                     include_activename=False,
                     **loraparams):
    assert isinstance(parentid, str), parentid

    kwargs = dict(
        include_children=include_children,
        include_parents=include_parents,
        include_activename=include_activename,
        **loraparams,
    )

    unitids = lora.organisationenhed(
        tilhoerer=orgid,
        overordnet=parentid,
        gyldighed='Aktiv',
        **loraparams,
    )

    return sorted(
        filter(None, (full_hierarchy(orgid, unitid, **kwargs)
                      for unitid in unitids)),
        key=lambda r: r['name'].lower(),
    )


def full_hierarchy(orgid: str, unitid: str,
                   include_children=True,
                   include_parents=False,
                   include_activename=False,
                   **loraparams):
    assert isinstance(orgid, str)
    assert isinstance(unitid, str)

    kwargs = dict(
        include_children=False,
        include_parents=include_parents,
        include_activename=include_activename,
    )
    kwargs.update(loraparams)

    orgunit = lora.organisationenhed.get(unitid, **loraparams)

    # TODO: check validity?

    try:
        attrs = orgunit['attributter']['organisationenhedegenskaber'][0]
    except LookupError:
        return None

    rels = orgunit['relationer']

    # Get the current org unit end-date and use this for past and future too
    current_orgunit = lora.organisationenhed.get(uuid=unitid)
    orgunit_validity = current_orgunit['tilstande'][
        'organisationenhedgyldighed'][0]['virkning']

    children = lora.organisationenhed(tilhoerer=orgid, overordnet=unitid,
                                      gyldighed='Aktiv',
                                      **loraparams)

    unit_types = orgunit['relationer']['enhedstype']
    if unit_types:
        # TODO: should we pass on loraparams? perhaps, but not validity
        unit_type = lora.klasse.get(uuid=unit_types[0]['uuid'])
    else:
        unit_type = None

    validity = loraparams.get('validity')
    if not validity or validity == 'present':
        parent = rels['overordnet'][0]['uuid']
        orgid = rels['tilhoerer'][0]['uuid']
    else:
        parent = None

    r = {
        'name': attrs['enhedsnavn'],
        'user-key': attrs['brugervendtnoegle'],
        'uuid': unitid,
        'type': {
            'name': unit_type['attributter']['klasseegenskaber'][0]['titel']
            if unit_type else ''  # TODO: problem with ['klasseegenskaber'][0]?
        },
        'valid-from': util.to_frontend_time(
            orgunit_validity['from'],
        ),
        'valid-to': util.to_frontend_time(
            orgunit_validity['to'],
        ),
        'hasChildren': bool(children),
        'org': str(orgid),
        'parent': parent if parent and parent != orgid else None,
    }

    if include_parents:
        assert not include_children, 'including both parents and children?'

        r["parent-object"] = (
            full_hierarchy(orgid, parent, **kwargs)
            if parent and parent != orgid else None
        )
    else:
        r['children'] = (
            full_hierarchies(orgid, unitid, **kwargs)
            if include_children else []
        )

    if include_activename:
        r['activeName'] = attrs['enhedsnavn']

    return r


def wrap_in_org(orgid, value, org=None):
    if not org:
        org = lora.organisation.get(orgid)

    orgattrs = org['attributter']['organisationegenskaber'][0]
    org_validity = org['tilstande']['organisationgyldighed'][0]

    return {
        'hierarchy': value,
        'name': orgattrs['organisationsnavn'],
        'user-key': orgattrs['brugervendtnoegle'],
        'uuid': orgid,
        'valid-from': util.to_frontend_time(
            org_validity['virkning']['from'],
        ),
        'valid-to': util.to_frontend_time(
            org_validity['virkning']['to'],
        ),
    }


def unit_history(orgid, unitid):
    # TODO: verify orgid?

    regs = lora.organisationenhed.get(unitid, registreretfra='-infinity',
                                      registrerettil='infinity')

    for reg in regs:
        yield {
            'changedBy': reg['brugerref'],
            'object': unitid,
            'date': reg['fratidspunkt']['tidsstempeldatotid'],
            'from': reg['fratidspunkt']['tidsstempeldatotid'],
            'to': reg['tiltidspunkt']['tidsstempeldatotid'],
            'section': reg['livscykluskode'],
            'action': reg.get('note'),
        }
