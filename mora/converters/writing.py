#
# Copyright (c) 2017, Magenta ApS
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

import mora.lora as lora
import mora.util as util


class AbstractManipulateVirkning(object):
    """
    Template design pattern
    """

    def __init__(self, lora_obj: dict, virkning: dict):
        self.lora_obj = lora_obj
        self.virkning = virkning

    def do_work(self):
        for k, v in self.lora_obj.items():
            if isinstance(v, dict):
                self.do_work()
            elif isinstance(v, list):
                hook1_output = self.hook1()
                for d in v:
                    self.hook2(d, v, hook1_output)
                self.hook3(v, hook1_output)
            else:
                pass
        return self.lora_obj

    def hook1(self, *args):
        pass

    def hook2(self, *args):
        pass

    def hook3(self, *args):
        pass


def _add_virkning(lora_obj: dict, virkning: dict) -> dict:
    """
    Adds virkning to the "leafs" of the given LoRa JSON (tree) object
    :param lora_obj: a LoRa object without virkning
    :param virkning: the virkning to add to the LoRa object
    :return: the LoRa object with virkning
    """
    for k, v in lora_obj.items():
        if isinstance(v, dict):
            _add_virkning(v, virkning)
        else:
            assert isinstance(v, list)
            for d in v:
                d['virkning'] = virkning
    return lora_obj


def _create_virkning(req: dict, from_included=True, to_included=False) -> dict:
    """
    Create virkning from frontend request
    :param req: the JSON request object provided by the frontend
    :param from_included: specify if the from-date should be included or not
    :param to_included: specify if the to-date should be included or not
    :return: the virkning object
    """
    return {
        'from': util.reparsedate(req.get('valid-from')),
        'to': util.reparsedate(req.get('valid-to')),
        'from_included': from_included,
        'to_included': to_included
    }


# def _extend_current_virkning(lora_registrering_obj: dict, virkning: dict) -> dict:
#     """
#     Extend the elements in a given LoRa "registrering" object to also apply during the new "virkning"
#     :param lora_registrering_obj: a LoRa "registrering" object (pre-condition: must only contain data for present date)
#     :param virkning: the new "virkning" to apply
#     :return: a LoRa "registrering" object extended with the given "virkning"
#     """
#
#     # TODO: Quick and dirty to make things work...
#     # TODO: refactor common functionality in this function and _add_virkning into separate function (or make class)
#     # TODO: add (more) test cases!!!
#
#     for k, v in lora_registrering_obj.items():
#         if isinstance(v, dict):
#             _extend_current_virkning(v, virkning)
#         elif isinstance(v, list):
#             new_objs = []
#             for d in v:
#                 d_copy = d.copy()
#                 d_copy['virkning'] = virkning
#                 new_objs.append(d_copy)
#             v.extend(new_objs)
#         else:
#             pass
#     return lora_registrering_obj


class ExtendCurrentVirkning(AbstractManipulateVirkning):

    def hook1(self, *args):
        return []

    def hook2(self, *args):
        d_copy = args[0].copy()
        d_copy['virkning'] = self.virkning
        args[2].append(d_copy)

    def hook3(self, *args):
        args[0].extend(args[1])




def _extend_current_virkning(lora_registrering_obj: dict, virkning: dict) -> dict:
    """
    Extend the elements in a given LoRa "registrering" object to also apply during the new "virkning" 
    :param lora_registrering_obj: a LoRa "registrering" object (pre-condition: must only contain data for present date)
    :param virkning: the new "virkning" to apply
    :return: a LoRa "registrering" object extended with the given "virkning"
    """

    # TODO: Quick and dirty to make things work...
    # TODO: refactor common functionality in this function and _add_virkning into separate function (or make class)
    # TODO: add (more) test cases!!!

    for k, v in lora_registrering_obj.items():
        if isinstance(v, dict):
            _extend_current_virkning(v, virkning)
        elif isinstance(v, list):
            new_objs = []
            for d in v:
                d_copy = d.copy()
                d_copy['virkning'] = virkning
                new_objs.append(d_copy)
            v.extend(new_objs)
        else:
            pass
    return lora_registrering_obj


def _set_virkning_enddate(lora_registrering_obj: dict, req: dict) -> dict:
    pass


def create_org_unit(req: dict) -> dict:
    """
    Create org unit data to send to LoRa
    :param : Dictionary representation of JSON request from the frontend 
    :return: Dictionary representation of the org unit JSON object to send to LoRa
    """

    # Create virkning
    virkning = _create_virkning(req)

    nullrelation = [{
        'virkning': virkning,
    }]

    # Create the organisation unit object
    org_unit = {
        'attributter': {
            'organisationenhedegenskaber': [
                {
                    'enhedsnavn': req['name'],
                    'brugervendtnoegle': req['name'].replace(' ', ''),  # TODO: make a proper function to set the bvn
                },
            ],
        },
        'tilstande': {
            'organisationenhedgyldighed': [
                {
                    'gyldighed': 'Aktiv',
                },
            ],
        },
        'relationer': {
            'adresser': [
                            {
                                'uuid': location['location']['UUID_EnhedsAdresse'],
                            }
                            # TODO: will we ever have more than one location? (multiple locations not tested)
                            # TODO: (however, multible contact channels are tested)
                            for location in req.get('locations', [])
                        ] + [
                            {
                                'urn': 'urn:magenta.dk:telefon:{}'.format(
                                    channel['contact-info'],
                                ),
                            }
                            for location in req.get('locations', [])
                            for channel in location.get('contact-channels', [])
                        ] or nullrelation,  # TODO: will "... or nullrelation" ever happen? (no test for this yet...)
            'tilhoerer': [
                {
                    'uuid': req['org'],
                }
            ],
            'enhedstype': [
                {
                    'uuid': req['type']['uuid'],
                }
            ],
            'overordnet': [
                {
                    'uuid': req['parent'],
                }
            ],
        }
    }

    return _add_virkning(org_unit, virkning)


def rename_org_unit(req: dict) -> dict:
    """
    Rename org unit
    :param req: 
    :return: 
    """

    virkning = _create_virkning(req)

    # Get the current org unit and update this
    org_unit = lora.organisationenhed(uuid=req['uuid'])[0]['registreringer'][-1]

    # TODO: we are not handling overlapping virknings
    # Assumption for now: 'valid-from' is greater than or equal to the latest 'valid-to'

    x = ExtendCurrentVirkning(org_unit, virkning)
    x.do_work()
    # _extend_current_virkning(org_unit, virkning)
    org_unit['attributter']['organisationenhedegenskaber'][-1]['enhedsnavn'] = req['name']

    return org_unit
