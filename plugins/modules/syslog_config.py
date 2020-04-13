#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}
DOCUMENTATION = """
---
module: syslog_config
short_description: Configure or create a syslog configuration for TrendMicro Deep Security
description:
  - Configure or create a syslog configuration for TrendMicro Deep Security
version_added: "2.9"
options:
  name:
    description:
      - The name for this syslog configuration.
    required: false
    type: str
  id:
    description:
      - The ID of the syslog configuration (when editing an existing configuration).
    required: false
    type: str
  certificate_chain:
    description:
      - The identity certificate chain the Deep Security Manager will use when it contacts the syslog server over TLS.
      - The identity certificate must be the first certificate in the list,
        followed by the certificate for the issuing certificate authority (if any) and continuing up the issuer chain.
      - The root certificate authority's certificate does not need to be included.
      - Each element in the list will be an unencrypted PEM-encoded certificate.
    required: false
    type: str
  description:
    description:
      - The description for this syslog configuration.
    required: false
    type: str
  direct:
    description:
      - The "direct delivery from agent to syslog server" flag.
    required: false
    type: bool
  event_format:
    description:
      - The event format to use when sending syslog messages.
    type: str
    required: false
    choices:
      - 'standard'
      - 'cef'
      - 'leef'
    default: 'standard'
  facility:
    description:
      - The facility value to send with each syslog message.
    required: false
    type: str
    choices:
      - 'kernel'
      - 'user'
      - 'mail'
      - 'daemon'
      - 'authorization'
      - 'syslog'
      - 'printer'
      - 'news'
      - 'uucp'
      - 'clock'
      - 'authpriv'
      - 'ftp'
      - 'ntp'
      - 'log-audit'
      - 'log-alert'
      - 'cron'
      - 'local0'
      - 'local1'
      - 'local2'
      - 'local3'
      - 'local4'
      - 'local5'
      - 'local6'
      - 'local7'
    default: 'syslog'
  port:
    description:
      - The destination port for syslog messages.
    type: int
    required: no
    default: 514
  private_key:
    description:
      - The private key the Deep Security Manager will use when it contacts the syslog server over TLS.
      - The private key must be an RSA key in PEM-encoded PKCS#1 or PKCS#8 format.
      - To prevent accidental disclosure of the private key, the Deep Security Manager will not return this value;
        therefore Ansible does not have access to it and it can only be used to set the private key.
    type: str
    required: no
  server:
    description:
      - The destination server for syslog messages.
    type: str
    required: no
  transport:
    description:
      - The transport to use when sending syslog messages.
    required: false
    type: str
    choices:
      - 'udp'
      - 'tcp'
      - 'tls'
    default: 'udp'

notes:
  - Must provide one of either: C(name) or C(id)

author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>"
"""


# FIXME - provide correct example here
RETURN = """
"""

EXAMPLES = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text

from ansible.module_utils.urls import Request
from ansible.module_utils.six.moves.urllib.parse import quote, urlencode
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible_collections.trendmicro.deepsecurity.plugins.module_utils.deepsecurity import DeepSecurityRequest

import copy
import json

def translate_syslog_dict_keys(key_to_translate, to_camel_case=False, to_snake_case=False):
    """
    It is not idiomatic Ansible to use snake case so we do bookkeeping here for that
    """
    camel_case_to_snake_case = {
        'certificateChain': 'certificate_chain',
        'eventFormat': 'event_format',
        'privateKey': 'private_key',
        'ID': 'id',
    }

    if to_camel_case:
        if key_to_translate in camel_case_to_snake_case:
            return camel_case_to_snake_case[key_to_translate]
    if to_snake_case:
        snake_case_to_camel_case = {}

        for key in camel_case_to_snake_case:
            snake_case_to_camel_case[camel_case_to_snake_case[key]] = key

        if key_to_translate in snake_case_to_camel_case:
            return snake_case_to_camel_case[key_to_translate]

    return key_to_translate


import q;
@q.t
def sync_configs(trendmicro_config, module_config):
    for key in module_config:
        if key in trendmicro_config:
            trendmicro_config[key] = module_config[key]

    ## Trend Micro REST API for syslog returns the key
    ## of ID from a GET but wants a key of iD on a POST
    # FIXME FIXME FIXME - I don't know what this wants, the docs are wrong nothing seemd to work
    #if 'ID' in trendmicro_config:
    #    trendmicro_config['iD'] = trendmicro_config['ID']
    #    del trendmicro_config['ID']

    ## Trend Micro REST API for syslog returns the key
    ## of ID from a GET but wants a key of iD on a POST
    #for snake_key in ['certificateChain', 'eventFormat', 'privateKey']:
    #    if snake_key in trendmicro_config:
    #        snake_key_capitalized = snake_key[0].capitalize() + snake_key[1:]
    #        trendmicro_config[snake_key_capitalized] = trendmicro_config[snake_key]
    #        del trendmicro_config[snake_key]

    ## Trend Micro REST API for syslog returns certain keys in lower case
    ## from a GET but wants a capitalized key of on a POST
    #for key in ['description', 'direct', 'facility', 'name', 'server', 'transport', 'port']:
    #    if key in trendmicro_config:
    #        trendmicro_config[key.capitalize()] = trendmicro_config[key]
    #        del trendmicro_config[key]

    return trendmicro_config


def main():

    argspec = dict(
        name=dict(required=False, type="str"),
        id=dict(required=False, type="int"),
        certificate_chain=dict(required=False, type="str"),
        description=dict(required=False, type="str"),
        direct=dict(required=False, type="bool"),
        event_format=dict(required=False, type="str",
                          choices=['standard', 'cef', 'leef'], default='standard'),
        facility=dict(required=False, type="str",
                    choices=[
                        'kernel', 'user', 'mail', 'daemon', 'authorization', 'syslog',
                        'printer', 'news', 'uucp', 'clock', 'authpriv', 'ftp', 'ntp',
                        'log-audit', 'log-alert', 'cron', 'local0', 'local1', 'local2',
                        'local3', 'local4', 'local5', 'local6', 'local7'
                    ], default='syslog'),
        port=dict(required=False, type="int", default=514),
        private_key=dict(required=False, type="str", no_log=True),
        server=dict(required=False, type="str"),
        transport=dict(required=False, type="str",
                          choices=['udp', 'tcp', 'tls'], default='udp'),
    )

    module = AnsibleModule(
        argument_spec=argspec,
        supports_check_mode=True,
        required_one_of=[
            ['name', 'id'],
        ]
    )

    deepsec_request = DeepSecurityRequest(module)

    syslog_config_found = {}

    # Query System to get current state of config
    if module.params['id']:
        syslog_config_query = deepsec_request.get(
            '/rest/syslog-configurations',
            params={'syslogConfigurationID': module.params['id']},
        )
        if 'ListSyslogConfigurationsResponse' in syslog_config_query:
            syslog_config_found = syslog_config_query['ListSyslogConfigurationsResponse']['syslogConfigurations'][0]
    else:
        syslog_configs = deepsec_request.get('/rest/syslog-configurations')
        if 'ListSyslogConfigurationsResponse' in syslog_configs:
            for syslog_config in syslog_configs['ListSyslogConfigurationsResponse']['syslogConfigurations']:
                if syslog_config['name'] == module.params['name']:
                    syslog_config_found = syslog_config
                    break


    # Run transaction against Trend Micro Deep Security
    changed = False
    syslog_module_config = {}
    for param in module.params:
        if module.params[param]:
            syslog_module_config[
                translate_syslog_dict_keys(param, to_snake_case=True)
            ] = module.params[param]

    for key in syslog_module_config:
        if (
            key in syslog_config_found and
            syslog_module_config[key] != syslog_config_found[key]
        ):
            if module.check_mode:
                module.exit_json(syslog_config={}, msg="Check Mode Run", changed=True)
            else:
                syslog_config_synced = sync_configs(syslog_config_found, syslog_module_config)
                import q; q.q(syslog_config_synced)
                syslog_config_modified = deepsec_request.post(
                    '/rest/syslog-configurations',
                    data={'SyslogConfiguration': syslog_config_synced},
                )
            module.exit_json(syslog_config=syslog_config_modified, changed=True)

    module.exit_json(syslog_config=syslog_config_found, changed=False)


if __name__ == "__main__":
    main()
