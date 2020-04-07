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

import q;
@q.t
def translate_syslog_dict_keys(key_to_translate, to_camel_case=False, to_snake_case=False):
    camel_case_to_snake_case = {
        'certificateChain': 'certificate_chain',
        'eventFormat': 'event_format',
        'privateKey': 'private_key',
        'ID': 'id',
    }

    snake_case_to_camel_case = {}

    if to_snake_case:
        for key in camel_case_to_snake_case:
            snake_case_to_camel_case[camel_case_to_snake_case[key]] = key

        import q; q.q( "SNAKE_CASE_TO_CAMEL_CASE: %s" % snake_case_to_camel_case )
        if key_to_translate in snake_case_to_camel_case:
            return snake_case_to_camel_case[key]

    if to_camel_case:
        if key_to_translate in camel_case_to_snake_case:
            return camel_case_to_snake_case[key_to_translate]

    return key_to_translate


def main():

    # FIXME - MAKE THE ARGSPEC MATCH DOCS
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

    syslog_module_config = {}
    for param in module.params:
        import q; q.q("PARAM: %s" % param)

        if module.params[param]:
            import q; q.q( "TRANSLATE_SYSLOG_DICT_KEYS_SNAKE: %s" % translate_syslog_dict_keys(param, to_snake_case=True) )
            import q; q.q("MODULE.PARAMS[PARAM]: %s" % module.params[param])
            syslog_module_config[translate_syslog_dict_keys(param, to_snake_case=True)] = module.params[param]
    import q; q.q(syslog_module_config)

    syslog_config_found = {}

    if module.params['id']:

        syslog_config_query = deepsec_request.get(
            '/rest/syslog-configurations',
            params={'syslogConfigurationID': module.params['id']},
            query_string_auth=True
        )
        if 'ListSyslogConfigurationsResponse' in syslog_config_query:
            syslog_config_found = syslog_config_query['ListSyslogConfigurationsResponse']['syslogConfigurations'][0]
    else:
        syslog_configs = deepsec_request.get('/rest/syslog-configurations', query_string_auth=True)
        if 'ListSyslogConfigurationsResponse' in syslog_configs:
            for syslog_config in syslog_configs['ListSyslogConfigurationsResponse']['syslogConfigurations']:
                if syslog_config['name'] == module.params['name']:
                    syslog_config_found = syslog_config
                    break

    changed = False
    for key in syslog_module_config:
        if (
            key in syslog_config_found and
            syslog_module_config[key] != syslog_config_found[key]
        ):
            if module.check_mode:
                module.exit_json(syslog_config={}, msg="Check Mode Run", changed=True)
            else:
                syslog_config_modified = deepsec_request.post(
                    '/rest/syslog-configurations?{}'.format(urlencode(syslog_module_config)),
                    query_string_auth=True
                )

            module.exit_json(syslog_config=syslog_config_modified, changed=True)


    module.exit_json(syslog_config=syslog_config_found, changed=False)


if __name__ == "__main__":
    main()
