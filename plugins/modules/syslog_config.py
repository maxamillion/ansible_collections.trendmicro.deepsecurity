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
  eventFormat
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
  privateKey:
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
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible_collections.trendmicro.deepsecurity.plugins.module_utils.deepsecurity import DeepSecurityRequest

import copy
import json


def main():

    # FIXME - MAKE THE ARGSPEC MATCH DOCS
    argspec = dict(
        id=dict(required=False, type="int"),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)

    deepsec_request = DeepSecurityRequest(module)

    syslog_configs = deepsec_request.get('/rest/syslog-configurations')


    module.exit_json(syslog_config=syslog_configs, changed=False)


if __name__ == "__main__":
    main()
