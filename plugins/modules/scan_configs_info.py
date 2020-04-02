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
module: scan_configs_info
short_description: Obtain information about AntiMalware Scan Configs in TrendMicro Deep Security
description:
  - Obtain information about AntiMalware Scan Configs in TrendMicro Deep Security
version_added: "2.9"
options:
  id:
    description:
      - FIXME FIXME FIXME
    required: false
    type: str

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

    argspec = dict(
        id=dict(required=False, type="int"),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)

    deepsec_request = DeepSecurityRequest(module)

    scan_configs = deepsec_request.get('/rest/policies/antimalware/scanConfigs')

    module.exit_json(scan_configs=scan_configs, changed=False)


if __name__ == "__main__":
    main()
