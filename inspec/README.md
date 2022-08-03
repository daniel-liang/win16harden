## Windows 2016 CIS

This Baseline ensures, that all hardening projects keep the same quality.
These tests were originally source from:
- https://github.com/dev-sec/chef-windows-hardening

They have been modified to suit the eHealth CST standard testing CIS level 1 compliance:

## Attributes

Individual rules can be controlled via attributes in [inspec.yml](./inspec.yml).

```yaml
    # Enable test for CIS Rule 1.1.1
    attributes:
        - name: win2016cis_rule_1_1_1
        value: 'true'

    # Disable test for CIS Rule 1.1.1
    attributes:
        - name: win2016cis_rule_1_1_1
        value: 'Provide exception reason'
```

## Standalone Usage

This Compliance Profile requires [InSpec](https://github.com/chef/inspec) for execution:
```
inspec exec inspec -t winrm://<userame>@<host> --password <password>
```

## License and Author

* Copyright 2019, eHealth CST Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
