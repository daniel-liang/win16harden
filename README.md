# Win2016 CIS Ansible role

Configure a Windows 2016 server to be [CIS](https://www.cisecurity.org/cis-benchmarks/) compliant. Level 1 findings will be corrected by default with some exceptions as part of eHealth Remediation and/or technical considerations.

Based on [CIS Microsoft Windows Server 2016 Benchmark v1.1.0](./docs/CIS_Microsoft_Windows_Server_2016_RTM_Release_1607_Benchmark_v1.1.0.pdf).

## Requirements

N/A

## Role Variables

This role has no variables.

## Dependencies

Ansible > 2.2

## Example Playbook

```yaml
    - hosts: Windows_2016_Hosts
      roles:
         - ansible-role-win2016cis
```

## Testing

## CIS Win2016 Rule Exception List
Rules implemented from source document: CIS_Microsoft_Windows_Server_2016_RTM_Release_1607_Benchmark_v1.1.0.pdf

| Rule | Exception Reason |
--- | --- |
| win2016cis_rule_2_2_2 | Domain Controller only |
| win2016cis_rule_2_2_5 | Domain Controller only |
| win2016cis_rule_2_2_8 | Domain Controller only |
| win2016cis_rule_2_2_17 | Domain Controller only |
| win2016cis_rule_2_2_20 | Domain Controller only |
| win2016cis_rule_2_2_21 | Not recommended for non domain joined servers |
| win2016cis_rule_2_2_25 | Domain Controller only |
| win2016cis_rule_2_2_26 | Prevents remote management of  non domain joined servers |
| win2016cis_rule_2_2_27 | Domain Controller only |
| win2016cis_rule_2_2_31 | Domain Controller only |
| win2016cis_rule_2_2_36 | Domain Controller only |
| win2016cis_rule_2_2_37 | Domain Controller only |
| win2016cis_rule_2_2_47 | Domain Controller only |
| win2016cis_rule_2_3_1_1 | Disables the standard AWS features i.e. retrieving encrypted password |
| win2016cis_rule_2_3_1_5 | Not applicable in Azure as local administrator account name is created at vm build time |
| win2016cis_rule_2_3_5_1 | Domain Controller only |
| win2016cis_rule_2_3_5_2 | Domain Controller only |
| win2016cis_rule_2_3_5_3 | Domain Controller only |
| win2016cis_rule_2_3_7_6 | Level 2 |
| win2016cis_rule_2_3_7_8 | Recommended CIS setting is reverted in Exclusions.yml |
| win2016cis_rule_2_3_9_4 | Recommended CIS setting is reverted in Exclusions.yml |
| win2016cis_rule_2_3_10_4 | Level 2 |
| win2016cis_rule_2_3_10_6 | Domain Controller only |
| win2016cis_rule_2_3_17_1 | Causes loss of connectivity during packer builds |
| win2016cis_rule_2_3_17_4 | Disabled in favour of conflicting rule win2016ewrc_rule_14 which recommends UAC prompt |
| win2016cis_rule_9_3_5 | Causes RDP connection issues |
| win2016cis_rule_9_3_6 | Causes RDP connection issues |
| win2016cis_rule_17_2_3 | Domain Controller only |
| win2016cis_rule_17_3_1 | Unable to implement. Ansible win_audit_policy_system module does not support PNP Activity subcategory |
| win2016cis_rule_17_4_1 | Domain Controller only |
| win2016cis_rule_17_4_2 | Domain Controller only |
| win2016cis_rule_18_1_3 | Level 2 |
| win2016cis_rule_18_2_1 | Applies to domain joined servers only |
| win2016cis_rule_18_2_2 | Applies to domain joined servers only |
| win2016cis_rule_18_2_3 | Applies to domain joined servers only |
| win2016cis_rule_18_2_4 | Applies to domain joined servers only |
| win2016cis_rule_18_2_5 | Applies to domain joined servers only |
| win2016cis_rule_18_2_6 | Applies to domain joined servers only |
| win2016cis_rule_18_3_1 | Elevation required for remote shell such as bootstrap_win |
| win2016cis_rule_18_4_1 | ansible enters the key but is missing when inspec checks for it |
| win2016cis_rule_18_4_5 | Level 2 |
| win2016cis_rule_18_4_7 | Level 2 |
| win2016cis_rule_18_4_10 | Level 2 |
| win2016cis_rule_18_4_11 | Level 2 |
| win2016cis_rule_18_5_5_1 | Level 2 |
| win2016cis_rule_18_5_9_1 | Level 2 |
| win2016cis_rule_18_5_9_2 | Level 2 |
| win2016cis_rule_18_5_10_2 | Level 2 |
| win2016cis_rule_18_5_14_1 | Found commented out due to erroring out |
| win2016cis_rule_18_5_19_2_1 | Level 2 |
| win2016cis_rule_18_5_20_1 | Level 2 |
| win2016cis_rule_18_5_20_2 | Level 2 |
| win2016cis_rule_18_5_21_2 | Level 2 |
| win2016cis_rule_18_8_5_1 | Level 2 |
| win2016cis_rule_18_8_5_2 | Level 2 |
| win2016cis_rule_18_8_5_3 | Level 2 |
| win2016cis_rule_18_8_5_4 | Level 2 |
| win2016cis_rule_18_8_5_5 | Level 2 |
| win2016cis_rule_18_8_22_1_2 | Level 2 |
| win2016cis_rule_18_8_22_1_3 | Level 2 |
| win2016cis_rule_18_8_22_1_4 | Level 2 |
| win2016cis_rule_18_8_22_1_7 | Level 2 |
| win2016cis_rule_18_8_22_1_8 | Level 2 |
| win2016cis_rule_18_8_22_1_9 | Level 2 |
| win2016cis_rule_18_8_22_1_10 | Level 2 |
| win2016cis_rule_18_8_22_1_11 | Level 2 |
| win2016cis_rule_18_8_22_1_12 | Level 2 |
| win2016cis_rule_18_8_22_1_13 | Level 2 |
| win2016cis_rule_18_8_25_1 | Level 2 |
| win2016cis_rule_18_8_26_1 | Level 2 |
| win2016cis_rule_18_8_33_6_1 | Level 2 |
| win2016cis_rule_18_8_33_6_2 | Level 2 |
| win2016cis_rule_18_8_36_2 | Level 2 |
| win2016cis_rule_18_8_44_5_1 | Level 2 |
| win2016cis_rule_18_8_44_11_1 | Level 2 |
| win2016cis_rule_18_8_46_1 | Level 2 |
| win2016cis_rule_18_8_49_1_1 | Level 2 |
| win2016cis_rule_18_8_49_1_2 | Level 2 |
| win2016cis_rule_18_9_4_1 | Level 2 |
| win2016cis_rule_18_9_12_1 | Level 2 |
| win2016cis_rule_18_9_16_2 | Level 2 |
| win2016cis_rule_18_9_39_2 | Level 2 |
| win2016cis_rule_18_9_43_1 | Level 2 |
| win2016cis_rule_18_9_58_3_2_1 | Level 2 |
| win2016cis_rule_18_9_58_3_3_1 | Level 2 |
| win2016cis_rule_18_9_58_3_3_3 | Level 2 |
| win2016cis_rule_18_9_58_3_3_4 | Level 2 |
| win2016cis_rule_18_9_58_3_10_1 | Level 2 |
| win2016cis_rule_18_9_58_3_10_2 | Level 2 |
| win2016cis_rule_18_9_60_2 | Level 2 |
| win2016cis_rule_18_9_65_1 | Level 2 |
| win2016cis_rule_18_9_76_3_2 | Level 2 |
| win2016cis_rule_18_9_76_9_1 | Level 2 |
| win2016cis_rule_18_9_78_3_1 | Section 18.9.78 is blank in the CIS document |
| win2016cis_rule_18_9_84_1 | Level 2 |
| win2016cis_rule_18_9_85_3 | Level 2 |
| win2016cis_rule_18_9_95_1 | Disabled in favour  conflicting rule win2016ewrc_rule_76 |
| win2016cis_rule_18_9_97_2_2 | Level 2 |
| win2016cis_rule_18_9_98_1 | Level 2 |
| win2016cis_rule_19_6_5_1_1 | Level 2 |
| win2016cis_rule_19_7_7_3 | Level 2 |
| win2016cis_rule_19_7_7_4 | Level 2 |
| win2016cis_rule_19_7_44_2_1 | Level 2 |


## Health Remediation Exception List
Rules implemented from source document: Content Security Report - eHealth - Windows Registry Changes.xlsx

| Rule | Exception Reason |
--- | --- |
| win2016ewrc_rule_1 | Domain Controller only |
| win2016ewrc_rule_21 | Disables the standard AWS features i.e. retreiving encrypted password' |
| win2016ewrc_rule_32 | Too restrictive |
| win2016ewrc_rule_33 | Too restrictive |
| win2016ewrc_rule_42 | Domain Controller only |
| win2016ewrc_rule_77 | Causes issue when running unsigned powershell scripts, complexity getting signing root on devices |
| win2016ewrc_rule_120 | Already covered by default NSG/SG security rules |


## CIS IIS10 Exception List
Rules implemented from source document: CIS_Microsoft_IIS_10_Benchmark_v1.0.0.pdf

| Rule | Exception Reason |
--- | --- |
| win2016cisiis10_rule_7_8 | anisble confirmed but inspec unable to check registry path with forward slashes |
| win2016cisiis10_rule_7_9_1 | anisble confirmed but inspec unable to check registry path with forward slashes |
| win2016cisiis10_rule_7_9_2 | anisble confirmed but inspec unable to check registry path with forward slashes |
| win2016cisiis10_rule_7_9_3 | anisble confirmed but inspec unable to check registry path with forward slashes |
| win2016cisiis10_rule_7_9_4 | anisble confirmed but inspec unable to check registry path with forward slashes |
| win2016cisiis10_rule_7_10 | anisble confirmed but inspec unable to check registry path with forward slashes |

## Author Information

eHealth NSW - Cloud Services Team