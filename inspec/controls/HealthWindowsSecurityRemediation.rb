# encoding: utf-8

# Rule toggle enabled/disabled variables
win2016ewrc_rule_5 = attribute('win2016ewrc_rule_5')
win2016ewrc_rule_14 = attribute('win2016ewrc_rule_14')
win2016ewrc_rule_37 = attribute('win2016ewrc_rule_37')
win2016ewrc_rule_38 = attribute('win2016ewrc_rule_38')
win2016ewrc_rule_39 = attribute('win2016ewrc_rule_39')
win2016ewrc_rule_64 = attribute('win2016ewrc_rule_64')
win2016ewrc_rule_66 = attribute('win2016ewrc_rule_66')
win2016ewrc_rule_70 = attribute('win2016ewrc_rule_70')
win2016ewrc_rule_76 = attribute('win2016ewrc_rule_76')
win2016ewrc_rule_77 = attribute('win2016ewrc_rule_77')
win2016ewrc_rule_80 = attribute('win2016ewrc_rule_80')
win2016ewrc_rule_104 = attribute('win2016ewrc_rule_104')
win2016cisiis10_rule_7_8 = attribute('win2016cisiis10_rule_7_8')
win2016cisiis10_rule_7_9_1 = attribute('win2016cisiis10_rule_7_9_1')
win2016cisiis10_rule_7_9_2 = attribute('win2016cisiis10_rule_7_9_2')
win2016cisiis10_rule_7_9_3 = attribute('win2016cisiis10_rule_7_9_3')
win2016cisiis10_rule_7_9_4 = attribute('win2016cisiis10_rule_7_9_4')
win2016cisiis10_rule_7_10 = attribute('win2016cisiis10_rule_7_10')
win2016ewrc_rule_21 = attribute('win2016ewrc_rule_21')
win2016ewrc_rule_65 = attribute('win2016ewrc_rule_65')
win2016ewrc_rule_32 = attribute('win2016ewrc_rule_32')
win2016ewrc_rule_33 = attribute('win2016ewrc_rule_33')
win2016ewrc_rule_24 = attribute('win2016ewrc_rule_24')
win2016ewrc_rule_1 = attribute('win2016ewrc_rule_1')
win2016ewrc_rule_42 = attribute('win2016ewrc_rule_42')
win2016ewrc_rule_46 = attribute('win2016ewrc_rule_46')
win2016ewrc_rule_53 = attribute('win2016ewrc_rule_53')
win2016ewrc_rule_54 = attribute('win2016ewrc_rule_54')
win2016ewrc_rule_55 = attribute('win2016ewrc_rule_55')
win2016ewrc_rule_57 = attribute('win2016ewrc_rule_57')
win2016ewrc_rule_59 = attribute('win2016ewrc_rule_59')
win2016ewrc_rule_112 = attribute('win2016ewrc_rule_112')
win2016ewrc_rule_113 = attribute('win2016ewrc_rule_113')
win2016ewrc_rule_120 = attribute('win2016ewrc_rule_120')

## rule 5 from Content Security Report - eHealth - Windows Registry Changes.xlsx
control 'csr-eH-wrc.remediation_rule_5_require-trusted-path-for-credential-entry' do
  title "Require trusted path for credential entry"
  desc  "
  	Network Vulnerability Assessment - 5
    This setting should remain disabled as it creates difficulty in performing standard administrative tasks.
  "
  impact 1.0

  only_if (win2016ewrc_rule_5) { win2016ewrc_rule_5 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI') do
    it { should have_property 'EnableSecureCredentialPrompting' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI') do
    its('EnableSecureCredentialPrompting') { should cmp == 0 }
  end
end

## rule 11 describe statements were already commented out (in ansible as well) prior to toggles being implemented.
## commented out the skip as well due to being a duplicate of the (v1.1.0) CIS 2.3.17.1 check in 2_localpolicies.rb (which is not commented out)
# control 'csr-eH-wrc.remediation_rule_11_user-account-control' do
#  title "User Account Control: Admin Approval Mode for the Built-in Administrator account"
#  desc  "
#  	Network Vulnerability Assessment - 11
#
#    The User Account Control: Admin Approval Mode for the built-in Administrator account policy setting controls the behavior of Admin Approval Mode for the built-in Administrator account.
#		The options are:
#			Enabled. The built-in Administrator account uses Admin Approval Mode. By default, any operation that requires elevation of privilege will prompt the user to approve the operation.
#			Disabled. (Default) The built-in Administrator account runs all applications with full administrative privilege.
#  "
#  impact 1.0
#  # describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
#  #   it { should have_property 'FilterAdministratorToken' }
#  # end
#  # describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
#  #   its('FilterAdministratorToken') { should cmp == 1 }
#  # end
#  describe "Disable administrative privileges for built in Administrator accout" do
#    skip "Causes loss of connectivity during packer builds"
#  end
#end

## rule 13 from "Content Security Report - eHealth - Windows Registry Changes.xlsx"
## commented out due to being a duplicate of the (v1.1.0) CIS 2.3.17.3 check in 2_localpolicies.rb
#control 'csr-eH-wrc.remediation_rule_13_User_Account_Control:_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode' do
#  title "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode"
#  desc  "
#  	Network Vulnerability Assessment - 13
#
#		The User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode policy setting controls the behavior of the elevation prompt for administrators.
#		The options are:
#		0 Elevate without prompting. Allows privileged accounts to perform an operation that requires elevation without requiring consent or credentials. Note Use this option only in the most constrained environments.
#		1 Prompt for credentials on the secure desktop. When an operation requires elevation of privilege, the user is prompted on the secure desktop to enter a privileged user name and password. If the user enters valid credentials, the operation continues with the user's highest available privilege.
#		2 Prompt for consent on the secure desktop. When an operation requires elevation of privilege, the user is prompted on the secure desktop to select either Permit or Deny. If the user selects Permit, the operation continues with the user's highest available privilege.
#		3 Prompt for credentials. When an operation requires elevation of privilege, the user is prompted to enter an administrative user name and password. If the user enters valid credentials, the operation continues with the applicable privilege.
#		4 Prompt for consent. When an operation requires elevation of privilege, the user is prompted to select either Permit or Deny. If the user selects Permit, the operation continues with the user's highest available privilege.
#		5 Prompt for consent for non-Windows binaries. (Default) When an operation for a non-Microsoft application requires elevation of privilege, the user is prompted on the secure desktop to select either Permit or Deny. If the user selects Permit, the operation continues with the user's highest available privilege.
#
#  Setting is 2 as prompting for credentials constantly in an existing privileged session is counterproductive.
#
#  "
#  impact 1.0
#  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
#    it { should have_property 'ConsentPromptBehaviorAdmin' }
#  end
#  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
#    its('ConsentPromptBehaviorAdmin') { should cmp == 2 }
#  end
#end

## Similar to v1.1.0 CIS 2.3.17.4 for UAC deny
control 'csr-eH-wrc.remediation_rule_14_User_Account_Control:_Behavior_of_the_elevation_prompt_for_standard users' do
  title "User Account Control: Behavior of the elevation prompt for standard users"
  desc  "
  	Network Vulnerability Assessment - 14

    The User Account Control: Behavior of the elevation prompt for standard users policy setting controls the behavior of the elevation prompt for standard users.
		The options are:
		0 Automatically deny elevation requests. When an operation requires elevation of privilege, a configurable access denied error message is displayed. An enterprise that is running desktops as standard user may choose this setting to reduce help desk calls.
		1 Prompt for credentials on the secure desktop. (Default) When an operation requires elevation of privilege, the user is prompted on the secure desktop to enter a different user name and password. If the user enters valid credentials, the operation continues with the applicable privilege.
		2 Prompt for credentials. When an operation requires elevation of privilege, the user is prompted to enter an administrative user name and password. If the user enters valid credentials, the operation continues with the applicable privilege.
  "
  impact 1.0

  only_if (win2016ewrc_rule_14) { win2016ewrc_rule_14 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'ConsentPromptBehaviorUser' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('ConsentPromptBehaviorUser') { should cmp == 1 }
  end
end

## Similar to v1.1.0 CIS 18.9.26.1.2 for log file >32K
control 'csr-eH-wrc.remediation_rule_37_The_maximum_log_file_size_should_be_65536' do
  title "Specify the maximum log file size (KB) (Application)"
  desc  "
  	Network Vulnerability Assessment - 37

    Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.
		https://www.stigviewer.com/stig/windows_10/2017-12-01/finding/V-63519
  "
  impact 1.0

  only_if (win2016ewrc_rule_37) { win2016ewrc_rule_37 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application') do
    it { should have_property 'MaxSize' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application') do
    its('MaxSize') { should cmp == 65536 }
  end
end

## Similar to v1.1.0 CIS 18.9.26.2.2 for log file >196608
control 'csr-eH-wrc.remediation_rule_38_The_maximum_log_file_size_should_be_2097152' do
  title "Specify the maximum log file size (KB) (Security)"
  desc  "
  	Network Vulnerability Assessment - 38

    Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.
		https://www.stigviewer.com/stig/windows_10/2017-12-01/finding/V-63519
  "
  impact 1.0

  only_if (win2016ewrc_rule_38) { win2016ewrc_rule_38 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security') do
    it { should have_property 'MaxSize' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security') do
    its('MaxSize') { should cmp == 2097152 }
  end
end

## Similar to v1.1.0 CIS 18.9.26.4.2
control 'csr-eH-wrc.remediation_rule_39_The_maximum_log_file_size_should_be_65536' do
  title "Specify the maximum log file size (KB) (System)"
  desc  "
  	Network Vulnerability Assessment - 39

    Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.
		https://www.stigviewer.com/stig/windows_10/2017-12-01/finding/V-63519
  "
  impact 1.0

  only_if (win2016ewrc_rule_39) { win2016ewrc_rule_39 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System') do
    it { should have_property 'MaxSize' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System') do
    its('MaxSize') { should cmp == 65536 }
  end
end

## Similar to v1.1.0 CIS 18.9.8.3
control 'csr-eH-wrc.remediation_rule_64_Turn_off_Autoplay' do
  title "Turn off Autoplay"
  desc  "
  	Network Vulnerability Assessment - 64

    The NoDriveTypeAutoRun value disables AutoRun for a class of drives.
    https://docs.microsoft.com/en-us/windows/desktop/shell/autoplay-reg#using-the-registry-to-disable-autorun
    NOTE: 255 does not match any of the specific values mentioned in the article
  "
  impact 1.0

  only_if (win2016ewrc_rule_64) { win2016ewrc_rule_64 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoDriveTypeAutoRun' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    its('NoDriveTypeAutoRun') { should cmp == 0xFF }
  end
end

control 'csr-eH-wrc.remediation_rule_66_Prevent_the_computer_from_joining_a_homegroup' do
  title "Prevent the computer from joining a homegroup"
  desc  "
  	Network Vulnerability Assessment - 66
  "
  impact 1.0

  only_if (win2016ewrc_rule_66) { win2016ewrc_rule_66 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\HomeGroup') do
    it { should have_property 'DisableHomeGroup' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\HomeGroup') do
    its('DisableHomeGroup') { should cmp == 1 }
  end
end

## Similar to v1.1.0 CIS 2.3.11.7
control 'csr-eH-wrc.remediation_rule_70_Set_LAN_Manager_authentication_level_to_5' do
  title "Network security: LAN Manager authentication level"
  desc  "
  	Network Vulnerability Assessment - 70
  "
  impact 1.0

  only_if (win2016ewrc_rule_70) { win2016ewrc_rule_70 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should have_property 'LmCompatibilityLevel' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('LmCompatibilityLevel') { should cmp == 5 }
  end
end

## rule 71 from "Content Security Report - eHealth - Windows Registry Changes.xlsx"
## commented out due to being a duplicate of the (v1.1.0) CIS 2.3.11.9 check in 2_localpolicies.rb
#control 'csr-eH-wrc.remediation_rule_71_Set_Minimum_session_security_for_NTLM_SSP_based_(including_secure_RPC)_clients_to_537395200' do
#  title "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients"
#  desc  "
#  	Network Vulnerability Assessment - 71
#  "
#  impact 1.0
#  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
#    it { should have_property 'NtlmMinClientSec' }
#  end
#  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
#    its('NtlmMinClientSec') { should cmp == 537395200 }
#  end
#end

## Opposite setting to v1.1.0 CIS 18.9.95.1
## In Microsoft's hardening guidance, they recommend Enabled, because having this data logged improves investigations of PowerShell attack incidents.
## However, the default ACL on the PowerShell Operational log allows Interactive User (i.e. any logged on user) to read it, and therefore possibly
## expose passwords or other sensitive information to unauthorized users which is why CIS recommends Disabled.
control 'csr-eH-wrc.remediation_rule_76_Turn_on_PowerShell_Script_Block_Logging' do
  title "Turn on PowerShell Script Block Logging"
  desc  "
  "
  impact 1.0

  only_if (win2016ewrc_rule_76) { win2016ewrc_rule_76 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging') do
    it { should have_property 'EnableScriptBlockLogging' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging') do
    its('EnableScriptBlockLogging') { should cmp == 1 }
  end
end

control 'csr-eH-wrc.remediation_rule_77_Turn_on_Script_Execution' do
  title "Turn on Script Execution"
  desc  "
  77
  "

  impact 1.0

  only_if (win2016ewrc_rule_77) { win2016ewrc_rule_77 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell') do
    it { should have_property 'EnableScripts' }
  end

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell') do
    its('EnableScripts') { should cmp == '>0' }
  end

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell') do
    it { should have_property 'ExecutionPolicy' }
  end

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell') do
    its('ExecutionPolicy') { should cmp == 'AllSigned' }
  end
end

## rule 78 from "Content Security Report - eHealth - Windows Registry Changes.xlsx"
## commented out due to being a duplicate of the (v1.1.0) CIS 18.9.58.2.2 check in 18_AdminTemplatesComputer.rb
#control 'csr-eH-wrc.remediation_rule_78_Do_not_allow_passwords_to_be_saved' do
#  title "Do not allow passwords to be saved"
#  desc  "
#    78
#  "
#  impact 1.0
#  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
#    it { should have_property 'DisablePasswordSaving' }
#  end
#  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
#    its('DisablePasswordSaving') { should cmp == 1 }
#  end
#end

control 'csr-eH-wrc.remediation_rule_80_Safe_Mode_Block_Non-Admins' do
  title "Safe Mode Block Non-Admins"
  desc  "
  80
  "
  impact 1.0

  only_if (win2016ewrc_rule_80) { win2016ewrc_rule_80 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'SafeModeBlockNonAdmins' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('SafeModeBlockNonAdmins') { should cmp == 1 }
  end
end

## rule 103 from "Content Security Report - eHealth - Windows Registry Changes.xlsx"
## commented out due to being a duplicate of the (v1.1.0) CIS 19.5.1.1 check in 18_AdminTemplatesComputer.rb
#control 'csr-eH-wrc.remediation_rule_103_Turn_off_toast_notifications_on_the_lock_screen' do
#  title "Turn off toast notifications on the lock screen"
#  desc  "
#    103
#  "
#  impact 1.0
#  describe registry_key('HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications') do
#    it { should have_property 'NoToastApplicationNotificationOnLockScreen' }
#  end
#  describe registry_key('HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications') do
#    its('NoToastApplicationNotificationOnLockScreen') { should cmp == 1 }
#  end
#end

control 'csr-eH-wrc.remediation_rule_104_Disable_WPAD' do
    title "Disable WPAD"
    desc  "
      104
    "
    impact 1.0

    only_if (win2016ewrc_rule_104) { win2016ewrc_rule_104 == 'true' }

    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinHttpAutoProxySvc') do
      it { should have_property 'Start' }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinHttpAutoProxySvc') do
      its('Start') { should cmp == 4 }
    end
end

## rule 107 from "Content Security Report - eHealth - Windows Registry Changes.xlsx"
## commented out due to being a duplicate of the (v1.1.0) CIS 18.9.97.1.3 check in 18_AdminTemplatesComputer.rb
#control 'csr-eH-wrc.remediation_rule_107_Disallow_Digest_Authentication_in_WinRm' do
#    title "Disallow Digest Authentication - WinRm"
#    desc  "
#      107
#    "
#    impact 1.0
#    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
#      it { should have_property 'AllowDigest' }
#    end
#    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
#      its('AllowDigest') { should cmp == 0 }
#    end
#end

## rule 108 from "Content Security Report - eHealth - Windows Registry Changes.xlsx"
## commented out due to being a duplicate of the (v1.1.0) CIS 18.9.97.2.1 check in 18_AdminTemplatesComputer.rb
#control 'csr-eH-wrc.remediation_rule_108_Disallow_Basic_Authentication_in_WinRm' do
#    title "Disallow Basic Authentication - WinRm"
#    desc  "
#      108
#    "
#    impact 1.0
#    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
#      it { should have_property 'AllowBasic' }
#    end
#    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
#      its('AllowBasic') { should cmp == 0 }
#    end
#end

## rule 110 from "Content Security Report - eHealth - Windows Registry Changes.xlsx"
## commented out due to being a duplicate of the (v1.1.0) CIS 18.9.97.2.4 check in 18_AdminTemplatesComputer.rb
#control 'csr-eH-wrc.remediation_rule_110_Disallow_WinRM_from_storing_RunAs_credentials' do
#    title "Disallow WinRM from storing RunAs credentials"
#    desc  "
#      110
#    "
#    impact 1.0
#    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
#      it { should have_property 'DisableRunAs' }
#    end
#    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
#      its('DisableRunAs') { should cmp == 1 }
#    end
#end

control 'cisiis10.benchmark_rule_7.8_Ensure_DES_Cipher_Suites_is_disabled' do
  title "Ensure DES Cipher Suites is disabled (Scored)"
  desc  "
  "
  impact 1.0

  only_if (win2016cisiis10_rule_7_8) { win2016cisiis10_rule_7_8 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\DES 56/56') do
    it { should have_property 'Enabled' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\DES 56/56') do
    its('Enabled') { should cmp == 0 }
  end
end

control 'cisiis10.benchmark_rule_7.9.1_Ensure_RC4_Cipher_Suites_is_disabled' do
  title "Ensure RC4 Cipher Suites is disabled (Scored)"
  desc  "
  "
  impact 1.0

  only_if (win2016cisiis10_rule_7_9_1) { win2016cisiis10_rule_7_9_1 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RCA 40/128') do
    it { should have_property 'Enabled' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RCA 40/128') do
    its('Enabled') { should cmp == 0 }
  end
end

control 'cisiis10.benchmark_rule_7.9.2_Ensure_RC4_Cipher_Suites_is_disabled' do
  title "Ensure RC4 Cipher Suites is disabled (Scored)"
  desc  "
  "
  impact 1.0

  only_if (win2016cisiis10_rule_7_9_2) { win2016cisiis10_rule_7_9_2 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RCA 56/128') do
    it { should have_property 'Enabled' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RCA 56/128') do
    its('Enabled') { should cmp == 0 }
  end
end

control 'cisiis10.benchmark_rule_7.9.3_Ensure_RC4_Cipher_Suites_is_disabled' do
  title "Ensure RC4 Cipher Suites is disabled (Scored)"
  desc  "
  "
  impact 1.0

  only_if (win2016cisiis10_rule_7_9_3) { win2016cisiis10_rule_7_9_3 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RCA 64/128') do
    it { should have_property 'Enabled' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RCA 64/128') do
    its('Enabled') { should cmp == 0 }
  end
end

control 'cisiis10.benchmark_rule_7.9.4_Ensure_RC4_Cipher_Suites_is_disabled' do
  title "Ensure RC4 Cipher Suites is disabled (Scored)"
  desc  "
  "
  impact 1.0

  only_if (win2016cisiis10_rule_7_9_4) { win2016cisiis10_rule_7_9_4 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RCA 128/128') do
    it { should have_property 'Enabled' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RCA 128/128') do
    its('Enabled') { should cmp == 0 }
  end
end

control 'cisiis10.benchmark_rule_7.10_Ensure_RC4_Cipher_Suites_is_disabled' do
  title "Ensure RC4 Cipher Suites is disabled (Scored)"
  desc  "
  "
  impact 1.0

  only_if (win2016cisiis10_rule_7_10) { win2016cisiis10_rule_7_10 == 'true' }

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\Triple DES 128/128') do
    it { should have_property 'Enabled' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\Triple DES 128/128') do
    its('Enabled') { should cmp == ['TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256' ]}
  end
end

#### Secedit Remediation ####
# The below controls reference configuration set by Ansible task HealthWindowsSecurityRemediation

control 'csr-eH-wrc.remediation_rule_21_Disable_Local_Administrator_Account' do
  title "Disable Local Administrator Account"
  desc "
    This setting specifies whether the Administrator account on the local computer is enabled.
    If the value element contains a nonzero value, the setting is enabled; otherwise, the setting is disabled.
  "
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: ""

  impact 1.0

  # describe security_policy do
  #   its('EnableAdminAccount') { should eq 0 }
  # end

  only_if (win2016ewrc_rule_21) { win2016ewrc_rule_21 == 'true' }

  describe "Disable Local Administrator Account" do
    skip "Disabling the security account has been skipped as this disables the standard AWS features i.e. retreiving encrypted password"
  end
end

# rule 65 from Content Security Report - eHealth - Windows Registry Changes.xlsx
# this appears to do the same as win2016cis_rule_2_3_1_3 in 2_localpolicies.rb CIS 2.3.1.3 v1.1.0
control 'csr-eH-wrc.remediation_rule_65_Ensure_Guest_account_on_the_local_computer_is_set_to_False' do
  title "Ensure Guest account on the local computer is set to False"
  desc  "
    This setting specifies whether the Guest account on the local computer is enabled.
    If the value element contains a nonzero value, the setting is enabled; otherwise, the setting is disabled.
  "
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: "The guest account is a potential security risk and is not required"

  impact 1.0

  only_if (win2016ewrc_rule_65) { win2016ewrc_rule_65 == 'true' }

  describe security_policy do
    its('EnableGuestAccount') { should eq 0 }
  end
end


control 'csr-eH-wrc.remediation_rule_32_Disable_access_to_this_computer_from_the_network' do
  title "Disable access to this computer from the network"
  desc "
    The Access this computer from the network policy setting determines which users can connect to the device from the network.
    This capability is required by a number of network protocols, including Server Message Block (SMB)-based protocols, NetBIOS, Common Internet File System (CIFS), and Component Object Model Plus (COM+).

    Users, devices, and service accounts gain or lose the Access this computer from network user right by being explicitly or implicitly added or removed from a security group that has been granted this user right.
    For example, a user account or a machine account may be explicitly added to a custom security group or a built-in security group, or it may be implicitly added by Windows to a computed security group such as Domain Users, Authenticated Users, or Enterprise Domain Controllers.
    By default, user accounts and machine accounts are granted the Access this computer from network user right when computed groups such as Authenticated Users, and for domain controllers, the Enterprise Domain Controllers group, are defined in the default domain controllers Group Policy Object (GPO).

    Refer to Microsoft Documentation [Access this computer from the network - security policy setting](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/access-this-computer-from-the-network)
  "
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: ""

  impact 1.0

  only_if (win2016ewrc_rule_32) { win2016ewrc_rule_32 == 'true' }

  describe "Disable access to this computer from the network" do
    skip "Too restrictive"
  end
end

control 'csr-eH-wrc.remediation_rule_33_Deny_access_to_this_computer_from_the_network' do
  title "Deny access to this computer from the network"
  desc "
    This security setting determines which users are prevented from accessing a device over the network.
    Users who can log on to the device over the network can enumerate lists of account names, group names, and shared resources.
    Users with permission to access shared folders and files can connect over the network and possibly view or modify data.
    Refer to Microsoft Documentation [Deny access to this computer from the network](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/deny-access-to-this-computer-from-the-network)
  "
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: ""

  impact 1.0

  only_if (win2016ewrc_rule_33) { win2016ewrc_rule_33 == 'true' }

  describe "Deny access to this computer from the network" do
    skip "Too restrictive"
  end
end

control 'csr-eH-wrc.remediation_rule_24_Disable_anonymous_SID_Name_translation' do
  title "Disable anonymous SID/Name translation"
  desc  "
    This setting specifies whether the Guest account on the local computer is enabled.
    If the value element contains a nonzero value, the setting is enabled; otherwise, the setting is disabled.
  "
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: ""

  impact 1.0

  only_if (win2016ewrc_rule_24) { win2016ewrc_rule_24 == 'true' }

  describe security_policy do
    its('LSAAnonymousNameLookup') { should eq 0 }
  end
end

#### Auditpol Remediation ####
# The below controls reference configuration set by Ansible tasks in HealthWindowsSecurityRemediation and elsewhere

control 'csr-eH-wrc.remediation_rule_1_Ensure_Audit_Computer_Account_Management_is_set_to_Success_and_Failure' do
  title "Ensure 'Audit Computer Account Management' is set to Success and Failure"
  desc "
    Audit Process Termination determines whether the operating system generates audit events when process has exited.
    Success audits record successful attempts and Failure audits record unsuccessful attempts.
    This policy setting can help you track user activity and understand how the computer is used.

    Refer to Microsoft Documentation: [Audit Computer Account Management](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-computer-account-management)
  "
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: ""

  impact 1.0

  only_if (win2016ewrc_rule_1) { win2016ewrc_rule_1 == 'true' }

  # describe audit_policy do
  #   its('Computer Account Management') { should eq 'Success and Failure' }
  # end
  describe 'Ensure Audit Computer Account Management is set to Success and Failure' do
    skip "Not required - used on Domain Controllers Only"
  end
end


control 'csr-eH-wrc.remediation_rule_42_Ensure_Audit_Other_Account_Management_Events_is_set_to_Success_and_Failure' do
  title "Ensure 'Audit Other Account Management Events' is set to Success and Failure"
  desc "
    Audit Other Account Management Events determines whether the operating system generates user account management audit events.

    Refer to Microsoft Documentation: [Audit Other Account Management Events](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-account-management-events)
  "
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: ""

  impact 1.0

  only_if (win2016ewrc_rule_42) { win2016ewrc_rule_42 == 'true' }

  # describe audit_policy do
  #   its('Other Account Management Events') { should eq 'Success and Failure' }
  # end
  describe 'Ensure Audit Other Account Management Events is set to Success and Failure' do
    skip "Not required - used on Domain Controllers Only"
  end
end


control 'csr-eH-wrc.remediation_rule_46_Ensure_Audit_Process_Termination_is_set_to_Success' do
  title "Ensure 'Audit Process Termination' is set to 'Success'"
  desc  "
    Audit Process Termination determines whether the operating system generates audit events when process has exited.
    Success audits record successful attempts and Failure audits record unsuccessful attempts.
    This policy setting can help you track user activity and understand how the computer is used

    Refer to Microsoft Documentation: [Audit Process Termination](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-termination)

    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: ""

  impact 1.0

  only_if (win2016ewrc_rule_46) { win2016ewrc_rule_46 == 'true' }

  describe audit_policy do
    its('Process Termination') { should eq 'Success' }
  end
end

control 'csr-eH-wrc.remediation_rule_53_Ensure_Audit_File_Share_is_set_to_Success_and_Failure' do
  title "Ensure 'Audit File Share' is set to Success and Failure"
  desc  "
    Audit File Share allows you to audit events related to file shares: creation, deletion, modification, and access attempts.
    Also, it shows failed SMB SPN checks.
    There are no system access control lists (SACLs) for shares; therefore, after this setting is enabled, access to all shares
    on the system will be audited.
    Combined with File System auditing, File Share auditing enables you to track what content was accessed, the source (IP address and port)
    of the request, and the user account that was used for the access.

    Refer to Microsoft Documentation: [Audit File Share](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-share)

    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: ""

  impact 1.0

  only_if (win2016ewrc_rule_53) { win2016ewrc_rule_53 == 'true' }

  describe audit_policy do
    its('File Share') { should eq 'Success and Failure' }
  end
end

control 'csr-eH-wrc.remediation_rule_54_Ensure_Audit_File_System_is_set_to_Success_and_Failure' do
  title "Ensure 'Audit File System' is set to Success and Failure"
  desc  "
    Audit File System determines whether the operating system generates audit events when users attempt to access file system objects.
    Audit events are generated only for objects that have configured system access control lists (SACLs), and only if the type of access
    requested (such as Write, Read, or Modify) and the account making the request match the settings in the SACL.
    If success auditing is enabled, an audit entry is generated each time any account successfully accesses a file system object that has a matching SACL.
    If failure auditing is enabled, an audit entry is generated each time any user unsuccessfully attempts to access a file system object that has a matching SACL.
    These events are essential for tracking activity for file objects that are sensitive or valuable and require extra monitoring.

    Refer to Microsoft Documentation: [Audit File System](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-system)

    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: ""

  impact 1.0

  only_if (win2016ewrc_rule_54) { win2016ewrc_rule_54 == 'true' }

  describe audit_policy do
    its('File System') { should eq 'Success and Failure' }
  end
end

control 'csr-eH-wrc.remediation_rule_55_Ensure_Audit_Kernel_Object_is_set_to_Success_and_Failure' do
  title "Ensure 'Audit Kernel Object' is set to Success and Failure"
  desc  "
    Audit Kernel Object determines whether the operating system generates audit events when users attempt to access the system kernel, which includes mutexes and semaphores.
    Only kernel objects with a matching system access control list (SACL) generate security audit events. The audits generated are usually useful only to developers.
    Typically, kernel objects are given SACLs only if the AuditBaseObjects or AuditBaseDirectories auditing options are enabled.

    Refer to Microsoft Documentation: [Audit Kernel Object](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kernel-object)

    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: ""

  impact 1.0

  only_if (win2016ewrc_rule_55) { win2016ewrc_rule_55 == 'true' }

  describe audit_policy do
    its('Kernel Object') { should eq 'Success and Failure' }
  end
end

control 'csr-eH-wrc.remediation_rule_57_Ensure_Audit_Registry_is_set_to_Success_and_Failure' do
  title "Ensure 'Audit Registry' is set to Success and Failure"
  desc  "
    Audit Registry allows you to audit attempts to access registry objects. A security audit event is generated only for objects that have system access control lists (SACLs) specified,
    and only if the type of access requested, such as Read, Write, or Modify, and the account making the request match the settings in the SACL.

    If success auditing is enabled, an audit entry is generated each time any account successfully accesses a registry object that has a matching SACL. If failure auditing is enabled,
    an audit entry is generated each time any user unsuccessfully attempts to access a registry object that has a matching SACL.

    Refer to Microsoft Documentation: [Audit Registry](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-registry)

    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: ""

  impact 1.0

  only_if (win2016ewrc_rule_57) { win2016ewrc_rule_57 == 'true' }

  describe audit_policy do
    its('Registry') { should eq 'Success and Failure' }
  end
end

control 'csr-eH-wrc.remediation_rule_59_Ensure_Audit_Other_Policy_Change_Events_is_set_to_Success_and_Failure' do
  title "Ensure 'Audit Other Policy Change Events' is set to Success and Failure"
  desc  "
    Audit Other Policy Change Events contains events about EFS Data Recovery Agent policy changes, changes in Windows Filtering Platform filter, status on Security policy settings
    updates for local Group Policy settings, Central Access Policy changes, and detailed troubleshooting events for Cryptographic Next Generation (CNG) operations.

    Refer to Microsoft Documentation: [Audit Other Policy Change Events](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-policy-change-events)

    Rationale: Auditing these events may be useful when investigating a security incident.
  "
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: ""

  impact 1.0

  only_if (win2016ewrc_rule_59) { win2016ewrc_rule_59 == 'true' }

  describe audit_policy do
    its('Other Policy Change Events') { should eq 'Success and Failure' }
  end
end


#### Powershell Remediation ####
# The below controls reference configuration set by Ansible tasks in HealthWindowsSecurityRemediation and elsewhere


control 'csr-eH-wrc.remediation_rule_112_Ensure_PowshellV2_is_disabled' do
  title "Ensure PowshellV2 is disabled"
  desc  "As recommanded by Content Scurity, PowshellV2 should be disabled"
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: ""

  impact 1.0

  only_if (win2016ewrc_rule_112) { win2016ewrc_rule_112 == 'true' }

  describe windows_feature('PowerShell-V2') do
      it { should_not be_installed }
  end
end

control 'csr-eH-wrc.remediation_rule_113_Remove_SMB1_Client_and_Server_functions' do
  title "Remove SMB1 Client and Server functions"
  desc ""
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: "SMBv1 is deprecated and considered insecure"

  impact 1.0

  only_if (win2016ewrc_rule_113) { win2016ewrc_rule_113 == 'true' }

  # Remove SMB1 Client and Server functions for Server 2012 and newer
  describe windows_feature('SMB1Protocol') do
    it { should_not be_installed }
  end

  # Disable SMB1 Server functionality
  describe registry_key('SMB1','HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('SMB1') { should eq 0 }
  end

end


control 'csr-eH-wrc.remediation_rule_120_NBNS_Disabled_on_all_interfaces' do
  title 'NBNS Disabled on all interfaces'
  desc ""
  tag source: "third-party"
  tag version: "1.0"
  tag rationale: "SMBv1 is deprecated and considered insecure"

  impact 1.0

  only_if (win2016ewrc_rule_120) { win2016ewrc_rule_120 == 'true' }

  describe 'NBNS Disabled on all interfaces' do
    skip "Already covered by default NSG/SG security rules"
  end

end
