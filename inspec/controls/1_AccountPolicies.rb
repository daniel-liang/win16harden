# encoding: utf-8

# Rule toggle enabled/disabled variables
win2016cis_rule_1_1_1 = attribute('win2016cis_rule_1_1_1')
win2016cis_rule_1_1_2 = attribute('win2016cis_rule_1_1_2')
win2016cis_rule_1_1_3 = attribute('win2016cis_rule_1_1_3')
win2016cis_rule_1_1_4 = attribute('win2016cis_rule_1_1_4')
win2016cis_rule_1_1_5 = attribute('win2016cis_rule_1_1_5')
win2016cis_rule_1_1_6 = attribute('win2016cis_rule_1_1_6')
win2016cis_rule_1_2_1 = attribute('win2016cis_rule_1_2_1')
win2016cis_rule_1_2_2 = attribute('win2016cis_rule_1_2_2')
win2016cis_rule_1_2_3 = attribute('win2016cis_rule_1_2_3')

title 'Section 1 Account Policies'

control 'cis-enforce-password-history-1.1.1' do
  impact 0.7
  title '1.1.1 Set Enforce password history to 24 or more passwords'
  desc 'Set Enforce password history to 24 or more passwords'

  only_if (win2016cis_rule_1_1_1) { win2016cis_rule_1_1_1 == 'true' }

  describe security_policy do
    its('PasswordHistorySize') { should be >= 24 }
  end
end

control 'cis-maximum-password-age-1.1.2' do
  impact 0.7
  title '1.1.2 Set Maximum password age to 60 or fewer days, but not 0'
  desc 'Set Maximum password age to 60 or fewer days, but not 0'

  only_if (win2016cis_rule_1_1_2) { win2016cis_rule_1_1_2 == 'true' }

  describe security_policy do
    its('MaximumPasswordAge') { should be <= 60 }
    its('MaximumPasswordAge') { should be > 0 }
  end
end

control 'cis-minimum-password-age-1.1.3' do
  impact 0.7
  title '1.1.3 Set Minimum password age to 1 or more days'
  desc 'Set Minimum password age to 1 or more days'

  only_if (win2016cis_rule_1_1_3) { win2016cis_rule_1_1_3 == 'true' }

  describe security_policy do
    its('MinimumPasswordAge') { should be >= 1 }
  end
end

control 'cis-minimum-password-length-1.1.4' do
  impact 0.7
  title '1.1.4 Set Minimum password length to 14 or more characters'
  desc 'Set Minimum password length to 14 or more characters'

  only_if (win2016cis_rule_1_1_4) { win2016cis_rule_1_1_4 == 'true' }

  describe security_policy do
    its('MinimumPasswordLength') { should be >= 14 }
  end
end

control 'cis-password- complexity-1.1.5' do
  impact 1.0
  title 'Windows Password Complexity is Enabled'
  tag cis: ['windows_2012r2:1.1.5', 'windows_2016:1.1.5']
  ref 'Password must meet complexity requirements', url: 'https://technet.microsoft.com/en-us/library/hh994562(v=ws.11).aspx'
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark'

  only_if (win2016cis_rule_1_1_5) { win2016cis_rule_1_1_5 == 'true' }

  describe security_policy do
    its('PasswordComplexity') { should eq 1 }
  end
end

control 'cis-reversible encryption-1.1.6' do
  impact 0.7
  title '1.1.6 Set Store passwords using reversible encryption to Disabled'
  desc 'Set Store passwords using reversible encryption to Disabled'

  only_if (win2016cis_rule_1_1_6) { win2016cis_rule_1_1_6 == 'true' }

  describe security_policy do
    its('ClearTextPassword') { should eq 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.2.1_L1_Ensure_Account_lockout_duration_is_set_to_15_or_more_minutes' do
  title "(L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'"
  desc  "
    This policy setting determines the length of time that must pass before a locked account is unlocked and a user can try to log on again. The setting does this by specifying the number of minutes a locked out account will remain unavailable. If the value for this policy setting is configured to 0, locked out accounts will remain locked out until an administrator manually unlocks them.
    Although it might seem like a good idea to configure the value for this policy setting to a high value, such a configuration will likely increase the number of calls that the help desk receives to unlock accounts locked by mistake. Users should be aware of the length of time a lock remains in place, so that they realize they only need to call the help desk if they have an extremely urgent need to regain access to their computer.
    The recommended state for this setting is: 15 or more minute(s).
    Rationale: A denial of service (DoS) condition can be created if an attacker abuses the Account lockout threshold and repeatedly attempts to log on with a specific account. Once you configure the Account lockout threshold setting, the account will be locked out after the specified number of failed attempts. If you configure the Account lockout duration setting to 0, then the account will remain locked out until an administrator unlocks it manually.
  "
  impact 1.0

  only_if (win2016cis_rule_1_2_1) { win2016cis_rule_1_2_1 == 'true' }

  describe security_policy do
    its('LockoutDuration') { should be >= 900 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.2.2_L1_Ensure_Account_lockout_threshold_is_set_to_10_or_fewer_invalid_logon_attempts_but_not_0' do
  title "(L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'"
  desc  "
    This policy setting determines the number of failed logon attempts before the account is locked. Setting this policy to 0 does not conform with the benchmark as doing so disables the account lockout threshold.
    The recommended state for this setting is: 10 or fewer invalid logon attempt(s), but not 0.
    Rationale: Setting an account lockout threshold reduces the likelihood that an online password brute force attack will be successful. Setting the account lockout threshold too low introduces risk of increased accidental lockouts and/or a malicious actor intentionally locking out accounts.
  "
  impact 1.0

  only_if (win2016cis_rule_1_2_2) { win2016cis_rule_1_2_2 == 'true' }

  describe security_policy do
    its('LockoutBadCount') { should be <= 10 }
  end
  describe security_policy do
    its('LockoutBadCount') { should be > 0 }
  end
end

control 'xccdf_org.cisecurity.benchmarks_rule_1.2.3_L1_Ensure_Reset_account_lockout_counter_after_is_set_to_15_or_more_minutes' do
  title "(L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"
  desc  "
    This policy setting determines the length of time before the Account lockout threshold resets to zero. The default value for this policy setting is Not Defined. If the Account lockout threshold is defined, this reset time must be less than or equal to the value for the Account lockout duration setting.
    If you leave this policy setting at its default value or configure the value to an interval that is too long, your environment could be vulnerable to a DoS attack. An attacker could maliciously perform a number of failed logon attempts on all users in the organization, which will lock out their accounts. If no policy were determined to reset the account lockout, it would be a manual task for administrators. Conversely, if a reasonable time value is configured for this policy setting, users would be locked out for a set period until all of the accounts are unlocked automatically.
    The recommended state for this setting is: 15 or more minute(s).
    Rationale: Users can accidentally lock themselves out of their accounts if they mistype their password multiple times. To reduce the chance of such accidental lockouts, the Reset account lockout counter after setting determines the number of minutes that must elapse before the counter that tracks failed logon attempts and triggers lockouts is reset to 0.
  "
  impact 1.0

  only_if (win2016cis_rule_1_2_3) { win2016cis_rule_1_2_3 == 'true' }

  describe security_policy do
    its('ResetLockoutCount') { should be >= 0 }
  end
end
