# OpenSCAP summary (20261026-042910)

- Datastream: `SSG 0.1.78: ssg-ubuntu2404-ds.xml`
- Profile: `xccdf_org.ssgproject.content_profile_cis_level2_server`
- Before: pass=163 fail=44 notapplicable=299 notchecked=0 error=0 
- After:  pass=190 fail=17 notapplicable=299 notchecked=0 error=0 

## Rules not at pass after remediation

| Result | Rule |
|--------|------|
| fail | partition_for_home |
| fail | partition_for_tmp |
| fail | partition_for_var |
| fail | partition_for_var_log |
| fail | partition_for_var_log_audit |
| fail | partition_for_var_tmp |
| fail | all_apparmor_profiles_enforced |
| fail | all_apparmor_profiles_in_enforce_complain_mode |
| fail | grub2_enable_apparmor |
| unknown | firewall_single_service_active |
| fail | nftables_ensure_default_deny_policy |
| fail | nftables_rules_permanent |
| fail | set_nftables_base_chain |
| fail | set_nftables_loopback_traffic |
| fail | set_nftables_table |
| fail | mount_option_dev_shm_nodev |
| fail | mount_option_dev_shm_noexec |
| fail | mount_option_dev_shm_nosuid |
