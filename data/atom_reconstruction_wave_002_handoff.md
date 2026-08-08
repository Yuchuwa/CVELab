# Atom Reconstruction Wave 002 Handoff

- Selected: 25; accepted: 16; deferred: 9
- Evidence columns are intentionally independent: native, Guide, runtime, and orchestrated.

| CVE | planned path | role/family/access | verified capabilities | native | Guide | runtime | classification / failure class |
|---|---|---|---|---|---|---|---|
| CVE-2025-68613 | rebuild_runtime_or_bundle | web_application / - / `-` | execute_command, read_file | pass | ready | ready/ready | template-candidate / - |
| CVE-2017-1000028 | rebuild_runtime_or_bundle | web_application / - / `{"port":4848,"protocol":"https"}` | read_credential, read_file | pass | ready | ready/ready | template-candidate / - |
| CVE-2025-55182 | rebuild_runtime_or_bundle | web_application / - / `-` | execute_command, read_file | pass | ready | ready/ready | template-candidate / - |
| CVE-2024-9264 | rebuild_runtime_or_bundle | web_application / - / `-` | execute_command, read_file | pass | ready | ready/ready | template-candidate / - |
| CVE-2024-38856 | rebuild_runtime_or_bundle | web_application / - / `-` | execute_command, read_file | pass | ready | ready/ready | template-candidate / - |
| CVE-2013-4547 | rebuild_runtime_or_bundle | web_application / - / `{"port":80,"protocol":"http"}` | execute_command, read_file | pass | ready | failed | deferred / environment/build risk |
| CVE-2026-25887 | rebuild_runtime_or_bundle | web_application / - / `-` | execute_command, read_file | pass | ready | ready/ready | template-candidate / - |
| CVE-2024-45195 | rebuild_runtime_or_bundle | web_application / - / `-` | execute_command, read_file | pass | ready | ready/ready | template-candidate / - |
| CVE-2022-41678 | rebuild_runtime_or_bundle | web_application / - / `-` | execute_command, read_file | pass | ready | ready/ready | template-candidate / - |
| CVE-2021-32682 | rebuild_runtime_or_bundle | web_application / - / `-` | execute_command, read_file | pass | ready | ready/ready | template-candidate / - |
| CVE-2023-26360 | rebuild_runtime_or_bundle | web_application / - / `{"port":8500,"protocol":"http"}` | read_file | pass | ready | ready/ready | template-candidate / - |
| CVE-2018-18778 | rebuild_runtime_or_bundle | web_application / - / `{"port":8080,"protocol":"http"}` | read_file | pass | ready | ready/ready | template-candidate / - |
| CVE-2017-14849 | rebuild_runtime_or_bundle | web_application / - / `{"port":3000,"protocol":"http"}` | read_file | pass | ready | ready/ready | template-candidate / - |
| CVE-2010-2861 | rebuild_runtime_or_bundle | web_application / - / `{"port":8500,"protocol":"http"}` | read_file | pass | ready | ready/ready | template-candidate / - |
| CVE-2022-24706 | full_reconstruction | database / - / `-` | - | fail | ready | ready/ready | deferred / validation-model mismatch |
| CVE-2021-40438 | full_reconstruction | middleware / - / `-` | - | pass | missing | unsupported | deferred / environment/build risk, validation-model mismatch |
| CVE-2026-24061 | full_reconstruction | system_service / - / `-` | - | pass | ready | ready/ready | template-anchor / - |
| CVE-2021-42392 | full_reconstruction | framework / - / `-` | - | fail | missing | ready/ready | deferred / exploit automation instability |
| CVE-2014-0160 | full_reconstruction | web_application / - / `{"port":443,"protocol":"https"}` | - | pass | missing | ready/ready | deferred / validation-model mismatch |
| CVE-2026-21858 | full_reconstruction | web_application / - / `-` | - | pass | ready | ready/ready | template-anchor / - |
| CVE-2024-1561 | full_reconstruction | web_application / - / `-` | - | pass | ready | failed | deferred / runtime tool/profile compatibility |
| CVE-2018-1273 | full_reconstruction | web_application / - / `-` | - | fail | missing | ready/ready | deferred / exploit automation instability |
| CVE-2017-12794 | full_reconstruction | web_application / - / `-` | - | pass | ready | failed | deferred / environment/build risk |
| CVE-2025-32433 | full_reconstruction | middleware / - / `-` | - | pass | ready | ready/ready | template-anchor / - |
| CVE-2024-45507 | full_reconstruction | web_application / - / `-` | - | pass | missing | ready/ready | deferred / validation-model mismatch |
