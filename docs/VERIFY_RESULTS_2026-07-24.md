# Stratified-50 Environment-Only Verification Results

**Date:** 2026-07-24
**Commits:** 57f36d7, f2125df, ed9695c
**Template:** enterprise_3tier L2, environment-only

## PASS Cases (5/50, more as images cache)

| Case ID | CVEs | Status |
|---------|------|--------|
| matrix-2018-16509-2012-1823-2015-1427 | CVE-2018-16509 → CVE-2012-1823 → CVE-2015-1427 | ✅ PASS |
| matrix-2021-42013-2012-1823-2015-1427 | CVE-2021-42013 → CVE-2012-1823 → CVE-2015-1427 | ✅ PASS |
| matrix-2012-1823-2021-42013-2014-3120 | CVE-2012-1823 → CVE-2021-42013 → CVE-2014-3120 | ✅ PASS |
| matrix-2012-1823-2024-27348-2014-3120 | CVE-2012-1823 → CVE-2024-27348 → CVE-2014-3120 | ✅ PASS |
| matrix-2018-16509-2018-19475-2015-1427 | CVE-2018-16509 → CVE-2018-19475 → CVE-2015-1427 | ✅ PASS |

## Image Availability (progressive)

- 8/24 CVEs have local images (6+2 new)
- 16/24 CVEs still need pulling from docker.1ms.run
- Background pulls running continuously

## Fixes Applied

1. `runtime_tools.py` — EOL Debian proactive detection → archive.debian.org
2. `runtime_builder.py` — docker build --network host
3. `scenario_assembler.py` — _mirror() for registry prefix
4. `verifier.py` — busybox nc fallback replacing nsenter

## Test Results

134 tests passed (test_runtime_tools.py + test_runtime_builder_flow.py + test_verifier.py)
