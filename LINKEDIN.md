# LinkedIn project draft

Status: Draft. No LinkedIn project, Featured item, or post has been published or verified.

**Project:** Security Log Explorer

**Repository and suggested Featured link:** https://github.com/KENNETH-R-THOMPSON/security-log-explorer

**Description:** I worked on an AI-assisted Java 17 practice tool that reads fictional sign-in events and flags repeated failures by address. It handles quoted CSV, UTF-8 BOM headers, rolling time windows and JSON reports. I improved how text alerts and command-line errors display untrusted characters, and added regression tests for terminal controls and bidirectional formatting characters. All 71 checks passed on hosted Java 17 in GitHub Actions on November 1, 2026.

**Skills:** Java, CSV parsing, JSON, input validation, safe terminal output, Java collections, automated testing, Git, GitHub Actions.

**Verification:** https://github.com/KENNETH-R-THOMPSON/security-log-explorer/actions/runs/41362100107

**Limits:** All test data are fictional. Addresses are grouping labels, not validated IP addresses. Multiline CSV fields aren't supported. Rolling-window mode keeps failed timestamps in memory, and the tool isn't a live security monitor. I haven't tested this version on my Mac. AI assistance was used to prepare the project; review the code before describing individual contributions in an interview.

**Resume bullet to adapt after reviewing the code:** Extended an AI-assisted Java 17 log-analysis practice tool with safe text alert labels, safe terminal error output and UTF-8 BOM CSV import; 71 checks passed in hosted GitHub Actions.

## Optional short post

I updated the text reports in my Java Security Log Explorer practice project. Address labels now escape terminal control and bidirectional formatting characters, while JSON output stays available for scripts. The examples use fictional sign-in events. All 71 checks passed in GitHub Actions on Java 17, including tests for safe error output, literal backslashes in alert labels and UTF-8 BOM CSV headers.

Repository: https://github.com/KENNETH-R-THOMPSON/security-log-explorer
