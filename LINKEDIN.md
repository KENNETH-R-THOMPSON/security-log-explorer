# LinkedIn project draft

Status: Draft. No LinkedIn project, Featured item, or post has been published or verified.

**Project:** Security Log Explorer

**Repository and suggested Featured link:** https://github.com/KENNETH-R-THOMPSON/security-log-explorer

**Description:** I worked on an AI-assisted Java 17 practice project that reads fictional sign-in events and flags repeated failures by address. It supports rolling time windows, quoted CSV fields, and JSON reports. I updated the text report to escape control and bidirectional formatting characters in address labels, so the alert lines don't echo raw terminal escape sequences. I also fixed the streaming parser so event-handler exceptions keep their original message. I then updated text alert output to distinguish literal backslashes from escaped control characters. I added support for CSV exports that begin with a UTF-8 byte order mark, with a fictional sample and tests for invalid headers. All 69 checks passed on hosted Java 17 in GitHub Actions on November 1, 2026.

**Skills:** Java, CSV parsing, JSON, input validation, safe terminal output, Java collections, automated testing, Git, GitHub Actions.

**Verification:** https://github.com/KENNETH-R-THOMPSON/security-log-explorer/actions/runs/41321001774

**Limits:** All test data are fictional. Addresses are grouping labels, not validated IP addresses. Multiline CSV fields aren't supported. Rolling-window mode keeps failed timestamps in memory, and the tool isn't a live security monitor. I haven't tested this version on my Mac. AI assistance was used to prepare the project; review the code before describing individual contributions in an interview.

**Resume bullet to adapt after reviewing the code:** Extended an AI-assisted Java 17 log-analysis practice tool with safe text alert labels, clear streamed-parser errors and UTF-8 BOM CSV import; 69 checks passed in hosted GitHub Actions.

## Optional short post

I updated the text reports in my Java Security Log Explorer practice project. Address labels now escape terminal control and bidirectional formatting characters, while JSON output stays available for scripts. The examples use fictional sign-in events. All 69 checks passed in GitHub Actions on Java 17, including tests for event-handler errors, literal backslashes in alert labels and UTF-8 BOM CSV headers.

Repository: https://github.com/KENNETH-R-THOMPSON/security-log-explorer
