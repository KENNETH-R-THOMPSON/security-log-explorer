# LinkedIn project draft

Status: Draft. No LinkedIn project, Featured item, or post has been published or verified.

**Project:** Security Log Explorer

**Repository and suggested Featured link:** https://github.com/KENNETH-R-THOMPSON/security-log-explorer

**Description:** I worked on an AI-assisted Java 17 practice project that reads fictional authentication logs and identifies repeated failed sign-ins by address. It supports full-file counts, rolling time windows, and JSON reports. I updated the command-line analyzer to process events as it reads the CSV file. Full-file mode keeps per-address failure counts; rolling-window mode stores failed timestamps so it can handle out-of-order events. All 52 automated checks passed on hosted Java 17 in GitHub Actions on October 31, 2026.

**Skills:** Java, CSV parsing, JSON, Java collections, unit testing, Git, GitHub Actions, basic log analysis.

**Verification:** https://github.com/KENNETH-R-THOMPSON/security-log-explorer/actions/runs/41196945985

**Limits:** All data used in tests and examples is fictional. The rolling-window mode still keeps failed timestamps in memory. I haven't tested this version on my Mac or connected it to a live authentication system. I used AI assistance in preparing the project and should review the implementation before discussing individual contributions in an interview.

**Resume bullet to adapt after reviewing the code:** Updated an AI-assisted Java 17 authentication-log practice tool with streamed CSV summaries, rolling-window failure detection and JSON output; 52 automated checks passed in hosted GitHub Actions.

## Optional short post

I updated my Java Security Log Explorer practice project to process fictional sign-in events as the CSV file is read. It keeps per-address counts for full-file reports and failed timestamps for rolling-window reports. The current Java 17 GitHub Actions run passed 52 checks, including tests with 5,000 fictional events. I'm reviewing the code and tests as part of my computer science studies.

Repository: https://github.com/KENNETH-R-THOMPSON/security-log-explorer
