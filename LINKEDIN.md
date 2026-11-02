# LinkedIn project draft

Status: Draft. No LinkedIn project, Featured item, or post has been published or verified.

**Project:** Security Log Explorer

**Repository and suggested Featured link:** https://github.com/KENNETH-R-THOMPSON/security-log-explorer

**Description:** I worked on an AI-assisted Java 17 practice tool that reads fictional sign-in events and summarizes repeated failures by address or username. I added optional username grouping and reduced temporary memory use during rolling-window sorting by avoiding a second full timestamp list. The tool handles quoted CSV, JSON reports, UTF-8 BOM headers and unsafe terminal characters. All 83 checks passed on hosted Java 17, including a separate test run with a 64 MB Java heap and 50,000 fictional failures.

**Skills:** Java, CSV parsing, JSON, input validation, safe terminal output, Java collections, automated testing, Git, GitHub Actions.

**Verification:** https://github.com/KENNETH-R-THOMPSON/security-log-explorer/actions/runs/41382945615

**Limits:** All test data are fictional. Addresses are grouping labels, not validated IP addresses. Multiline CSV fields aren't supported. Rolling-window mode still keeps all failed timestamps in memory; the 64 MB heap test doesn't establish a fixed memory bound. The tool isn't a live security monitor. I haven't tested this version on my Mac. AI assistance was used to prepare the project; review the code before describing individual contributions in an interview.

**Resume bullet to adapt after reviewing the code:** Improved rolling-window sorting and tested 50,000 fictional failures in an AI-assisted Java 17 log analyzer; 83 checks passed on hosted GitHub Actions.

## Optional short post

I improved rolling-window sorting in my Java Security Log Explorer practice project so it doesn't make an extra full list of failure timestamps. I also added tests with 50,000 fictional failures in reverse timestamp order. All 83 checks passed on hosted Java 17, including a run with a 64 MB Java heap. The project doesn't monitor live systems.

Repository: https://github.com/KENNETH-R-THOMPSON/security-log-explorer
