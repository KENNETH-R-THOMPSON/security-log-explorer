# LinkedIn project draft

Status: Draft. No LinkedIn project, Featured item, or post has been published or verified.

**Project:** Security Log Explorer

**Repository and suggested Featured link:** https://github.com/KENNETH-R-THOMPSON/security-log-explorer

**Description:** I worked on an AI-assisted Java 17 practice tool that reads fictional sign-in events and summarizes repeated failures by address or username. I added an optional chronological mode that processes sorted CSV rows with a sliding window, instead of retaining all past failure timestamps. It checks timestamp order and keeps the original mode for unsorted files. The project also supports JSON reports, quoted CSV and terminal-safe output. All 95 checks passed on hosted Java 17, including a separate run with a 64 MB heap and fictional 50,000-row examples.

**Skills:** Java, CSV parsing, JSON, Java collections, sliding windows, input validation, regression testing, Git, GitHub Actions.

**Verification:** https://github.com/KENNETH-R-THOMPSON/security-log-explorer/actions/runs/41388126648

**Limits:** All records are fictional. Chronological mode requires nondecreasing timestamps and its memory use still depends on events within the window and the number of groups. The 64 MB test doesn't establish a general memory limit. The tool isn't a live security monitor, and this version hasn't been tested on my Mac. AI assistance was used to prepare the project; review the code before describing individual contributions in an interview.

**Resume bullet to adapt after reviewing the code:** Added chronological sliding-window analysis to an AI-assisted Java 17 fictional log analyzer; 95 checks passed on hosted GitHub Actions.

## Optional short post

I added an optional chronological streaming mode to my Java Security Log Explorer practice project. It tracks recent fictional login failures without keeping every older failure timestamp. I tested equal timestamps, out-of-order input, username and address grouping, and 50,000-row examples. All 95 checks passed on hosted Java 17, including a 64 MB heap run. This project uses fictional data and doesn't monitor live systems.

Repository: https://github.com/KENNETH-R-THOMPSON/security-log-explorer
