# Suggested project entry

**Title:** Security Log Explorer: Java Authentication Log Analysis

**Description:** A personal Java learning and portfolio project, prepared with AI assistance, that analyzes synthetic login-event CSV files. It summarizes successful and failed attempts and flags addresses reaching a configurable threshold across the full file or within an inclusive rolling time window. It handles out-of-order timestamps, uses strict input validation and immutable report data, and can print a JSON report for other scripts to read. It includes dependency-free automated tests and IntelliJ practice configurations. Alerts are investigation leads, not proof of attacks.

**Skills:** Java, Unit Testing, JSON, Debugging, IntelliJ IDEA, Log Analysis, Sliding Window Algorithms.

**Resume bullet options (adapt after reviewing and practicing):**

- Built a Java 17 authentication-log analyzer that groups failed sign-ins by address and identifies suspicious concentrations using configurable rolling time windows.
- Implemented timestamp sorting, inclusive window-boundary handling, input validation, and deterministic reports; verified the current project with 45 local automated checks.

**Accuracy note:** The initial project and this feature were prepared with AI assistance. Review and practice the implementation before describing your individual contributions in an interview. These checks use synthetic data; no live security deployment or production monitoring has been verified.

# Post to adapt after practicing

I’m working through Security Log Explorer, a Java portfolio project that reads synthetic sign-in logs and reports repeated failures. The project supports rolling time windows, so alerts can reflect bursts of failed attempts. I also added an optional JSON report for scripts to read.

I used AI assistance in developing the project and am practicing the Java collections, sorting, debugging, and tests behind the implementation. The current project passed 45 local checks on Linux with Java 21 compiling for Java 17. GitHub Actions verification of the JSON change is tracked in the repository.

Repository: https://github.com/KENNETH-R-THOMPSON/security-log-explorer
