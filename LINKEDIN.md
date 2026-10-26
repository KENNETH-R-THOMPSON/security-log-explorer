# Suggested project entry

**Title:** Security Log Explorer: Java Authentication Log Analysis

**Description:** A personal Java learning and portfolio project, prepared with AI assistance, that analyzes synthetic login-event CSV files. It summarizes successful and failed attempts and flags addresses reaching a configurable threshold across the full file or within an inclusive rolling time window. It handles out-of-order timestamps, uses strict input validation and immutable report data, and includes dependency-free automated tests and IntelliJ practice configurations. Alerts are investigation leads, not proof of attacks.

**Skills:** Java, Unit Testing, Debugging, IntelliJ IDEA, Log Analysis, Sliding Window Algorithms.

**Resume bullet options (adapt after reviewing and practicing):**

- Built a Java 17 authentication-log analyzer that groups failed sign-ins by address and identifies suspicious concentrations using configurable rolling time windows.
- Implemented timestamp sorting, inclusive window-boundary handling, input validation, and deterministic reports; verified the project with 37 local automated checks.

**Accuracy note:** The initial project and this feature were prepared with AI assistance. Review and practice the implementation before describing your individual contributions in an interview. These checks use synthetic data; no live security deployment or production monitoring has been verified.

# Post to adapt after practicing

I’m working through Security Log Explorer, a Java portfolio project that reads synthetic sign-in logs and reports repeated failures. The latest update adds configurable rolling time windows, so alerts reflect bursts of failed attempts instead of counting the entire file.

I used AI assistance in developing the project and am practicing the Java collections, sorting, debugging, and tests behind the implementation. The project includes 37 passing local checks.

Repository: https://github.com/KENNETH-R-THOMPSON/security-log-explorer
