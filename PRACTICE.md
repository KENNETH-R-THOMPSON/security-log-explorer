# IntelliJ practice path

## 1. Run and understand

Run **Demo - sample login report**. Predict why one address has 3 failures while the overall failure count is 4. Change the run parameters from threshold 3 to 4 and compare. Then use `sample/login-events.csv 3 2` and `sample/login-events.csv 3 1` to compare rolling windows. Run **Tests - all checks**.

## 2. Navigate

In Main, use Go to Declaration on `SecurityAnalyzer.analyzeFile` (Command+B on the macOS keymap). Follow `LogParser.forEach` into the `Summary.accept` method, then find usages of `LoginEvent`. Use Search Everywhere (double Shift) to locate `LogParser`, then Find in Files (Command+Shift+F) for `threshold`. Shortcuts depend on your keymap; all actions are available through Find Action.

## 3. Debug

Put a breakpoint inside `maxFailuresInWindow`. Debug the 2-minute demo. Inspect `left`, `right`, and `maximum` while stepping through the timestamps. Explain why the first and third failures count together and why sorting is needed for out-of-order events.

## 4. Refactor safely

Use IntelliJ Rename on local variable `successful` to rename it `successCount`. Preview affected references, apply the change, and rerun tests. Use Undo to compare. This exercises IDE refactoring without changing behavior.

## 5. Make your next feature

Add failed-attempt counts by username. Start by adding a failing test, implement the smallest change, then rerun all checks. Keep existing address alerts unchanged. Use the integrated terminal for the scripts and review the diff before committing.

## Badge expectations

The LinkedIn Connected Apps badge comes from JetBrains' recorded IDE usage and syncs automatically. Practice these features as part of understanding the project. Completing this guide does not guarantee a particular badge level or update time; automated setup is not evidence of personal proficiency.

Official guide: https://www.jetbrains.com/help/idea/linkedin-connected-apps.html
