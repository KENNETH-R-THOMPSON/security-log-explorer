#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p build/test-classes
javac --release 17 -d build/test-classes src/main/java/com/kenneth/security/*.java src/test/java/com/kenneth/security/*.java
java -cp build/test-classes com.kenneth.security.SecurityTests
