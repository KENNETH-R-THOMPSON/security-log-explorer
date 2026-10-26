#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p build/classes
javac --release 17 -d build/classes src/main/java/com/kenneth/security/*.java
if [ "$#" -eq 0 ]; then set -- sample/login-events.csv; fi
java -cp build/classes com.kenneth.security.Main "$@"
