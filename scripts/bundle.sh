#!/bin/bash
# Builds a launchable Sentinel.app bundle into dist/
set -euo pipefail
cd "$(dirname "$0")/.."

swift build -c release

APP=dist/Sentinel.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp .build/release/sentinel "$APP/Contents/MacOS/Sentinel"
cp Resources/Info.plist "$APP/Contents/Info.plist"

echo "built $APP - run it or drag to /Applications"
