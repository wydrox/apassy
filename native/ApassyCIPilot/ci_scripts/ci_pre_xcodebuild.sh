#!/bin/bash
set -euo pipefail
# Cloud hooks may be shared across projects. Refuse all unrelated actions.
if [[ "${CI_WORKFLOW:-}" != "Apassy macOS quality pilot" ]]; then
  echo 'Apassy pilot hook: unrelated workflow; no work.'
  exit 0
fi
[[ "${CI_XCODEBUILD_ACTION:-}" == build ]] || { echo 'Pilot requires one Build action.' >&2; exit 1; }
root="${CI_PRIMARY_REPOSITORY_PATH:?Missing primary checkout}"
[[ "${CI_PROJECT_FILE_PATH:-}" == "$root/native/ApassyCIPilot/ApassyCIPilot.xcodeproj" ]] || {
  echo 'Pilot project identity mismatch.' >&2; exit 1;
}
exec bash "$root/scripts/ci-macos-quality.sh" --cloud
