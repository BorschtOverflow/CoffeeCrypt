#!/usr/bin/env bash

set -euo pipefail

CHANGELOG_FILE="CHANGELOG.md"
TEMP_FILE=$(mktemp)

git tag --sort=-taggerdate --sort=-creatordate | while read -r tag; do
[ -z "$tag" ] && continue

date=$(git log -1 --format="%ad" --date=short "$tag")

  # Get tag message without the signature
  message=$(git tag -l --format="%(contents)" "$tag" \
      | sed -E '/^-----BEGIN .* SIGNATURE-----/,/^-----END .* SIGNATURE-----/d' \
      | sed -E '/^[A-Za-z-]+-by:/d' \
      | awk '/./{p=1} p')

  printf "## %s - %s\n\n%s\n\n" "$tag" "$date" "$message" >> "$TEMP_FILE"
done

# Trim trailing empty line from the end of the file
awk '/^$/ {blank++} /./ {for (i=0; i<blank; i++) print ""; blank=0; print}' "$TEMP_FILE" > "$CHANGELOG_FILE"
rm -f "$TEMP_FILE"

echo "Successfully updated $CHANGELOG_FILE"
