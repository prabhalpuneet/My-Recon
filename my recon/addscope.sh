#!/bin/bash

# Check if file argument is given
if [ -z "$1" ]; then
  echo "Usage: $0 wildcard.txt"
  exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE=".scope"

# Empty or create the output file
> "$OUTPUT_FILE"

# Read the file line by line
while IFS= read -r domain; do
  # Skip empty lines
  [ -z "$domain" ] && continue

  # Escape dots
  escaped_domain=$(echo "$domain" | sed 's/\./\\./g')

  # Append to output file
  echo ".*\\.$escaped_domain\$" >> "$OUTPUT_FILE"
  echo "^$escaped_domain\$" >> "$OUTPUT_FILE"
done < "$INPUT_FILE"

echo "Regex patterns saved to $OUTPUT_FILE"
