#!/bin/bash
set -e
cwd="$(pwd)"

protocol=$1
port=$2
host="${3:-localhost}"
cd site/root

# Skip huge mp4 file because it dominates in benchmark
# find . -type f ! -path "*/.*" ! -path "*/facebook_bot.mp4" ! -name '*.gz' ! -name '*.br' ! -name '*.zst' -exec echo -e "GET $protocol://$host:$port/{}\n" \; >"$cwd/site/targets-vegeta"
find . -type f ! -path "*/.*" ! -path "*/facebook_bot.mp4" ! -name '*.gz' ! -name '*.br' ! -name '*.zst' ! -name '*.sh' -exec echo -e "$protocol://$host:$port/{}" \; >"$cwd/site/targets-oha"

cd "$cwd"
