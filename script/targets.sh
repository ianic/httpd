#!/bin/bash
set -e
cwd="$(pwd)"

protocol=$1
port=$2
host="${3:-localhost}"
cd site/www.ziglang.org/zig-out

# # all files
# find . -type f -exec echo -e "GET $protocol://localhost:$port/{}\n" \; >"$cwd/site/targets"

# Skip huge mp4 file because it dominates in benchmark
find . -type f ! -path "*/facebook_bot.mp4" ! -name '*.gz' ! -name '*.br' ! -name '*.zst' -exec echo -e "GET $protocol://$host:$port/{}\n" \; >"$cwd/site/targets-vegeta"
find . -type f ! -path "*/facebook_bot.mp4" ! -name '*.gz' ! -name '*.br' ! -name '*.zst' -exec echo -e "$protocol://$host:$port/{}" \; >"$cwd/site/targets-oha"

# # only x largest(head)/smalles(tail) files
# rm "$cwd/site/targets"
# find . -type f ! -path "*/facebook_bot.mp4" -exec ls -S {} + | head -n 10 | while IFS= read -r file; do
#     echo -e "GET $protocol://localhost:$port/$file\n" >>"$cwd/site/targets"
# done
cd "$cwd"
