#!/usr/bin/env bash
set -euo pipefail

# A clean downstream Laravel app must be able to install and discover the
# package from its checkout. No application secrets or external keys needed.
workspace="${GITHUB_WORKSPACE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
workspace="$(cd "$workspace" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

composer create-project "laravel/laravel:^13.0" "$tmp/consumer" --no-interaction --no-progress --prefer-dist
cd "$tmp/consumer"
composer config repositories.local-leakproof '{"type":"path","url":"'"$workspace"'","options":{"symlink":false}}'
composer require --dev "mykholy/laravel-leakproof:@dev" --no-interaction --no-progress --with-all-dependencies

php artisan list --raw | grep -q '^leakproof:scan'
printf '%s\n' '{"data":{"name":"Test User"}}' > safe.json
php artisan leakproof:scan safe.json --format=json

printf '%s\n' '{"data":{"message":"sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}' > leak.json
if php artisan leakproof:scan leak.json --format=json; then
    echo 'Expected failure for synthetic leaked AI key, got success.' >&2
    exit 1
fi

echo 'Downstream Laravel consumer installation and detection succeeded.'
