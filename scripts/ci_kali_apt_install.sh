#!/usr/bin/env bash
# Retry transient Kali mirror failures without hiding real package failures.
# Only runs inside the disposable official Kali CI container.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

if (($# == 0)); then
    echo "Usage: ci_kali_apt_install.sh <packages...>" >&2
    exit 2
fi

install_packages() {
    apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=45 update &&
        apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=45 install -y "$@"
}

# Kali's default http.kali.org is a geo mirror redirector. It can point CI to
# a temporarily broken mirror; a failed install is not evidence of a bad build.
if install_packages "$@"; then
    exit 0
fi

echo "::warning::Kali apt failed using default mirror; retrying the official Cloudflare CDN" >&2

# Kali 2026.2+ uses Deb822 kali.sources, earlier images use sources.list.
# Preserve suites/components and Kali's signed-by keyring. Do not add repos,
# disable TLS or signature checks, or suppress a second failure.
if [[ -f /etc/apt/sources.list.d/kali.sources ]] &&
   grep -q 'http.kali.org/kali' /etc/apt/sources.list.d/kali.sources; then
    sed -i 's#http://http.kali.org/kali/#https://kali.download/kali/#g; s#http://http.kali.org/kali#https://kali.download/kali/#g' \
        /etc/apt/sources.list.d/kali.sources
elif [[ -f /etc/apt/sources.list ]] &&
     grep -q 'http.kali.org/kali' /etc/apt/sources.list; then
    sed -i 's#http://http.kali.org/kali#https://kali.download/kali#g' \
        /etc/apt/sources.list
else
    echo "::error::Kali APT source layout is unknown; refusing to modify repositories" >&2
    exit 1
fi

echo "::notice::Retrying apt against https://kali.download/kali" >&2
install_packages "$@"
