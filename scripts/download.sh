#!/usr/bin/env bash
# Download BIOS pack from GitHub Releases (Linux/macOS one-liner compatible)
#
# A pack over 2 GB is published in several parts. Each is a ZIP
# (.part1of2.zip), checked and extracted in turn. Releases up to v2026.09.04
# carry byte ranges of one archive instead (.zip.001), which are joined first.
#
# Usage:
#   bash scripts/download.sh retroarch ~/RetroArch/system/
#   bash scripts/download.sh --list
#
# Requires: curl, unzip

set -euo pipefail

REPO="Abdess/retrobios"
API_BASE="${RETROBIOS_API:-https://api.github.com}"

# This endpoint names the assets and so the bytes that land in the BIOS
# directory. Plain HTTP stays allowed to loopback, which is how the script
# is exercised end to end.
case "$API_BASE" in
    https://*) ;;
    http://127.0.0.1[:/]*|http://localhost[:/]*|"http://[::1]"[:/]*) ;;
    *)
        echo "Error: RETROBIOS_API must use HTTPS, got '$API_BASE'" >&2
        exit 1
        ;;
esac
API="${API_BASE%/}/repos/${REPO}/releases/latest"

usage() {
    echo "Usage: $0 <platform> <destination>"
    echo "       $0 --list"
    echo ""
    echo "Download BIOS packs from GitHub Releases."
    echo ""
    echo "Examples:"
    echo "  $0 retroarch ~/RetroArch/system/"
    echo "  $0 batocera /userdata/bios/"
    echo "  $0 --list"
    exit 1
}

# One asset URL per line, in the order the release lists them.
asset_urls() {
    printf '%s' "$1" | tr ',' '\n' |
        sed -n 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

# The archive name behind each asset, the files of one pack folded together:
# Pack.part1of2.zip and Pack.zip.001 both belong to Pack.zip.
pack_names() {
    asset_urls "$1" | sed 's#.*/##' |
        sed 's/\(_BIOS_Pack\)\.part[0-9][0-9]*of[0-9][0-9]*\.zip$/\1.zip/' |
        sed -n 's/\(.*_BIOS_Pack\.zip\)\(\.[0-9][0-9]*\)\{0,1\}$/\1/p' |
        LC_ALL=C sort -u
}

platform_names() {
    pack_names "$1" | sed 's/_BIOS_Pack\.zip$//' | tr '_' ' '
}

# Letters and digits only: the platform is `misterfpga`, the asset MiSTer_FPGA.
normalize() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9'
}

fetch_release() {
    curl -fsSL "$API"
}

list_platforms() {
    echo "Fetching available platforms..."
    platform_names "$(fetch_release)"
}

download_pack() {
    local platform="$1"
    local dest="$2"
    local normalized
    normalized=$(normalize "$platform")

    echo "Fetching release info..."
    local release_json
    release_json=$(fetch_release)

    local archive=""
    local candidate
    while read -r candidate; do
        [ -n "$candidate" ] || continue
        case "$(normalize "$candidate")" in
            *"$normalized"*)
                archive="$candidate"
                break
                ;;
        esac
    done <<EOF
$(pack_names "$release_json")
EOF

    if [ -z "$archive" ]; then
        echo "Error: Platform '$platform' not found in latest release."
        echo "Available platforms:"
        platform_names "$release_json"
        exit 1
    fi

    local stem="${archive%.zip}"
    local volumes
    volumes=$(asset_urls "$release_json" |
        grep -E "/${stem//./\\.}(\.zip(\.[0-9]+)?|\.part[0-9]+of[0-9]+\.zip)$" |
        LC_ALL=C sort)
    if [ -z "$volumes" ]; then
        echo "Error: no asset found for ${archive}." >&2
        exit 1
    fi

    local count
    count=$(printf '%s\n' "$volumes" | wc -l | tr -d ' ')

    # Parts that are each a ZIP say in their name how many there are.
    local declared
    declared=$(printf '%s\n' "$volumes" |
        sed -n 's/.*\.part[0-9][0-9]*of\([0-9][0-9]*\)\.zip$/\1/p' | head -1)
    if [ -n "$declared" ] && [ "$declared" != "$count" ]; then
        echo "Error: the release lists ${count} of ${declared} parts of ${archive}." >&2
        exit 1
    fi

    # Staged inside the destination: a pack is gigabytes, and /tmp is a RAM
    # disk on the appliances these packs target.
    mkdir -p "$dest"
    local staging="${dest%/}/.retrobios-download"
    rm -rf "$staging"
    mkdir -p "$staging"
    trap 'rm -rf "$staging"' EXIT

    local index=0
    local url name
    while read -r url; do
        [ -n "$url" ] || continue
        index=$((index + 1))
        name=$(basename "$url")
        if [ "$count" -gt 1 ]; then
            echo "Downloading ${name} (part ${index}/${count})..."
        else
            echo "Downloading ${name}..."
        fi
        curl -fL --progress-bar -o "${staging}/${name}" "$url"
    done <<EOF
$volumes
EOF

    if [ -z "$declared" ] && [ "$count" -gt 1 ]; then
        echo "Joining ${count} parts into ${archive}..."
        # Releases up to v2026.09.04: split(1) wrote plain byte ranges, so
        # concatenation rebuilds the ZIP.
        cat "${staging}/${archive}".[0-9][0-9][0-9] > "${staging}/${archive}"
        rm -f "${staging}/${archive}".[0-9][0-9][0-9]
    fi

    local file
    for file in "${staging}"/*.zip; do
        verify_checksum "$release_json" "$staging" "$(basename "$file")"
    done

    echo "Extracting to ${dest}/..."
    for file in "${staging}"/*.zip; do
        unzip -o -q "$file" -d "$dest"
    done

    rm -rf "$staging"
    trap - EXIT
    echo "Done! BIOS files extracted to ${dest}/"
}

verify_checksum() {
    local release_json="$1" staging="$2" archive="$3"

    local sums_url
    sums_url=$(asset_urls "$release_json" | grep -E '/SHA256SUMS\.txt$' | head -1)
    if [ -z "$sums_url" ]; then
        echo "No SHA256SUMS.txt in the release, skipping the checksum."
        return 0
    fi

    local hasher
    if command -v sha256sum >/dev/null 2>&1; then
        hasher="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        hasher="shasum -a 256"
    else
        echo "No sha256sum available, skipping the checksum."
        return 0
    fi

    local expected
    expected=$(curl -fsSL "$sums_url" | awk -v name="$archive" '$2 == name {print $1}')
    if [ -z "$expected" ]; then
        echo "No checksum published for ${archive}, skipping."
        return 0
    fi

    echo "Checking ${archive}..."
    local actual
    actual=$($hasher "${staging}/${archive}" | cut -d' ' -f1)
    if [ "$actual" != "$expected" ]; then
        echo "Error: checksum mismatch for ${archive}" >&2
        echo "  expected ${expected}" >&2
        echo "  got      ${actual}" >&2
        echo "Download the parts again; a truncated part gives this." >&2
        exit 1
    fi
}

# Main
case "${1:-}" in
    --list|-l)
        list_platforms
        ;;
    --help|-h|"")
        usage
        ;;
    *)
        if [[ -z "${2:-}" ]]; then
            echo "Error: Destination directory required."
            usage
        fi
        download_pack "$1" "$2"
        ;;
esac
