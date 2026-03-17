#!/usr/bin/env bash
# Download BIOS pack from GitHub Releases (Linux/macOS one-liner compatible)
#
# Usage:
#   bash scripts/download.sh retroarch ~/RetroArch/system/
#   bash scripts/download.sh --list
#
# Requires: curl, unzip, jq (optional, for --list)

set -euo pipefail

REPO="Abdess/retroarch_system"
API="https://api.github.com/repos/${REPO}/releases/latest"

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

list_platforms() {
    echo "Fetching available platforms..."
    if command -v jq &>/dev/null; then
        curl -sL "$API" | jq -r '.assets[].name' | grep '_BIOS_Pack.zip' | sed 's/_BIOS_Pack.zip//' | tr '_' ' '
    else
        curl -sL "$API" | grep -oP '"name":\s*"\K[^"]*_BIOS_Pack\.zip' | sed 's/_BIOS_Pack.zip//' | tr '_' ' '
    fi
}

download_pack() {
    local platform="$1"
    local dest="$2"
    local normalized
    normalized=$(echo "$platform" | tr ' ' '_' | tr '[:upper:]' '[:lower:]')

    echo "Fetching release info..."
    local release_json
    release_json=$(curl -sL "$API")

    # Find matching asset URL
    local download_url
    download_url=$(echo "$release_json" | grep -oP "\"browser_download_url\":\s*\"[^\"]*${normalized}[^\"]*_BIOS_Pack\.zip\"" | head -1 | grep -oP 'https://[^"]+')

    if [[ -z "$download_url" ]]; then
        echo "Error: Platform '$platform' not found in latest release."
        echo "Available platforms:"
        list_platforms
        exit 1
    fi

    local filename
    filename=$(basename "$download_url")

    local tmpfile
    tmpfile=$(mktemp "/tmp/${filename}.XXXXXX")

    echo "Downloading ${filename}..."
    curl -L --progress-bar -o "$tmpfile" "$download_url"

    echo "Extracting to ${dest}/..."
    mkdir -p "$dest"
    unzip -o -q "$tmpfile" -d "$dest"

    rm -f "$tmpfile"
    echo "Done! BIOS files extracted to ${dest}/"
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
