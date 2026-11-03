rp_module_id="pcsx2"
rp_module_section="exp"
rp_module_flags="!all x86"

function configure_pcsx2() {
    addEmulator 1 "$md_id" "psx" "pcsx2 %ROM%"
}
