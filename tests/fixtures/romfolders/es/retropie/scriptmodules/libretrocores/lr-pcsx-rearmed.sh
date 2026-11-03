rp_module_id="lr-pcsx-rearmed"
rp_module_section="main"
rp_module_flags="!x86"

function configure_lr-pcsx-rearmed() {
    addEmulator 1 "$md_id" "psx" "$md_inst/pcsx_rearmed_libretro.so"
}
