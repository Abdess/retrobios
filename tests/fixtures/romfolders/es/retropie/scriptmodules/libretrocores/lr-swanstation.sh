rp_module_id="lr-swanstation"
rp_module_section="opt"

function configure_lr-swanstation() {
    addEmulator 1 "$md_id" "psx" "$md_inst/swanstation_libretro.so"
}
