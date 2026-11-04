rp_module_id="lr-fceumm"
rp_module_section="main"

function configure_lr-fceumm() {
    local system
    for system in nes fds; do
        addEmulator 1 "$md_id" "$system" "$md_inst/fceumm_libretro.so"
    done
}
