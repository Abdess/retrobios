PKG_NAME="emulators"

makeinstall_target() {
  add_system_dir /storage/roms/bios

  add_emu_core 3do retroarch opera true
  add_es_system 3do

  case ${DEVICE} in
    RK3326)
      add_emu_core psx retroarch pcsx_rearmed true
      add_emu_core psx retroarch swanstation false
    ;;
    *)
      add_emu_core psx retroarch swanstation true
      add_emu_core psx retroarch pcsx_rearmed false
    ;;
  esac
  add_es_system psx

  add_emu_core tools ignore ignore true
  add_es_system tools
}
