local cpu = require('eka2l1.cpu')
local evt = require('eka2l1.events')

-- From Qt 4.7.4 on, QSymbianFontDatabaseExtrasImplementation::extras() compares the
-- current thread with QApplication::instance()->thread() on its first lookup, which
-- dereferences NULL in applications that paint text without creating a QApplication.
-- Taking the branch that skips the check restores the Qt 4.7.3 behaviour; only a
-- thread's cached font extras stop being released when that thread exits.
local function skipFontExtrasThreadCheck()
    cpu.setReg(15, cpu.getPc() + 0x74)
end

evt.registerBreakpointHook('qtgui.dll', 0x001570B5, 0, 0x2001B2DD, skipFontExtrasThreadCheck, 0x8E4B3F71)    -- Qt 4.7.4
evt.registerBreakpointHook('qtgui.dll', 0x0015DC71, 0, 0x2001B2DD, skipFontExtrasThreadCheck, 0xAA4C4DCA)    -- Qt 4.8.0
