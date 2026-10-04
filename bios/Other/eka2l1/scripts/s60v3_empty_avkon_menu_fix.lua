local cpu = require('eka2l1.cpu')
local events = require('eka2l1.events')

local function skipEmptyAvkonMenu(cleanupOffset)
    -- R1 is Count()-1. LuaJIT exposes uint32_t as an unsigned number, so test
    -- the sign bit through its numeric range.
    if tonumber(cpu.getReg(1)) >= 0x80000000 then
        cpu.setReg(7, 0)
        cpu.setReg(15, cpu.getPc() + cleanupOffset)
    end
end

local function skipRm409EmptyAvkonMenu()
    skipEmptyAvkonMenu(0xF4)
end

local function skipRm320EmptyAvkonMenu()
    skipEmptyAvkonMenu(0x12C)
end

events.registerRomExportBreakpointHook('eikcoctl.dll', 70, 0x39A36149,
    0x182, 0, 0x1000489E, skipRm409EmptyAvkonMenu)
events.registerRomExportBreakpointHook('eikcoctl.dll', 70, 0x1595EE13,
    0x17E, 0, 0x1000489E, skipRm320EmptyAvkonMenu)
