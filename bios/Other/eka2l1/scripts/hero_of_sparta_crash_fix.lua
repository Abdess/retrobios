local common = require('eka2l1.common')
local evt = require('eka2l1.events')
local cpu = require('eka2l1.cpu')

local ffi = require('ffi')

function fixTemporaryFileBufferTooSmall()
    -- The file buffer used to store the data is full too fast with the size of 0x80000 bytes (~0.5mb)
    -- On a real phone, maybe it overflows, but the OS is less forgiving, or it does not at all. But increase should do it right.
    cpu.setReg(0, 6 * 1024 * 1024)      -- 6MB
end

common.log('Script enabled: Hero of Sparta (Gameloft) crash fix.')
evt.registerBreakpointHook('heroofsparta.exe', 0x000886B3, 0, 0, fixTemporaryFileBufferTooSmall, 0x612393CE)		-- 1.1.6
evt.registerBreakpointHook('heroofsparta.exe', 0x00089063, 0, 0, fixTemporaryFileBufferTooSmall, 0x6094E8CC)		-- 1.0.9