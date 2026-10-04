local common = require('eka2l1.common')
local evt = require('eka2l1.events')
local cpu = require('eka2l1.cpu')

local ffi = require('ffi')

function fixWrongGLSLCodeHash()
	-- For some reason they try to hash configuration header string instead. They take the combined string
	-- length, so we can try to replace the configuration string with combined
	-- Again, this crash sometimes are constant!! Because the emulator's randomness does not exist. Note that
	-- OpenGL operations does not cause any allocations that is supposed to make the memory orders random.
	cpu.setReg(7, cpu.getReg(8))
end

common.log('Script enabled: Eternal Legacy (Gameloft) crash fix.')
evt.registerBreakpointHook('eternallegacy.exe', 0x00270488, 0, 0, fixWrongGLSLCodeHash, 0x7C16F812)