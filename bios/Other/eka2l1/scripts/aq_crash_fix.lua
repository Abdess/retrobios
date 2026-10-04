local common = require('eka2l1.common')
local evt = require('eka2l1.events')
local cpu = require('eka2l1.cpu')
local kern = require('eka2l1.kernel')
local std = require('eka2l1.std')

local ffi = require('ffi')

function fixGarbageValueNotZero()
	cpu.setReg(2, 0)
end

common.log('Script enabled: AstroQuest (mBounce) crash fix.')
common.log('Crash caused by garbage variable value not 0 because of User::Free R2 not set to 0. Require precise memory allocation.')

evt.registerBreakpointHook('AQ.app', 0x100040C9, 0, 0x004750E8, fixGarbageValueNotZero)