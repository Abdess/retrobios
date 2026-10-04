local cpu = require('eka2l1.cpu')
local events = require('eka2l1.events')

local function skipNullClientRead()
    -- A missing menu controller has the same offline state as a null client.
    if cpu.getReg(2) == 0 then
        cpu.setReg(3, 0)
        cpu.setReg(15, cpu.getPc() + 4)
    end
end

for _, address in ipairs({0x10024F88, 0x10024FDC, 0x10025030}) do
    events.registerBreakpointHook('6r65.app', address, 0, 0x101FD402,
        skipNullClientRead, 0xBA80BDA5)
end
