--- **CPU** provides access to read/write operations on the emulated CPU's general purpose registers (GPRs).
---
--- The CPU that is targetted by these functions is the one being emulated on the current caller thread. Because of that,
--- these functions can not be run on threads that are not emulating CPUs, as it may result in undefined behaviour.
-- @module cpu

cpu = {}

local ffi = require("ffi")

pcall(ffi.load, 'native-lib', true)

ffi.cdef([[
    uint32_t eka2l1_cpu_get_reg(const int idx);
    uint32_t eka2l1_cpu_get_cpsr();
    uint32_t eka2l1_cpu_get_pc();
    uint32_t eka2l1_cpu_get_sp();
    uint32_t eka2l1_cpu_get_lr();

    void eka2l1_cpu_set_reg(const int idx, uint32_t value);
]])

--- Read value of register from R0 - R15.
-- @param  idx The index of the register (0 - 15). Value outside the given range may produce undefined behaviour.
-- @return The value currently stored in the targetted register.
function cpu.getReg(idx)
    return ffi.C.eka2l1_cpu_get_reg(idx)
end

--- Read the CPSR register value.
-- @return CPSR register value.
function cpu.getCpsr()
    return ffi.C.eka2l1_cpu_get_cpsr()
end

--- Get the current program counter (PC) of the CPU.
---
--- This call is identical to **cpu.getReg(15)** *(PC is R15)*
-- @return Register PC's value
function cpu.getPc()
    return ffi.C.eka2l1_cpu_get_pc()
end

--- Get the current stack pointer (SP) of the CPU.
---
--- This call is identical to **cpu.getReg(13)** *(SP is R13)*
-- @return Register SP's value
function cpu.getSp()
    return ffi.C.eka2l1_cpu_get_sp()
end

--- Get the current stack pointer (LR) of the CPU.
---
--- This call is identical to **cpu.getReg(14)** *(LR is R14)*
-- @return Register SP's value
function cpu.getLr()
    return ffi.C.eka2l1_cpu_get_lr()
end

--- Set value of register from R0 - R15.
-- @param  idx The index of the register (0 - 15). Value outside the given range may produce undefined behaviour.
-- @param  val The value that is to write to the destinated register.
function cpu.setReg(idx, val)
    return ffi.C.eka2l1_cpu_set_reg(idx, val)
end

return cpu