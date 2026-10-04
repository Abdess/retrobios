--- **Common** contains utilities that is frequently used by the emulator.
-- @module common

common = {}

local ffi = require("ffi")

pcall(ffi.load, 'native-lib', true)

ffi.cdef([[
    void eka2l1_log(const char *line);
    int eka2l1_get_current_symbian_version();
]])

common.SYMBIAN_VERSION_EKA1 = 0
common.SYMBIAN_VERSION_EPOCU6 = 1
common.SYMBIAN_VERSION_EPOC6 = 2
common.SYMBIAN_VERSION_EPOC80 = 3
common.SYMBIAN_VERSION_EPOC81A = 4
common.SYMBIAN_VERSION_EKA2 = 5
common.SYMBIAN_VERSION_EPOC81B = 6
common.SYMBIAN_VERSION_EPOC93FP1 = 7
common.SYMBIAN_VERSION_EPOC93FP2 = 8
common.SYMBIAN_VERSION_EPOC94 = 9
common.SYMBIAN_VERSION_EPOC95 = 10
common.SYMBIAN_VERSION_EPOC100 = 11

--- Print a string into the emulator's log sinks.
---
--- The severity of the log will be **INFO**, and the category is **Scripting**
--- @param str The string to be logged out
function common.log(str)
	local target = ffi.new("char[?]", #str + 1, str)
    ffi.C.eka2l1_log(target)
end

--- Get the current symbian version that the emulator is emulating.
---
--- @return One of the value in SYMBIAN_VERSION enum. See common.SYMBIAN_VERSION_*
function common.getCurrentSymbianVersion()
    return ffi.C.eka2l1_get_current_symbian_version()
end

return common