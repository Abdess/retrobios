--- **Std** contains standard functions related to Symbian development's data structure.
--- @module std

std = {}

local kernel = require('eka2l1.kernel')
local helper = require('eka2l1.helper')
local bitops = require('bit')
local ffi = require('ffi')

pcall(ffi.load, 'native-lib', true)

ffi.cdef([[
    const char *eka2l1_std_utf16_to_utf8(const char *wstring, const int length);
    void eka2l1_free_string(const char* str);
]])

std.DESCRIPTOR_TYPE_BUF_CONST = 0
std.DESCRIPTOR_TYPE_PTR_CONST = 1
std.DESCRIPTOR_TYPE_PTR = 2
std.DESCRIPTOR_TYPE_BUF = 3
std.DESCRIPTOR_TYPE_BUF_CONST_PTR = 4
std.DESCRIPTOR_TYPE_MAX = 5

function GetPtrBufConstAddress(pr, address)
    return address + 4
end

function GetPtrPtrConstAddress(pr, address)
    return pr:readDword(address + 4)
end

function GetPtrBufAddress(pr, address)
    return address + 8
end

function GetPtrPtrAddress(pr, address)
    return pr:readDword(address + 8)
end

function GetPtrBufConstPtrAddress(pr, address)
    local realBufAddr = pr:readDword(address + 8)
    return realBufAddr + 4
end

--- Abstract class which allows the containment of data.
---
--- @param pr The process where this descriptor lives on.
--- @param addr The address of the descriptor in the process's memory.
std.descriptor = helper.class(function(self, pr, addr)
    local addressLookupTable = {
        [std.DESCRIPTOR_TYPE_BUF_CONST] = GetPtrBufConstAddress,
        [std.DESCRIPTOR_TYPE_BUF_CONST_PTR] = GetPtrBufConstPtrAddress,
        [std.DESCRIPTOR_TYPE_BUF] = GetPtrBufAddress,
        [std.DESCRIPTOR_TYPE_PTR] = GetPtrPtrAddress,
        [std.DESCRIPTOR_TYPE_PTR_CONST] = GetPtrPtrConstAddress
    }

    local desword = pr:readDword(addr)

    self.length = bitops.band(desword, 0xFFFFFFF);
    self.type = bitops.band(bitops.rshift(desword, 28), 0xF)

    if self.type >= std.DESCRIPTOR_TYPE_MAX then
        error('Descriptor type is invalid!')
    else
        self.dataAddr = addressLookupTable[self.type](pr, addr)
        self.pr = pr
    end
end)

--- Detailed descriptor that is designed to hold 8-bit data.
---
--- This kind of descriptor usually used to hold 8-bit string or binary data, and can be coverted
--- to string by using **tostring**.
---
--- @param pr The process where this descriptor lives on.
--- @param addr The address of the descriptor in the process's memory.
std.descriptor8 = helper.class(std.descriptor, function(self, pr, addr)
    std.descriptor.init(self, pr, addr)
end)

--- Get the raw data that this descriptor is containing.
---
--- @return A raw FFI byte array containing data.
function std.descriptor8:rawData()
    return self.pr:readMemory(self.dataAddr, self.length)
end

function std.descriptor8:__tostring()
    return ffi.string(self:rawData())
end

--- Detailed descriptor that is designed to hold 16-bit data.
---
--- This kind of descriptor usually used to hold 16-bit Unicode string, and can be coverted
--- to string by using **tostring**.
---
--- @param pr The process where this descriptor lives on.
--- @param addr The address of the descriptor in the process's memory.
std.descriptor16 = helper.class(std.descriptor, function(self, pr, addr)
    std.descriptor.init(self, pr, addr)
end)

--- Convert a raw 8-bit C FFI byte array into a 16-bit Unicode string/
---
--- @param raw The raw byte array to convert.
--- @param length The number of characters that the result string should produce.
---
--- @return Converted `string` object.
function std.rawUtf16ToString(raw, length)
    local result = ffi.C.eka2l1_std_utf16_to_utf8(raw, length)
    ffi.gc(result, ffi.C.eka2l1_free_string)

    return ffi.string(result)
end

--- Get the raw data that this descriptor is containing.
---
--- @return A raw FFI byte array containing data.
function std.descriptor16:rawData()
    return self.pr:readMemory(self.dataAddr, self.length * 2)
end

function std.descriptor16:__tostring()
	return std.rawUtf16ToString(self:rawData(), self.length)
end

-- Request status implementation

--- Struct holding the status of a request.
---
--- On EKA1, this struct simply holds an integer, which contains the result code
--- of completed operation.
---
--- However, on EKA2, 32-bit `flag` bitarray is also added to this struct to tell
--- the status of the sync object associated with this request
---
--- @param pr The process where this request status lives on.
--- @param addr The address of the request status in the process's memory.
std.requestStatus = helper.class(function(self, pr, addr)
    self.ownProcess = pr
    self.dataAddr = addr
end)

--- Retrieve the current value of the request status
---
--- @return A 32-bit integer as the status code.
function std.requestStatus:value()
    return self.pr:readDword(self.addr)
end

--- Retrieve the current flags of the request status
---
--- @return A 32-bit integer, which each bit as a flag.
function std.requestStatus:flags()
    return self.pr:readDword(self.addr + 4)
end

-- End request status implementation

return std