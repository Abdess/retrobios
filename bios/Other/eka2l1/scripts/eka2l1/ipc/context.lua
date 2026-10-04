--- **IPC context** provides utilities for manipulating an IPC request.
--- @module ipc.context

IpcContext = {}

local kernel = require('eka2l1.kernel')
local helper = require('eka2l1.helper')
local std = require('eka2l1.std')
local common = require('eka2l1.common')
local bitops = require('bit')

--- The argument type is not known.
IpcContext.IPC_ARGUMENT_TYPE_UNSPECIFIED = 0

--- Argument is a kernel handle.
IpcContext.IPC_ARGUMENT_TYPE_HANDLE = 1

--- Argument is a 8-bit descriptor.
IpcContext.IPC_ARGUMENT_TYPE_DES8 = 4

--- Argument is a 16-bit descriptor.
IpcContext.IPC_ARGUMENT_TYPE_DES16 = 5

--- Argument is a 8-bit constant descriptor.
IpcContext.IPC_ARGUMENT_TYPE_DESC8 = 6

--- Argument is a 16-bit constant descriptor.
IpcContext.IPC_ARGUMENT_TYPE_DESC16 = 7

IpcContext.arguments = helper.class(function(arg1, arg2, arg3, arg4, flags)
    self.args = {}
    self.args[1] = arg1
    self.args[2] = arg2
    self.args[3] = arg3
    self.args[4] = arg4
    self.flags = flags
end)

--- Get the type of an argument.
---
--- @param idx The argument to retrieve the type.
--- @return One of the `IPC_ARGUMENT_TYPE_` constants.
function IpcContext.arguments:valueType(idx)
    if (idx < 0) or (idx > 3) then
        error('Argument index out of range!')
    end

    return bitops.band(bitops.rshift(self.flags, idx * 3), 7)
end

--- Get the raw argument value.
---
--- @param idx The index of the argument to retrieve value from.
--- @return Argument in the form of 32-bit integer value.
function IpcContext.arguments:value(idx)
    if (idx < 0) or (idx > 3) then
        error('Argument index out of range!')
    end

    return self.args[idx]
end

IpcContext.context = helper.class(function(func, arg0, arg1, arg2, arg3, flags, reqsts, sender)
    self.args = arguments(arg0, arg1, arg2, arg3, flags)
    self.func = func
    self.sender = sender
    self.requestStatus = reqsts
end)

--- Get the raw argument value.
---
--- This is a direct call to `IpcContext.arguments:value`.
---
--- @param idx The index of the argument to retrieve value from.
--- @return Argument in the form of 32-bit integer value.
function IpcContext.context:rawArgument(idx)
    return self.args.value(idx)
end

--- Get the thread owning the context.
---
--- This is the thread that want to send the IPC message.
---
--- @return Own thread as `kernel.thread`.
function IpcContext.context:ownThread()
    return self.sender
end

--- Get the value of the argument processed.
---
--- For descriptor argument type, this will return either a `std.descriptor8` or `std.descriptor16` class.
---
--- Otherwise, this will return a 32-bit integer.
---
--- @param idx The index of the argument to retrieve value from.
---
--- @return The value at the target index processed.
function IpcContext.context:argument(idx)
    local argtype = self.args.valueType(idx)
    local value = self.args.value(idx)

    if (argtype == IPC_ARGUMENT_TYPE_UNSPECIFIED) or (IPC_ARGUMENT_TYPE_HANDLE) then
        return value
    end

    if (argtype == IPC_ARGUMENT_TYPE_DES8) or (argtype == IPC_ARGUMENT_TYPE_DESC8) then
        return std.descriptor8(self.sender:ownProcess(), value)
    end

    return std.descriptor16(self.sender:ownProcess(), value)
end

function IpcContext.makeFromMessage(msg)
    return context(msg:func(), msg:arg(0), msg:arg(1), msg:arg(2), msg:arg(3), msg:flags(),
        std.makeRequestStatus(msg:sender():ownProcess(), msg:requestStatusAddress()), msg:sender())
end

function IpcContext.makeFromValues(func, arg0, arg1, arg2, arg3, flags, reqsts, sender)
    return context(func, arg0, arg1, arg2, arg3, flags, std.makeRequestStatus(sender:ownProcess(), reqsts), sender)
end

return IpcContext