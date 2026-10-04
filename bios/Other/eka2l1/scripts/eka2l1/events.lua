--- **Events** module provides abilities to register callbacks at certain events in the emulator.
---
--- The current supported callback types are: breakpoint and IPC (Inter-process communication) callback. For breakpoint callback,
--- it's always preferred to not spend too much time in the callback, which may impact emulated app performance.
---
--- Each script is allowed to have a limit of 2^32 callbacks, but the true number depends on the memory of your system and how much the Lua
--- runner can hold. All callbacks are discarded on script unload.
---
-- @module events

local ipcCtx = require('eka2l1.ipc.context')
local kern = require('eka2l1.kernel')
local common = require('eka2l1.common')

events = {}

--- Passed to **registerIpcHook**, indicating that IPC callback will be invoked when the client process first
--- sends message to the server process.
events.EVENT_IPC_SEND = 0

--- Passed to **registerIpcHook**, indicating that IPC callback will be invoked after the server process finished
--- processing the request and tell the emulator to notify back to the waiting client.
events.EVENT_IPC_COMPLETE = 2

--- Constant indicating an invalid handle returned from callback registering.
events.INVALID_HOOK_HANDLE = 0xFFFFFFFF

local ffi = require("ffi")

pcall(ffi.load, 'native-lib', true)

ffi.cdef([[
    void free(void *ptr);

    typedef struct ipc_msg ipc_msg;
    typedef struct thread thread;

    typedef void (__stdcall *breakpoint_hit_lua_func)();
    typedef void (__stdcall *ipc_sent_lua_func)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, thread*);
    typedef void (__stdcall *ipc_completed_lua_func)(ipc_msg*);

    uint32_t eka2l1_cpu_register_lib_hook(const char *lib_name, const uint32_t ord, const uint32_t process_uid, const uint32_t codesegUid3, const uint32_t codesegHash, breakpoint_hit_lua_func func);
    uint32_t eka2l1_cpu_register_bkpt_hook(const char *image_name, const uint32_t addr, const uint32_t process_uid, const uint32_t codesegUid3, const uint32_t codesegHash, breakpoint_hit_lua_func func);
    uint32_t eka2l1_cpu_register_rom_export_bkpt_hook(const char *image_name, const uint32_t ordinal, const uint32_t methodHash, const uint32_t hookOffset, const uint32_t process_uid, const uint32_t codesegUid3, breakpoint_hit_lua_func func);
    uint32_t eka2l1_register_ipc_sent_hook(const char *server_name, const int opcode, ipc_sent_lua_func func);
    uint32_t eka2l1_register_ipc_completed_hook(const char *server_name, const int opcode, ipc_completed_lua_func func);

    void eka2l1_clear_hook(const uint32_t hook_handle);
]])

--- Register a callback on library function being called.
---
--- This is **registerBreakpointHook** in disguise, but with automated address detection. This is preferred
--- for the callback to work across many emulated devices, because address of the library function may change,
--- but the ordinal is consistent.
---
--- @param libName Name of the library that contains the target library function.
--- @param ord The ordinal of the function inside the library.
--- @param processUid UID3 of the process you want this callback to be triggered on. Use 0 for any active process.
--- @param codesegUid3 UID3 of the library the hook will be registered on. This is a safecheck to hook on the correct library.
--- @param func Callback function with no parameter and no return.
---
--- @return A handle to this callback (> 0), which can later be used for unregistering. `INVALID_HOOK_HANDLE` on failure.
---
--- @see clearHook
--- @see registerBreakpointHook
function events.registerLibraryHook(libName, ord, processUid, codesegUid3, func, codesegHash)
    local libNameInC = ffi.new("char[?]", #libName + 1, libName)
    local hash = codesegHash

    if (hash == nil) then
        hash = 0
    end

    return ffi.C.eka2l1_cpu_register_lib_hook(libNameInC, ord, processUid, codesegUid3, hash, function ()
        local ran, errorMsg = pcall(func)
        if not ran then
            common.log('Error running breakpoint script, ' .. errorMsg)
        end
    end)
end

--- Register a callback on a breakpoint.
---
--- The address passed to this function should be relative to the original code base address found in
--- disassemble/image explorer program. The emulator will rebase the address relatively to where the library
--- is loaded in memory.
---
--- In case the breakpoint address is constant and should not be related to any libraries or executables, pass the string "constantaddr"
--- to the `libName` variable.
---
--- @param libName Name of the library that contains the target breakpoint. Use "constantaddr" for no library.
--- @param addr The address of the breakpoint, relative to the library's original code base address if libName is not "constantaddr"
--- @param processUid UID3 of the process you want this callback to be triggered on. Use 0 for any active process.
--- @param codesegUid3 UID3 of the library the hook will be registered on. This is a safecheck to hook on the correct library.
--- @param func Callback function with no parameter and no return.
---
--- @return A handle to this callback (> 0), which can later be used for unregistering. `INVALID_HOOK_HANDLE` on failure.
---
--- @see clearHook
--- @see registerLibraryHook
function events.registerBreakpointHook(libName, addr, processUid, codesegUid3, func, codesegHash)
    local libNameInC = ffi.new("char[?]", #libName + 1, libName)
    local hash = codesegHash

    if (hash == nil) then
        hash = 0
    end

    return ffi.C.eka2l1_cpu_register_bkpt_hook(libNameInC, addr, processUid, codesegUid3, hash, function ()
        local ran, errorMsg = pcall(func)
        if not ran then
            common.log('Error running breakpoint script, ' .. errorMsg)
        end
    end)
end

--- Register a breakpoint at an offset inside a ROM export after verifying only
--- that exported method's code bytes. This avoids firmware-specific absolute
--- addresses and whole-DLL hashes while refusing methods with unknown code.
---
--- @param libName Name of the ROM library containing the method.
--- @param ordinal Export ordinal used to locate the method dynamically.
--- @param methodHash XXH32 fingerprint of the method, up to the next export.
--- @param hookOffset Byte offset from the method entry to the breakpoint.
--- @param processUid UID3 of the process to restrict the callback to, or 0.
--- @param codesegUid3 UID3 of the ROM library.
--- @param func Callback function with no parameter and no return.
function events.registerRomExportBreakpointHook(libName, ordinal, methodHash, hookOffset, processUid, codesegUid3, func)
    local libNameInC = ffi.new("char[?]", #libName + 1, libName)
    return ffi.C.eka2l1_cpu_register_rom_export_bkpt_hook(libNameInC, ordinal,
        methodHash, hookOffset, processUid, codesegUid3, function ()
        local ran, errorMsg = pcall(func)
        if not ran then
            common.log('Error running ROM export breakpoint script, ' .. errorMsg)
        end
    end)
end

--- Register a callback on IPC request send/complete.
---
--- For IPC send callback, you have the ability to read data the client sent before the request is delivered
--- to the server process.
---
--- For IPC complete callback, you will receive the message context before the request is signaled to be completed to
--- the client process.
---
--- Both the callback will receive an `ipc.context` object as its parameter.
---
---@param serverName Name of the server to intercept IPC messages.
---@param opcode The target message opcode to intercept.
---@param when The moment to receive the callback. Two options are `EVENT_IPC_SEND` and `EVENT_IPC_COMPLETE`
---@param func The callback function, with `ipc.context` object as its only parameter.
---
--- @return A handle to this callback (> 0), which can later be used for unregistering. `INVALID_HOOK_HANDLE` on failure.
---
--- @see clearHook
function events.registerIpcHook(serverName, opcode, when, func)
    local serverNameInC = ffi.new("char[?]", #serverName + 1, serverName)

    if when == events.EVENT_IPC_SEND then
        return ffi.C.eka2l1_register_ipc_sent_hook(serverNameInC, opcode, function (arg0, arg1, arg2, arg3, flags, reqsts, sender)
            local ran, retval = pcall(ipcCtx.makeFromValues, opcode, arg0, arg1, arg2, arg3, flags, reqsts, kern.thread(sender))
            if not ran then
                common.log('Fail to create IPC context, ' .. retval)
                return
            end

            ran, retval = pcall(func, retval)
            if not ran then
                common.log('IPC sent callback encountered error, '.. retval)
            end
        end)
    else
        return ffi.C.eka2l1_register_ipc_completed_hook(serverNameInC, opcode, function (msg)
            local ran, retval = pcall(ipcCtx.makeFromMessage, kern.message(msg))
            if not ran then
                common.log('Fail to create IPC context, ' .. retval)
                return
            end
            
            ran, retval = pcall(func, retval)
            if not ran then
                common.log('IPC sent callback encountered error, '.. retval)
            end
        end)
    end
end

--- Unregistering a callback.
---
--- This method is safe to call inside a callback. The callback will still continue to do the rest of its job
--- after the delete.
---
--- Note that failure is silent, and may only be reported on the log channel.
---
---@param handle The handle retrieved from registering.
function events.clearHook(handle)
    ffi.C.eka2l1_clear_hook(handle)
end

return events