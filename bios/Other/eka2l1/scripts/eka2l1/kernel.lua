--- **Kernel** module provides access to the emulated system's kernel object (read/write/...)
---
--- All kernel objects provided here are class-based.
---
--- @module kernel

kernel = {
}

local helper = require('eka2l1.helper')
local ffi = require('ffi')

ffi.cdef([[
    typedef struct codeseg codeseg;
    typedef struct process process;
    typedef struct thread thread;
    typedef struct server server;
    typedef struct session session;
    typedef struct ipc_msg ipc_msg;

    void eka2l1_free_codeseg(codeseg* seg);
    void eka2l1_free_process(process *pr);
    void eka2l1_free_thread(thread *thr);
    void eka2l1_free_server(server *svr);
    void eka2l1_free_session(session *ss);
    void eka2l1_free_ipc_msg(ipc_msg *msg);
	
    void eka2l1_free_string(const char* str);

    codeseg *eka2l1_load_codeseg(const char *path);
    uint32_t eka2l1_codeseg_lookup(codeseg *seg, process *pr, const uint32_t ord);
    uint32_t eka2l1_codeseg_code_run_address(codeseg *seg, process *pr);
    uint32_t eka2l1_codeseg_data_run_address(codeseg *seg, process *pr);
    uint32_t eka2l1_codeseg_bss_run_address(codeseg *seg, process *pr);
    uint32_t eka2l1_codeseg_get_export(codeseg *seg, process *pr, const uint32_t index);
    uint32_t eka2l1_codeseg_get_entry_point(codeseg *seg, process *pr);
    uint32_t eka2l1_codeseg_code_size(codeseg *seg);
    uint32_t eka2l1_codeseg_data_size(codeseg *seg);
    uint32_t eka2l1_codeseg_bss_size(codeseg *seg);
    uint32_t eka2l1_codeseg_export_count(codeseg *seg);
    uint32_t eka2l1_codeseg_get_hash(codeseg *seg);
    void eka2l1_codeseg_set_export(codeseg *seg, const uint32_t index, const uint32_t addr_or_offset);
    void eka2l1_codeseg_set_entry_point(codeseg *seg, const uint32_t addr_or_offset);
    void eka2l1_codeseg_set_patched(codeseg *seg);
    void eka2l1_codeseg_set_entry_point_disabled(codeseg *seg);

    int32_t eka2l1_queries_all_processes(process ***pr);
    process *eka2l1_get_current_process();
    const char *eka2l1_process_read_memory(process *pr, uint32_t addr, uint32_t size);
    int eka2l1_process_write_memory(process *pr, uint32_t addr, const char *buf, uint32_t size);
    uint8_t eka2l1_process_read_byte(process *pr, uint32_t addr);
    uint16_t eka2l1_process_read_word(process *pr, uint32_t addr);
    uint32_t eka2l1_process_read_dword(process *pr, uint32_t addr);
    uint64_t eka2l1_process_read_qword(process *pr, uint32_t addr);
    thread *eka2l1_process_first_thread(process *pr);
    const char *eka2l1_process_executable_path(process *pr);
    const char *eka2l1_process_name(process *pr);

    thread *eka2l1_get_current_thread();
    thread *eka2l1_next_thread_in_process(thread *thr);
    process *eka2l1_thread_own_process(thread *thr);
    uint32_t eka2l1_thread_stack_base(thread *thr);
    uint32_t eka2l1_thread_get_heap_base(thread *thr);
    uint32_t eka2l1_thread_get_register(thread *thr, uint8_t index);
    uint32_t eka2l1_thread_get_pc(thread *thr);
    uint32_t eka2l1_thread_get_lr(thread *thr);
    uint32_t eka2l1_thread_get_sp(thread *thr);
    uint32_t eka2l1_thread_get_cpsr(thread *thr);
    int eka2l1_thread_get_exit_reason(thread *thr);
    int eka2l1_thread_current_state(thread *thr);
    int eka2l1_thread_priority(thread *thr);
    const char *eka2l1_thread_name(thread *thr);

    const char *eka2l1_server_name(server *svr);

    session *eka2l1_session_from_handle(uint32_t handle);
    server *eka2l1_session_server(session *ss);
    
    ipc_msg *eka2l1_ipc_message_from_handle(int guest_handle);
    int eka2l1_ipc_message_function(ipc_msg *msg);
    uint32_t eka2l1_ipc_message_arg(ipc_msg *msg, const int idx);
    uint32_t eka2l1_ipc_message_flags(ipc_msg *msg);
    thread *eka2l1_ipc_message_sender(ipc_msg *msg);
    session *eka2l1_ipc_message_session_wrapper(ipc_msg *msg);
    uint32_t eka2l1_ipc_message_request_status_address(ipc_msg *msg);
]])

--- Thread is created but not yet to run.
kernel.THREAD_STATE_CREATED = 0

--- Thread is running.
kernel.THREAD_STATE_RUN = 1

--- Thread is currently blocked and is waiting for a sync object.
--- Currently unused.
kernel.THREAD_STATE_WAIT = 2

--- Thread is in the ready queue, waiting to be run.
kernel.THREAD_STATE_READY = 3

--- Thread is currently waiting for a fast semaphore.
kernel.THREAD_STATE_WAIT_FAST_SEMA = 4

--- Thread is currently waiting for a mutex.
kernel.THREAD_STATE_WAIT_MUTEX = 5

--- Thread is currently waiting for a mutex and is also suspended.
kernel.THREAD_STATE_WAIT_MUTEX_SUSPEND = 6

--- Thread is currently waiting for a fast semaphore and is also suspended.
kernel.THREAD_STATE_WAIT_FAST_SEMA_SUSPEND = 7

--- Thread is currently in queue to own the mutex object.
kernel.THREAD_STATE_HOLD_MUTEX_PENDING = 8

kernel.PRIORITY_NULL = -30
kernel.PRIORITY_MUCH_LESS = -20
kernel.PRIORITY_LESS = -10
kernel.PRIORITY_NORMAL = 0
kernel.PRIORITY_MORE = 10
kernel.PRIORITY_MUCH_MORE = 20
kernel.PRIORITY_REAL_TIME = 30
kernel.PRIORITY_ABSOLUTE_VERY_LOW = 100
kernel.PRIORITY_ABSOLUTE_LOW = 200
kernel.PRIORITY_ABSOLUTE_BACKGROUND_NORMAL = 250
kernel.PRIORITY_ABSOLUTE_BACKGROUND = 300
kernel.PRIORITY_ABSOLUTE_FOREGROUND_NORMAL = 350
kernel.PRIORITY_ABSOLUTE_FOREGROUND = 400
kernel.PRIORITY_ABSOLUTE_HIGH = 500

kernel.INVALID_ADDRESS = 0xFFFFFFFF

handle = helper.class(function(self, impl)
    self.impl = impl
end)

-- Code segment object implementation
kernel.codeseg = helper.class(handle, function(self, impl)
    handle.init(self, impl)
    ffi.gc(self.impl, ffi.C.eka2l1_free_codeseg)
end)

--- Get the size of the segment's code section.
--- @return A 32-bit integer as the code size.
function kernel.codeseg:codeSize()
    return ffi.C.eka2l1_codeseg_code_size(self.impl)
end

--- Get the size of the segment's data section.
--- @return A 32-bit integer as the data size.
function kernel.codeseg:dataSize()
    return ffi.C.eka2l1_codeseg_data_size(self.impl)
end

--- Get the size of the segment's bss (initialised data) section.
--- @return A 32-bit integer as the bss size.
function kernel.codeseg:bssSize()
    return ffi.C.eka2l1_codeseg_bss_size(self.impl)
end

--- Get the export value of a code segment.
---
--- @param pr       The process to retrieve the export value from its address space. Nil to get raw value.
--- @param index    The target export ordinal.
---
--- @return The export address value.
function kernel.codeseg:getExport(pr, index)
    prImpl = nil
    if (pr ~= nil) then
        prImpl = pr.impl
    end
    return ffi.C.eka2l1_codeseg_get_export(self.impl, prImpl, index)
end

--- Get the entry point of a code segment.
---
--- @param pr   The process to retrieve the entry point from its address space. Nil to get raw value.
--- @return The entry point address value.
function kernel.codeseg:getEntryPoint(pr)
    prImpl = nil
    if (pr ~= nil) then
        prImpl = pr.impl
    end
    return ffi.C.eka2l1_codeseg_get_entry_point(self.impl, prImpl)
end

--- Get the number of export functions (addresses) this code segment provides.
--- @return A 32-bit integer containing the export count.
function kernel.codeseg:exportCount()
    return ffi.C.eka2l1_codeseg_export_count(self.impl)
end

--- Get the 32-bit xxHash of the code data. This can be used for differentiate actions between different version of an executable.
--- @return A 32-bit integer as the hash of the code data.
function kernel.codeseg:hash()
    return ffi.C.eka2l1_codeseg_get_hash(self.impl)
end

--- Set the address or offset relative to the codeseg's code section, to one of the codeseg's export.
---
--- Depends on if the codeseg is XIP or not (in ROM for example), the address will be absolute in the memory.
--- Bit 0 on in the address value means that the function the export is pointing to will be in THUMB mode.
--- To make the address absolute in non-XIP, consider setting the codeseg patched attribute to true.
---
--- @param index    The index of the export to set the address/offset. Must be greater than 1.
--- @param addr     The offset/address value. Refer to detail description.
function kernel.codeseg:setExport(index, addr)
    if (index < 1) then
        error("Wrong index argument passed to codeseg:setExport. Index value must be larger than 1!")
    end

    ffi.C.eka2l1_codeseg_set_export(self.impl, index, addr)
end

--- Set the address or offset relative to the codeseg's code section as the code segment's entry point.

--- Depends on if the codeseg is XIP or not (in ROM for example), the address will be absolute in the memory.
--- Bit 0 on in the address value means that the function the export is pointing to will be in THUMB mode.
--- To make the address absolute in non-XIP, consider setting the codeseg patched attribute to true.
---
--- @param addr The address/offset value to set the entry point as.
function kernel.codeseg:setEntryPoint(addr)
    ffi.C.eka2l1_codeseg_set_entry_point(self.impl, addr)
end

--- Set the code segment as patched.
---
--- Patched code segment will have its export table value and the entry point address understood as absolute, and will be the
--- same for all the processes.
function kernel.codeseg:setPatched()
    ffi.C.eka2l1_codeseg_set_patched(self.impl)
end

--- Disable the entry point of the code segment from being used.
---
--- By calling this function on a codeseg, its entry point will not be query to the static call list, which means
--- that there's no static data initialised for the DLL.
function kernel.codeseg:setEntryPointDisabled()
    ffi.C.eka2l1_codeseg_set_entry_point_disabled(self.impl)
end

--- Search for a function with specified index (ordinal) in the library and retrieve its address.
---
--- For each process, a library may have different code address. ROM libraries are exception to this.
---
--- @param process A `process` object, where the address of the function should be retrieved on.
--- @param ord The ordinal identify the library function to get.
---
--- @return 32-bit integer as address to the function in the process's memory space, 0 on failure. 
function kernel.codeseg:lookup(process, ord)
	return ffi.C.eka2l1_codeseg_lookup(self.impl, process.impl, ord)
end

--- Load a new code segment.
---
--- This code segment is not attached to any process during this function.
---
--- @param path The emulated system's path to the codeseg to load.
--- @return codeseg class if the codeseg loads successfully, else nil.
function kernel.loadCodeseg(path)
	local target = ffi.new("char[?]", #path + 1, path)

    local res = ffi.C.eka2l1_load_codeseg(path)
    if res == nil then
        return nil
	end

    return kernel.codeseg(res)
end

-- End code segment object implementation

-- Begin process object implementation
kernel.process = helper.class(handle, function(self, impl)
    handle.init(self, impl)
    ffi.gc(self.impl, ffi.C.eka2l1_free_process)
end)

--- Read the byte value *(8-bit)* at the specified address from this process's memory space.
--- @param addr The address to perform the read.
--- @return Byte value stored at the given address.
function kernel.process:readByte(addr)
    return ffi.C.eka2l1_process_read_byte(self.impl, addr)
end

--- Read the word value *(16-bit)* at the specified address from this process's memory space.
--- @param addr The address to perform the read.
--- @return Word value stored at the given address.
function kernel.process:readWord(addr)
    return ffi.C.eka2l1_process_read_word(self.impl, addr)
end

--- Read the dword value *(32-bit)* at the specified address from this process's memory space.
--- @param addr The address to perform the read.
--- @return Dword value stored at the given address.
function kernel.process:readDword(addr)
    return ffi.C.eka2l1_process_read_dword(self.impl, addr)
end

--- Read the qword value *(64-bit)* at the specified address from this process's memory space.
--- @param addr The address to perform the read.
--- @return Qword value stored at the given address.
function kernel.process:readQword(addr)
    return ffi.C.eka2l1_process_read_qword(self.impl, addr)
end

--- Get the name of the process.
--- @return A `string` contains the process's name.
function kernel.process:name()
    local res = ffi.C.eka2l1_process_name(self.impl)
    local ret = ffi.string(res)

    ffi.C.eka2l1_free_string(ffi.gc(res, nil))
    return ret
end

--- Get the path to the running process's executable.
---
--- This path is in the emulated's virtual file system.
--- @return A `string` contains the executable path.
function kernel.process:executablePath()
    local res = ffi.C.eka2l1_process_executable_path(self.impl)
    local ret = ffi.string(res)

    ffi.C.eka2l1_free_string(ffi.gc(res, nil))
    return ret
end

--- Read a certain amount of data from the process's memory.
---
--- @param addr The address to read data from.
--- @param size The number of bytes to read.
---
--- @return A byte array contains the read result.
function kernel.process:readMemory(addr, size)
    local res = ffi.C.eka2l1_process_read_memory(self.impl, addr, size)
    ffi.gc(res, ffi.C.eka2l1_free_string)

    return res
end

--- Write a byte array into the process's memory space.
---
--- This function will call `error` on falure.
---
--- @param addr The address to write the byte array to.
--- @param buffer Byte array to write to the memory.
function kernel.process:writeMemory(addr, buffer)
    local cbuf = ffi.new('char[?]', #buffer + 1, buffer)

    local res = ffi.C.eka2l1_process_write_memory(addr, cbuf, #buffer)
    if res == 0 then
        error('Fail to write memory, address is invalid!')
    end
end

--- Get the current running process on the current emulated core.
--- @return Current process with type `process`.
function kernel.getCurrentProcess()
    local primpl = ffi.C.eka2l1_get_current_process()
    return kernel.process(primpl)
end

-- Get all running processes in the kernel.
-- @return An array of `process` objects containing all processes in the kernel.
function kernel.getAllProcesses()
    local arr = ffi.new('process**[1]', nil)
    local count = ffi.C.eka2l1_queries_all_processes(arr)

    if count <= 0 then
        ffi.C.free(ffi.gc(arr, nil))
        return {}
    end

    local retarr = {}

    for i=1, count do
        retarr[i] = kernel.process(arr[0][i - 1])
    end
    
    ffi.C.free(ffi.gc(arr[0], nil))
    return retarr
end
-- End process object implementation

-- Begin thread object implementation
kernel.thread = helper.class(handle, function(self, impl)
    handle.init(self, impl)
    ffi.gc(self.impl, ffi.C.eka2l1_free_thread)
end)

--- Get the name of the thread.
--- @return A `string` contains the thread's name.
function kernel.thread:name()
    local cname = ffi.C.eka2l1_thread_name(self.impl)
    local namer = ffi.string(cname)

    ffi.C.eka2l1_free_string(ffi.gc(cname, nil))

    return namer
end

--- Get the stack base of the thread.
--- 
--- This is the beginning address of the stack memory chunk, also can
--- be called as the highest point of the stack.
---
--- @return A 32-bit integer address as the stack base value.
function kernel.thread:stackBase()
    return ffi.C.eka2l1_thread_stack_base(self.impl)
end

--- Get the heap base of the thread.
--- 
--- This is the beginning address of the heap memory chunk, which is created by the
--- code in the thread and not directly managed by the kernel.
---
--- @return A 32-bit integer address as the heap base value.
function kernel.thread:heapBase()
    return ffi.C.eka2l1_thread_get_heap_base(self.impl)
end

--- Retrieve the value in register from R0 to R15.
--- 
--- This is the saved value from the last time this thread ran. If this is the current
--- thread, the value will be the same as the one called from `cpu` module.
---
--- @param idx The index of the register to retrieve (0 - 15). Undefined behaviour will raise for index out of the given range.
---
--- @return The value of the target register as a 32-bit integer.
function kernel.thread:getRegister(idx)
    return ffi.C.eka2l1_thread_get_register(self.impl, idx)
end

--- Retrieve the value in the PC (program counter) register.
--- 
--- This is the saved value from the last time this thread ran. If this is the current
--- thread, the value will be the same as the one called from `cpu` module.
---
--- The PC register is identical to the R15 register (PC is a different name for R15).
---
--- @return The value of the PC as a 32-bit integer.
function kernel.thread:getPc()
    return ffi.C.eka2l1_thread_get_pc(self.impl, idx)
end

--- Retrieve the value in the PC (program counter) register.
--- 
--- This is the saved value from the last time this thread ran. If this is the current
--- thread, the value will be the same as the one called from `cpu` module.
---
--- The PC register is identical to the R15 register (PC is a different name for R15).
---
--- @return The value of the PC as a 32-bit integer.
function kernel.thread:getLr()
    return ffi.C.eka2l1_thread_get_lr(self.impl, idx)
end

--- Retrieve the value in the SP (stack pointer) register.
--- 
--- This is the saved value from the last time this thread ran. If this is the current
--- thread, the value will be the same as the one called from `cpu` module.
---
--- The SP register is identical to the R13 register (SP is a different name for R13).
---
--- @return The value of the SP as a 32-bit integer.
function kernel.thread:getSp()
    return ffi.C.eka2l1_thread_get_sp(self.impl, idx)
end

--- Retrieve the value in the CPSR register.
--- 
--- This is the saved value from the last time this thread ran. If this is the current
--- thread, the value will be the same as the one called from `cpu` module.
---
--- @return The value of the CPSR as a 32-bit integer.
function kernel.thread:getCpsr()
    return ffi.C.eka2l1_thread_get_cpsr(self.impl, idx)
end

--- Get the reason this thread exited.
---
--- The reason is a code, which will be 0 if the thread is still running.
---
--- @return 32-bit integer code indicating the exit reason.
function kernel.thread:exitReason()
    return ffi.C.eka2l1_thread_get_exit_reason(self.impl)
end

--- Get the current scheduling state of the thread.
--- @return One of the value in `THREAD_STATE_WAIT_` constant enums.
function kernel.thread:currentState()
    return ffi.C.eka2l1_thread_current_state(self.impl)
end

--- Get the scheduling priority of the thread in the process.
--- @return One of the value in `PRIORITY_` constant enums.
function kernel.thread:priority()
    return ffi.C.eka2l1_thread_priority(self.impl)
end

--- Get the thread next to the caller thread in the thread's owning process.
---
--- Use this to iterate all threads in the process.
--- @return `nil` if there's no more thread in the process, else the next thread as a `thread` object.
function kernel.thread:nextInProcess()
    local thrimpl = ffi.C.eka2l1_next_thread_in_process(self.impl)
    if thrimpl == nil then
        return nil
    end

    return kernel.thread(thrimpl)
end

--- Get the process that owns this thread.
---
--- @return The owning process as a `process` object.
function kernel.thread:ownProcess()
    local primpl = ffi.C.eka2l1_thread_own_process(self.impl)
    if primpl == nil then
        return nil
    end

    return kernel.process(primpl)
end

--- Get the first thread of the process.
---
--- From the first thread you can travel to the next thread by using the `kernel.thread:nextInProcess` function.
--- @return The first thread of the process as a `process` object.
--- @see kernel.thread:nextInProcess
function kernel.process:firstThread()
    local thrimpl = ffi.C.eka2l1_process_first_thread(self.impl)
    return kernel.thread(thrimpl)
end

--- Get the current running thread on the current emulated core.
--- @return Current thread with type `thread`.
function kernel.getCurrentThread()
    local thrimpl = ffi.C.eka2l1_get_current_thread()
    return kernel.thread(thrimpl)
end
    
-- End thread object implementation

-- Begin server object implementation
kernel.server = helper.class(handle, function(self, impl)
    handle.init(self, impl)
    ffi.gc(self.impl, ffi.C.eka2l1_free_server)
end)

--- Get the name of the server.
--- @return A `string` object containing the server's name.
function kernel.server:name()
    local namec = ffi.C.eka2l1_server_name(self.impl)
    local namer = ffi.string(namec)

    ffi.C.eka2l1_free_string(ffi.gc(namec, nil))

    return namer
end
-- End server object implementation

-- Begin session object implementation
kernel.session = helper.class(handle, function(self, impl)
    handle.init(self, impl)
    ffi.gc(self.impl, ffi.C.eka2l1_free_session)
end)

--- Get the server that this session is connected to.
---
--- The session will be responsible for sending messages/requests to the connected server.
--- @return The connected server object with type of `server`.
function kernel.session:server()
    local svimpl = ffi.C.eka2l1_session_server(self.impl)
    return kernel.server(svimpl)
end

--- Retrieve the session object from the kernel handle.
---
--- @param handle The kernel handle of the session.
--- @return The `session` object correspond to this kernel handle.
function kernel.sessionFromHandle(handle)
    local ssimpl = ffi.C.eka2l1_session_from_handle(handle)
    if ssimpl == nil then
        return nil
    end

    return kernel.session(ssimpl)
end
-- End session object implementation

-- Begin IPC message implementation
kernel.ipcMessage = helper.class(handle, function(self, impl)
    handle.init(self, impl)
    ffi.gc(self.impl, ffi.C.eka2l1_free_ipc_msg)
end)

--- Get the function/opcode of this message.
--- @return 32-bit integer containing the message's function code.
function kernel.ipcMessage:func()
    return ffi.C.eka2l1_ipc_message_function(self.impl)
end

--- Get the argument flags of this message.
---
--- This value is only relevant on IPCv2 model (appears usually on late S60v2 and further).
--- On EKA1 this value is 0xFFFFFFFF.
---
--- @return 32-bit integer containing the message's argument flags.
function kernel.ipcMessage:flags()
    return ffi.C.eka2l1_ipc_message_flags(self.impl)
end

--- Get the argument value of the message.
---
--- Each message stores 4 integer arguments that can be considered as pointer,
--- handle or pure integer.
---
--- @param idx The index of the argument to retrieve (0 - 3). Undefined behaviour if value passed is not in specified range.
--- @return The value of the argument.
function kernel.ipcMessage:arg(idx)
    return ffi.C.eka2l1_ipc_message_arg(self.impl, idx)
end

--- Get the thread sending the message.
--- @return The `thread` object that sends the message.
function kernel.ipcMessage:sender()
    local thrimpl = ffi.C.eka2l1_ipc_message_sender(self.impl)
    return kernel.thread(thrimpl)
end

--- Get the session responsible for establishing connection to the server and sending the message.
--- @return The `session` object that does the message submit.
function kernel.ipcMessage:session()
    local ssimpl = ffi.C.eka2l1_ipc_message_session_wrapper(self.impl)
    return kernel.session(ssimpl)
end

--- Get the request status address in the sender process's memory space.
---
--- It's recommended to use `std.requestStatus` class for exploring more about the condition
--- of the status.
---
--- @return Address to the request status as a 32-bit integer.
function kernel.ipcMessage:requestStatusAddress()
    return ffi.C.eka2l1_ipc_message_request_status_address(self.impl)
end
-- End IPC message implementation

return kernel