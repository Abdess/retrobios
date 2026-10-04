local common = require('eka2l1.common')
local kernel = require('eka2l1.kernel')
local math = require('math')

function replaceCodesegFromOther(source, dest)
    if ((source == nil) or (dest == nil)) then
        return
    end

    totalPatch = math.min(source:exportCount(), dest:exportCount())
    for i = 1, totalPatch, 1
    do
        dest:setExport(i, source:getExport(nil, i))
    end

    dest:setEntryPoint(source:getEntryPoint(nil))
    dest:setPatched()
end

function patchOpenVGAccelToSw()
    segSw = kernel.loadCodeseg('z:\\sys\\bin\\libopenvg_sw.dll')
    segHw = kernel.loadCodeseg('z:\\sys\\bin\\libopenvg.dll')

    segUSw = kernel.loadCodeseg('z:\\sys\\bin\\libopenvgu_sw.dll')
    segUHw = kernel.loadCodeseg('z:\\sys\\bin\\libopenvgu.dll')

    replaceCodesegFromOther(segSw, segHw)
    replaceCodesegFromOther(segUSw, segUHw)
end

function loadNeccessaryRomDLLs()
    -- Required by EComServer.exe. Some of these are already loaded on real phone on startup
    kernel.loadCodeseg('z:\\sys\\bin\\domaincli.dll')
end

if (common.getCurrentSymbianVersion() >= common.SYMBIAN_VERSION_EPOC95) then
    common.log('Applying S^3 and higher patch')

    loadNeccessaryRomDLLs()
    --patchOpenVGAccelToSw()
end
