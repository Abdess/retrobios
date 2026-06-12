#Requires AutoHotkey v2.0
#SingleInstance Force

; ==========================================
; Initialize & Parse Data Files
; ==========================================
EmulatorsList := []
SystemsList   := []

; Extract the first column from listofemus.txt
if FileExist("listofemus.txt") {
    Loop Read, "listofemus.txt" {
        line := Trim(A_LoopReadLine)
        if (line != "") {
            parts := StrSplit(line, [A_Space, A_Tab], " `t")
            if (parts.Length > 0)
                EmulatorsList.Push(parts[1])
        }
    }
} else {
    EmulatorsList.Push("Error: listofemus.txt missing")
}

; Extract the first column from listofsyst.txt
if FileExist("listofsyst.txt") {
    Loop Read, "listofsyst.txt" {
        line := Trim(A_LoopReadLine)
        if (line != "") {
            parts := StrSplit(line, [A_Space, A_Tab], " `t")
            if (parts.Length > 0)
                SystemsList.Push(parts[1])
        }
    }
} else {
    SystemsList.Push("Error: listofsyst.txt missing")
}

; ==========================================
; GUI Construction
; ==========================================
Main := Gui("-MaximizeBox +MinSize620x580", "RetroBIOS Environment Manager")
Main.SetFont("s10", "Segoe UI")

; Header Logo
if FileExist("banner.png") {
    Main.Add("Picture", "w580 h-1 Center", "banner.png")
} else {
    Main.Add("Text", "w580 Center cRed", "[ banner.png not found ]")
}

; --- Generate Pack Section ---
Main.Add("GroupBox", "xm y+10 w580 h150 Section", "Generate Pack Tools")

; Radios to toggle DDLs
RadEmu := Main.Add("Radio", "xs+20 ys+30 Checked vGenMode", "Select Emulator:")
RadSys := Main.Add("Radio", "xs+20 ys+70", "Select System:")
RadEmu.OnEvent("Click", ToggleDDLs)
RadSys.OnEvent("Click", ToggleDDLs)

; DropDownLists
DdlEmu := Main.Add("DropDownList", "xs+160 ys+25 w250 vSelectedEmu Choose1", EmulatorsList)
DdlSys := Main.Add("DropDownList", "xs+160 ys+65 w250 vSelectedSys Disabled Choose1", SystemsList)

; Output Path for Generation
Main.Add("Text", "xs+20 ys+113", "Output Directory:")
GenPathEdit := Main.Add("Edit", "xs+160 ys+110 w250 vGenOutputPath")
;SendMessage(0x1501, 1, StrPtr("Leave Blank For Default Location (dist\)"), GenPathEdit) 
BtnGenBrowse := Main.Add("Button", "xs+420 ys+109 w60", "Browse...")
BtnGenBrowse.OnEvent("Click", SelectGenOutputPath)

; Generate Execute Button
BtnGenerate := Main.Add("Button", "xs+490 ys+24 w80 h115", "Generate")
BtnGenerate.OnEvent("Click", RunGenerateCmd)

; --- Install Section ---
Main.Add("GroupBox", "xm w580 h80 Section", "Install Process")
Main.Add("Text", "xs+20 ys+33", "Install Path:")
InstallPathEdit := Main.Add("Edit", "xs+160 ys+30 w250 vInstallPath")
BtnInstallBrowse := Main.Add("Button", "xs+420 ys+29 w60", "Browse...")
BtnInstallBrowse.OnEvent("Click", SelectInstallPath)
BtnInstall := Main.Add("Button", "xs+490 ys+29 w80", "Run Install")
BtnInstall.OnEvent("Click", RunInstallCmd)

; --- Console Log Window ---
Main.Add("Text", "xm y+25", "Console Output:")
LogEdit := Main.Add("Edit", "xm w580 h240 ReadOnly Multi vConsoleLog +Wrap", "Waiting for command...`r`n")

Main.Show()

; ==========================================
; UI Logic & Callbacks
; ==========================================

ToggleDDLs(*) {
    if RadEmu.Value {
        DdlEmu.Enabled := true
        DdlSys.Enabled := false
    } else {
        DdlEmu.Enabled := false
        DdlSys.Enabled := true
    }
}

SelectGenOutputPath(*) {
    selectedFolder := DirSelect("", 3, "Select Destination for Generated Pack")
    if (selectedFolder != "") {
        GenPathEdit.Value := selectedFolder
    }
}

SelectInstallPath(*) {
    selectedFolder := DirSelect("", 3, "Select Target Installation Directory")
    if (selectedFolder != "") {
        InstallPathEdit.Value := selectedFolder
    }
}

RunGenerateCmd(*) {
    Main.Submit(false)
    
    if (GenPathEdit.Value = "") {
        MsgBox("Please specify an output directory for the generated pack.", "Missing Destination", "Icon!")
        return
    }

    if RadEmu.Value {
        if (DdlEmu.Text = "" || InStr(DdlEmu.Text, "Error:")) {
            MsgBox("Invalid Emulator Selection.", "Selection Error", "Icon!")
            return
        }
        
        ; Convert chosen emulator to lowercase for safe string comparison
        selectedEmuLower := Format("{:L}", DdlEmu.Text)
        
        ; Array of emulators that require the '--platform' syntax
        PlatformEmus := ["batocera", "bizhawk", "emudeck", "lakka", "recalbox", "retroarch", "retrobat", "retrodeck", "retropie", "romm"]
        
        ; Check if the selected emulator is in the platform override list
        isPlatform := false
        for emu in PlatformEmus {
            if (selectedEmuLower == emu) {
                isPlatform := true
                break
            }
        }
        
        ; Route to the correct flag syntax based on the check
        if isPlatform {
            cmd := "python.exe `"" A_ScriptDir "\scripts\generate_pack.py`" --platform " DdlEmu.Text " --output `"" GenPathEdit.Value "`""
        } else {
            cmd := "python.exe `"" A_ScriptDir "\scripts\generate_pack.py`" --emulator " DdlEmu.Text " --output `"" GenPathEdit.Value "`""
        }
        
    } else {
        if (DdlSys.Text = "" || InStr(DdlSys.Text, "Error:")) {
            MsgBox("Invalid System Selection.", "Selection Error", "Icon!")
            return
        }
        cmd := "python.exe `"" A_ScriptDir "\scripts\generate_pack.py`" --system " DdlSys.Text " --output `"" GenPathEdit.Value "`""
    }
    ExecuteProcess(cmd)
}

RunInstallCmd(*) {
    Main.Submit(false)
    
    if (InstallPathEdit.Value = "") {
        MsgBox("Please specify an installation path.", "Missing Parameter", "Icon!")
        return
    }
    
    ; Determine the target token based on active UI states to align with install.py arguments
    targetFlag := ""
    if RadEmu.Value {
        if (DdlEmu.Text != "" && !InStr(DdlEmu.Text, "Error:"))
            targetFlag := "--platform " DdlEmu.Text
    } else {
        if (DdlSys.Text != "" && !InStr(DdlSys.Text, "Error:"))
            targetFlag := "--platform " DdlSys.Text
    }

    cmd := "python.exe `"" A_ScriptDir "\install.py`" " targetFlag " --dest `"" InstallPathEdit.Value "`""
    ExecuteProcess(cmd)
}

; ======================================================
; Execution & Real-Time Output Streaming (Hidden Window)
; ======================================================
global activeProc := ""

ExecuteProcess(cmd) {
    BtnGenerate.Enabled := false
    BtnInstall.Enabled  := false
    
	LogEdit.Value .= "`r`n=================================`r"
	LogEdit.Value .= "`r`n>>> PROCCESING COMMAND(s) NOW...`r"
	LogEdit.Value .= "`r`n=================================`r`n"
    LogEdit.Value .= "> Executing: " cmd "`r`n"
    ScrollToBottom()

    try {
        global activeProc := HiddenProcess(A_ComSpec " /c " cmd)
        SetTimer(PollStdOut, 40)
    } catch Error as err {
        LogEdit.Value .= "[ERROR] Failed to start process: " err.Message "`r`n"
        UnlockUI()
    }
}

PollStdOut() {
    global activeProc
    if (activeProc != "") {
        out := activeProc.Read()
        if (out != "") {
            LogEdit.Value .= out
            ScrollToBottom()
        }
        
        if !activeProc.IsRunning() {
            SetTimer(PollStdOut, 0)
            
            ; Final sweep for residual stream data
            out := activeProc.Read()
            if (out != "") {
                LogEdit.Value .= out
                ScrollToBottom()
            }
            
			LogEdit.Value .= "`r`n===========================`r"
			LogEdit.Value .= "`r`n>>> PROCCESING FINNISHED!`r"
			LogEdit.Value .= "`r`n===========================`r`n"
            LogEdit.Value .= "`r`n> Process Completed!.`r`n"
            ScrollToBottom()
            activeProc.Close()
            activeProc := ""
            UnlockUI()
        }
    }
}

ScrollToBottom() {
    SendMessage(0x0115, 7, 0, LogEdit.Hwnd) ; WM_VSCROLL, SB_BOTTOM
}

UnlockUI() {
    BtnGenerate.Enabled := true
    BtnInstall.Enabled  := true
}

; ==========================================
; Native Win32 Hidden Process Pipe Wrapper
; ==========================================
class HiddenProcess {
    hRead := 0
    hWrite := 0
    hProcess := 0
    hThread := 0

    __New(cmdLine) {
        ; Setup security attributes for handle inheritance
        sa := Buffer(A_PtrSize == 8 ? 24 : 12, 0)
        NumPut("UInt", sa.Size, sa, 0)
        NumPut("Ptr", 0, sa, A_PtrSize)
        NumPut("Int", 1, sa, A_PtrSize == 8 ? 16 : 8) ; bInheritHandles = TRUE

        if !DllCall("CreatePipe", "Ptr*", &hReadOut:=0, "Ptr*", &hWriteOut:=0, "Ptr", sa, "UInt", 0)
            throw Error("Failed to initialize standard data pipelines.")
        
        ; Prevent the read handle from being inherited by target processes
        DllCall("SetHandleInformation", "Ptr", hReadOut, "UInt", 1, "UInt", 0)

        ; Configure Startup Structural Context
        siSize := A_PtrSize == 8 ? 104 : 68
        si := Buffer(siSize, 0)
        NumPut("UInt", siSize, si, 0)
        NumPut("UInt", 0x00000100 | 0x00000001, si, A_PtrSize == 8 ? 60 : 44) ; STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
        NumPut("UShort", 0, si, A_PtrSize == 8 ? 64 : 48)                     ; SW_HIDE
        NumPut("Ptr", hWriteOut, si, siSize - A_PtrSize)                      ; hStdError
        NumPut("Ptr", hWriteOut, si, siSize - (2 * A_PtrSize))                ; hStdOutput

        pi := Buffer(A_PtrSize == 8 ? 24 : 16, 0)
        
        ; CREATE_NO_WINDOW = 0x08000000
        if !DllCall("CreateProcess", "Ptr", 0, "Str", cmdLine, "Ptr", 0, "Ptr", 0, "Int", 1, "UInt", 0x08000000, "Ptr", 0, "Ptr", 0, "Ptr", si, "Ptr", pi) {
            DllCall("CloseHandle", "Ptr", hReadOut)
            DllCall("CloseHandle", "Ptr", hWriteOut)
            throw Error("Execution execution failed to instantiate.")
        }

        ; Close the write channel safely within the main process scope to allow clean EOF signs
        DllCall("CloseHandle", "Ptr", hWriteOut)

        this.hRead := hReadOut
        this.hProcess := NumGet(pi, 0, "Ptr")
        this.hThread := NumGet(pi, A_PtrSize, "Ptr")
    }

    Read() {
        if !this.hRead
            return ""
        
        DllCall("PeekNamedPipe", "Ptr", this.hRead, "Ptr", 0, "UInt", 0, "Ptr", 0, "UInt*", &avail:=0, "Ptr", 0)
        if (avail > 0) {
            buf := Buffer(avail + 1, 0)
            DllCall("ReadFile", "Ptr", this.hRead, "Ptr", buf, "UInt", avail, "UInt*", &read:=0, "Ptr", 0)
            return StrGet(buf, "CP0") ; Standard local OEM terminal code mapping
        }
        return ""
    }

    IsRunning() {
        if !this.hProcess
            return false
        DllCall("GetExitCodeProcess", "Ptr", this.hProcess, "UInt*", &exitCode:=0)
        return exitCode == 259 ; STILL_ACTIVE
    }

    Close() {
        if this.hRead
            DllCall("CloseHandle", "Ptr", this.hRead), this.hRead := 0
        if this.hProcess
            DllCall("CloseHandle", "Ptr", this.hProcess), this.hProcess := 0
        if this.hThread
            DllCall("CloseHandle", "Ptr", this.hThread), this.hThread := 0
    }
}