local options = {}
--;===========================================================
--; COMMON
--;===========================================================
options.modified = false
options.needReload = false

--return string depending on bool
function options.f_boolDisplay(bool, t, f)
	if bool == true then
		return t or motif.option_info.menu.valuename.yes
	end
	return f or motif.option_info.menu.valuename.no
end

--return table entry (or ret if specified) if provided key exists in the table, otherwise return default argument
function options.f_definedDisplay(key, t, default, ret)
	if key ~= nil and t[key] ~= nil then
		return ret or t[key]
	end
	return default
end

--return correct precision
function options.f_precision(v, decimal)
	return tonumber(string.format(decimal, v))
end

--- Save the current configuration to the config file and handle common file modifications
local t_commonFilesOriginal = gameOption('Common')
function options.f_saveCfg(reload)
	-- Restore the original content of the common files
	local t_commonFiles = gameOption('Common')
	for _, k in ipairs({'Air', 'Cmd', 'Const', 'States', 'Fx', 'Modules', 'Lua'}) do
		modifyGameOption('Common.' .. k, t_commonFilesOriginal[k][k:lower()] or {})
	end
	-- Save the current configuration to 'config.ini'
	saveGameOption(getCommandLineValue("-config"))
	hook.run("options.save", reload)
	-- Reload the game if the reload parameter is true
	if reload then
		main.f_warning(motif.warning_info.text.text.reload, motif.option_info, motif.optionbgdef)
		os.exit()
	end
	-- Reapply modified common file arrays after saving
	for _, k in ipairs({'Air', 'Cmd', 'Const', 'States', 'Fx', 'Modules', 'Lua'}) do
		modifyGameOption('Common.' .. k, t_commonFiles[k][k:lower()] or {})
	end
end

--;===========================================================
--; LOOPS
--;===========================================================
local function f_switchLanguage(dir)
	sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
	-- collect available language keys
	local codes = {}
	for code in pairs(motif.languages) do
		table.insert(codes, code)
	end
	-- current language
	local cur = gameOption('Config.Language')
	-- find current index (fallback to 1 if not found)
	local curIndex = 1
	for i, code in ipairs(codes) do
		if code == cur then
			curIndex = i
			break
		end
	end
	-- move index with wrap
	local newIndex = curIndex + dir
	if newIndex < 1 then
		newIndex = #codes
	elseif newIndex > #codes then
		newIndex = 1
	end
	-- apply
	local newCode = codes[newIndex]
	modifyGameOption('Config.Language', newCode)
	options.modified = true
	options.needReload = true
end

-- Associative elements table storing functions controlling behaviour of each
-- option screen item. Can be appended via external module.
options.t_itemname = {
	--Back
	['back'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cancel.snd[1], motif.option_info.cancel.snd[2])
			return false
		end
		return true
	end,
	--Default Values
	['default'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
			--modifyGameOption('Common.Air', {"data/common.air"})
			--modifyGameOption('Common.Cmd', {"data/common.cmd"})
			--modifyGameOption('Common.Const', {"data/common.const"})
			--modifyGameOption('Common.States', {"data/action.zss", "data/dizzy.zss", "data/guardbreak.zss", "data/score.zss", "data/system.zss", "data/tag.zss", "data/training.zss"})
			--modifyGameOption('Common.Fx', {})
			--modifyGameOption('Common.Modules', {})
			--modifyGameOption('Common.Lua', {"loop()"})
			modifyGameOption('Options.Difficulty', 5)
			modifyGameOption('Options.Life', 100)
			modifyGameOption('Options.Time', 99)
			modifyGameOption('Options.GameSpeed', 0)
			--modifyGameOption('Options.GameSpeedStep', 5)
			modifyGameOption('Options.Match.Wins', 2)
			modifyGameOption('Options.Match.MaxDrawGames', 1)
			modifyGameOption('Options.Credits', 10)
			modifyGameOption('Options.QuickContinue', false)
			modifyGameOption('Options.AutoGuard', false)
			modifyGameOption('Options.GuardBreak', false)
			modifyGameOption('Options.Dizzy', false)
			modifyGameOption('Options.RedLife', true)
			modifyGameOption('Options.Team.Duplicates', true)
			modifyGameOption('Options.Team.LifeShare', false)
			modifyGameOption('Options.Team.PowerShare', true)
			modifyGameOption('Options.Team.SingleVsTeamLife', 100)
			modifyGameOption('Options.Simul.Min', 2)
			modifyGameOption('Options.Simul.Max', 4)
			modifyGameOption('Options.Simul.Match.Wins', 2)
			modifyGameOption('Options.Simul.LoseOnKO', true)
			modifyGameOption('Options.Tag.Min', 2)
			modifyGameOption('Options.Tag.Max', 4)
			modifyGameOption('Options.Tag.Match.Wins', 2)
			modifyGameOption('Options.Tag.LoseOnKO', false)	
			modifyGameOption('Options.Tag.TimeScaling', 1)
			modifyGameOption('Options.Turns.Min', 2)
			modifyGameOption('Options.Turns.Max', 4)
			modifyGameOption('Options.Turns.Recovery.Base', 12.5)
			modifyGameOption('Options.Turns.Recovery.Bonus', 27.5)
			--modifyGameOption('Config.Motif', "data/system.def")
			modifyGameOption('Config.Players', 4)
			modifyGameOption('Config.Language', "en")
			--modifyGameOption('Config.AfterImageMax', 128)
			--modifyGameOption('Config.ExplodMax', 512)
			--modifyGameOption('Config.HelperMax', 56)
			--modifyGameOption('Config.ProjectileMax', 256)
			--modifyGameOption('Config.PaletteMax', 100)
			--modifyGameOption('Config.TextMax', 128)
			--modifyGameOption('Config.TickInterpolation', true)
			--modifyGameOption('Config.ZoomActive', true)
			--modifyGameOption('Config.EscOpensMenu', true)
			modifyGameOption('Config.VsScreenLoading', false)
			modifyGameOption('Config.TurnsLoading', false)
			--modifyGameOption('Config.BootLoadingMode', 0)
			--modifyGameOption('Config.FirstRun', false)
			--modifyGameOption('Config.WindowTitle', "Ikemen GO")
			--modifyGameOption('Config.WindowIcon', {"external/icons/IkemenCylia_256.png", "external/icons/IkemenCylia_96.png", "external/icons/IkemenCylia_48.png"})
			--modifyGameOption('Config.System', "external/script/main.lua")
			--modifyGameOption('Config.ScreenshotFolder', "")
			--modifyGameOption('Config.TrainingChar', "")
			--modifyGameOption('Config.TrainingStage', "")
			modifyGameOption('Config.GamepadMappings', "external/gamecontrollerdb.txt")
			--modifyGameOption('Config.LegacyTime', 0)
			modifyGameOption('Debug.AllowDebugMode', true)
			modifyGameOption('Debug.AllowDebugKeys', true)
			--modifyGameOption('Debug.ClipboardRows', 2)
			--modifyGameOption('Debug.ConsoleRows', 15)
			--modifyGameOption('Debug.ClsnDarken', true)
			--modifyGameOption('Debug.DumpLuaTables', false)
			--modifyGameOption('Debug.Font', "font/debug.def")
			--modifyGameOption('Debug.FontScale', 1.0)
			--modifyGameOption('Debug.StartStage', "stages/stage0-720.def")
			--modifyGameOption('Debug.ForceStageZoomout', 0)
			--modifyGameOption('Debug.ForceStageZoomin', 0)
			--modifyGameOption('Debug.KeepSpritesOnReload', 0)
			--modifyGameOption('Debug.MacOSUseCommandKey', 0)
			--modifyGameOption('Debug.SpeedTest', 100)
			-- This is platform dependent now
			local runtimeOS = getRuntimeOS()
			if runtimeOS == 'android' then
				modifyGameOption('Video.RenderMode', 'OpenGL ES 3.2')
			elseif runtimeOS == 'ios' then
				modifyGameOption('Video.RenderMode', 'Vulkan 1.3')
			else
				modifyGameOption('Video.RenderMode', "OpenGL 3.3")
			end
			modifyGameOption('Video.GameWidth', 1280)
			modifyGameOption('Video.GameHeight', 720)
			--modifyGameOption('Video.WindowWidth', 0)
			--modifyGameOption('Video.WindowHeight', 0)
			modifyGameOption('Video.Fullscreen', false)
			--modifyGameOption('Video.Borderless', false)
			--modifyGameOption('Video.RGBSpriteBilinearFilter', true)
			--modifyGameOption('Video.Framerate', 60)
			modifyGameOption('Video.VSync', 1)
			modifyGameOption('Video.MSAA', 0)
			--modifyGameOption('Video.WindowCentered', true)
			modifyGameOption('Video.ExternalShaders', {})
			modifyGameOption('Video.WindowScaleMode', true)
			modifyGameOption('Video.FightAspectWidth', -1)
			modifyGameOption('Video.FightAspectHeight', -1)
			modifyGameOption('Video.KeepAspect', true)
			modifyGameOption('Video.EnableModel', true)
			modifyGameOption('Video.EnableModelShadow', true)
			--modifyGameOption('Sound.SampleRate', 44100)
			--modifyGameOption('Sound.SoundFont', "sound/soundfont.sf2")
			modifyGameOption('Sound.StereoEffects', true)
			modifyGameOption('Sound.PanningRange', 30)
			--modifyGameOption('Sound.WavChannels', 32)
			modifyGameOption('Sound.MasterVolume', 80)
			--modifyGameOption('Sound.PauseMasterVolume', 100)
			modifyGameOption('Sound.WavVolume', 80)
			modifyGameOption('Sound.BGMVolume', 80)
			--modifyGameOption('Sound.MaxBGMVolume', 100)
			modifyGameOption('Sound.AudioDucking', false)	
			--modifyGameOption('Sound.BGMRAMBuffer', true)	
			--modifyGameOption('Sound.AudioResampleQuality', 4)	
			modifyGameOption('Arcade.AI.RandomColor', false)
			modifyGameOption('Arcade.AI.SurvivalColor', true)
			modifyGameOption('Arcade.AI.Ramping', true)
			modifyGameOption('Netplay.RollbackNetcode', true)
			modifyGameOption('Netplay.ListenPort', 7500)
			modifyGameOption('Netplay.Rollback.Port', 7500)
			modifyGameOption('Netplay.Rollback.FrameDelay', 2)
			--modifyGameOption('Netplay.Rollback.DisconnectNotifyStart', 1000)
			--modifyGameOption('Netplay.Rollback.DisconnectTimeout', 3000)
			--modifyGameOption('Netplay.Rollback.StateLogsEnabled', false)
			--modifyGameOption('Netplay.Rollback.GgpoLogsEnabled', false)
			--modifyGameOption('Netplay.Rollback.SaveStageData', false)
			--modifyGameOption('Netplay.Rollback.DesyncTest', false)
			--modifyGameOption('Netplay.Rollback.DesyncTestFrames', false)
			--modifyGameOption('Netplay.Rollback.DesyncTestAI', false)
			--modifyGameOption('Netplay.IP.<>', "")
			--modifyGameOption('Input.ButtonAssist', true)
			--modifyGameOption('Input.SOCDResolution', 4)
			--modifyGameOption('Input.ControllerStickSensitivity', 0.4)
			--modifyGameOption('Input.XinputTriggerSensitivity', 0.5)
			--modifyGameOption('Input.UiRepeatDelay', 30)
			--modifyGameOption('Input.UiRepeatRate', 4)
			--modifyGameOption('Input.PauseExitDelay', 10)

			loadFightScreen(motif.files.fight)
			setPlayers()
			for _, v in ipairs(options.t_vardisplayPointers) do
				v.vardisplay = options.f_vardisplay(v.itemname)
			end
			toggleFullscreen(gameOption('Video.Fullscreen'))
			toggleVSync(gameOption('Video.VSync'))
			updateVolume()
			options.modified = true
			options.needReload = true
			hook.run("options.default")
		end
		return true
	end,
	--Difficulty Level
	['difficulty'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Difficulty') < 8 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Difficulty', gameOption('Options.Difficulty') + 1)
			t.items[item].vardisplay = options.t_vardisplay['difficulty']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Difficulty') > 1 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Difficulty', gameOption('Options.Difficulty') - 1)
			t.items[item].vardisplay = options.t_vardisplay['difficulty']()
			options.modified = true
		end
		return true
	end,
	--Time Limit
	['roundtime'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Time') < 1000 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Time', gameOption('Options.Time') + 1)
			t.items[item].vardisplay = options.t_vardisplay['roundtime']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Time') > -1 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Time', gameOption('Options.Time') - 1)
			t.items[item].vardisplay = options.t_vardisplay['roundtime']()
			options.modified = true
		end
		return true
	end,
	--Language Setting
	['language'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and (main.f_tableLength(motif.languages) > 1 or motif.languages[gameOption('Config.Language')] == nil) then
			f_switchLanguage(1)
			t.items[item].vardisplay = options.t_vardisplay['language']()
		elseif getInput(-1, motif.option_info.menu.subtract.key) and (main.f_tableLength(motif.languages) > 1 or motif.languages[gameOption('Config.Language')] == nil) then
			f_switchLanguage(-1)
			t.items[item].vardisplay = options.t_vardisplay['language']()
		end
		return true
	end,
	--Life
	['lifemul'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Life') < 300 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Life', gameOption('Options.Life') + 10)
			t.items[item].vardisplay = options.t_vardisplay['lifemul']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Life') > 10 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Life', gameOption('Options.Life') - 10)
			t.items[item].vardisplay = options.t_vardisplay['lifemul']()
			options.modified = true
		end
		return true
	end,
	--Single VS Team Life
	['singlevsteamlife'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Team.SingleVsTeamLife') < 300 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Team.SingleVsTeamLife', gameOption('Options.Team.SingleVsTeamLife') + 10)
			t.items[item].vardisplay = options.t_vardisplay['singlevsteamlife']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Team.SingleVsTeamLife') > 10 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Team.SingleVsTeamLife', gameOption('Options.Team.SingleVsTeamLife') - 10)
			t.items[item].vardisplay = options.t_vardisplay['singlevsteamlife']()
			options.modified = true
		end
		return true
	end,
	-- Game Speed
	['gamespeed'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.GameSpeed') < 9 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.GameSpeed', gameOption('Options.GameSpeed') + 1)
			t.items[item].vardisplay = options.t_vardisplay['gamespeed']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.GameSpeed') > -9 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.GameSpeed', gameOption('Options.GameSpeed') - 1)
			t.items[item].vardisplay = options.t_vardisplay['gamespeed']()
			options.modified = true
		end
		return true
	end,
	--Rounds to Win (Single)
	['roundsnumsingle'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Match.Wins') < 10 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Match.Wins', gameOption('Options.Match.Wins') + 1)
			t.items[item].vardisplay = options.t_vardisplay['roundsnumsingle']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Match.Wins') > 1 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Match.Wins', gameOption('Options.Match.Wins') - 1)
			t.items[item].vardisplay = options.t_vardisplay['roundsnumsingle']()
			options.modified = true
		end
		return true
	end,
	--Max Draw Games
	['maxdrawgames'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Match.MaxDrawGames') < 10 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Match.MaxDrawGames', gameOption('Options.Match.MaxDrawGames') + 1)
			t.items[item].vardisplay = options.t_vardisplay['maxdrawgames']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Match.MaxDrawGames') > 0 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Match.MaxDrawGames', gameOption('Options.Match.MaxDrawGames') - 1)
			t.items[item].vardisplay = options.t_vardisplay['maxdrawgames']()
			options.modified = true
		end
		return true
	end,
	--Credits
	['credits'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Credits') < 99 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Credits', gameOption('Options.Credits') + 1)
			t.items[item].vardisplay = options.t_vardisplay['credits']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Credits') > 0 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Credits', gameOption('Options.Credits') - 1)
			t.items[item].vardisplay = options.t_vardisplay['credits']()
			options.modified = true
		end
		return true
	end,
	--Arcade Palette
	['aipalette'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Arcade.AI.RandomColor') then
				modifyGameOption('Arcade.AI.RandomColor', false)
			else
				modifyGameOption('Arcade.AI.RandomColor', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['aipalette']()
			options.modified = true
		end
		return true
	end,
	--Survival Palette
	['aisurvivalpalette'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Arcade.AI.SurvivalColor') then
				modifyGameOption('Arcade.AI.SurvivalColor', false)
			else
				modifyGameOption('Arcade.AI.SurvivalColor', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['aisurvivalpalette']()
			options.modified = true
		end
		return true
	end,
	--AI Ramping
	['airamping'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Arcade.AI.Ramping') then
				modifyGameOption('Arcade.AI.Ramping', false)
			else
				modifyGameOption('Arcade.AI.Ramping', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['airamping']()
			options.modified = true
		end
		return true
	end,
	--Quick Continue
	['quickcontinue'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Options.QuickContinue') then
				modifyGameOption('Options.QuickContinue', false)
			else
				modifyGameOption('Options.QuickContinue', true)
				end
			t.items[item].vardisplay = options.t_vardisplay['quickcontinue']()
			options.modified = true
		end
		return true
	end,
	--Auto-Guard
	['autoguard'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Options.AutoGuard') then
				modifyGameOption('Options.AutoGuard', false)
			else
				modifyGameOption('Options.AutoGuard', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['autoguard']()
			options.modified = true
		end
		return true
	end,
	--Dizzy
	['dizzy'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Options.Dizzy') then
				modifyGameOption('Options.Dizzy', false)
			else
				modifyGameOption('Options.Dizzy', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['dizzy']()
			options.modified = true
		end
		return true
	end,
	--Guard Break
	['guardbreak'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Options.GuardBreak') then
				modifyGameOption('Options.GuardBreak', false)
			else
				modifyGameOption('Options.GuardBreak', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['guardbreak']()
			options.modified = true
		end
		return true
	end,
	--Red Life
	['redlife'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Options.RedLife') then
				modifyGameOption('Options.RedLife', false)
			else
				modifyGameOption('Options.RedLife', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['redlife']()
			options.modified = true
		end
		return true
	end,
	--Team Duplicates
	['teamduplicates'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Options.Team.Duplicates') then
				modifyGameOption('Options.Team.Duplicates', false)
			else
				modifyGameOption('Options.Team.Duplicates', true)
				end
			t.items[item].vardisplay = options.t_vardisplay['teamduplicates']()
			options.modified = true
		end
		return true
	end,
	--Team Life Share
	['teamlifeshare'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Options.Team.LifeShare') then
				modifyGameOption('Options.Team.LifeShare', false)
			else
				modifyGameOption('Options.Team.LifeShare', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['teamlifeshare']()
			options.modified = true
		end
		return true
	end,
	--Team Power Share
	['teampowershare'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Options.Team.PowerShare') then
				modifyGameOption('Options.Team.PowerShare', false)
			else
				modifyGameOption('Options.Team.PowerShare', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['teampowershare']()
			options.modified = true
		end
		return true
	end,
	--Rounds to Win (Tag)
	['roundsnumtag'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Tag.Match.Wins') < 10 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Tag.Match.Wins', gameOption('Options.Tag.Match.Wins') + 1)
			t.items[item].vardisplay = options.t_vardisplay['roundsnumtag']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Tag.Match.Wins') > 1 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Tag.Match.Wins', gameOption('Options.Tag.Match.Wins') - 1)
			t.items[item].vardisplay = options.t_vardisplay['roundsnumtag']()
			options.modified = true
		end
		return true
	end,
	--Partner KOed Lose
	['losekotag'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Options.Tag.LoseOnKO') then
				modifyGameOption('Options.Tag.LoseOnKO', false)
			else
				modifyGameOption('Options.Tag.LoseOnKO', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['losekotag']()
			options.modified = true
		end
		return true
	end,
	--Min Tag Chars
	['mintag'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Tag.Min') < gameOption('Options.Tag.Max') then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Tag.Min', gameOption('Options.Tag.Min') + 1)
			t.items[item].vardisplay = options.t_vardisplay['mintag']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Tag.Min') > 2 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Tag.Min', gameOption('Options.Tag.Min') - 1)
			t.items[item].vardisplay = options.t_vardisplay['mintag']()
			options.modified = true
		end
		return true
	end,
	--Max Tag Chars
	['maxtag'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Tag.Max') < 4 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Tag.Max', gameOption('Options.Tag.Max') + 1)
			t.items[item].vardisplay = options.t_vardisplay['maxtag']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Tag.Max') > gameOption('Options.Tag.Min') then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Tag.Max', gameOption('Options.Tag.Max') - 1)
			t.items[item].vardisplay = options.t_vardisplay['maxtag']()
			options.modified = true
		end
		return true
	end,
	--Rounds to Win (Simul)
	['roundsnumsimul'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Simul.Match.Wins') < 10 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Simul.Match.Wins', gameOption('Options.Simul.Match.Wins') + 1)
			t.items[item].vardisplay = options.t_vardisplay['roundsnumsimul']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Simul.Match.Wins') > 1 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Simul.Match.Wins', gameOption('Options.Simul.Match.Wins') - 1)
			t.items[item].vardisplay = options.t_vardisplay['roundsnumsimul']()
			options.modified = true
		end
		return true
	end,
	--Simul Player KOed Lose
	['losekosimul'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Options.Simul.LoseOnKO') then
				modifyGameOption('Options.Simul.LoseOnKO', false)
			else
				modifyGameOption('Options.Simul.LoseOnKO', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['losekosimul']()
			options.modified = true
		end
		return true
	end,
	--Min Simul Chars
	['minsimul'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Simul.Min') < gameOption('Options.Simul.Max') then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Simul.Min', gameOption('Options.Simul.Min') + 1)
			t.items[item].vardisplay = options.t_vardisplay['minsimul']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Simul.Min') > 2 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Simul.Min', gameOption('Options.Simul.Min') - 1)
			t.items[item].vardisplay = options.t_vardisplay['minsimul']()
			options.modified = true
		end
		return true
	end,
	--Max Simul Chars
	['maxsimul'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Simul.Max') < 4 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Simul.Max', gameOption('Options.Simul.Max') + 1)
			t.items[item].vardisplay = options.t_vardisplay['maxsimul']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Simul.Max') > gameOption('Options.Simul.Min') then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Simul.Max', gameOption('Options.Simul.Max') - 1)
			t.items[item].vardisplay = options.t_vardisplay['maxsimul']()
			options.modified = true
		end
		return true
	end,
	--Turns Recovery Base
	['turnsrecoverybase'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Turns.Recovery.Base') < 100 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Turns.Recovery.Base', gameOption('Options.Turns.Recovery.Base') + 0.5)
			t.items[item].vardisplay = options.t_vardisplay['turnsrecoverybase']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Turns.Recovery.Base') > 0 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Turns.Recovery.Base', gameOption('Options.Turns.Recovery.Base') - 0.5)
			t.items[item].vardisplay = options.t_vardisplay['turnsrecoverybase']()
			options.modified = true
		end
		return true
	end,
	--Turns Recovery Bonus
	['turnsrecoverybonus'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Turns.Recovery.Bonus') < 100 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Turns.Recovery.Bonus', gameOption('Options.Turns.Recovery.Bonus') + 0.5)
			t.items[item].vardisplay = options.t_vardisplay['turnsrecoverybonus']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Turns.Recovery.Bonus') > 0 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Turns.Recovery.Bonus', gameOption('Options.Turns.Recovery.Bonus') - 0.5)
			t.items[item].vardisplay = options.t_vardisplay['turnsrecoverybonus']()
			options.modified = true
		end
		return true
	end,
	--Min Turns Chars
	['minturns'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Turns.Min') < gameOption('Options.Turns.Max') then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Turns.Min', gameOption('Options.Turns.Min') + 1)
			t.items[item].vardisplay = options.t_vardisplay['minturns']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Turns.Min') > 1 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Turns.Min', gameOption('Options.Turns.Min') - 1)
			t.items[item].vardisplay = options.t_vardisplay['minturns']()
			options.modified = true
		end
		return true
	end,
	--Max Turns Chars
	['maxturns'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Options.Turns.Max') < 8 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Turns.Max', gameOption('Options.Turns.Max') + 1)
			t.items[item].vardisplay = options.t_vardisplay['maxturns']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Options.Turns.Max') > gameOption('Options.Turns.Min') then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Options.Turns.Max', gameOption('Options.Turns.Max') - 1)
			t.items[item].vardisplay = options.t_vardisplay['maxturns']()
			options.modified = true
		end
		return true
	end,
	--Renderer (submenu)
	['renderer'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			for k, v in ipairs(t.submenu[t.items[item].itemname].items) do
				if gameOption('Video.RenderMode') == v.itemname then
					v.selected = true
				else
					v.selected = false
				end
			end
			t.submenu[t.items[item].itemname].loop()
			t.items[item].vardisplay = options.t_vardisplay['renderer']()
			options.modified = true
			options.needReload = true
		end
		return true
	end,
	--gles32
	['gles32'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Video.RenderMode', "OpenGL ES 3.2")
			options.modified = true
			options.needReload = true
			return false
		end
		return true
	end,
	--gl33
	['gl33'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Video.RenderMode', "OpenGL 3.3")
			options.modified = true
			options.needReload = true
			return false
		end
		return true
	end,
	--vk13
	['vk13'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Video.RenderMode', "Vulkan 1.3")
			options.modified = true
			options.needReload = true
			return false
		end
		return true
	end,
	--Resolution (submenu)
	['resolution'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			local t_pos = {}
			local ok = false
			for k, v in ipairs(t.submenu[t.items[item].itemname].items) do
				local width, height = v.itemname:match('^([0-9]+)x([0-9]+)$')
				if tonumber(width) == gameOption('Video.GameWidth') and tonumber(height) == gameOption('Video.GameHeight') then
					v.selected = true
					ok = true
				else
					v.selected = false
				end
				if v.itemname == 'customres' then
					t_pos = v
				end
			end
			if not ok and t_pos.selected ~= nil then
				t_pos.selected = true
			end
			t.submenu[t.items[item].itemname].loop()
			t.items[item].vardisplay = options.t_vardisplay['resolution']()
		end
		return true
	end,
	--Custom resolution
	['customres'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			local reswidth = tonumber(main.f_drawInput(
				motif.option_info.textinput.TextSpriteData,
				motif.option_info.textinput.text.reswidth,
				motif.option_info,
				motif.optionbgdef,
				motif.option_info.textinput.overlay.RectData
			))
			if reswidth ~= nil then
				sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
				local resheight = tonumber(main.f_drawInput(
					motif.option_info.textinput.TextSpriteData,
					motif.option_info.textinput.text.resheight,
					motif.option_info,
					motif.optionbgdef,
					motif.option_info.textinput.overlay.RectData
				))
				if resheight ~= nil then
					modifyGameOption('Video.GameWidth', reswidth)
					modifyGameOption('Video.GameHeight', resheight)
					sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
					options.modified = true
					options.needReload = true
				else
					sndPlay(motif.Snd, motif.option_info.cancel.snd[1], motif.option_info.cancel.snd[2])
				end
			else
				sndPlay(motif.Snd, motif.option_info.cancel.snd[1], motif.option_info.cancel.snd[2])
			end
			return false
		end
		return true
	end,
	--Fullscreen
	['fullscreen'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Video.Fullscreen') then
				modifyGameOption('Video.Fullscreen', false)
			else
				modifyGameOption('Video.Fullscreen', true)
			end
			toggleFullscreen(gameOption('Video.Fullscreen'))
			t.items[item].vardisplay = options.t_vardisplay['fullscreen']()
			options.modified = true
		end
		return true
	end,
	--VSync
	['vsync'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Video.VSync') == 1 then
				modifyGameOption('Video.VSync', 0)
			else
				modifyGameOption('Video.VSync', 1)
			end
			toggleVSync(gameOption('Video.VSync'))
			t.items[item].vardisplay = options.t_vardisplay['vsync']()
			options.modified = true
		end
		return true
	end,
	--MSAA
	['msaa'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Video.MSAA') < 32 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Video.MSAA') == 0 then
				modifyGameOption('Video.MSAA', 2)
			else
				modifyGameOption('Video.MSAA', gameOption('Video.MSAA') * 2)
			end
			t.items[item].vardisplay = options.t_vardisplay['msaa']()
			options.modified = true
			options.needReload = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Video.MSAA') > 1 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Video.MSAA') == 2 then
				modifyGameOption('Video.MSAA', 0)
			else
				modifyGameOption('Video.MSAA', gameOption('Video.MSAA') / 2)
			end
			t.items[item].vardisplay = options.t_vardisplay['msaa']()
			options.modified = true
			options.needReload = true
		end
		return true
	end,
	--Window scaling mode
	['windowscalemode'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Video.WindowScaleMode') then
				modifyGameOption('Video.WindowScaleMode', false)
			else
				modifyGameOption('Video.WindowScaleMode', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['windowscalemode']()
			options.modified = true
		end
		return true
	end,
	-- Match Aspect Ratio (submenu)
	['aspectratio'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			local t_pos = {}
			local ok = false
			local currentWidth = gameOption('Video.FightAspectWidth')
			local currentHeight = gameOption('Video.FightAspectHeight')
			for k, v in ipairs(t.submenu[t.items[item].itemname].items) do
				if v.itemname == 'defaultaspect' and currentWidth == 0 and currentHeight == 0 then
					v.selected = true
					ok = true
				elseif v.itemname == 'stageaspect' and currentWidth == -1 and currentHeight == -1 then
					v.selected = true
					ok = true
				else
					local width, height = v.itemname:match('^([0-9]+)x([0-9]+)$')
					if width and height and tonumber(width) == currentWidth and tonumber(height) == currentHeight then
						v.selected = true
						ok = true
					else
						v.selected = false
					end
				end
				if v.itemname == 'customaspect' then
					t_pos = v
				end
			end
			if not ok and t_pos.selected ~= nil then
				t_pos.selected = true
			end
			t.submenu[t.items[item].itemname].loop()
			t.items[item].vardisplay = options.t_vardisplay['aspectratio']()
		end
		return true
	end,
	--Custom aspect ratio
	['customaspect'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			local aspectwidth = tonumber(main.f_drawInput(
				motif.option_info.textinput.TextSpriteData,
				motif.option_info.textinput.text.aspectwidth,
				motif.option_info,
				motif.optionbgdef,
				motif.option_info.textinput.overlay.RectData
			))
			if aspectwidth ~= nil and aspectwidth > 0 then
				sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
				local aspectheight = tonumber(main.f_drawInput(
					motif.option_info.textinput.TextSpriteData,
					motif.option_info.textinput.text.aspectheight,
					motif.option_info,
					motif.optionbgdef,
					motif.option_info.textinput.overlay.RectData
				))
				if aspectheight ~= nil and aspectheight > 0 then
					modifyGameOption('Video.FightAspectWidth', aspectwidth)
					modifyGameOption('Video.FightAspectHeight', aspectheight)
					sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
					options.modified = true
					options.needReload = true
				else
					sndPlay(motif.Snd, motif.option_info.cancel.snd[1], motif.option_info.cancel.snd[2])
				end
			else
				sndPlay(motif.Snd, motif.option_info.cancel.snd[1], motif.option_info.cancel.snd[2])
			end
			return false
		end
		return true
	end,
	--Keep Aspect Ratio
	['keepaspect'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Video.KeepAspect') then
				modifyGameOption('Video.KeepAspect', false)
			else
				modifyGameOption('Video.KeepAspect', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['keepaspect']()
			options.modified = true
		end
		return true
	end,
	--Shaders (submenu)
	['shaders'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if #options.t_shaders == 0 then
				main.f_warning(motif.warning_info.text.text.shaders, motif.option_info, motif.optionbgdef)
				return true
			end
			t.submenu[t.items[item].itemname].loop()
			t.items[item].vardisplay = options.t_vardisplay['shaders']()
			options.modified = true
			options.needReload = true
		end
		return true
	end,
	--Disable (shader)
	['noshader'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cancel.snd[1], motif.option_info.cancel.snd[2])
			modifyGameOption('Video.ExternalShaders', {})
			options.modified = true
			options.needReload = true
			return false
		end
		return true
	end,
	--Enable Model
	['enablemodel'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Video.EnableModel') then
				modifyGameOption('Video.EnableModel', false)
			else
				modifyGameOption('Video.EnableModel', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['enablemodel']()
			options.modified = true
			options.needReload = true
		end
		return true
	end,
	--Enable Model Shadow
	['enablemodelshadow'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Video.EnableModelShadow') then
				modifyGameOption('Video.EnableModelShadow', false)
			else
				modifyGameOption('Video.EnableModelShadow', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['enablemodelshadow']()
			options.modified = true
			options.needReload = true
		end
		return true
	end,
	--Master Volume
	['mastervolume'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Sound.MasterVolume') < 200 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Sound.MasterVolume', gameOption('Sound.MasterVolume') + 1)
			t.items[item].vardisplay = options.t_vardisplay['mastervolume']()
			options.modified = true
			updateVolume()
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Sound.MasterVolume') > 0 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Sound.MasterVolume', gameOption('Sound.MasterVolume') - 1)
			t.items[item].vardisplay = options.t_vardisplay['mastervolume']()
			options.modified = true
			updateVolume()
		end
		return true
	end,
	--BGM Volume
	['bgmvolume'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Sound.BGMVolume') < 100 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Sound.BGMVolume', gameOption('Sound.BGMVolume') + 1)
			t.items[item].vardisplay = options.t_vardisplay['bgmvolume']()
			options.modified = true
			updateVolume()
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Sound.BGMVolume') > 0 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Sound.BGMVolume', gameOption('Sound.BGMVolume') - 1)
			t.items[item].vardisplay = options.t_vardisplay['bgmvolume']()
			options.modified = true
			updateVolume()
		end
		return true
	end,
	--SFX Volume
	['sfxvolume'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Sound.WavVolume') < 100 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Sound.WavVolume', gameOption('Sound.WavVolume') + 1)
			t.items[item].vardisplay = options.t_vardisplay['sfxvolume']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Sound.WavVolume') > 0 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Sound.WavVolume', gameOption('Sound.WavVolume') - 1)
			t.items[item].vardisplay = options.t_vardisplay['sfxvolume']()
			options.modified = true
		end
		return true
	end,
	--Audio Ducking
	['audioducking'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Sound.AudioDucking') then
				modifyGameOption('Sound.AudioDucking', false)
			else
				modifyGameOption('Sound.AudioDucking', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['audioducking']()
			options.modified = true
		end
		return true
	end,
	--Stereo Effects
	['stereoeffects'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Sound.StereoEffects') then
				modifyGameOption('Sound.StereoEffects', false)
			else
				modifyGameOption('Sound.StereoEffects', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['stereoeffects']()
			options.modified = true
		end
		return true
	end,
	--Panning Range
	['panningrange'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Sound.PanningRange') < 100 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Sound.PanningRange', gameOption('Sound.PanningRange') + 1)
			t.items[item].vardisplay = options.t_vardisplay['panningrange']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Sound.PanningRange') > 0 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Sound.PanningRange', gameOption('Sound.PanningRange') - 1)
			t.items[item].vardisplay = options.t_vardisplay['panningrange']()
			options.modified = true
		end
		return true
	end,
	--Key Config
	['keyboard'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
			options.f_keyCfgInit('Keys', t.submenu[t.items[item].itemname].title)
			while true do
				if not options.f_keyCfg('Keys', t.items[item].itemname, motif.optionbgdef, false) then
					break
				end
			end
		end
		return true
	end,
	--Joystick Config
	['gamepad'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
			if getCommandLineValue("-nojoy") == nil then
				options.f_keyCfgInit('Joystick', t.submenu[t.items[item].itemname].title)
				while true do
					if not options.f_keyCfg('Joystick', t.items[item].itemname, motif.optionbgdef, false) then
						break
					end
				end
			end
		end
		return true
	end,
	--Default
	['inputdefault'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
			options.f_keyDefault()
			options.f_setKeyConfig('Keys')
			if getCommandLineValue("-nojoy") == nil then
				options.f_setKeyConfig('Joystick')
			end
			options.modified = true
		end
		return true
	end,
	--Players
	['players'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Config.Players') < 8 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Config.Players', math.min(8, gameOption('Config.Players') + 2))
			t.items[item].vardisplay = options.t_vardisplay['players']()
			setPlayers()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Config.Players') > 2 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Config.Players', math.max(2, gameOption('Config.Players') - 2))
			t.items[item].vardisplay = options.t_vardisplay['players']()
			setPlayers()
			options.modified = true
		end
		return true
	end,
	--Debug Keys
	['debugkeys'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Debug.AllowDebugKeys') then
				modifyGameOption('Debug.AllowDebugKeys', false)
			else
				modifyGameOption('Debug.AllowDebugKeys', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['debugkeys']()
			options.modified = true
		end
		return true
	end,
	--Debug Mode
	['debugmode'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Debug.AllowDebugMode') then
				modifyGameOption('Debug.AllowDebugMode', false)
			else
				modifyGameOption('Debug.AllowDebugMode', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['debugmode']()
			options.modified = true
		end
		return true
	end,
	--Background Loading
	['vsscreenloading'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Config.VsScreenLoading') then
				modifyGameOption('Config.VsScreenLoading', false)
			else
				modifyGameOption('Config.VsScreenLoading', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['vsscreenloading']()
			options.modified = true
		end
		return true
	end,
	--Turns Preloading
	['turnsloading'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Config.TurnsLoading') then
				modifyGameOption('Config.TurnsLoading', false)
			else
				modifyGameOption('Config.TurnsLoading', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['turnsloading']()
			options.modified = true
		end
		return true
	end,
	--Rollback Netcode
	['netcode'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key, motif.option_info.menu.subtract.key, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			if gameOption('Netplay.RollbackNetcode') then
				modifyGameOption('Netplay.RollbackNetcode', false)
			else
				modifyGameOption('Netplay.RollbackNetcode', true)
			end
			t.items[item].vardisplay = options.t_vardisplay['netcode']()
			options.modified = true
		end
		return true
	end,
	--Host Port (TCP)
	['portchange'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			local port = tonumber(main.f_drawInput(
				motif.option_info.textinput.TextSpriteData,
				motif.option_info.textinput.text.port,
				motif.option_info,
				motif.optionbgdef,
				motif.option_info.textinput.overlay.RectData
			))
			if port ~= nil and port == math.floor(port) and port >= 1 and port <= 65535 then
				sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
				modifyGameOption('Netplay.ListenPort', port)
				t.items[item].vardisplay = options.t_vardisplay['portchange']()
				options.modified = true
			else
				sndPlay(motif.Snd, motif.option_info.cancel.snd[1], motif.option_info.cancel.snd[2])
			end
		end
		return true
	end,
	--Rollback Port (UDP)
	['rollbackport'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			local port = tonumber(main.f_drawInput(
				motif.option_info.textinput.TextSpriteData,
				motif.option_info.textinput.text.port,
				motif.option_info,
				motif.optionbgdef,
				motif.option_info.textinput.overlay.RectData
			))
			if port ~= nil and port == math.floor(port) and port >= 1 and port <= 65535 then
				sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
				modifyGameOption('Netplay.Rollback.Port', port)
				t.items[item].vardisplay = options.t_vardisplay['rollbackport']()
				options.modified = true
			else
				sndPlay(motif.Snd, motif.option_info.cancel.snd[1], motif.option_info.cancel.snd[2])
			end
		end
		return true
	end,
	--Rollback Frame Delay
	['framedelay'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.add.key) and gameOption('Netplay.Rollback.FrameDelay') < 10 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Netplay.Rollback.FrameDelay', gameOption('Netplay.Rollback.FrameDelay') + 1)
			t.items[item].vardisplay = options.t_vardisplay['framedelay']()
			options.modified = true
		elseif getInput(-1, motif.option_info.menu.subtract.key) and gameOption('Netplay.Rollback.FrameDelay') > 0 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			modifyGameOption('Netplay.Rollback.FrameDelay', gameOption('Netplay.Rollback.FrameDelay') - 1)
			t.items[item].vardisplay = options.t_vardisplay['framedelay']()
			options.modified = true
		end
		return true
	end,
	--Save and Return
	['savereturn'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
			if options.modified then
				options.f_saveCfg(options.needReload)
			end
			fadeOutInit(motif.option_info.fadeout.FadeData)
			main.close = true
			--return false
		end
		return true
	end,
	--Return Without Saving
	['return'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cancel.snd[1], motif.option_info.cancel.snd[2])
			if options.needReload then
				main.f_warning(motif.warning_info.text.text.noreload, motif.option_info, motif.optionbgdef)
			end
			fadeOutInit(motif.option_info.fadeout.FadeData)
			main.close = true
			--return false
		end
		return true
	end,
	--Save Settings
	['savesettings'] = function(t, item, cursorPosY, moveTxt)
		if getInput(-1, motif.option_info.menu.done.key) then
			sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
			if options.modified then
				options.f_saveCfg(options.needReload)
			end
		end
		return true
	end,
}

-- Shared menu loop logic
function options.f_createMenu(tbl, bool_main)
	return function()
		hook.run("options.menu.loop")
		local cursorPosY = 1
		local moveTxt = 0
		local item = 1
		local t = tbl.items
		main.f_menuSnap(motif.option_info)
		main.f_menuItemBgAnimReset(motif.option_info)
		if bool_main then
			bgReset(motif.optionbgdef.BGDef)
			fadeInInit(motif.option_info.fadein.FadeData)
			playBgm({source = "motif.option"})
			main.close = false
		end
		while true do
			if tbl.reset then
				tbl.reset = false
			else
				main.f_menuCommonDraw(t, item, cursorPosY, moveTxt, motif.option_info, motif.optionbgdef, false)
			end
			-- While fading, ignore normal option-menu inputs, but still allow ESC / menu-cancel to skip the fade.
			if fadeActive() then
				if esc() or getInput(-1, motif.option_info.menu.cancel.key) then
					fadeSkip()
				end
			else
				cursorPosY, moveTxt, item = main.f_menuCommonCalc(t, item, cursorPosY, moveTxt, motif.option_info, motif.option_info.cursor)
				textImgReset(motif.option_info.title.TextSpriteData)
				textImgSetText(motif.option_info.title.TextSpriteData, tbl.title)
				if main.close then
					bgReset(motif[main.background].BGDef)
					fadeInInit(motif[main.group].fadein.FadeData)
					playBgm({source = "motif.title", interrupt = true})
					main.close = false
					break
				elseif esc() or getInput(-1, motif.option_info.menu.cancel.key) then
					sndPlay(motif.Snd, motif.option_info.cancel.snd[1], motif.option_info.cancel.snd[2])
					if bool_main then
						if options.modified then
							--options.f_saveCfg(options.needReload)
						end
						if options.needReload then
							main.f_warning(motif.warning_info.text.text.noreload, motif.option_info, motif.optionbgdef)
						end
						fadeOutInit(motif.option_info.fadeout.FadeData)
						main.close = true
					else
						break
					end
				elseif options.t_itemname[t[item].itemname] ~= nil then
					if not options.t_itemname[t[item].itemname](tbl, item, cursorPosY, moveTxt) then
						break
					end
				elseif getInput(-1, motif.option_info.menu.done.key) then
					local f = t[item].itemname
					if tbl.submenu[f].loop ~= nil then
						sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
						tbl.submenu[f].loop()
						main.f_menuSnap(motif.option_info)
						main.f_menuItemBgAnimReset(motif.option_info)
					elseif not options.t_itemname[f](tbl, item, cursorPosY, moveTxt) then
						break
					end
				end
			end
		end
	end
end

options.t_vardisplayPointers = {}

local function findItemnameBySuffix(sfx)
	for _, k in ipairs(motif.option_info.menu.itemname_order) do
		if k:match(sfx) then
			return motif.option_info.menu.itemname[k]
		end
	end
	return ''
end

-- Associative elements table storing functions returning current setting values
-- rendered alongside menu item name. Can be appended via external module.
options.t_vardisplay = {
	['aipalette'] = function()
		return options.f_boolDisplay(gameOption('Arcade.AI.RandomColor'), motif.option_info.menu.valuename.random, motif.option_info.menu.valuename.default)
	end,
	['aisurvivalpalette'] = function()
		return options.f_boolDisplay(gameOption('Arcade.AI.SurvivalColor'), motif.option_info.menu.valuename.random, motif.option_info.menu.valuename.default)
	end,
	['airamping'] = function()
		return options.f_boolDisplay(gameOption('Arcade.AI.Ramping'))
	end,
	['aspectratio'] = function()
		local width = gameOption('Video.FightAspectWidth')
		local height = gameOption('Video.FightAspectHeight')
		if width > 0 and height > 0 then
			return width .. ':' .. height
		elseif width < 0 and height < 0 then
			return findItemnameBySuffix('stageaspect$')
		else
			return findItemnameBySuffix('defaultaspect$')
		end
	end,
	['audioducking'] = function()
		return options.f_boolDisplay(gameOption('Sound.AudioDucking'), motif.option_info.menu.valuename.enabled, motif.option_info.menu.valuename.disabled)
	end,
	['autoguard'] = function()
		return options.f_boolDisplay(gameOption('Options.AutoGuard'))
	end,
	['vsscreenloading'] = function()
		return options.f_boolDisplay(gameOption('Config.VsScreenLoading'), motif.option_info.menu.valuename.enabled, motif.option_info.menu.valuename.disabled)
	end,
	['turnsloading'] = function()
		return options.f_boolDisplay(gameOption('Config.TurnsLoading'), motif.option_info.menu.valuename.enabled, motif.option_info.menu.valuename.disabled)
	end,
	['bgmvolume'] = function()
		return gameOption('Sound.BGMVolume') .. '%'
	end,
	['credits'] = function()
		return options.f_definedDisplay(gameOption('Options.Credits'), {[0] = motif.option_info.menu.valuename.disabled}, gameOption('Options.Credits'))
	end,
	['debugkeys'] = function()
		return options.f_boolDisplay(gameOption('Debug.AllowDebugKeys'), motif.option_info.menu.valuename.enabled, motif.option_info.menu.valuename.disabled)
	end,
	['debugmode'] = function()
		return options.f_boolDisplay(gameOption('Debug.AllowDebugMode'), motif.option_info.menu.valuename.enabled, motif.option_info.menu.valuename.disabled)
	end,
	['difficulty'] = function()
		return gameOption('Options.Difficulty')
	end,
	['enablemodel'] = function()
		return options.f_definedDisplay(gameOption('Video.EnableModel'), {[true] = motif.option_info.menu.valuename.enabled}, motif.option_info.menu.valuename.disabled)
	end,
	['enablemodelshadow'] = function()
		return options.f_definedDisplay(gameOption('Video.EnableModelShadow'), {[true] = motif.option_info.menu.valuename.enabled}, motif.option_info.menu.valuename.disabled)
	end,
	['fullscreen'] = function()
		return options.f_boolDisplay(gameOption('Video.Fullscreen'))
	end,
	['gamespeed'] = function()
		return options.f_boolDisplay(gameOption('Options.GameSpeed') == 0, motif.option_info.menu.valuename.normal, options.f_boolDisplay(gameOption('Options.GameSpeed') < 0, string.format(motif.option_info.menu.valuename.slow, 0 - gameOption('Options.GameSpeed')), string.format(motif.option_info.menu.valuename.fast, gameOption('Options.GameSpeed'))))
	end,
	['guardbreak'] = function()
		return options.f_boolDisplay(gameOption('Options.GuardBreak'))
	end,
	['keepaspect'] = function()
		return options.f_boolDisplay(gameOption('Video.KeepAspect'), motif.option_info.menu.valuename.enabled, motif.option_info.menu.valuename.disabled)
	end,
	['language'] = function()
		sfs = motif.languages[gameOption('Config.Language')]
		return sfs or gameOption('Config.Language')
	end,
	['lifemul'] = function()
		return gameOption('Options.Life') .. '%'
	end,
	['losekosimul'] = function()
		return options.f_boolDisplay(gameOption('Options.Simul.LoseOnKO'))
	end,
	['losekotag'] = function()
		return options.f_boolDisplay(gameOption('Options.Tag.LoseOnKO'))
	end,
	['mastervolume'] = function()
		return gameOption('Sound.MasterVolume') .. '%'
	end,
	['maxdrawgames'] = function()
		return gameOption('Options.Match.MaxDrawGames')
	end,
	['maxsimul'] = function()
		return gameOption('Options.Simul.Max')
	end,
	['maxtag'] = function()
		return gameOption('Options.Tag.Max')
	end,
	['maxturns'] = function()
		return gameOption('Options.Turns.Max')
	end,
	['minsimul'] = function()
		return gameOption('Options.Simul.Min')
	end,
	['mintag'] = function()
		return gameOption('Options.Tag.Min')
	end,
	['minturns'] = function()
		return gameOption('Options.Turns.Min')
	end,
	['msaa'] = function()
		return options.f_definedDisplay(gameOption('Video.MSAA'), {[0] = motif.option_info.menu.valuename.disabled}, gameOption('Video.MSAA') .. 'x')
	end,
	['panningrange'] = function()
		return gameOption('Sound.PanningRange') .. '%'
	end,
	['players'] = function()
		return gameOption('Config.Players')
	end,
	['portchange'] = function()
		return gameOption('Netplay.ListenPort')
	end,
	['quickcontinue'] = function()
		return options.f_boolDisplay(gameOption('Options.QuickContinue'))
	end,
	['redlife'] = function()
		return options.f_boolDisplay(gameOption('Options.RedLife'))
	end,
	['renderer'] = function()
		return gameOption('Video.RenderMode')
	end,
	['resolution'] = function()
		return gameOption('Video.GameWidth') .. 'x' .. gameOption('Video.GameHeight')
	end,
	['rollbackport'] = function()
		return gameOption('Netplay.Rollback.Port')
	end,
	['roundsnumsimul'] = function()
		return gameOption('Options.Simul.Match.Wins')
	end,
	['roundsnumsingle'] = function()
		return gameOption('Options.Match.Wins')
	end,
	['roundsnumtag'] = function()
		return gameOption('Options.Tag.Match.Wins')
	end,
	['roundtime'] = function()
		return options.f_definedDisplay(gameOption('Options.Time'), {[-1] = motif.option_info.menu.valuename.none}, gameOption('Options.Time'))
	end,
	['rumble'] = function(player)
		return options.f_boolDisplay(gameOption('Joystick_P' .. player .. '.RumbleOn'))
	end,
	['sfxvolume'] = function()
		return gameOption('Sound.WavVolume') .. '%'
	end,
	['shaders'] = function()
		return options.f_boolDisplay(#gameOption('Video.ExternalShaders') > 0, motif.option_info.menu.valuename.enabled, motif.option_info.menu.valuename.disabled)
	end,
	['singlevsteamlife'] = function()
		return gameOption('Options.Team.SingleVsTeamLife') .. '%'
	end,
	['stereoeffects'] = function()
		return options.f_boolDisplay(gameOption('Sound.StereoEffects'), motif.option_info.menu.valuename.enabled, motif.option_info.menu.valuename.disabled)
	end,
	['dizzy'] = function()
		return options.f_boolDisplay(gameOption('Options.Dizzy'))
	end,
	['teamduplicates'] = function()
		return options.f_boolDisplay(gameOption('Options.Team.Duplicates'))
	end,
	['teamlifeshare'] = function()
		return options.f_boolDisplay(gameOption('Options.Team.LifeShare'))
	end,
	['teampowershare'] = function()
		return options.f_boolDisplay(gameOption('Options.Team.PowerShare'))
	end,
	['turnsrecoverybase'] = function()
		return gameOption('Options.Turns.Recovery.Base') .. '%'
	end,
	['turnsrecoverybonus'] = function()
		return gameOption('Options.Turns.Recovery.Bonus') .. '%'
	end,
	['vsync'] = function()
		return options.f_definedDisplay(gameOption('Video.VSync'), {[1] = motif.option_info.menu.valuename.enabled}, motif.option_info.menu.valuename.disabled)
	end,
	['windowscalemode'] = function()
		return options.f_boolDisplay(gameOption('Video.WindowScaleMode'), motif.option_info.menu.valuename.bilinear, motif.option_info.menu.valuename.nearest)
	end,
	['netcode'] = function()
		return options.f_boolDisplay(gameOption('Netplay.RollbackNetcode'), motif.option_info.menu.valuename.rollbacknetcode, motif.option_info.menu.valuename.delaynetcode)
	end,
	['framedelay'] = function()
		return gameOption('Netplay.Rollback.FrameDelay')
	end,
}

-- Returns setting value rendered alongside menu item name (calls appropriate
-- function from t_vardisplay table)
function options.f_vardisplay(itemname, player)
	if options.t_vardisplay[itemname] ~= nil then
		if itemname == 'rumble' then
			return options.t_vardisplay[itemname](player)
		end
		return options.t_vardisplay[itemname]()
	end
	return ''
end

-- Dynamically generates all menus and submenus
function options.f_start()
	-- external shaders
	options.t_shaders = {}
	for _, v in ipairs(getDirectoryFiles('external/shaders')) do
		v:gsub('^(.-)([^\\/]+)%.([^%.\\/]-)$', function(path, filename, ext)
			path = path:gsub('\\', '/')
			ext = ext:lower()
			if ext == 'frag' then
				table.insert(options.t_shaders, {path = path, filename = filename})
			end
			if ext:match('vert') or ext:match('frag') --[[or ext:match('shader')]] then
				options.t_itemname[path .. filename] = function(t, item, cursorPosY, moveTxt)
					if getInput(-1, motif.option_info.menu.done.key) then
						sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
						local t_externalShaders = gameOption('Video.ExternalShaders')
						for k, v in ipairs(t.items) do
							if v.itemname == path .. filename then
								v.selected = not v.selected
								if v.selected then
									table.insert(t_externalShaders, v.itemname)
								else
									for k2, v2 in ipairs(t_externalShaders) do
										if v2 == v.itemname then
											table.remove(t_externalShaders, k2)
											v.vardisplay = options.f_boolDisplay(v.selected, tostring(k2), '')
											break
										end
									end
								end
							end
						end
						-- Need to correct ALL indices
						for k, v in ipairs(t.items) do
							for k2, v2 in ipairs(t_externalShaders) do
								if v2 == v.itemname then
									v.vardisplay = options.f_boolDisplay(v.selected, tostring(k2), '')
								end
							end
						end
						modifyGameOption('Video.ExternalShaders', t_externalShaders)
						return true
					end
					return true
				end
			end
		end)
	end
	for _, v in ipairs(motif.option_info.menu.itemname_order) do
		-- resolution
		if v:match('_resolution_[0-9]+x[0-9]+$') then
			local width, height = v:match('_resolution_([0-9]+)x([0-9]+)$')
			options.t_itemname[width .. 'x' .. height] = function(t, item, cursorPosY, moveTxt)
				if getInput(-1, motif.option_info.menu.done.key) then
					sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
					modifyGameOption('Video.GameWidth', tonumber(width))
					modifyGameOption('Video.GameHeight', tonumber(height))
					options.modified = true
					options.needReload = true
					return false
				end
				return true
			end
		-- aspect ratio
		elseif v:match('_aspectratio_') then
			-- aspect ratio default
			if v:match('_aspectratio_defaultaspect$') then
				options.t_itemname['defaultaspect'] = function(t, item, cursorPosY, moveTxt)
					if getInput(-1, motif.option_info.menu.done.key) then
						sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
						modifyGameOption('Video.FightAspectWidth', 0)
						modifyGameOption('Video.FightAspectHeight', 0)
						options.modified = true
						return false
					end
					return true
				end
			-- aspect ratio stage
			elseif v:match('_aspectratio_stageaspect$') then
				options.t_itemname['stageaspect'] = function(t, item, cursorPosY, moveTxt)
					if getInput(-1, motif.option_info.menu.done.key) then
						sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
						modifyGameOption('Video.FightAspectWidth', -1)
						modifyGameOption('Video.FightAspectHeight', -1)
						options.modified = true
						return false
					end
					return true
				end
			-- aspect ratio presets (4x3, 16x9, etc.)
			elseif v:match('_aspectratio_[0-9]+x[0-9]+$') then
				local width, height = v:match('_aspectratio_([0-9]+)x([0-9]+)$')
				options.t_itemname[width .. 'x' .. height] = function(t, item, cursorPosY, moveTxt)
					if getInput(-1, motif.option_info.menu.done.key) then
						sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
						modifyGameOption('Video.FightAspectWidth', tonumber(width))
						modifyGameOption('Video.FightAspectHeight', tonumber(height))
						options.modified = true
						return false
					end
					return true
				end
			end
		end
	end
	if gameOption('Debug.DumpLuaTables') then main.f_printTable(options.t_itemname, 'debug/t_optionsItemname.txt') end
	-- create menu
	options.menu = {title = main.f_itemnameUpper(motif.option_info.title.text, motif.option_info.menu.title.uppercase), submenu = {}, items = {}}
	options.menu.loop = options.f_createMenu(options.menu, true)
	local w = main.f_menuWindow(motif.option_info.menu)
	local t_pos = {} --for storing current options.menu table position
	local lastNum = 0
	for i, suffix in ipairs(motif.option_info.menu.itemname_order) do
		for j, c in ipairs(main.f_strsplit('_', suffix)) do --split using "_" delimiter
			--populate shaders submenu
			if suffix:match('_shaders_back$') and c == 'back' then
				for k = #options.t_shaders, 1, -1 do
					local itemname = options.t_shaders[k].path .. options.t_shaders[k].filename
					local idx = 0
					-- Has the shader been enabled?
					local isSelected = false
					for i, v in ipairs(gameOption('Video.ExternalShaders')) do
						if itemname == v then
							isSelected = true
							idx = i
							break
						end
					end
					table.insert(t_pos.items, 1, {
						itemname = itemname,
						displayname = options.t_shaders[k].filename,
						paramname = suffix:gsub('back$', itemname),
						vardisplay = options.f_boolDisplay(idx > 0, tostring(idx), ''),
						selected = isSelected,
					})
					table.insert(options.t_vardisplayPointers, t_pos.items[#t_pos.items])
				end
			end
			--appending the menu table
			if j == 1 then --first string after menu.itemname (either reserved one or custom submenu assignment)
				if options.menu.submenu[c] == nil or c:match("^spacer%d*$") then
					options.menu.submenu[c] = {title = main.f_itemnameUpper(motif.option_info.menu.itemname[suffix], motif.option_info.menu.title.uppercase), submenu = {}, items = {}}
					options.menu.submenu[c].loop = options.f_createMenu(options.menu.submenu[c], false)
					if not suffix:match(c .. '_') then
						table.insert(options.menu.items, {
							itemname = c,
							displayname = motif.option_info.menu.itemname[suffix],
							paramname = suffix,
							vardisplay = c == 'rumble' and options.f_vardisplay(c, i) or options.f_vardisplay(c),
							selected = false,
						})
						table.insert(options.t_vardisplayPointers, options.menu.items[#options.menu.items])
					end
				end
				t_pos = options.menu.submenu[c]
				t_pos.name = c
			else --following strings
				if t_pos.submenu[c] == nil or c:match("^spacer%d*$") then
					t_pos.submenu[c] = {title = main.f_itemnameUpper(motif.option_info.menu.itemname[suffix], motif.option_info.menu.title.uppercase), submenu = {}, items = {}}
					t_pos.submenu[c].loop = options.f_createMenu(t_pos.submenu[c], false)
					table.insert(t_pos.items, {
						itemname = c,
						displayname = motif.option_info.menu.itemname[suffix],
						paramname = suffix,
						vardisplay = options.f_vardisplay(c),
						selected = false,
					})
					table.insert(options.t_vardisplayPointers, t_pos.items[#t_pos.items])
				end
				if j > lastNum then
					t_pos = t_pos.submenu[c]
					t_pos.name = c
				end
			end
			lastNum = j
		end
	end
	-- Runtime platform filtering
	local runtimeOS = getRuntimeOS()
	local excluded = {gles32 = true}
	if runtimeOS == 'android' then
		excluded = {keyboard = true, gl33 = true}
	elseif runtimeOS == 'ios' then
		excluded = {keyboard = true, gl33 = true, gles32 = true}
	end
	main.f_pruneMenu(options.menu, excluded)
	main.f_prunePointers(options.t_vardisplayPointers, excluded)
	-- Menu windows
	textImgSetWindow(motif.option_info.menu.item.selected.active.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif.option_info.menu.item.active.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif.option_info.menu.item.value.active.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif.option_info.menu.item.selected.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif.option_info.menu.item.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif.option_info.menu.item.value.TextSpriteData, w[1], w[2], w[3], w[4])
	for _, v in pairs(motif.option_info.menu.item.bg) do
		animSetWindow(v.AnimData, w[1], w[2], w[3], w[4])
	end
	for _, v in pairs(motif.option_info.menu.item.active.bg) do
		animSetWindow(v.AnimData, w[1], w[2], w[3], w[4])
	end
	-- Keymenu windows
	-- The first entry in t_keyCfg is a "spacer" row. We want that row to sit *above* the visible clipping area.
	-- To do that we keep the same window height, but slide the window down by one row of keymenu item spacing.
	-- Only the Y offset matters here (X uses full screen width).
	local keyWinOffsetY = motif.option_info.keymenu.p1.menuoffset[2] + motif.option_info.keymenu.item.spacing[2]
	local kw = main.f_menuWindow(motif.option_info.keymenu, {0, keyWinOffsetY})
	-- keep the window shifted down, but crop one row at the bottom
	kw[4] = kw[4] - motif.option_info.keymenu.item.spacing[2]
	-- base / selected label text
	textImgSetWindow(motif.option_info.keymenu.item.TextSpriteData, kw[1], kw[2], kw[3], kw[4])
	textImgSetWindow(motif.option_info.keymenu.item.selected.TextSpriteData, kw[1], kw[2], kw[3], kw[4])
	-- value text (normal / active / conflict)
	textImgSetWindow(motif.option_info.keymenu.item.value.TextSpriteData, kw[1], kw[2], kw[3], kw[4])
	textImgSetWindow(motif.option_info.keymenu.item.value.active.TextSpriteData, kw[1], kw[2], kw[3], kw[4])
	textImgSetWindow(motif.option_info.keymenu.item.value.conflict.TextSpriteData, kw[1], kw[2], kw[3], kw[4])
	textImgSetWindow(motif.option_info.keymenu.item.info.TextSpriteData, kw[1], kw[2], kw[3], kw[4])
	textImgSetWindow(motif.option_info.keymenu.item.info.active.TextSpriteData, kw[1], kw[2], kw[3], kw[4])
	-- selected / active label variants
	textImgSetWindow(motif.option_info.keymenu.item.selected.active.TextSpriteData, kw[1], kw[2], kw[3], kw[4])
	textImgSetWindow(motif.option_info.keymenu.item.active.TextSpriteData, kw[1], kw[2], kw[3], kw[4])
	-- item backgrounds share the same clipping window
	for _, v in pairs(motif.option_info.keymenu.item.bg) do
		animSetWindow(v.AnimData, kw[1], kw[2], kw[3], kw[4])
	end
	for _, v in pairs(motif.option_info.keymenu.item.active.bg) do
		animSetWindow(v.AnimData, kw[1], kw[2], kw[3], kw[4])
	end
	-- log
	if gameOption('Debug.DumpLuaTables') then main.f_printTable(options.menu, 'debug/t_optionsMenu.txt') end
end

--;===========================================================
--; KEY SETTINGS
--;===========================================================
local t_keyCfg = {}
table.insert(t_keyCfg, {itemname = 'spacer', displayname = '-', paramname = 'spacer'})
for _, v in ipairs(motif.option_info.keymenu.itemname_order or {}) do
	if isUIKeyAction(v) or v == "configall" then
		table.insert(t_keyCfg, {itemname = v, displayname = motif.option_info.keymenu.itemname[v] or '', paramname = v, infodisplay = ''})
	end
end
table.insert(t_keyCfg, {itemname = 'page', displayname = '', paramname = 'page', infodisplay = ''})

-- find the index of the "Config all" row
local configall_start = 2
for i, row in ipairs(t_keyCfg) do
	if row.itemname == 'configall' then
		configall_start = i
		break
	end
end
-- initial selection: keep it on the Config all row
local cursorPosY = configall_start
local item = configall_start
local item_start = configall_start
local captureActive = false
local captureMode = nil
local key = ''
local t_keyList = {}
local t_conflict = {}
local t_savedConfig = {}
local btnReleased = false
local player = 1
local side = 1
local btn = ''
local joyNum = 0

-- which actions we save / restore per player
local t_keyCfgFields = {
	'Joystick', 'up', 'down', 'left', 'right',
	'a', 'b', 'c', 'x', 'y', 'z',
	'start', 'd', 'w', 'menu', 'GUID',
}

local t_btnEnabled = {}
for _, row in ipairs(t_keyCfg) do
	if isUIKeyAction(row.itemname) then
		t_btnEnabled[row.itemname] = true
	end
end

-- Restore saved key config for a single player from t_savedConfig
local function f_restoreKeyConfigPlayer(cfgType, pn)
	local saved = t_savedConfig[pn]
	if not saved then
		return
	end
	for _, field in ipairs(t_keyCfgFields) do
		local oldVal = saved[field]
		if oldVal ~= nil then
			modifyGameOption(string.format('%s_P%d.%s', cfgType, pn, field), oldVal)
		end
	end
end

function options.f_keyDefault()
	for i = 1, gameOption('Config.Players') do
		setDefaultConfig('Keys', i, t_btnEnabled)
		setDefaultConfig('Joystick', i, t_btnEnabled)
	end
	resetRemapInput()
end

if gameOption('Config.FirstRun') then
	options.f_keyDefault()
end

function options.f_keyCfgReset(cfgType)
	t_keyList = {}
	for i = 1, gameOption('Config.Players') do
		local c = gameOption(cfgType .. '_P' .. i)
		if t_keyList[c.Joystick] == nil then
			t_keyList[c.Joystick] = {} --creates subtable for each controller (1 for all keyboard configs, new one for each gamepad)
			t_conflict[c.Joystick] = false --set default conflict flag for each controller
		end
		for k, v in ipairs(t_keyCfg) do
			if t_btnEnabled[v.itemname] then
				local btn = c[v.itemname]
				t_keyCfg[k]['vardisplay' .. i] = btn
				if btn ~= tostring(motif.option_info.menu.valuename.nokey) then --if button is not disabled
					t_keyList[c.Joystick][btn] = (t_keyList[c.Joystick][btn] or 0) + 1
				end
			elseif v.itemname == 'rumble' then
				t_keyCfg[k]['vardisplay' .. i] = options.f_boolDisplay(c.RumbleOn)
			end
		end
	end
end

function options.f_setKeyConfig(cfgType)
	for i = 1, gameOption('Config.Players') do
		local c = gameOption(cfgType .. '_P' .. i)
		setKeyConfig(i, c.Joystick, {c.up, c.down, c.left, c.right, c.a, c.b, c.c, c.x, c.y, c.z, c.start, c.d, c.w, c.menu})
	end
end

function options.f_keyCfgInit(cfgType, title)
	resetKey()
	cursorPosY = configall_start
	item = configall_start
	item_start = configall_start
	captureMode = nil
	captureActive = false
	key = ''
	t_conflict = {}
	t_savedConfig = {}
	for i = 1, gameOption('Config.Players') do
		table.insert(t_savedConfig, gameOption(cfgType .. '_P' .. i))
	end
	btnReleased = false
	player = 1
	side = 1
	btn = ''
	textImgReset(motif.option_info.title.TextSpriteData)
	textImgSetText(motif.option_info.title.TextSpriteData, title)
	options.f_keyCfgReset(cfgType)
	joyNum = gameOption(cfgType .. '_P' .. player .. '.Joystick')
end

function options.f_keyCfg(cfgType, controller, bg, skipClear)
	local t = t_keyCfg
	local side_before = side
	-- Dynamically add/remove the "Rumble" option based on type
	if motif.option_info.keymenu.itemname.rumble ~= nil then
		if cfgType ~= 'Joystick' then
			for k,v in ipairs(t) do
				if t[k].itemname == 'rumble' then
					table.remove(t, k)
					break
				end
			end
		else
			local found = false
			for k,v in ipairs(t) do
				if t[k].itemname == 'rumble' then
					found = true
					break
				end
			end
			if not found then
				table.insert(t, #t, {itemname = 'rumble', displayname = motif.option_info.keymenu.itemname.rumble, paramname = 'rumble', infodisplay = ''})
				options.f_keyCfgReset(cfgType)
			end
		end
	end
	local moveTxt = 0
	local forcedDir = nil
	-- Config all / single-button capture
	if captureActive then
		-- esc while capturing (cancel)
		if esc() --[[or getInput(-1, motif.option_info.menu.cancel.key)]] then
			sndPlay(motif.Snd, motif.option_info.cancel.snd[1], motif.option_info.cancel.snd[2])
			esc(false)
			for i = 1, gameOption('Config.Players') do
				if i == player then
					f_restoreKeyConfigPlayer(cfgType, i)
				end
			end
			options.f_setKeyConfig(cfgType)
			options.f_keyCfgReset(cfgType)
			-- on cancel, Config all should always return to the Config all row, while single-button capture should keep the row it started from
			local resetIndex
			if captureMode == 'all' then
				resetIndex = configall_start
			else
				resetIndex = item_start
			end
			captureMode = nil
			captureActive = false
			item = resetIndex
			cursorPosY = resetIndex
		-- unbind key
		elseif getKey(motif.option_info.keymenu.unbind.keycode) then
			key = '__UNBIND__'
		--keyboard key detection
		elseif cfgType == 'Keys' then
			key = getKey()
		--gamepad key detection
		else
			local tmp = getJoystickKey(joyNum)
			local guid = getJoystickGUID(joyNum)

			-- Fix the joystick index so that configs are preserved between boots
			if gameOption(cfgType .. '_P' .. player .. '.GUID') ~= guid and guid ~= '' then
				modifyGameOption(cfgType .. '_P' .. player .. '.GUID', guid)
				options.modified = true
			end

			if tmp == '' then
				btnReleased = true
			elseif btnReleased then
				key = tmp
				btnReleased = false
			end
		end
		-- while Config all is active we lock menu movement by default
		forcedDir = 0
		--other keyboard or gamepad key
		if key ~= '' and key ~= 'nil' then
			if key == '__UNBIND__' then
				sndPlay(motif.Snd, motif.option_info.cancel.snd[1], motif.option_info.cancel.snd[2])
				--decrease old button count
				if t_keyList[joyNum][btn] ~= nil and t_keyList[joyNum][btn] > 1 then
					t_keyList[joyNum][btn] = t_keyList[joyNum][btn] - 1
				else
					t_keyList[joyNum][btn] = nil
				end
				--update vardisplay / config data
				t[item]['vardisplay' .. player] = motif.option_info.menu.valuename.nokey
				modifyGameOption(cfgType .. '_P' .. player .. '.' .. t[item].itemname, tostring(motif.option_info.menu.valuename.nokey))
				options.modified = true
			elseif cfgType == 'Keys' or (cfgType == 'Joystick' and key ~= 'nil') then
				sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
				--decrease old button count
				if t_keyList[joyNum][btn] ~= nil and t_keyList[joyNum][btn] > 1 then
					t_keyList[joyNum][btn] = t_keyList[joyNum][btn] - 1
				else
					t_keyList[joyNum][btn] = nil
				end
				--remove previous button assignment if already set
				for k, v in ipairs(t) do
					if v['vardisplay' .. player] == key then
						v['vardisplay' .. player] = tostring(motif.option_info.menu.valuename.nokey)
						modifyGameOption(cfgType .. '_P' .. player .. '.' .. v.itemname, tostring(motif.option_info.menu.valuename.nokey))
						if t_keyList[joyNum][key] ~= nil and t_keyList[joyNum][key] > 1 then
							t_keyList[joyNum][key] = t_keyList[joyNum][key] - 1
						else
							t_keyList[joyNum][key] = nil
						end
					end
				end
				--increase new button count
				if t_keyList[joyNum][key] == nil then
					t_keyList[joyNum][key] = 1
				else
					t_keyList[joyNum][key] = t_keyList[joyNum][key] + 1
				end
				--update vardisplay / config data
				t[item]['vardisplay' .. player] = key
				modifyGameOption(cfgType .. '_P' .. player .. '.' .. t[item].itemname, key)
				options.modified = true
			end
			if captureMode == 'all' then
				-- decide what to do next: move down or finish Config all
				local nextIndex = item + 1
				local nextRow = t[nextIndex]
				if nextRow == nil or nextRow.itemname == 'page' or nextRow.itemname == 'rumble' then
					-- reached end sentinel, stop Config all and reset selection
					item = configall_start
					cursorPosY = configall_start
					captureActive = false
					captureMode = nil
					options.f_setKeyConfig(cfgType)
					forcedDir = 0 -- keep cursor where we reset it
				else
					-- continue Config all: simulate one "down" press so scrolling / wrapping is handled by common menu code
					forcedDir = 1
				end
			else
				-- single-button capture: finish after one assignment, keep current scroll / cursor
				captureActive = false
				captureMode = nil
				options.f_setKeyConfig(cfgType)
				forcedDir = 0
			end
			key = ''
		end
		if t_btnEnabled[t[item].itemname] then
			btn = gameOption(cfgType .. '_P' .. player .. '.' .. t[item].itemname)
		end
		resetKey()
	else
		key = getKey()
		--back
		if esc() or getInput(-1, motif.option_info.menu.cancel.key) or (t[item].itemname == 'page' and (side == 1 or gameOption('Config.Players') <= 2) and getInput(-1, motif.option_info.keymenu.done.key)) then
			if t_conflict[joyNum] then
				if not main.f_warning(motif.warning_info.text.text.keys, motif.option_info, motif.optionbgdef) then
					for i = 1, gameOption('Config.Players') do
						f_restoreKeyConfigPlayer(cfgType, i)
					end
					options.f_setKeyConfig(cfgType)
					menu.itemname = ''
					return false
				end
			else
				sndPlay(motif.Snd, motif.option_info.cancel.snd[1], motif.option_info.cancel.snd[2])
				options.f_setKeyConfig(cfgType)
				menu.itemname = ''
				return false
			end
		--switch page
		elseif gameOption('Config.Players') > 2 and ((t[item].itemname == 'page' and side == 2 and getInput(-1, motif.option_info.keymenu.done.key)) or key == 'TAB') then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			player = player + 2
			if player > gameOption('Config.Players') then
				player = side
			else
				side = main.f_playerSide(player)
			end
			joyNum = gameOption(cfgType .. '_P' .. player .. '.Joystick')
		--move right
		elseif getInput(-1, motif.option_info.menu.add.key) and player + 1 <= gameOption('Config.Players') then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			player = player + 1
			side = main.f_playerSide(player)
			joyNum = gameOption(cfgType .. '_P' .. player .. '.Joystick')
		--move left
		elseif getInput(-1, motif.option_info.menu.subtract.key) and player - 1 >= 1 then
			sndPlay(motif.Snd, motif.option_info.cursor.move.snd[1], motif.option_info.cursor.move.snd[2])
			player = player - 1
			side = main.f_playerSide(player)
			joyNum = gameOption(cfgType .. '_P' .. player .. '.Joystick')
		--Config all
		elseif t[item].itemname == 'configall' or key:match('^F[0-9]+$') then
			local pn = key:match('^F([0-9]+)$')
			if pn ~= nil then
				pn = tonumber(pn)
				key = ''
			end
			if getInput(-1, motif.option_info.keymenu.done.key) or (pn ~= nil and pn >= 1 and pn <= gameOption('Config.Players')) then
				sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
				if pn ~= nil then
					player = pn
					side = main.f_playerSide(player)
					joyNum = gameOption(cfgType .. '_P' .. player .. '.Joystick')
				end
				if cfgType == 'Joystick' and getJoystickPresent(joyNum) == false then
					main.f_warning(motif.warning_info.text.text.pad, motif.option_info, motif.optionbgdef)
					item = configall_start
					cursorPosY = configall_start
				else
					-- start "Config all" capture
					captureMode = 'all'
					item = configall_start + 1
					cursorPosY = configall_start + 1
					btnReleased = false
					captureActive = true
				end
			end
		-- Single-button assignment
		elseif t_btnEnabled[t[item].itemname] and getInput(-1, motif.option_info.keymenu.done.key) then
			if cfgType == 'Joystick' and getJoystickPresent(joyNum) == false then
				-- same behaviour as Config all when no gamepad is connected
				main.f_warning(motif.warning_info.text.text.pad, motif.option_info, motif.optionbgdef)
				item = configall_start
				cursorPosY = configall_start
			else
				-- enter capture mode but only for this single row
				sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
				-- item_start remembers which row started this single-button capture;
				item_start = item
				btnReleased = false
				captureMode = 'single'
				captureActive = true
				-- preload current button for this action (used by configall logic)
				if t_btnEnabled[t[item].itemname] then
					btn = gameOption(cfgType .. '_P' .. player .. '.' .. t[item].itemname)
				else
					btn = ''
				end
			end
		-- Rumble toggle
		elseif t[item].itemname == 'rumble' then
			if getInput(-1, motif.option_info.keymenu.done.key) then
				sndPlay(motif.Snd, motif.option_info.cursor.done.snd[1], motif.option_info.cursor.done.snd[2])
				local rgo = cfgType .. '_P' .. player .. '.RumbleOn'
				local rumble = gameOption(rgo)
				modifyGameOption(rgo, not rumble)
				options.f_keyCfgReset(cfgType)
				options.modified = true
			end
		end
		resetKey()
	end

	-- Reset active background animation when switching side
	if side_before ~= side and t ~= nil and t[item] ~= nil then
		local bgTable = motif.option_info.keymenu.item.active.bg
		if bgTable ~= nil then
			local params = bgTable[t[item].paramname] or bgTable.default
			if params ~= nil and params.AnimData ~= nil then
				animReset(params.AnimData)
				animUpdate(params.AnimData)
			end
		end
	end

	-- standard / forced menu movement (up/down)
	-- When Config all is active, movement is driven by forcedDir (0 = locked, 1 = down).
	cursorPosY, moveTxt, item = main.f_menuCommonCalc(t, item, cursorPosY, moveTxt, motif.option_info.keymenu, motif.option_info.cursor, forcedDir)
	-- recompute current-player conflict flag (used on exit)
	t_conflict[joyNum] = false
	local curVal = nil
	for i = 1, #t do
		curVal = t[i]['vardisplay' .. player]
		if curVal ~= nil then
			local cnt = t_keyList[joyNum][tostring(curVal)]
			if cnt ~= nil and cnt > 1 then
				t_conflict[joyNum] = true
				break
			end
		end
	end
	if not skipClear then
		clearColor(bg.bgclearcolor[1], bg.bgclearcolor[2], bg.bgclearcolor[3])
	end
	--draw layerno = 0 backgrounds
	bgDraw(bg.BGDef, 0)
	--draw title
	textImgDraw(motif.option_info.title.TextSpriteData)
	-- Build per-pane item arrays with correct vardisplay/infodisplay and conflict flags
	local function buildPaneItems(pane)
		local pn = pane + player - side
		local joy = gameOption(cfgType .. '_P' .. pn .. '.Joystick')
		local list = {}
		for i = 1, #t do
			local base = t[i]
			local row = {
				itemname    = base.itemname,
				displayname = base.displayname,
				paramname   = base.paramname,
				selected    = base.selected,
				vardisplay  = base['vardisplay' .. pn],
				infodisplay = base.infodisplay,
			}
			-- contextual labels
			if base.itemname == 'configall' then
				row.infodisplay = string.format(motif.option_info.menu.valuename.f, pane + player - side)
			elseif base.itemname == 'page' then
				if pane == 1 then
					row.displayname = motif.option_info.keymenu.itemname.back
					row.infodisplay = motif.option_info.menu.valuename.esc
				else
					if gameOption('Config.Players') > 2 then
						row.displayname = motif.option_info.keymenu.itemname.page
						row.infodisplay = motif.option_info.menu.valuename.page
					else
						row.displayname = motif.option_info.keymenu.itemname.back
						row.infodisplay = motif.option_info.menu.valuename.esc
					end
				end
			end
			-- custom vardisplay when single-button capture is waiting for input on this row
			if captureMode == 'single' and captureActive and pn == player and i == item and t_btnEnabled[base.itemname] then
				row.vardisplay = tostring(motif.option_info.menu.valuename.presskey)
			end
			-- conflict marker per pane
			if row.vardisplay ~= nil then
				local cnt = t_keyList[joy][tostring(row.vardisplay)]
				row.conflict = (cnt ~= nil and cnt > 1) or false
			end
			table.insert(list, row)
		end
		return list
	end
	local leftItems  = buildPaneItems(1)
	local rightItems = buildPaneItems(2)
	-- left pane (active highlight only if side == 1)
	main.f_menuCommonDraw(
		leftItems, item, cursorPosY, moveTxt, motif.option_info.keymenu, bg, true,
		{
			offx = motif.option_info.keymenu.p1.menuoffset[1],
			offy = motif.option_info.keymenu.p1.menuoffset[2],
			forceInactive = (side ~= 1),
			skipBG0 = true, skipBG1 = true, skipTitle = true,
		}
	)
	-- right pane (active highlight only if side == 2)
	main.f_menuCommonDraw(
		rightItems, item, cursorPosY, moveTxt, motif.option_info.keymenu, bg, true,
		{
			offx = motif.option_info.keymenu.p2.menuoffset[1],
			offy = motif.option_info.keymenu.p2.menuoffset[2],
			forceInactive = (side ~= 2),
			skipBG0 = true, skipBG1 = true, skipTitle = true,
		}
	)
	-- draw player labels on top of panels (above boxbg)
	for i = 1, 2 do
		textImgReset(motif.option_info.keymenu['p' .. i].playerno.TextSpriteData)
		textImgSetText(
			motif.option_info.keymenu['p' .. i].playerno.TextSpriteData,
			string.format(motif.option_info.keymenu['p' .. i].playerno.text, i + player - side)
		)
		textImgDraw(motif.option_info.keymenu['p' .. i].playerno.TextSpriteData)
	end
	--draw layerno = 1 backgrounds
	bgDraw(bg.BGDef, 1)
	if not skipClear then
		refresh()
	end
	return true
end

return options
