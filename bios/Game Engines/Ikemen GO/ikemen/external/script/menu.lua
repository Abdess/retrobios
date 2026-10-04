local menu = {}

--;===========================================================
--; PAUSE MENU
--;===========================================================

-- Associative elements table storing arrays with training menu option names.
-- Can be appended via external module.
menu.t_valuename = {
	dummycontrol = {
		{itemname = 'cooperative', displayname = motif.pause_menu.training_pause_menu.menu.valuename.dummycontrol_cooperative},
		{itemname = 'ai', displayname = motif.pause_menu.training_pause_menu.menu.valuename.dummycontrol_ai},
		{itemname = 'manual', displayname = motif.pause_menu.training_pause_menu.menu.valuename.dummycontrol_manual},
	},
	ailevel = {
		{itemname = '1', displayname = motif.pause_menu.training_pause_menu.menu.valuename.ailevel_1},
		{itemname = '2', displayname = motif.pause_menu.training_pause_menu.menu.valuename.ailevel_2},
		{itemname = '3', displayname = motif.pause_menu.training_pause_menu.menu.valuename.ailevel_3},
		{itemname = '4', displayname = motif.pause_menu.training_pause_menu.menu.valuename.ailevel_4},
		{itemname = '5', displayname = motif.pause_menu.training_pause_menu.menu.valuename.ailevel_5},
		{itemname = '6', displayname = motif.pause_menu.training_pause_menu.menu.valuename.ailevel_6},
		{itemname = '7', displayname = motif.pause_menu.training_pause_menu.menu.valuename.ailevel_7},
		{itemname = '8', displayname = motif.pause_menu.training_pause_menu.menu.valuename.ailevel_8},
	},
	dummymode = {
		{itemname = 'stand', displayname = motif.pause_menu.training_pause_menu.menu.valuename.dummymode_stand},
		{itemname = 'crouch', displayname = motif.pause_menu.training_pause_menu.menu.valuename.dummymode_crouch},
		{itemname = 'jump', displayname = motif.pause_menu.training_pause_menu.menu.valuename.dummymode_jump},
		{itemname = 'wjump', displayname = motif.pause_menu.training_pause_menu.menu.valuename.dummymode_wjump},
	},
	guardmode = {
		{itemname = 'none', displayname = motif.pause_menu.training_pause_menu.menu.valuename.guardmode_none},
		{itemname = 'auto', displayname = motif.pause_menu.training_pause_menu.menu.valuename.guardmode_auto},
		{itemname = 'all', displayname = motif.pause_menu.training_pause_menu.menu.valuename.guardmode_all},
		{itemname = 'random', displayname = motif.pause_menu.training_pause_menu.menu.valuename.guardmode_random},
	},
	fallrecovery = {
		{itemname = 'none', displayname = motif.pause_menu.training_pause_menu.menu.valuename.fallrecovery_none},
		{itemname = 'ground', displayname = motif.pause_menu.training_pause_menu.menu.valuename.fallrecovery_ground},
		{itemname = 'air', displayname = motif.pause_menu.training_pause_menu.menu.valuename.fallrecovery_air},
		{itemname = 'random', displayname = motif.pause_menu.training_pause_menu.menu.valuename.fallrecovery_random},
	},
	distance = {
		{itemname = 'any', displayname = motif.pause_menu.training_pause_menu.menu.valuename.distance_any},
		{itemname = 'close', displayname = motif.pause_menu.training_pause_menu.menu.valuename.distance_close},
		{itemname = 'medium', displayname = motif.pause_menu.training_pause_menu.menu.valuename.distance_medium},
		{itemname = 'far', displayname = motif.pause_menu.training_pause_menu.menu.valuename.distance_far},
	},
	buttonjam = {
		{itemname = 'none', displayname = motif.pause_menu.training_pause_menu.menu.valuename.buttonjam_none},
		{itemname = 'a', displayname = motif.pause_menu.training_pause_menu.menu.valuename.buttonjam_a},
		{itemname = 'b', displayname = motif.pause_menu.training_pause_menu.menu.valuename.buttonjam_b},
		{itemname = 'c', displayname = motif.pause_menu.training_pause_menu.menu.valuename.buttonjam_c},
		{itemname = 'x', displayname = motif.pause_menu.training_pause_menu.menu.valuename.buttonjam_x},
		{itemname = 'y', displayname = motif.pause_menu.training_pause_menu.menu.valuename.buttonjam_y},
		{itemname = 'z', displayname = motif.pause_menu.training_pause_menu.menu.valuename.buttonjam_z},
		{itemname = 's', displayname = motif.pause_menu.training_pause_menu.menu.valuename.buttonjam_s},
		{itemname = 'd', displayname = motif.pause_menu.training_pause_menu.menu.valuename.buttonjam_d},
		{itemname = 'w', displayname = motif.pause_menu.training_pause_menu.menu.valuename.buttonjam_w},
	},
}

-- Shared logic for pause menu option change, returns 2 values:
-- * boolean depending if option has changed (via right/left button press)
-- * itemname read from t_valuename table based on currently active option
--   (or nil, if there was no option change in this frame)
function menu.f_valueChanged(t, sec)
	local valueitem = menu[t.itemname] or 1
	local chk = valueitem
	if getInput(-1, sec.menu.add.key) then
		valueitem = valueitem + 1
	elseif getInput(-1, sec.menu.subtract.key) then
		valueitem = valueitem - 1
	end
	if valueitem > #menu.t_valuename[t.itemname] then
		valueitem = 1
	elseif valueitem < 1 then
		valueitem = #menu.t_valuename[t.itemname]
	end
	-- true upon option change
	if chk ~= valueitem then
		sndPlay(motif.Snd, sec.cursor.move.snd[1], sec.cursor.move.snd[2])
		t.vardisplay = menu.t_valuename[t.itemname][valueitem].displayname
		menu[t.itemname] = valueitem
		menu.itemname = t.itemname
		return true, menu.t_valuename[t.itemname][valueitem].itemname
	end
	return false, nil
end

-- Current pause menu itemname for internal use (key from menu.t_itemname table)
menu.itemname = ''

-- Associative elements table storing functions controlling behaviour of each
-- pause menu item. Can be appended via external module.
menu.t_itemname = {
	--Back
	['back'] = function(t, item, cursorPosY, moveTxt, sec)
		if getInput(-1, sec.menu.done.key) then
			if menu.currentMenu[1] == menu.currentMenu[2] then
				sndPlay(motif.Snd, sec.exit.snd[1], sec.exit.snd[2])
				menu.pauseExitDelay = gameOption('Input.PauseExitDelay')
			else
				sndPlay(motif.Snd, sec.cancel.snd[1], sec.cancel.snd[2])
			end
			if menu.currentMenu[1] ~= menu.currentMenu[2] then
				main.f_menuSnap(sec)
			end
			menu.currentMenu[1] = menu.currentMenu[2]
			return false
		end
		return true
	end,
	--Dummy Control
	['dummycontrol'] = function(t, item, cursorPosY, moveTxt, sec)
		local ok, name = menu.f_valueChanged(t.items[item], sec)
		if ok then
			if name == 'cooperative' or name == 'manual' then
				player(2)
				setAILevel(0)
			elseif name == 'ai' then
				player(2)
				setAILevel(menu.ailevel)
			end
			player(2)
			mapSet('_iksys_trainingDummyControl', menu.dummycontrol - 1)
		end
		return true
	end,
	--AI Level
	['ailevel'] = function(t, item, cursorPosY, moveTxt, sec)
		if menu.f_valueChanged(t.items[item], sec) then
			if menu.t_valuename.dummycontrol[menu.dummycontrol or 1].itemname == 'ai' then
				player(2)
				setAILevel(menu.ailevel)
			end
		end
		return true
	end,
	--Dummy Mode
	['dummymode'] = function(t, item, cursorPosY, moveTxt, sec)
		if menu.f_valueChanged(t.items[item], sec) then
			player(2)
			mapSet('_iksys_trainingDummyMode', menu.dummymode - 1)
		end
		return true
	end,
	--Guard Mode
	['guardmode'] = function(t, item, cursorPosY, moveTxt, sec)
		if menu.f_valueChanged(t.items[item], sec) then
			player(2)
			mapSet('_iksys_trainingGuardMode', menu.guardmode - 1)
		end
		return true
	end,
	--Fall Recovery
	['fallrecovery'] = function(t, item, cursorPosY, moveTxt, sec)
		if menu.f_valueChanged(t.items[item], sec) then
			player(2)
			mapSet('_iksys_trainingFallRecovery', menu.fallrecovery - 1)
		end
		return true
	end,
	--Distance
	['distance'] = function(t, item, cursorPosY, moveTxt, sec)
		if menu.f_valueChanged(t.items[item], sec) then
			player(2)
			mapSet('_iksys_trainingDistance', menu.distance - 1)
		end
		return true
	end,
	--Button Jam
	['buttonjam'] = function(t, item, cursorPosY, moveTxt, sec)
		if menu.f_valueChanged(t.items[item], sec) then
			player(2)
			mapSet('_iksys_trainingButtonJam', menu.buttonjam - 1)
		end
		return true
	end,
	--Key Config
	['keyboard'] = function(t, item, cursorPosY, moveTxt, sec)
		if getInput(-1, sec.menu.done.key) then
			sndPlay(motif.Snd, sec.cursor.done.snd[1], sec.cursor.done.snd[2])
			options.f_keyCfgInit('Keys', t.submenu[t.items[item].itemname].title)
			menu.itemname = t.items[item].itemname
		end
		return true
	end,
	--Joystick Config
	['gamepad'] = function(t, item, cursorPosY, moveTxt, sec)
		if getInput(-1, sec.menu.done.key) then
			sndPlay(motif.Snd, sec.cursor.done.snd[1], sec.cursor.done.snd[2])
			options.f_keyCfgInit('Joystick', t.submenu[t.items[item].itemname].title)
			menu.itemname = t.items[item].itemname
		end
		return true
	end,
	--Default
	['inputdefault'] = function(t, item, cursorPosY, moveTxt, sec)
		if getInput(-1, sec.menu.done.key) then
			sndPlay(motif.Snd, sec.cursor.done.snd[1], sec.cursor.done.snd[2])
			options.f_keyDefault()
			options.f_setKeyConfig('Keys')
			if getCommandLineValue("-nojoy") == nil then
				options.f_setKeyConfig('Joystick')
			end
			options.f_saveCfg(false)
		end
		return true
	end,
	--Round Reset
	['reset'] = function(t, item, cursorPosY, moveTxt, sec)
		if getInput(-1, sec.menu.done.key) then
			sndPlay(motif.Snd, sec.cursor.done.snd[1], sec.cursor.done.snd[2])
			--togglePause(false)
			resetRound()
			main.pauseMenuActive = false
			return false
		end
		return true
	end,
	--Reload (Rematch)
	['reload'] = function(t, item, cursorPosY, moveTxt, sec)
		if getInput(-1, sec.menu.done.key) then
			sndPlay(motif.Snd, sec.cursor.done.snd[1], sec.cursor.done.snd[2])
			--togglePause(false)
			reload()
			main.pauseMenuActive = false
			return false
		end
		return true
	end,
	--Command List
	['commandlist'] = function(t, item, cursorPosY, moveTxt, sec)
		if getInput(-1, sec.menu.done.key) then
			sndPlay(motif.Snd, sec.cursor.done.snd[1], sec.cursor.done.snd[2])
			menu.f_commandlistParse()
			menu.itemname = t.items[item].itemname
		end
		return true
	end,
	--Character Change
	['characterchange'] = function(t, item, cursorPosY, moveTxt, sec)
		if getInput(-1, sec.menu.done.key) then
			sndPlay(motif.Snd, sec.cursor.done.snd[1], sec.cursor.done.snd[2], 100, 0, 0, 0, 0, true)
			--togglePause(false)
			endMatch()
			start.characterchange = true
			main.pauseMenuActive = false
			return false
		end
		return true
	end,
	--Exit
	['exit'] = function(t, item, cursorPosY, moveTxt, sec)
		if getInput(-1, sec.menu.done.key) then
			sndPlay(motif.Snd, sec.cursor.done.snd[1], sec.cursor.done.snd[2], 100, 0, 0, 0, 0, true)
			--togglePause(false)
			endMatch()
			start.exit = true
			main.pauseMenuActive = false
			return false
		end
		return true
	end,
}
-- options.t_itemname table functions are also appended to this table, to make
-- option screen settings logic accessible from within pause menu.
for k, v in pairs(options.t_itemname) do
	if menu.t_itemname[k] == nil then
		menu.t_itemname[k] = v
	end
end

-- Shared menu loop logic
function menu.f_createMenu(tbl, sec, bg, bool_main)
	return function()
		hook.run("menu.menu.loop")
		if menu._lastMenuTbl ~= tbl then
			menu._lastMenuTbl = tbl
			main.f_menuItemBgAnimReset(sec)
		end
		local t = tbl.items
		if tbl.reset then
			tbl.reset = false
		else
			main.f_menuCommonDraw(t, tbl.item, tbl.cursorPosY, tbl.moveTxt, sec, bg, true)
		end
		-- Draw during fades, but don't accept menu input until they finish.
		if not main.pauseMenuActive or fadeActive() or menu.pauseExitDelay >= 0 then
			return
		end
		tbl.cursorPosY, tbl.moveTxt, tbl.item = main.f_menuCommonCalc(t, tbl.item, tbl.cursorPosY, tbl.moveTxt, sec, sec.cursor)
		textImgReset(sec.title.TextSpriteData)
		textImgSetText(sec.title.TextSpriteData, tbl.title)
		if esc() or getInput(-1, sec.menu.cancel.key) then
			if bool_main then
				sndPlay(motif.Snd, sec.exit.snd[1], sec.exit.snd[2])
				menu.pauseExitDelay = gameOption('Input.PauseExitDelay')
			else
				sndPlay(motif.Snd, sec.cancel.snd[1], sec.cancel.snd[2])
			end
			if menu.currentMenu[1] ~= menu.currentMenu[2] then
				main.f_menuSnap(sec)
			end
			menu.currentMenu[1] = menu.currentMenu[2]
			return
		elseif menu.t_itemname[t[tbl.item].itemname] ~= nil then
			if not menu.t_itemname[t[tbl.item].itemname](tbl, tbl.item, tbl.cursorPosY, tbl.moveTxt, sec) then
				return
			end
		elseif getInput(-1, sec.menu.done.key) then
			local f = t[tbl.item].itemname
			if tbl.submenu[f].loop ~= nil then
				sndPlay(motif.Snd, sec.cursor.done.snd[1], sec.cursor.done.snd[2])
				menu.currentMenu[1] = tbl.submenu[f].loop
				main.f_menuSnap(sec)
			elseif not menu.t_itemname[f](tbl, tbl.item, tbl.cursorPosY, tbl.moveTxt, sec) then
				return
			end
		end
	end
end

menu.t_vardisplayPointers = {}

-- Associative elements table storing functions returning current setting values
-- rendered alongside menu item name. Can be appended via external module.
menu.t_vardisplay = {
	['dummycontrol'] = function()
		return menu.t_valuename.dummycontrol[menu.dummycontrol or 1].displayname
	end,
	['ailevel'] = function()
		return menu.t_valuename.ailevel[menu.ailevel or gameOption('Options.Difficulty')].displayname
	end,
	['dummymode'] = function()
		return menu.t_valuename.dummymode[menu.dummymode or 1].displayname
	end,
	['guardmode'] = function()
		return menu.t_valuename.guardmode[menu.guardmode or 1].displayname
	end,
	['fallrecovery'] = function()
		return menu.t_valuename.fallrecovery[menu.fallrecovery or 1].displayname
	end,
	['distance'] = function()
		return menu.t_valuename.distance[menu.distance or 1].displayname
	end,
	['buttonjam'] = function()
		return menu.t_valuename.buttonjam[menu.buttonjam or 1].displayname
	end,
}

-- Returns setting value rendered alongside menu item name (calls appropriate
-- function from menu or options t_vardisplay table)
function menu.f_vardisplay(itemname)
	if menu.t_vardisplay[itemname] ~= nil then
		return menu.t_vardisplay[itemname]()
	end
	if options.t_vardisplay[itemname] ~= nil then
		return options.t_vardisplay[itemname]()
	end
	return ''
end

-- Table storing arrays with data used for different pause menu types generation.
-- Can be appended via external module but not necessary - can specify gamemode-specific [<gamemode> Pause Menu] sections in `system.def` instead.
menu.t_menus = {
	{id = 'menu', sec = motif.pause_menu.pause_menu, bg = motif.pausebgdef.pausebgdef, movelist = true},
	{id = 'training', sec = motif.pause_menu.training_pause_menu, bg = motif.pausebgdef.trainingpausebgdef, movelist = true},
}
menu.t_menuIndex = {}

local function f_pauseMenuKey(gamemodeName)
	gamemodeName = tostring(gamemodeName or ''):lower()
	gamemodeName = gamemodeName:gsub('%s+', '_')
	if gamemodeName == '' then
		return ''
	end
	return gamemodeName .. '_pause_menu'
end

local function f_pauseMenuIdFromKey(key)
	key = tostring(key or ''):lower()
	if key:sub(-11) == '_pause_menu' then
		key = key:sub(1, -12)
	end
	return key
end

local function f_pauseMenuBgKey(gamemodeName)
	gamemodeName = tostring(gamemodeName or ''):lower()
	gamemodeName = gamemodeName:gsub('%s+', '_')
	if gamemodeName == '' then
		return ''
	end
	return gamemodeName .. 'pausebgdef'
end

local function f_registerPauseMenu(id, sec, bg, movelist)
	if id == '' or sec == nil then
		return
	end
	for i = 1, #menu.t_menus do
		if menu.t_menus[i].id == id then
			return
		end
	end
	table.insert(menu.t_menus, {id = id, sec = sec, bg = bg, movelist = movelist})
end

local function f_indexPauseMenus()
	menu.t_menuIndex = {}
	for i = 1, #menu.t_menus do
		menu.t_menuIndex[menu.t_menus[i].id] = menu.t_menus[i]
	end
end

-- Dynamically generates all menus and submenus
function menu.f_start()
	if motif.pause_menu ~= nil then
		for k, sec in pairs(motif.pause_menu) do
			local id = f_pauseMenuIdFromKey(k)
			if id ~= '' and id ~= 'pause_menu' then
				local bg = motif.pausebgdef.pausebgdef
				local bgKey = f_pauseMenuBgKey(id)
				if bgKey ~= '' and motif.pausebgdef ~= nil and motif.pausebgdef[bgKey] ~= nil then
					bg = motif.pausebgdef[bgKey]
				end
				f_registerPauseMenu(id, sec, bg, true)
			end
		end
	end
	f_indexPauseMenus()
	for k, v in ipairs(menu.t_menus) do
		menu[v.id] = {
			title = main.f_itemnameUpper(v.sec.title.text, v.sec.menu.title.uppercase),
			cursorPosY = 1,
			moveTxt = 0,
			item = 1,
			submenu = {},
			items = {}
		}
		menu[v.id].loop = menu.f_createMenu(menu[v.id], v.sec, v.bg, true)
		local w = main.f_menuWindow(v.sec.menu)
		local t_pos = {} --for storing current table position
		local lastNum = 0
		for i, suffix in ipairs(v.sec.menu.itemname_order) do
			for j, c in ipairs(main.f_strsplit('_', suffix)) do --split using "_" delimiter
				--appending the menu table
				if j == 1 then --first string after menu.itemname (either reserved one or custom submenu assignment)
					if menu[v.id].submenu[c] == nil or c:match("^spacer%d*$") then
						menu[v.id].submenu[c] = {}
						menu[v.id].submenu[c].title = main.f_itemnameUpper(v.sec.menu.itemname[suffix], v.sec.menu.title.uppercase)
						if menu.t_itemname[c] == nil and not c:match("^spacer%d*$") then
							menu[v.id].submenu[c].cursorPosY = 1
							menu[v.id].submenu[c].moveTxt = 0
							menu[v.id].submenu[c].item = 1
							menu[v.id].submenu[c].submenu = {}
							menu[v.id].submenu[c].items = {}
							menu[v.id].submenu[c].loop = menu.f_createMenu(menu[v.id].submenu[c], v.sec, v.bg, false)
						end
						if not suffix:match(c .. '_') then
							table.insert(menu[v.id].items, {
								itemname = c,
								displayname = v.sec.menu.itemname[suffix],
								paramname = suffix,
								vardisplay = menu.f_vardisplay(c),
								selected = false,
							})
							table.insert(menu.t_vardisplayPointers, menu[v.id].items[#menu[v.id].items])
						end
					end
					t_pos = menu[v.id].submenu[c]
					t_pos.name = c
				else --following strings
					if t_pos.submenu[c] == nil or c:match("^spacer%d*$") then
						t_pos.submenu[c] = {}
						t_pos.submenu[c].title = main.f_itemnameUpper(v.sec.menu.itemname[suffix], v.sec.menu.title.uppercase)
						if menu.t_itemname[c] == nil and not c:match("^spacer%d*$") then
							t_pos.submenu[c].cursorPosY = 1
							t_pos.submenu[c].moveTxt = 0
							t_pos.submenu[c].item = 1
							t_pos.submenu[c].submenu = {}
							t_pos.submenu[c].items = {}
							t_pos.submenu[c].loop = menu.f_createMenu(t_pos.submenu[c], v.sec, v.bg, false)
						end
						table.insert(t_pos.items, {
							itemname = c,
							displayname = v.sec.menu.itemname[suffix],
							paramname = suffix,
							vardisplay = menu.f_vardisplay(c),
							selected = false,
						})
						table.insert(menu.t_vardisplayPointers, t_pos.items[#t_pos.items])
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
		if getRuntimeOS() == 'android' then
			local excluded = {keyboard = true}
			main.f_pruneMenu(menu[v.id], excluded)
			main.f_prunePointers(menu.t_vardisplayPointers, excluded)
		end
		-- Menu windows
		textImgSetWindow(v.sec.menu.item.selected.active.TextSpriteData, w[1], w[2], w[3], w[4])
		textImgSetWindow(v.sec.menu.item.active.TextSpriteData, w[1], w[2], w[3], w[4])
		textImgSetWindow(v.sec.menu.item.value.active.TextSpriteData, w[1], w[2], w[3], w[4])
		textImgSetWindow(v.sec.menu.item.selected.TextSpriteData, w[1], w[2], w[3], w[4])
		textImgSetWindow(v.sec.menu.item.TextSpriteData, w[1], w[2], w[3], w[4])
		textImgSetWindow(v.sec.menu.item.value.TextSpriteData, w[1], w[2], w[3], w[4])
		--for _, v2 in pairs(v.sec.menu.item.bg) do
		--	animSetWindow(v2.AnimData, w[1], w[2], w[3], w[4])
		--end
		--for _, v2 in pairs(v.sec.menu.item.active.bg) do
		--	animSetWindow(v2.AnimData, w[1], w[2], w[3], w[4])
		--end
		if gameOption('Debug.DumpLuaTables') then main.f_printTable(menu[v.id], 'debug/t_' .. v.id .. 'Menu.txt') end
		-- Move list
		if v.movelist then
			local t = v.sec.movelist
			if t.window.margins.y[1] ~= 0 or t.window.margins.y[2] ~= 0 then
				local fontProps = motif.files.font['font' .. v.sec.movelist.text.font[1]]
				if fontProps ~= nil then
					menu.movelistW = {
						0,
						math.max(0, t.pos[2] + t.text.offset[2] - t.window.margins.y[1]),
						t.pos[1] + t.text.offset[1] + t.window.width,
						t.pos[2] + t.text.offset[2] + (t.window.visibleitems - 1) * main.f_round((fontProps.size[2] + fontProps.spacing[2]) * t.text.scale[2] + t.text.spacing[2]) + t.window.margins.y[2] + math.max(0, t.glyphs.offset[2])
					}
					textImgSetWindow(t.text.TextSpriteData, menu.movelistW[1], menu.movelistW[2], menu.movelistW[3], menu.movelistW[4])
				end
			end
		end
	end
end

-- Called from start.lua right before game() function to reset training menu values and p2 settings for a new match
function menu.f_trainingReset()
	for k, _ in pairs(menu.t_valuename) do
		menu[k] = 1
	end
	menu.ailevel = gameOption('Options.Difficulty')
	for _, v in ipairs(menu.t_vardisplayPointers) do
		v.vardisplay = menu.f_vardisplay(v.itemname)
	end
	player(2)
	setAILevel(0)
end

hook.add('loop#training', 'trainingSettings', function()
	if not roundStart() then return end
	player(2)
	setAILevel(menu.dummycontrol == 2 and menu.ailevel or 0)
	mapSet('_iksys_trainingDummyControl', menu.dummycontrol - 1)
	mapSet('_iksys_trainingDummyMode', menu.dummymode - 1)
	mapSet('_iksys_trainingGuardMode', menu.guardmode - 1)
	mapSet('_iksys_trainingFallRecovery', menu.fallrecovery - 1)
	mapSet('_iksys_trainingDistance', menu.distance - 1)
	mapSet('_iksys_trainingButtonJam', menu.buttonjam - 1)
end)

menu.movelistChar = 1
function menu.f_init()
	esc(false)
	main.pauseMenuActive = true
	bgReset(motif.optionbgdef.BGDef)
	local id = f_pauseMenuIdFromKey(f_pauseMenuKey(gameMode()))
	if id == '' or menu.t_menuIndex == nil or menu.t_menuIndex[id] == nil then
		id = 'menu'
	end
	if menu.t_menuIndex ~= nil and menu.t_menuIndex[id] ~= nil then
		local entry = menu.t_menuIndex[id]
		sndPlay(motif.Snd, entry.sec.enter.snd[1], entry.sec.enter.snd[2])
		bgReset(entry.bg.BGDef)
		if menu[id] ~= nil and menu[id].loop ~= nil then
			menu.currentMenu = {menu[id].loop, menu[id].loop}
			menu.currentMenuId = id
		else
			menu.currentMenu = {menu.menu.loop, menu.menu.loop}
			menu.currentMenuId = 'menu'
		end
	else
		sndPlay(motif.Snd, motif.pause_menu.pause_menu.enter.snd[1], motif.pause_menu.pause_menu.enter.snd[2])
		bgReset(motif.pausebgdef.pausebgdef.BGDef)
		menu.currentMenu = {menu.menu.loop, menu.menu.loop}
		menu.currentMenuId = 'menu'
	end
end

menu.pauseExitDelay = -1

function menu.f_run()
	local entry = nil
	if menu.t_menuIndex ~= nil then
		if menu.currentMenuId ~= nil and menu.t_menuIndex[menu.currentMenuId] ~= nil then
			entry = menu.t_menuIndex[menu.currentMenuId]
		else
			local id = f_pauseMenuIdFromKey(f_pauseMenuKey(gameMode()))
			if id ~= '' and menu.t_menuIndex[id] ~= nil then
				entry = menu.t_menuIndex[id]
			elseif menu.t_menuIndex['menu'] ~= nil then
				entry = menu.t_menuIndex['menu']
			end
		end
	end
	local sec = motif.pause_menu.pause_menu
	local bg = motif.pausebgdef.pausebgdef
	if entry ~= nil and entry.sec ~= nil and entry.bg ~= nil then
		sec = entry.sec
		bg = entry.bg
	end
	--draw overlay
	rectDraw(sec.overlay.RectData)
	--pause exit delay
	if menu.pauseExitDelay >= 0 then
		if menu.pauseExitDelay > 0 then
			menu.pauseExitDelay = menu.pauseExitDelay - 1
		else
			-- Keep the game paused. Go owns the fade-out/fade-in handoff and unpauses afterwards.
			main.pauseMenuActive = false
		end
	end
	--Button Config
	if menu.itemname == 'keyboard' or menu.itemname == 'gamepad' then
		if menu.itemname == 'keyboard' then
			options.f_keyCfg('Keys', menu.itemname, bg, true)
		else
			options.f_keyCfg('Joystick', menu.itemname, bg, true)
		end
	--Command List
	elseif menu.itemname == 'commandlist' then
		menu.f_commandlistRender(sec, menu.t_movelists[menu.movelistChar])
	--Menu
	else
		menu.currentMenu[1]()
	end
	local active = main.pauseMenuActive
	if not active then
		menu.pauseExitDelay = -1
	end
	return active
end

-- Reset selection/scroll state recursively for a menu table (root + submenus)
local function f_resetMenuState(tbl)
	if type(tbl) ~= "table" then return end
	-- Reset cursor/scroll
	tbl.cursorPosY = 1
	tbl.moveTxt = 0
	tbl.item = 1
	-- Clear any "selected" flags on items (if used by custom menus)
	if type(tbl.items) == "table" then
		for i = 1, #tbl.items do
			if type(tbl.items[i]) == "table" then
				tbl.items[i].selected = false
			end
		end
	end
	-- Recurse into submenus
	if type(tbl.submenu) == "table" then
		for _, sub in pairs(tbl.submenu) do
			f_resetMenuState(sub)
		end
	end
end

function menu.f_reset()
	-- exit any special screens rendered by menu.f_run()
	menu.itemname = ''
	-- Reset movelist selector (command list screen)
	menu.movelistChar = 1
	-- Reset tween caches
	if menu.t_menus ~= nil then
		for i = 1, #menu.t_menus do
			local sec = menu.t_menus[i].sec
			if sec ~= nil then
				sec.menuTweenData = nil
				sec.boxCursorData = nil
			end
		end
	end
	-- Determine which root menu is active and reset its cursor/item/scroll (and all submenus)
	if menu.currentMenu ~= nil and menu.currentMenu[2] ~= nil then
		if menu.currentMenuId ~= nil and menu[menu.currentMenuId] ~= nil then
			f_resetMenuState(menu[menu.currentMenuId])
		elseif menu.training ~= nil and menu.training.loop ~= nil and menu.currentMenu[2] == menu.training.loop then
			f_resetMenuState(menu.training)
		else
			f_resetMenuState(menu.menu)
		end
	end
	-- Force snap on next calc so we don't keep old scroll offsets.
	main.menuSnap = true
	-- restore root menu loop
	if menu.currentMenu ~= nil and menu.currentMenu[2] ~= nil then
		menu.currentMenu[1] = menu.currentMenu[2]
	end
end

function menuInit()
	return menu.f_init()
end

function menuRun()
	return menu.f_run()
end

function menuReset()
	return menu.f_reset()
end

--;===========================================================
--; COMMAND LIST
--;===========================================================
function colorFromHex(h)
	h = tostring(h)
	if h:sub(0, 1) =="#" then h = h:sub(2, -1) end
	if h:sub(0, 2) =="0x" then h = h:sub(3, -1) end
	local r = tonumber(h:sub(1, 2), 16) or 255
	local g = tonumber(h:sub(3, 4), 16) or 255
	local b = tonumber(h:sub(5, 6), 16) or 255
	local src = tonumber(h:sub(7, 8), 16) or 255
	local dst = tonumber(h:sub(9, 10), 16) or 0
	return {r = r, g = g, b = b, src = src, dst = dst}
end

local function f_commandlistData(t, str, align, col)
	local t_insert = {}
	str = str .. '<#>'
	for m1, m2 in str:gmatch('(.-)<([^<>%s]+)>') do
		if m1 ~= '' then
			table.insert(t_insert, {glyph = false, text = m1, align = align, col = col})
		end
		m2 = m2:gsub('&lt;', '<'):gsub('&gt;', '>'):gsub('&amp;', '&')
		if not m2:match('^#[A-Za-z0-9]+$') and not m2:match('^/$') and not m2:match('^#$') then
			table.insert(t_insert, {glyph = true, text = m2, align = align, col = col})
		elseif m2:match('^#[A-Za-z0-9]+$') then
			col = colorFromHex(m2)
		elseif m2:match('^/$') then
			col = {}
		end
	end
	if align == -1 then
		for i = #t_insert, 1, -1 do
			table.insert(t, t_insert[i])
		end
	else
		for i = 1, #t_insert do
			table.insert(t, t_insert[i])
		end
	end
	return t, col
end

function menu.f_commandlistParse()
	menu.t_movelists = {}
	for side, tbl in ipairs({start.p[1].t_selected, start.p[2].t_selected}) do
		for member, sel in ipairs(tbl) do
			if sel.movelistLine == nil then
				sel.movelistLine = 1
			end
			local pn = side
			if member > 1 then
				pn = pn + (member - 1) * 2
			end
			if player(pn) and aiLevel() == 0 then
				local movelist = getMovelist()
				if sel.movelistText ~= movelist then
					sel.movelistText = movelist
					sel.commandlist = nil
					sel.movelistLine = 1
					if movelist ~= '' then
						-- Replace glyph tokens with <token> for later lookup in motif.glyphs.
						for k, v in main.f_sortKeys(motif.glyphs, function(t, a, b) return string.len(a) > string.len(b) end) do
							local s = movelist
							movelist = s:gsub('()' .. main.f_escapePattern(k), function(pos)
								-- If the match starts immediately after a '<', it's already inside a tag.
								-- Leave it unchanged to prevent nested replacements.
								if pos > 1 and s:sub(pos - 1, pos - 1) == '<' then
									return k
								end
								local escaped = k:gsub('&', '&amp;'):gsub('<', '&lt;'):gsub('>', '&gt;')
								return '<' .. escaped .. '>'
							end)
						end
						local t = {}
						local col = {}
						for line in movelist:gmatch('([^\n]*)\n?') do
							line = line:gsub('%s+$', '')
							local subt = {}
							for m in line:gmatch('(	*[^	]+)') do
								local tabs = 0
								m = m:gsub('^(	*)', function(m1)
									tabs = string.len(m1)
									return ''
								end)
								local align = 1 --left align
								if tabs == 1 then
									align = 0 --center align
								elseif tabs > 1 then
									align = -1 --right align
								end
								subt, col = f_commandlistData(subt, m, align, col)
							end
							table.insert(t, subt)
						end
						t[#t] = nil --blank line produced by regexp matching
						sel.commandlist = t
					end
				end
				table.insert(menu.t_movelists, {
					pn = pn,
					name = displayName(),
					tbl = sel,
					commandlist = sel.commandlist,
				})
			end
		end
	end
	if #menu.t_movelists == 0 then
		table.insert(menu.t_movelists, {
			pn = 1,
			name = "",
			tbl = {movelistLine = 1},
			commandlist = nil,
		})
	end
	if menu.movelistChar > #menu.t_movelists then
		menu.movelistChar = 1
	end
	if gameOption('Debug.DumpLuaTables') then main.f_printTable(menu.t_movelists, "debug/t_movelists.txt") end
end

function menu.f_commandlistRender(sec, t)
	local cmdList = {}
	if t.commandlist ~= nil then
		cmdList = t.commandlist
	else
		table.insert(cmdList, {{glyph = false, text = sec.movelist.text.text, align = 1, col = {}}})
	end
	if esc() or getInput(-1, sec.menu.cancel.key, sec.menu.done.key) then
		sndPlay(motif.Snd, sec.cancel.snd[1], sec.cancel.snd[2])
		menu.itemname = ''
		return
	elseif getInput(-1, sec.menu.subtract.key) and #menu.t_movelists > 1 then
		sndPlay(motif.Snd, sec.cursor.move.snd[1], sec.cursor.move.snd[2])
		menu.movelistChar = menu.movelistChar - 1
		if menu.movelistChar < 1 then
			menu.movelistChar = #menu.t_movelists
		end
	elseif getInput(-1, sec.menu.add.key) and #menu.t_movelists > 1 then
		sndPlay(motif.Snd, sec.cursor.move.snd[1], sec.cursor.move.snd[2])
		menu.movelistChar = menu.movelistChar + 1
		if menu.movelistChar > #menu.t_movelists then
			menu.movelistChar = 1
		end
	elseif getInput(-1, sec.menu.previous.key) and t.tbl.movelistLine > 1 then
		sndPlay(motif.Snd, sec.cursor.move.snd[1], sec.cursor.move.snd[2])
		t.tbl.movelistLine = t.tbl.movelistLine - 1
	elseif getInput(-1, sec.menu.next.key) and t.tbl.movelistLine <= #cmdList - sec.movelist.window.visibleitems then
		sndPlay(motif.Snd, sec.cursor.move.snd[1], sec.cursor.move.snd[2])
		t.tbl.movelistLine = t.tbl.movelistLine + 1
	end
	--draw overlay
	rectDraw(sec.movelist.overlay.RectData)
	--draw title
	textImgReset(sec.movelist.title.TextSpriteData)
	textImgSetText(sec.movelist.title.TextSpriteData, main.f_itemnameUpper(string.format(sec.movelist.title.text, t.name), sec.movelist.title.uppercase))
	textImgDraw(sec.movelist.title.TextSpriteData)
	--draw commands
	local i = 0
	for n = t.tbl.movelistLine, math.min(t.tbl.movelistLine + sec.movelist.window.visibleitems + 1, #cmdList) do
		i = i + 1
		local alignOffset = 0
		local lengthOffset = 0
		local align = 1
		local width = 0
		for k, v in ipairs(cmdList[n]) do
			if v.text ~= '' then
				alignOffset = 0
				if v.align == 0 then --center align
					alignOffset = sec.movelist.window.width * 0.5
				elseif v.align == -1 then --right align
					alignOffset = sec.movelist.window.width
				end
				if v.align ~= align then
					lengthOffset = 0
					align = v.align
				end
				local fontProps = motif.files.font['font' .. sec.movelist.text.font[1]]
				--render glyph
				if v.glyph and motif.glyphs[v.text] ~= nil then
					local g = motif.glyphs[v.text]
					if g.Size ~= nil and g.AnimData ~= nil then
						local scaleX = fontProps.size[2] * sec.movelist.text.scale[2] / g.Size[2] * sec.movelist.glyphs.scale[1]
						local scaleY = fontProps.size[2] * sec.movelist.text.scale[2] / g.Size[2] * sec.movelist.glyphs.scale[2]
						if v.align == -1 then
							alignOffset = alignOffset - g.Size[1] * scaleX
						end
						animSetScale(g.AnimData, scaleX, scaleY)
						--animSetFacing(g.AnimData, facing)
						animSetPos(
							g.AnimData,
							math.floor(sec.movelist.pos[1] + sec.movelist.text.offset[1] + sec.movelist.glyphs.offset[1] + alignOffset + lengthOffset),
							sec.movelist.pos[2] + sec.movelist.text.offset[2] + sec.movelist.glyphs.offset[2] + main.f_round((fontProps.size[2] + fontProps.spacing[2]) * sec.movelist.text.scale[2] + sec.movelist.text.spacing[2]) * (i - 1)
						)
						animSetWindow(g.AnimData, menu.movelistW[1], menu.movelistW[2], menu.movelistW[3], menu.movelistW[4])
						--animUpdate(g.AnimData)
						animDraw(g.AnimData)
						if k < #cmdList[n] then
							width = g.Size[1] * scaleX + sec.movelist.glyphs.spacing[1]
						end
					end
				--render text
				else
					textImgReset(sec.movelist.text.TextSpriteData)
					local align = v.align
					if align == 0 and lengthOffset ~= 0 then
						align = 1
					end
					textImgSetAlign(sec.movelist.text.TextSpriteData, align)
					textImgSetColor(
						sec.movelist.text.TextSpriteData,
						v.col.r or sec.movelist.text.font[4],
						v.col.g or sec.movelist.text.font[5],
						v.col.b or sec.movelist.text.font[6],
						v.col.a or sec.movelist.text.font[7]
					)
					textImgAddPos(
						sec.movelist.text.TextSpriteData,
						alignOffset + lengthOffset,
						main.f_round((fontProps.size[2] + fontProps.spacing[2]) * sec.movelist.text.scale[2] + sec.movelist.text.spacing[2]) * (i - 1)
					)
					textImgSetText(sec.movelist.text.TextSpriteData, v.text)
					textImgDraw(sec.movelist.text.TextSpriteData)
					if k < #cmdList[n] then
						width = textImgGetTextWidth(sec.movelist.text.TextSpriteData, v.text) * sec.movelist.text.scale[1] + sec.movelist.text.spacing[1]
					end
				end
				if v.align == 0 and not v.glyph and lengthOffset == 0 then
					lengthOffset = lengthOffset + width / 2
				elseif v.align == -1 then
					lengthOffset = lengthOffset - width
				else
					lengthOffset = lengthOffset + width
				end
			end
		end
	end
	--draw scroll arrows
	if #cmdList > sec.movelist.window.visibleitems then
		if t.tbl.movelistLine > 1 then
			animUpdate(sec.movelist.arrow.up.AnimData)
			animDraw(sec.movelist.arrow.up.AnimData)
		end
		if t.tbl.movelistLine <= #cmdList - sec.movelist.window.visibleitems then
			animUpdate(sec.movelist.arrow.down.AnimData)
			animDraw(sec.movelist.arrow.down.AnimData)
		end
	end
end

return menu
