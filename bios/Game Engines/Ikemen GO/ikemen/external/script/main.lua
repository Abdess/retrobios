main = {}
--;===========================================================
--; INITIALIZE DATA
--;===========================================================
do
	local RANDOM_IMAX = 2147483647 -- Go IMax / Park-Miller modulus
	function math.random(min, max)
		local r = getRandom()
		-- math.random() -> float in [0, 1)
		if min == nil then
			return r / RANDOM_IMAX
		end
		-- math.random(max) -> integer in [1, max]
		if max == nil then
			max = min
			min = 1
		end
		min = math.floor(min)
		max = math.floor(max)
		if max < min then
			error("bad argument #2 to 'random' (interval is empty)", 2)
		end
		local range = max - min + 1
		if range <= 0 or range > RANDOM_IMAX then
			error("bad argument to 'random' (interval is too large)", 2)
		end
		-- Match Go Rand(min, max):
		-- return min + Random() / (IMax / range + 1)
		return min + math.floor(r / (math.floor(RANDOM_IMAX / range) + 1))
	end
	-- Keep deterministic engine RNG authoritative.
	-- math.randomseed(...) is intentionally ignored because math.random uses getRandom().
	function math.randomseed(_)
		-- intentionally ignored
	end
end

--;===========================================================
--; COMMON FUNCTIONS
--;===========================================================

--return file content
function main.f_fileRead(path, mode, noError)
	local file = io.open(path, mode or 'r')
	if not file then
		if not noError then
			panicError("\nFile doesn't exist: " .. path)
		end
		return nil
	end

	local str = file:read("*all")
	file:close()
	return str
end

--write to file
function main.f_fileWrite(path, str, mode)
	if str == nil then
		return
	end
	local file = io.open(path, mode or 'w+')
	if file == nil then
		panicError("\nFile doesn't exist: " .. path)
		return
	end
	file:write(str)
	file:close()
end

--returns value depending on button pressed (a = 1; a + start = 7 etc.)
function main.f_btnPalNo(p)
	local s = 0
	if commandGetState(p, '/s') then s = 6 end
	for i, k in ipairs({'a', 'b', 'c', 'x', 'y', 'z'}) do
		if commandGetState(p, k) then return i + s end
	end
	return 0
end

--restore screenpack remapped inputs
function main.f_restoreInput()
	if start.challenger > 0 then
		return
	end
	resetRemapInput()
	-- Restore to the base mapping captured at the mode start.
	for i = 1, gameOption('Config.Players') do
		local v = main.t_baseRemapInput[i] or i
		if i ~= v then
			remapInput(i, v)
		end
	end
end

-- capture current remap state as the "base" mapping restored after each match
function main.f_saveBaseRemapInput()
	main.t_baseRemapInput = {}
	for i = 1, gameOption('Config.Players') do
		main.t_baseRemapInput[i] = getRemapInput(i)
	end
end

--check if file exists
function main.f_fileExists(file)
	if file == '' then
		return false
	end
	return fileExists(file)
end

--prints "t" table content into "toFile" file
function main.f_printTable(t, toFile)
	local txt = ''
	local print_t_cache = {}
	local function sub_print_t(t, indent)
		if print_t_cache[tostring(t)] then
			txt = txt .. indent .. '*' .. tostring(t) .. '\n'
		else
			print_t_cache[tostring(t)] = true
			if type(t) == 'table' then
				for pos, val in pairs(t) do
					local k = (type(pos) == 'string') and ('[' .. string.format('%q', pos) .. ']') or  ('[' .. tostring(pos) .. ']')
					if type(val) == 'table' then
						txt = txt .. indent .. k .. ' => ' .. tostring(val) .. ' {' .. '\n'
						sub_print_t(val, indent .. string.rep(' ', string.len(k) + 6))
						txt = txt .. indent .. string.rep(' ', string.len(k) + 4) .. '}' .. '\n'
					elseif type(val) == 'string' then
						txt = txt .. indent .. k .. ' => "' .. val .. '"' .. '\n'
					else
						txt = txt .. indent .. k .. ' => ' .. tostring(val) ..'\n'
					end
				end
			else
				txt = txt .. indent .. tostring(t) .. '\n'
			end
		end
	end
	if type(t) == 'table' then
		txt = txt .. tostring(t) .. ' {' .. '\n'
		sub_print_t(t, '  ')
		txt = txt .. '}' .. '\n'
	else
		sub_print_t(t, '  ')
	end
	main.f_fileWrite(toFile or 'debug/table_print.txt', txt)
end

--split strings
function main.f_strsplit(delimiter, text)
	local list = {}
	local pos = 1
	if string.find('', delimiter, 1) then
		if string.len(text) == 0 then
			table.insert(list, text)
		else
			for i = 1, string.len(text) do
				table.insert(list, string.sub(text, i, i))
			end
		end
	else
		while true do
			local first, last = string.find(text, delimiter, pos)
			if first then
				table.insert(list, string.sub(text, pos, first - 1))
				pos = last + 1
			else
				table.insert(list, string.sub(text, pos))
				break
			end
		end
	end
	return list
end

--escape ().%+-*?[^$ characters
function main.f_escapePattern(str)
	return str:gsub('([^%w])', '%%%1')
end

--return argument or default value
function main.f_arg(arg, default)
	if arg ~= nil then
		return arg
	end
	return default
end

--command line global flags
if getCommandLineValue("-ailevel") ~= nil then
	modifyGameOption('Options.Difficulty', math.max(1, math.min(tonumber(getCommandLineValue("-ailevel")), 8)))
end
if getCommandLineValue("-speed") ~= nil then
	local speed_input = tonumber(getCommandLineValue("-speed"))
	if speed_input ~= nil and speed_input >= -9 and speed_input <= 9 then
		local target_game_speed
		if speed_input > 0 then
			target_game_speed = speed_input
		elseif speed_input == 0 then
			target_game_speed = 0
		else
			if speed_input >= -1 then
				target_game_speed = speed_input * 5
			else
				target_game_speed = speed_input * 0.5 - 4.5
			end
		end
		setGameSpeed(target_game_speed)
	end
end
if getCommandLineValue("-speedtest") ~= nil then
	local target_speed = gameOption('Debug.SpeedTest')
	local custom_speed = tonumber(getCommandLineValue("-speedtest"))
	if custom_speed ~= nil and custom_speed > 0 then
		target_speed = custom_speed
	end

	setGameSpeed(math.floor(60 * (target_speed - 1) / gameOption('Options.GameSpeedStep') + 0.5))
end
if getCommandLineValue("-framerate") ~= nil then
	local target_framerate = gameOption('Video.Framerate')
	custom_framerate = tonumber(getCommandLineValue("-framerate"))
	if custom_framerate ~= nil and custom_framerate > 0 then
		target_framerate = custom_framerate
	end
	modifyGameOption('Video.Framerate', target_framerate)
end
if getCommandLineValue("-nosound") ~= nil then
	modifyGameOption('Sound.MasterVolume', 0)
end
if getCommandLineValue("-togglelifebars") ~= nil then
	toggleLifebarDisplay()
end
if getCommandLineValue("-maxpowermode") ~= nil then
	toggleMaxPowerMode()
end
if getCommandLineValue("-debug") ~= nil then
	toggleDebugDisplay()
end
if getCommandLineValue("-setvolume") ~= nil and getCommandLineValue("-nosound") == nil then
	modifyGameOption('Sound.MasterVolume', getCommandLineValue("-setvolume"))
end
if getCommandLineValue("-windowed") ~= nil then
	modifyGameOption('Video.Fullscreen', false)
end
if getCommandLineValue("-width") ~= nil then
	modifyGameOption('Video.GameWidth', getCommandLineValue("-width"))
end
if getCommandLineValue("-height") ~= nil then 
	modifyGameOption('Video.GameHeight', getCommandLineValue("-height"))
end
if getCommandLineValue("-tcpport") ~= nil then
	modifyGameOption('Netplay.ListenPort', getCommandLineValue("-tcpport"))
end
if getCommandLineValue("-udpport") ~= nil then
	modifyGameOption('Netplay.Rollback.Port', getCommandLineValue("-udpport"))
end

-- Lua Hook System
-- Allows hooking additional code into existing functions, from within external
-- modules, without having to worry as much about your code being removed by
-- engine update.
-- https://github.com/ikemen-engine/Ikemen-GO/wiki/lua#hook-system
hook = {
	lists = {}
}

function hook.add(list, name, func)
	if hook.lists[list] == nil then
		hook.lists[list] = {}
	end
	hook.lists[list][name] = func
end

function hook.run(list, ...)
	if hook.lists[list] then
		for i, k in pairs(hook.lists[list]) do
			k(...)
		end
	end
end

function hook.runFirst(list, ...)
	if hook.lists[list] then
		for _, k in pairs(hook.lists[list]) do
			local ret = k(...)
			if ret ~= nil then
				return ret
			end
		end
	end
end

function hook.stop(list, name)
	hook.lists[list][name] = nil
end

--animDraw at specified coordinates
function main.f_animPosDraw(a, x, y, f)
	if a == nil then
		return
	end
	if x ~= nil then
		animReset(a, {"pos"})
		animAddPos(a, x, y)
	end
	if f ~= nil then
		animSetFacing(a, f)
	end
	animDraw(a)
	animUpdate(a)
end

--copy table content into new table
function main.f_tableCopy(t)
	if t == nil then
		return nil
	end
	t = t or {}
	local t2 = {}
	for k, v in pairs(t) do
		if type(v) == "table" then
			t2[k] = main.f_tableCopy(v)
		else
			t2[k] = v
		end
	end
	return t2
end

--returns table length
function main.f_tableLength(t)
	local n = 0
	for _ in pairs(t) do
		n = n + 1
	end
	return n
end

--randomizes table content
function main.f_tableShuffle(t)
	local rand = math.random
	assert(t, "main.f_tableShuffle() expected a table, got nil")
	local iterations = #t
	local j
	for i = iterations, 2, -1 do
		j = rand(i)
		t[i], t[j] = t[j], t[i]
	end
end

--remove from table
function main.f_tableRemove(t, value)
	for k, v in pairs(t) do
		if v == value then
			table.remove(t, k)
			break
		end
	end
end

--merge 2 tables into 1 overwriting values
local function f_printValue(arg)
	if type(arg) == "table" then
		return arg[1]
	end
	return arg
end
function main.f_tableMerge(t1, t2, key)
	for k, v in pairs(t2) do
		if type(v) == "table" then
			if type(t1[k] or false) == "table" then
				main.f_tableMerge(t1[k] or {}, t2[k] or {}, k)
			elseif (t1[k] ~= nil and type(t1[k]) ~= type(v)) then
				--panicError("\n" .. (k or ''):gsub('_', '.') .. ": Incorrect data type (" .. type(t1[k]) .. " expected, got " .. type(v) .. "): " .. f_printValue(v))
				print((k or ''):gsub('_', '.') .. ": Incorrect data type (" .. type(t1[k]) .. " expected, got " .. type(v) .. "): " .. f_printValue(v))
			else
				t1[k] = v
			end
		elseif type(t1[k] or false) == "table" then
			if v ~= '' then
				t1[k][1] = v
			end
		elseif t1[k] ~= nil and type(t1[k]) ~= type(v) then
			if type(t1[k]) == "string" then
				t1[k] = tostring(v)
			else
				--panicError("\n" .. (k or ''):gsub('_', '.') .. ": Incorrect data type (" .. type(t1[k]) .. " expected, got " .. type(v) .. "): " .. f_printValue(v))
				print((k or ''):gsub('_', '.') .. ": Incorrect data type (" .. type(t1[k]) .. " expected, got " .. type(v) .. "): " .. f_printValue(v))
			end
		else
			t1[k] = v
		end
	end
	return t1
end

-- Appends an itemname entry, or a whole submenu tree, to an already parsed motif menu table.
-- Existing motif entries win: if the same itemname already exists, nothing is overwritten.
function main.f_appendItemname(menu, parent, name, src, before)
	local function itemnameExists(t, name)
		name = tostring(name or '')
		if type(t) ~= 'table' or name == 'back' or name:match('^spacer%d*$') then
			return false
		end
		local pat = '_' .. main.f_escapePattern(name) .. '$'
		local stack = { t }
		while #stack > 0 do
			local cur = stack[#stack]
			stack[#stack] = nil

			for k, v in pairs(cur) do
				if type(k) == 'string' and not k:match('^__') and (k == name or k:match(pat)) then
					return true
				end

				if type(v) == 'table' then
					stack[#stack + 1] = v
				end
			end
		end
		return false
	end

	local function itemnameValue(src)
		if type(src) == 'table' then
			return src.__value
		end
		return src
	end

	local function itemnameOrderedKeys(src)
		local ret, seen = {}, {}
		if type(src.__order) == 'table' then
			for _, k in ipairs(src.__order) do
				if type(k) == 'string' and src[k] ~= nil and not k:match('^__') then
					table.insert(ret, k)
					seen[k] = true
				end
			end
		end
		local rest = {}
		for k in pairs(src) do
			if type(k) == 'string' and not k:match('^__') and not seen[k] then
				table.insert(rest, k)
			end
		end
		table.sort(rest)
		for _, k in ipairs(rest) do
			table.insert(ret, k)
		end
		return ret
	end

	local function insertItemnameOrder(order, key, before)
		if type(order) ~= 'table' then
			return
		end
		for _, v in ipairs(order) do
			if v == key then
				return
			end
		end
		local pos = #order + 1
		if before ~= nil and before ~= '' then
			local anchor = tostring(before)
			if not anchor:find('_', 1, true) then
				local parent = tostring(key):match('^(.*)_')
				if parent ~= nil and parent ~= '' then
					anchor = parent .. '_' .. anchor
				end
			end
			for i, v in ipairs(order) do
				if v == anchor then
					pos = i
					break
				end
			end
		end
		table.insert(order, pos, key)
	end

	if type(menu) ~= 'table' or type(menu.itemname) ~= 'table' or type(menu.itemname_order) ~= 'table' then
		return false
	end
	parent = parent or ''
	name = tostring(name or '')
	if name == '' or src == nil then
		return false
	end

	-- Grouped itemname tables, used by select_info.teammenu.itemname.default.
	if type(menu.itemname[parent]) == 'table' and type(menu.itemname_order[parent]) == 'table' then
		if menu.itemname[parent][name] ~= nil or itemnameExists(menu.itemname, name) then
			return false
		end
		local value = itemnameValue(src)
		if value == nil then
			return false
		end
		menu.itemname[parent][name] = value
		insertItemnameOrder(menu.itemname_order[parent], name, before)
		return true
	end

	-- Flat itemname tables, used by normal motif menus.
	local key = name
	if parent ~= '' then
		key = parent .. '_' .. name
	end
	if menu.itemname[key] ~= nil or itemnameExists(menu.itemname, name) then
		return false
	end
	local value = itemnameValue(src)
	if value == nil then
		return false
	end
	menu.itemname[key] = value
	insertItemnameOrder(menu.itemname_order, key, before)
	if type(src) == 'table' then
		for _, child in ipairs(itemnameOrderedKeys(src)) do
			main.f_appendItemname(menu, key, child, src[child])
		end
	end
	return true
end

--returns bool if table contains value
function main.f_tableHasValue(t, val)
	for k, v in pairs(t) do
		--if v == val then
		if v:match(val) then
			return true
		end
	end
	return false
end

-- rearrange array table indexes based on index numbers stored in a second array table
function main.f_remapTable(src, remap)
	local t = {}
	for i = 1, #remap do
		table.insert(t, src[remap[i]])
	end
	return t
end

--iterate over the table in order
-- basic usage, just sort by the keys:
--for k, v in main.f_sortKeys(t) do
--	print(k, v)
--end
-- this uses an custom sorting function ordering by score descending
--for k, v in main.f_sortKeys(t, function(t, a, b) return t[b] < t[a] end) do
--	print(k, v)
--end
function main.f_sortKeys(t, order)
	-- collect the keys
	local keys = {}
	for k in pairs(t) do table.insert(keys, k) end
	-- if order function given, sort it by passing the table and keys a, b,
	-- otherwise just sort the keys
	if order then
		table.sort(keys, function(a, b) return order(t, a, b) end)
	else
		table.sort(keys)
	end
	-- return the iterator function
	local i = 0
	return function()
		i = i + 1
		if keys[i] then
			return keys[i], t[keys[i]]
		end
	end
end

--round value
function main.f_round(num, places)
	if places ~= nil and places > 0 then
		local mult = 10 ^ places
		return math.floor(num * mult + 0.5) / mult
	end
	return math.floor(num + 0.5)
end

--return playerno teamside
function main.f_playerSide(pn)
	if pn % 2 ~= 0 then --odd value (Player1 side)
		return 1
	end
	return 2
end

--count occurrences of a substring
function main.f_countSubstring(s1, s2)
	return select(2, s1:gsub(s2, ""))
end

-- formats using %s / %i in the order they appear in fmt
function main.f_formatBySpec(fmt, specMap)
	if fmt == nil then return "" end
	if type(fmt) ~= "string" then fmt = tostring(fmt) end
	local args = {}
	local pos = 1
	while true do
		local p = fmt:find("%%", pos)
		if not p then break end
		local nextc = fmt:sub(p + 1, p + 1)
		if nextc == "%" then
			-- literal %%
			pos = p + 2
		else
			-- match a printf-like directive
			local _, e, verb = fmt:find("%%[%-%+ #0]*%d*%.?%d*([A-Za-z])", p)
			if not e then break end
			if verb == "s" then
				args[#args + 1] = tostring(specMap.s or "")
			elseif verb == "i" or verb == "d" or verb == "u" then
				args[#args + 1] = tonumber(specMap.i) or 0
			end
			pos = e + 1
		end
	end
	if #args == 0 then return fmt end
	local fmt2 = fmt
	local ok, out = pcall(string.format, fmt2, unpack(args))
	if not ok then
		print("main.f_formatBySpec ERROR: " .. tostring(out))
		return fmt
	end
	return out
end

--refresh screen every 0.02 during initial loading
main.nextRefresh = os.clock() + 0.02
function main.f_loadingRefresh()
	if os.clock() >= main.nextRefresh then
		refresh()
		textImgDraw(motif.title_info.loading.TextSpriteData)
		main.nextRefresh = os.clock() + 0.02
	end
end

main.pauseMenuActive = false
require('external.script.debug')

loadDebugFont(gameOption('Debug.Font'), gameOption('Debug.FontScale'))

main.t_stageDef = {['random'] = 0}
main.t_charDef = {}
main.t_selChars = {}
main.t_selStages = {}
main.preload = {
	lowQueued = false,
	charState = {},
	stageState = {},
	charHighlight = {},
}

function main.f_waitForPreloads(force)
	if not preloading() then
		return
	end
	if gameOption('Config.BootLoadingMode') ~= 1 and not force then
		return
	end
	local path = motif.title_info.loading.storyboard
	if path ~= '' and loadStoryboard(path) ~= nil then
		while preloading() do
			if not runStoryboard() or storyboardCanceled() then
				break
			end
			main.f_preloadTick(2)
			refresh()
		end
	end
	while preloading() do
		clearColor(0, 0, 0)
		main.f_animPosDraw(motif.title_info.loading.wait.AnimData)
		textImgDraw(motif.title_info.loading.wait.TextSpriteData)
		main.f_preloadTick(2)
		refresh()
	end
end

function main.f_syncCharPaletteData(ref)
	if ref == nil then return false end
	local t_info = getCharInfo(ref)
	if t_info == nil then return false end
	local changed = false
	for row, ch in ipairs(main.t_selChars) do
		if ch.playable and ch.char_ref == ref then
			local oldPalCount = ch.pal and #ch.pal or 0
			local oldDefaultCount = ch.pal_defaults and #ch.pal_defaults or 0
			ch.pal = t_info.pal
			ch.pal_defaults = t_info.pal_defaults
			ch.pal_keymap = t_info.pal_keymap
			if oldPalCount ~= #ch.pal or oldDefaultCount ~= #ch.pal_defaults then
				changed = true
			end
		end
	end
	if changed and start ~= nil and start.p ~= nil then
		for side = 1, 2 do
			if start.p[side] ~= nil and start.p[side].t_selTemp ~= nil then
				for _, st in ipairs(start.p[side].t_selTemp) do
					if st ~= nil and st.ref == ref then
						-- Force palette menu to rebuild using the refreshed palette list.
						st.validPals = nil
						st.validPalsCharRef = nil
						st.currentIdx = nil
					end
				end
			end
		end
	end
	return changed
end

function main.f_preloadSetCharHighlight(player, ref)
	if gameOption('Config.BootLoadingMode') == 0 then
		return
	end
	if player == nil then return end
	local old = main.preload.charHighlight[player]
	if old == ref then
		return
	end
	main.preload.charHighlight[player] = ref
	if old ~= nil then
		local stillHighlighted = false
		for _, v in pairs(main.preload.charHighlight) do
			if v == old then
				stillHighlighted = true
				break
			end
		end
		if not stillHighlighted then
			queueCharPreload(old, 1)
		end
	end
	if ref ~= nil then
		queueCharPreload(ref, 2)
		if getCharPreloadStatus(ref) == 'ready' then
			main.f_syncCharPaletteData(ref)
			main.f_materializeCharByRef(ref)
		end
	end
end

function main.f_materializeCharCell(row)
	local ch = main.t_selChars[row]
	if ch == nil or ch.playable ~= true or ch.char_ref == nil or ch.cell_data_ready then
		return ch and ch.cell_data_ready or false
	end
	local params = motif.select_info.portrait
	for _, v in pairs({{params.anim, -1}, params.spr}) do
		if v[1] ~= -1 then
			local a = animGetPreloadedCharData(ch.char_ref, v[1], v[2])
			if a then
				animSetLocalcoord(a, motif.info.localcoord[1], motif.info.localcoord[2])
				animSetLayerno(a, params.layerno)
				animSetPos(a, 0, 0)
				animSetScale(
					a,
					params.scale[1] * ch.portraitscale * motif.info.localcoord[1] / ch.localcoord,
					params.scale[2] * ch.portraitscale * motif.info.localcoord[1] / ch.localcoord
				)
				animSetFacing(a, params.facing)
				animSetXShear(a, params.xshear)
				animSetAngle(a, params.angle)
				animSetXAngle(a, params.xangle)
				animSetYAngle(a, params.yangle)
				animSetProjection(a, params.projection)
				animSetFocalLength(a, params.focallength)
				animSetWindow(a, params.window[1], params.window[2], params.window[3], params.window[4])
				animUpdate(a)
				ch.cell_data = a
				ch.cell_data_ready = true
				return true
			end
		end
	end
	return false
end

function main.f_materializeStagePortrait(stageNo)
	local st = main.t_selStages[stageNo]
	if st == nil or st.anim_data_ready then
		return st and st.anim_data_ready or false
	end
	local function f_makeStageAnim(params, fieldName)
		for _, v in pairs({{params.anim, -1}, params.spr}) do
			if #v > 0 and v[1] ~= -1 then
				local a = animGetPreloadedStageData(stageNo, v[1], v[2])
				if a then
					animSetLocalcoord(a, motif.info.localcoord[1], motif.info.localcoord[2])
					animSetLayerno(a, params.layerno)
					animSetPos(a, 0, 0)
					animSetScale(
						a,
						params.scale[1] * st.portraitscale * motif.info.localcoord[1] / st.localcoord,
						params.scale[2] * st.portraitscale * motif.info.localcoord[1] / st.localcoord
					)
					animSetFacing(a, params.facing)
					animSetXShear(a, params.xshear)
					animSetAngle(a, params.angle)
					animSetXAngle(a, params.xangle)
					animSetYAngle(a, params.yangle)
					animSetProjection(a, params.projection)
					animSetFocalLength(a, params.focallength)
					local wnd = params.window
					if wnd == nil or #wnd < 4 then
						wnd = {0, 0, motif.info.localcoord[1], motif.info.localcoord[2]}
					end
					animSetWindow(a, wnd[1], wnd[2], wnd[3], wnd[4])
					animUpdate(a)
					st[fieldName] = a
					return true
				end
			end
		end
		return false
	end
	local ok1 = f_makeStageAnim(motif.select_info.stage.portrait, "anim_data")
	local ok2 = f_makeStageAnim(motif.vs_screen.stage.portrait, "vs_anim_data")
	st.anim_data_ready = ok1 or ok2
	return st.anim_data_ready
end

function main.f_preloadTick(limit)
	if gameOption('Config.BootLoadingMode') == 0 then
		return
	end
	limit = limit or 4
	local n = 0

	for row, ch in ipairs(main.t_selChars) do
		if n >= limit then break end
		if ch.playable and ch.char_ref ~= nil and not ch.cell_data_ready then
			local state, err = getCharPreloadStatus(ch.char_ref)
			local prev = main.preload.charState[ch.char_ref]
			if state ~= prev then
				main.preload.charState[ch.char_ref] = state
				if state == 'ready' then
					--print("Char preload ready ref=" .. tostring(ch.char_ref) .. " row=" .. tostring(row))
					main.f_syncCharPaletteData(ch.char_ref)
				-- elseif state == 'error' then
					-- print("Char preload error ref=" .. tostring(ch.char_ref) .. " row=" .. tostring(row) .. ": " .. tostring(err))
				end
			end
			if state == 'ready' then
				if main.f_materializeCharCell(row) then
					start.needUpdateDrawList = true
					n = n + 1
				end
			end
		end
	end
	for stageNo, st in ipairs(main.t_selStages) do
		if n >= limit then break end
		if not st.anim_data_ready then
			local state, err = getStagePreloadStatus(stageNo)
			local prev = main.preload.stageState[stageNo]
			if state ~= prev then
				main.preload.stageState[stageNo] = state
				if state == 'ready' then
					--print("Stage preload ready stage=" .. tostring(stageNo))
				-- elseif state == 'error' then
					-- print("Stage preload error stage=" .. tostring(stageNo) .. ": " .. tostring(err))
				end
			end
			if state == 'ready' then
				if main.f_materializeStagePortrait(stageNo) then
					start.needUpdateDrawList = true
					n = n + 1
				end
			end
		end
	end
end

function main.f_queueAllPreloadsLow()
	if gameOption('Config.BootLoadingMode') == 0 then
		return
	end
	if main.preload.lowQueued then
		return
	end
	main.preload.lowQueued = true
	for _, ch in ipairs(main.t_selChars) do
		if ch.playable and ch.char_ref ~= nil then
			queueCharPreload(ch.char_ref, 1)
		end
	end
	for stageNo = 1, #main.t_selStages do
		queueStagePreload(stageNo, 1)
	end
end

function main.f_materializeCharByRef(ref)
	if ref == nil then return false end
	local ok = false
	for row, ch in ipairs(main.t_selChars) do
		if ch.playable and ch.char_ref == ref and not ch.cell_data_ready then
			main.f_syncCharPaletteData(ref)
			if main.f_materializeCharCell(row) then
				start.needUpdateDrawList = true
				ok = true
			end
		end
	end
	return ok
end

function main.f_preloadBoostChar(ref)
	if gameOption('Config.BootLoadingMode') == 0 then
		return
	end
	if ref == nil then return end
	queueCharPreload(ref, 2)
	if getCharPreloadStatus(ref) == 'ready' then
		main.f_syncCharPaletteData(ref)
		main.f_materializeCharByRef(ref)
	end
end

function main.f_preloadBoostStage(stageNo)
	if gameOption('Config.BootLoadingMode') == 0 then
		return
	end
	if stageNo == nil or stageNo <= 0 then return end
	queueStagePreload(stageNo, 2)
	if getStagePreloadStatus(stageNo) == 'ready' then
		if main.f_materializeStagePortrait(stageNo) then
			start.needUpdateDrawList = true
		end
	end
end

--;===========================================================
--; COMMAND LINE QUICK VS
--;===========================================================
function main.f_commandLine()
	local flags = getCommandLineFlags()
	local loadMotif = flags['-loadmotif'] ~= nil
	if loadMotif then
		main.f_default()
	end
	main.pauseMenu = loadMotif
	setGameMode('quickvs')
	if loadMotif then
		start.f_selectReset(true)
	end
	setCredits(-1)
	-- No need for asynchronous loading when running from command line. Fixes race conditions with Turns teammate faces
	modifyGameOption('Config.BootLoadingMode', 0)
	if not loadMotif then
		loadFightScreen()
	end
	local ref = #main.t_selChars
	local t_teamMode = {0, 0}
	local t_numChars = {0, 0}
	local t_matchWins = {
		draw = {gameOption('Options.Match.MaxDrawGames'), gameOption('Options.Match.MaxDrawGames')},
		simul = {gameOption('Options.Simul.Match.Wins'), gameOption('Options.Simul.Match.Wins')},
		single = {gameOption('Options.Match.Wins'), gameOption('Options.Match.Wins')},
		tag = {gameOption('Options.Tag.Match.Wins'), gameOption('Options.Tag.Match.Wins')},
	}
	local roundTime = gameOption('Options.Time')
	setFightScreenElements({guardbar = gameOption('Options.GuardBreak'), stunbar = gameOption('Options.Dizzy'), redlifebar = gameOption('Options.RedLife')})
	local frames = fightScreenVar("time.framespercount")
	local t = {}
	local t_assignedPals = {}
	for k, v in pairs(flags) do
		if k:match('^-p[0-9]+$') then
			local num = tonumber(k:match('^-p([0-9]+)'))
			local player = main.f_playerSide(num)
			t_numChars[player] = t_numChars[player] + 1
			local pal = 1
			if flags['-p' .. num .. '.color'] ~= nil or flags['-p' .. num .. '.pal'] ~= nil then
				pal = tonumber(flags['-p' .. num .. '.color']) or tonumber(flags['-p' .. num .. '.pal'])
			elseif t_assignedPals[v] ~= nil then
				for i = 1, 12 do
					if t_assignedPals[v][i] == nil then
						pal = i
						break
					end
				end
			end
			if t_assignedPals[v] == nil then
				t_assignedPals[v] = {}
			end
			t_assignedPals[v][pal] = true
			local ai = 0
			if flags['-p' .. num .. '.ai'] ~= nil then
				ai = tonumber(flags['-p' .. num .. '.ai'])
			end
			local input = player
			if flags['-p' .. num .. '.input'] ~= nil then
				input = tonumber(flags['-p' .. num .. '.input'])
			end
			table.insert(t, {character = v, player = player, num = num, pal = pal, ai = ai, input = input, override = {}})
			if flags['-p' .. num .. '.life'] ~= nil then
				t[#t].override['life'] = tonumber(flags['-p' .. num .. '.life'])
			end
			if flags['-p' .. num .. '.lifeMax'] ~= nil then
				t[#t].override['lifemax'] = tonumber(flags['-p' .. num .. '.lifeMax'])
			end
			if flags['-p' .. num .. '.power'] ~= nil then
				t[#t].override['power'] = tonumber(flags['-p' .. num .. '.power'])
			end
			if flags['-p' .. num .. '.dizzyPoints'] ~= nil then
				t[#t].override['dizzypoints'] = tonumber(flags['-p' .. num .. '.dizzyPoints'])
			end
			if flags['-p' .. num .. '.guardPoints'] ~= nil then
				t[#t].override['guardpoints'] = tonumber(flags['-p' .. num .. '.guardPoints'])
			end
			hook.run("main.f_commandLine.player", t[#t], flags, num, player)
			refresh()
		elseif k:match('^-tmode1$') then
			t_teamMode[1] = tonumber(v)
		elseif k:match('^-tmode2$') then
			t_teamMode[2] = tonumber(v)
		elseif k:match('^-time$') then
			roundTime = tonumber(v)
		elseif k:match('^-rounds$') then
			for i = 1, 2 do
				t_matchWins.single[i] = tonumber(v)
				t_matchWins.simul[i] = tonumber(v)
				t_matchWins.tag[i] = tonumber(v)
			end
		elseif k:match('^-draws$') then
			for i = 1, 2 do
				t_matchWins.draw[i] = tonumber(v)
			end
		end
	end
	--Ensure proper team modes and prepare time scaling
	local t_framesMul = {1, 1} --Skip Options.Tag.TimeScaling here for simplicity
	for side = 1, 2 do
		if t_teamMode[side] == 0 and t_numChars[side] > 1 then
			t_teamMode[side] = 1 --Default to Simul if multiple characters
		end
		if t_teamMode[side] == 3 then --Tag
			t_framesMul[side] = t_numChars[side]
		end
		if loadMotif then
			start.p[side].teamMode = t_teamMode[side]
			start.p[side].numChars = t_numChars[side]
		end
	end
	--Rounds to win. Determined by enemy team mode
	for side = 1, 2 do
		local enemy = 3 - side
		if t_teamMode[enemy] == 1 then --Simul
			setMatchWins(side, t_matchWins.simul[enemy])
		elseif t_teamMode[enemy] == 2 then --Turns
			setMatchWins(side, t_numChars[enemy])
		elseif t_teamMode[enemy] == 3 then --Tag
			setMatchWins(side, t_matchWins.tag[enemy])
		else --Single
			setMatchWins(side, t_matchWins.single[enemy])
		end
		setMatchMaxDrawGames(side, t_matchWins.draw[side])
	end
	frames = frames * math.max(t_framesMul[1], t_framesMul[2])
	setTimeFramesPerCount(frames)
	setRoundTime(math.max(-1, roundTime * frames))
	local stage = gameOption('Debug.StartStage')
	if flags['-s'] ~= nil then
		for _, v in ipairs({flags['-s'], 'stages/' .. flags['-s'], 'stages/' .. flags['-s'] .. '.def'}) do
			if main.f_fileExists(v) then
				stage = v
				break
			end
		end
	end
	local stageKey = stage:lower()
	local stageRef = main.t_stageDef[stageKey]
	if stageRef == nil then
		if loadMotif then
			stageRef = start.f_getStageRef(stage)
		else
			if addStage(stage) == 0 then
				panicError("\nUnable to add stage: " .. stage .. "\n")
			end
			stageRef = #main.t_selStages + 1
			main.t_stageDef[stageKey] = stageRef
		end
		if stageRef == nil then
			panicError("\nUnable to add stage: " .. stage .. "\n")
		end
	end
	clearSelected()
	setMatchNo(1)
	selectStage(stageRef)
	setTeamMode(1, t_teamMode[1], t_numChars[1])
	setTeamMode(2, t_teamMode[2], t_numChars[2])
	if gameOption('Debug.DumpLuaTables') then main.f_printTable(t, 'debug/t_quickvs.txt') end
	local t_params = {}
	--iterate over the table in -p order ascending
	for _, v in main.f_sortKeys(t, function(t, a, b) return t[b].num > t[a].num end) do
		local charKey = v.character:lower()
		local charRef = main.t_charDef[charKey]
		if charRef == nil then
			if loadMotif then
				charRef = start.f_getCharRef(v.character)
			else
				addChar(v.character)
				charRef = ref
				main.t_charDef[charKey] = charRef
				ref = ref + 1
			end
		end
		if charRef == nil then
			panicError("\nUnable to add character. No such file or directory: " .. v.character .. "\n")
		end
		selectChar(v.player, charRef, v.pal)
		setCom(v.num, v.ai)
		remapInput(v.num, v.input)
		-- fold overrides into loadStart() params (p1.<member>.<field>=...)
		local member = math.ceil(v.num / 2)
		for k2, v2 in pairs(v.override) do
			table.insert(t_params, 'p' .. v.player .. '.' .. member .. '.' .. k2 .. '=' .. tostring(v2))
		end
		if loadMotif then
			table.insert(start.p[v.player].t_selected, {
				ref = charRef,
				pal = v.pal,
				pn = start.f_getPlayerNo(v.player, #start.p[v.player].t_selected + 1)
			})
		end
	end
	hook.run("main.f_commandLine", t, flags, t_teamMode, t_numChars, t_matchWins, t_params)
	if flags['-ip'] ~= nil then
		enterNetPlay(flags['-ip'])
		while not connected() do
			if esc() then
				exitNetPlay()
				os.exit()
			end
			refresh()
		end
		refresh()
		if not synchronize() then
			replayStop()
			exitNetPlay()
			exitReplay()
			print(getSessionWarning())
			os.exit()
		end
		if loadMotif then
			main.f_clearShuffleTables()
		end
		refresh()
	end
	if loadMotif then
		table.insert(t_params, 1, start.f_buildLoadStartParams())
	else
		table.insert(t_params, 'pausemenu=false')
	end
	loadStart(table.concat(t_params, ', '))
	while loading() do
		--do nothing
	end
	game()
	if flags['-log'] ~= nil then
		main.f_printTable(getGameStats().Matches[matchNo()], flags['-log'])
	end
	os.exit()
end

--initiate quick match only if -loadmotif flag is missing
if getCommandLineValue("-p1") ~= nil and getCommandLineValue("-p2") ~= nil and getCommandLineValue("-loadmotif") == nil then
	main.f_commandLine()
end

--;===========================================================
--; LOAD DATA
--;===========================================================
main.t_unlockLua = {chars = {}, stages = {}, modes = {}}

motif = loadMotif()
if gameOption('Debug.DumpLuaTables') then main.f_printTable(motif, "debug/loadMotif.txt") end

loadFightScreen()
main.f_loadingRefresh()

local function showSessionWarning()
	local text = getSessionWarning()
	if text == nil or text == '' then
		return false
	end
	main.f_warning(text, motif[main.group], motif[main.background])
	return true
end

--warning display
function main.f_warning(text, sec, background, overlay, titleData, textData, cancel_snd, done_snd)
	local overlay = overlay or motif.warning_info.overlay.RectData
	local titleData = titleData or motif.warning_info.title.TextSpriteData
	local textData = textData or motif.warning_info.text.TextSpriteData
	local cancel_snd = cancel_snd or motif.warning_info.cancel.snd
	local done_snd = done_snd or motif.warning_info.done.snd
	local ret
	textImgReset(textData)
	textImgSetText(textData, text)
	resetKey()
	esc(false)
	while true do
		if esc() or getInput(-1, sec.menu.cancel.key) then
			esc(false)
			sndPlay(motif.Snd, cancel_snd[1], cancel_snd[2])
			ret = false
			break
		elseif getKey() ~= '' or getInput(-1, sec.menu.done.key) then
			sndPlay(motif.Snd, done_snd[1], done_snd[2])
			resetKey()
			ret = true
			break
		end
		--draw clearcolor
		clearColor(background.bgclearcolor[1], background.bgclearcolor[2], background.bgclearcolor[3])
		--draw layerno = 0 backgrounds
		bgDraw(background.BGDef, 0)
		--draw overlay
		rectDraw(overlay)
		--draw title
		textImgDraw(titleData)
		--draw text
		textImgDraw(textData)
		--draw layerno = 1 backgrounds
		bgDraw(background.BGDef, 1)
		--tick preload
		main.f_preloadTick(2)
		--end loop
		refresh()
	end
	resetTokenGuard()
	return ret
end

function main.f_drawInput(textData, text, sec, background, overlay, defaultInput)
	local input = defaultInput or ''
	resetKey()
	while true do
		if esc() then
			input = ''
			break
		end
		if getKey(sec.textinput.confirm.keycode) then
			break
		elseif getKey(sec.textinput.trim.keycode) then
			input = input:sub(2)
		elseif getKey(sec.textinput.truncate.keycode) then
			input = input:sub(1, -2)
		elseif getKey(sec.textinput.paste.keycode) then
			input = input .. getClipboardString()
		else
			input = input .. getKeyText()
		end
		resetKey()
		--draw clearcolor
		clearColor(background.bgclearcolor[1], background.bgclearcolor[2], background.bgclearcolor[3])
		--draw layerno = 0 backgrounds
		bgDraw(background.BGDef, 0)
		--draw overlay
		rectDraw(overlay)
		--draw text
		textImgReset(textData)
		textImgSetText(textData, text)
		textImgAddText(textData, '\\n\\n' .. input)
		textImgDraw(textData)
		--draw layerno = 1 backgrounds
		bgDraw(background.BGDef, 1)
		--tick preload
		main.f_preloadTick(2)
		--end loop
		refresh()
	end
	resetKey()
	resetTokenGuard()
	return input
end

--add characters and stages using select.def
function main.f_charParam(t, c)
	if c:match('%.[Dd][Ee][Ff]$') then --stage
		c = c:gsub('\\', '/')
		if main.f_fileExists(c) then
			if t.stage == nil then
				t.stage = {}
			end
			table.insert(t.stage, c)
		else
			print("Stage doesn't exist: " .. c)
		end
	else --param = value
		local param, value = c:match('^(.-)%s*=%s*(.-)$')
		if param ~= nil and value ~= nil and param ~= '' and value ~= '' then
			t[param] = tonumber(value)
			if t[param] == nil then
				t[param] = value
			end
		end
	end
end

-- Converts character order params to a roster order-table key:
local function orderParamMode(param)
	if param == 'order' then
		return 'default'
	end
	local mode = tostring(param or ''):match('^order(.+)$')
	if mode ~= nil and mode ~= '' then
		return mode
	end
	return nil
end

-- Add char ref to unified per-mode order table.
local function addOrderChar(mode, order, ref)
	mode = mode or 'default'
	order = tonumber(order)
	if order == nil or ref == nil then
		return
	end
	if main.t_orderChars[mode] == nil then
		main.t_orderChars[mode] = {}
	end
	if main.t_orderChars[mode][order] == nil then
		main.t_orderChars[mode][order] = {}
	end
	table.insert(main.t_orderChars[mode][order], ref)
end

function main.f_addChar(line, playable, loading, slot)
	table.insert(main.t_selChars, {})
	local row = #main.t_selChars
	local slot = slot or false
	local valid = false
	--store 'unlock' param and get rid of everything that follows it
	local unlock = ''
	line = line:gsub(',%s*unlock%s*=%s*(.-)%s*$', function(m1)
		unlock = (m1 or ''):match('^%s*(.-)%s*$')
		return ''
	end)
	--parse rest of the line
	for i, c in ipairs(main.f_strsplit(',', line)) do --split using "," delimiter
		c = c:match('^%s*(.-)%s*$')
		if i == 1 then
			if c == '' then
				playable = false
				break
			end
			c = c:gsub('\\', '/')
			c = tostring(c)
			addChar(c, line)
			if c:lower() == 'skipslot' then
				main.t_selChars[row].skip = 1
				playable = false
				break
			end
			if getCharName(row - 1) == 'dummyslot' then
				playable = false
				break
			end
			main.t_charDef[c:lower()] = row - 1
			if c:lower() == 'randomselect' then
				main.t_selChars[row].char = c:lower()
				playable = false
				break
			end
			main.t_selChars[row].char = c
			valid = true
			main.t_selChars[row].playable = playable
			local t_info = getCharInfo(row - 1)
			main.t_selChars[row] = main.f_tableMerge(main.t_selChars[row], t_info)
			main.t_selChars[row].dir = main.t_selChars[row].def:gsub('[^/]+%.def$', '')
			if playable then
				for _, v in ipairs({'intro', 'ending', 'arcadepath'}) do
					if main.t_selChars[row][v] ~= '' then
						main.t_selChars[row][v] = searchFile(main.t_selChars[row][v], {main.t_selChars[row].dir, '', motif.def, 'data/'})
					end
				end
				hook.run("main.f_addChar.files", main.t_selChars[row])
				main.t_selChars[row].order = 1
			end
		else
			main.f_charParam(main.t_selChars[row], c)
		end
	end
	if main.t_selChars[row].hidden == nil then
		main.t_selChars[row].hidden = 0
	end
	if main.t_selChars[row].char ~= nil then
		main.t_selChars[row].char_ref = main.t_charDef[main.t_selChars[row].char:lower()]
	end
	if playable then
		-- order / order<gamemode> params
		local hasSurvivalOrder = false
		for k, v in pairs(main.t_selChars[row]) do
			local mode = orderParamMode(k)
			if mode ~= nil then
				if mode == 'survival' then
					hasSurvivalOrder = true
				end
				addOrderChar(mode, v, row - 1)
			end
		end
		-- Preserve legacy Survival behavior: chars without ordersurvival still belong to survival order 1.
		if not hasSurvivalOrder then
			addOrderChar('survival', 1, row - 1)
		end
		--bonus games mode
		if main.t_selChars[row].bonus ~= nil and main.t_selChars[row].bonus == 1 then
			table.insert(main.t_bonusChars, row - 1)
		end
		--unlock
		if unlock ~= '' then
			--main.t_selChars[row].unlock = unlock
			main.t_unlockLua.chars[row] = unlock
		end
		--cell data
		main.t_selChars[row].cell_data = animNew(nil, '-1,0, 0,0, -1')
		main.t_selChars[row].cell_data_ready = false
		if gameOption('Config.BootLoadingMode') == 0 then
			main.f_syncCharPaletteData(main.t_selChars[row].char_ref)
			main.f_materializeCharCell(row)
		end
	end
	--slots
	if not slot then
		table.insert(main.t_selGrid, {['chars'] = {row}, ['slot'] = 1})
	else
		table.insert(main.t_selGrid[#main.t_selGrid].chars, row)
		-- marks all chars using this slot
		for _, idx in ipairs(main.t_selGrid[#main.t_selGrid].chars) do
			main.t_selChars[idx].hasSlot = true
		end
	end
	for _, v in ipairs({'next', 'previous', 'select'}) do
		if main.t_selChars[row][v] ~= nil then
			commandAdd(main.t_selChars[row][v], main.t_selChars[row][v])
			if main.t_selGrid[#main.t_selGrid][v] == nil then
				main.t_selGrid[#main.t_selGrid][v] = {}
			end
			if main.t_selGrid[#main.t_selGrid][v][main.t_selChars[row][v]] == nil then
				main.t_selGrid[#main.t_selGrid][v][main.t_selChars[row][v]] = {}
			end
			table.insert(main.t_selGrid[#main.t_selGrid][v][main.t_selChars[row][v]], #main.t_selGrid[#main.t_selGrid].chars)
		end
	end
	if loading then
		main.f_loadingRefresh()
	end
	return valid
end

function main.f_addStage(file, hidden, line)
	file = file:gsub('\\', '/')
	if file:match('/$') then
		return
	end
	if not addStage(file, line) then
		return
	end
	local stageNo = #main.t_selStages + 1
	local t_info = getStageInfo(stageNo)
	table.insert(main.t_selStages, {
		name = t_info.name,
		def = file,
		dir = t_info.def:gsub('[^/]+%.def$', ''),
		portraitscale = t_info.portraitscale,
		localcoord = t_info.localcoord
	})
	main.t_stageDef[file:lower()] = stageNo
	--attachedchar
	if t_info.attachedchardef ~= '' then
		local attachedList = t_info.attachedchardef
		if type(attachedList) ~= 'table' then
			attachedList = {attachedList} -- Convert string to list
		end
		main.t_selStages[stageNo].attachedChar = {}
		for i = 1, #attachedList do
			local acInfo = getCharAttachedInfo(attachedList[i])
			if acInfo ~= nil then
				acInfo.dir = acInfo.def:gsub('[^/]+%.def$', '')
				table.insert(main.t_selStages[stageNo].attachedChar, acInfo)
			end
		end
	end
	--anim data
	if hidden ~= nil and hidden ~= 0 then
		main.t_selStages[stageNo].hidden = hidden
	end
	main.t_selStages[stageNo].anim_data = animNew(nil, '-1,0, 0,0, -1')
	main.t_selStages[stageNo].vs_anim_data = animNew(nil, '-1,0, 0,0, -1')
	main.t_selStages[stageNo].anim_data_ready = false
	if gameOption('Config.BootLoadingMode') == 0 then
		main.f_materializeStagePortrait(stageNo)
	end
	return stageNo
end

main.t_includeStage = {{}, {}} --includestage = 1, includestage = -1
main.t_orderChars = {default = {}}
main.t_orderStages = {}
main.t_bonusChars = {}
main.t_selGrid = {}
main.t_selOptions = {}
main.t_selStoryMode = {}
local t_storyModeList = {}
local t_addExluded = {}
local tmp = ''
local section = 0
local row = 0
local slot = false
local csCell = 0
local content = main.f_fileRead(motif.files.select)
content = content:gsub('([^\r\n;]*)%s*;[^\r\n]*', '%1')
content = content:gsub('\n%s*\n', '\n')

lanChars = false
lanStages = false
lanOptions = false
lanStory = false
for line in content:gmatch('[^\r\n]+') do
	local lineCase = line:lower()
	if lineCase:match('^%s*%[%s*' .. gameOption('Config.Language') .. '.characters' .. '%s*%]') then
		lanChars = true
	elseif lineCase:match('^%s*%[%s*' .. gameOption('Config.Language') .. '.extrastages' .. '%s*%]') then
		lanStages = true
	elseif lineCase:match('^%s*%[%s*' .. gameOption('Config.Language') .. '.options' .. '%s*%]') then
		lanOptions = true
	elseif lineCase:match('^%s*%[%s*' .. gameOption('Config.Language') .. '.storymode' .. '%s*%]') then
		lanStory = true
	end
end

for line in content:gmatch('[^\r\n]+') do
--for line in io.lines("data/select.def") do
	local lineCase = line:lower()
	if lineCase:match('^%s*%[%s*characters%s*%]') then
		row = 0
		section = 1
	elseif lineCase:match('^%s*%[%s*' .. gameOption('Config.Language') .. '.characters' .. '%s*%]') then
		if lanChars then
			row = 0
			section = 1
		else 
			section = -1
		end
	elseif lineCase:match('^%s*%[%s*extrastages%s*%]') then
		row = 0
		section = 2
	elseif lineCase:match('^%s*%[%s*' .. gameOption('Config.Language') .. '.extrastages' .. '%s*%]') then
		if lanStages then
			row = 0
			section = 2
		else 
			section = -1
		end
	elseif lineCase:match('^%s*%[%s*options%s*%]') then
		row = 0
		section = 3
	elseif lineCase:match('^%s*%[%s*' .. gameOption('Config.Language') .. '.options' .. '%s*%]') then
		if lanOptions then
			row = 0
			section = 3
		else
			section = -1
		end
	elseif lineCase:match('^%s*%[%s*storymode%s*%]') then
		row = 0
		section = 4
	elseif lineCase:match('^%s*%[%s*' .. gameOption('Config.Language') .. '.storymode' .. '%s*%]') then
		if lanStory then
			row = 0
			section = 4
		else
			section = -1
		end
	elseif lineCase:match('^%s*%[%w+%]$') then
		section = -1
	elseif section == 1 then --[Characters]
		local csCol = (csCell % motif.select_info.columns) + 1
		local csRow = math.floor(csCell / motif.select_info.columns) + 1
		local cellKey = (csCol - 1) .. '-' .. (csRow - 1)
		while not slot and motif.select_info.cell[cellKey] ~= nil and motif.select_info.cell[cellKey].skip do
			main.f_addChar('skipslot', true, true, false, line)
			csCell = csCell + 1
			csCol = (csCell % motif.select_info.columns) + 1
			csRow = math.floor(csCell / motif.select_info.columns) + 1
			cellKey = (csCol - 1) .. '-' .. (csRow - 1)
		end
		local slotStart = lineCase:match('^%s*slot%s*=%s*{%s*()')
		if slotStart ~= nil then
			table.insert(main.t_selGrid, {['chars'] = {}, ['slot'] = 1})
			slot = true
			line = line:sub(slotStart)
			lineCase = line:lower()
		end
		local slotEnd = false
		if slot then
			local slotLine = line:match('^(.-)%s*}%s*$')
			if slotLine ~= nil then
				line = slotLine
				lineCase = line:lower()
				slotEnd = true
			end
		end
		if lineCase:match(',%s*exclude%s*=%s*1') then --character should be added after all slots are filled
			table.insert(t_addExluded, line)
		elseif line:match('%S') then
			if slot then
				for _, entry in ipairs(main.f_strsplit('|', line)) do
					entry = entry:match('^%s*(.-)%s*$')
					if entry ~= '' then
						main.f_addChar(entry, true, true, true)
					end
				end
			else
				main.f_addChar(line, true, true, false)
				csCell = csCell + 1
			end
		end
		if slotEnd then
			slot = false
			csCell = csCell + 1
		end
	elseif section == 2 then --[ExtraStages]
		--store 'unlock' param and get rid of everything that follows it
		local unlock = ''
		local hidden = 0 --TODO: temporary flag, won't be used once stage selection screen is ready
		line = line:gsub(',%s*unlock%s*=%s*(.-)%s*$', function(m1)
			unlock = (m1 or ''):match('^%s*(.-)%s*$')
			hidden = 1
			return ''
		end)
		--parse rest of the line
		for i, c in ipairs(main.f_strsplit(',', line)) do --split using "," delimiter
			c = c:gsub('^%s*(.-)%s*$', '%1')
			if i == 1 then
				row = main.f_addStage(c, hidden, line)
				if row == nil then
					break
				end
				table.insert(main.t_includeStage[1], row)
				table.insert(main.t_includeStage[2], row)
			else
				local param, value = c:match('^(.-)%s*=%s*(.-)$')
				if param ~= nil and value ~= nil and param ~= '' and value ~= '' then
					main.t_selStages[row][param] = tonumber(value)
					--order (more than 1 order param can be set at the same time)
					if param:match('order') then
						if main.t_orderStages[main.t_selStages[row].order] == nil then
							main.t_orderStages[main.t_selStages[row].order] = {}
						end
						table.insert(main.t_orderStages[main.t_selStages[row].order], row)
					end
				end
			end
		end
		if row ~= nil then
			--default order (only if no explicit order was set)
			if main.t_selStages[row].order == nil then
				main.t_selStages[row].order = 1
				if main.t_orderStages[main.t_selStages[row].order] == nil then
					main.t_orderStages[main.t_selStages[row].order] = {}
				end
				table.insert(main.t_orderStages[main.t_selStages[row].order], row)
			end
			--unlock param
			if unlock ~= '' then
				--main.t_selStages[row].unlock = unlock
				main.t_unlockLua.stages[row] = unlock
			end
		end
	elseif section == 3 then --[Options]
		if lineCase:match('%.maxmatches%s*=') then
			local rowName, line = lineCase:match('^%s*(.-)%.maxmatches%s*=%s*(.+)')
			rowName = rowName:gsub('%.', '_')
			main.t_selOptions[rowName .. 'maxmatches'] = {}
			for i, c in ipairs(main.f_strsplit(',', line:gsub('%s*(.-)%s*', '%1'))) do --split using "," delimiter
				main.t_selOptions[rowName .. 'maxmatches'][i] = tonumber(c)
			end
		end
		hook.run("main.selectDef.options", main.t_selOptions, lineCase)
	elseif section == 4 then --[StoryMode]
		local param, value = line:match('^%s*(.-)%s*=%s*(.-)%s*$')
		if param ~= nil and value ~= nil and param ~= '' and value ~= '' then
			if param:match('^name$') then
				table.insert(main.t_selStoryMode, {name = value, displayname = '', path = '', unlock = 'true'})
				t_storyModeList[value] = true
			elseif main.t_selStoryMode[#main.t_selStoryMode][param] ~= nil then
				main.t_selStoryMode[#main.t_selStoryMode][param] = value
			end
		end
	end
end

for k, v in ipairs(main.t_selStoryMode) do
	main.t_unlockLua.modes[v.name] = v.unlock
end

--add excluded characters once all slots are filled
for i = #main.t_selGrid, motif.select_info.rows * motif.select_info.columns - 1 do
	table.insert(main.t_selChars, {})
	table.insert(main.t_selGrid, {['chars'] = {}, ['slot'] = 1})
	addChar('dummyslot') --Must match Select.AddChar() in system.go
end
for i = 1, #t_addExluded do
	main.f_addChar(t_addExluded[i], true, true)
end

--add Training char if defined and not included in select.def
if gameOption('Config.TrainingChar') ~= '' and main.t_charDef[gameOption('Config.TrainingChar'):lower()] == nil then
	main.f_addChar(gameOption('Config.TrainingChar') .. ', order = 0, ordersurvival = 0, exclude = 1', false, true)
end

--add remaining character parameters
--for each character loaded
for i = 1, #main.t_selChars do
	--character stage param
	if main.t_selChars[i].stage ~= nil then
		for j, v in ipairs(main.t_selChars[i].stage) do
			--add 'stage' param stages if needed or reference existing ones
			if main.t_stageDef[v:lower()] == nil then
				main.t_selChars[i].stage[j] = main.f_addStage(v)
				if main.t_selChars[i].includestage == nil or main.t_selChars[i].includestage == 1 then --stage available all the time
					table.insert(main.t_includeStage[1], main.t_selChars[i].stage[j])
					table.insert(main.t_includeStage[2], main.t_selChars[i].stage[j])
				elseif main.t_selChars[i].includestage == -1 then --excluded stage that can be still manually selected
					table.insert(main.t_includeStage[2], main.t_selChars[i].stage[j])
				end
			else --already added
				main.t_selChars[i].stage[j] = main.t_stageDef[v:lower()]
			end
		end
	end
end

-- (Re)build list of characters allowed to be randomly selected. Must be called after any unlock/hidden state changes.
main.t_randomChars = {}
function main.f_updateRandomChars()
	local t = {}
	for i = 1, #main.t_selChars do
		local ch = main.t_selChars[i]
		-- only real character entries
		if ch ~= nil and ch.name ~= nil then
			-- generate table with characters allowed to be randomly selected
			if ch.playable
				and (ch.hidden == nil or ch.hidden <= 1)
				and (ch.exclude == nil or ch.exclude == 0) then
				table.insert(t, i - 1)
			end
		end
	end
	main.t_randomChars = t
	if gameOption('Debug.DumpLuaTables') then main.f_printTable(main.t_randomChars, "debug/t_randomChars.txt") end
end

-- build initial pool (may be refreshed later after unlock() runs)
main.f_updateRandomChars()

--add default starting stage if no stages have been added via select.def
if #main.t_includeStage[1] == 0 or #main.t_includeStage[2] == 0 then
	local row = main.f_addStage(gameOption('Debug.StartStage'))
	table.insert(main.t_includeStage[1], row)
	table.insert(main.t_includeStage[2], row)
end

--update selectableStages table
function main.f_updateSelectableStages()
	main.t_selectableStages = {}
	for _, v in ipairs(main.t_includeStage[2]) do
		if main.t_selStages[v].hidden == nil or main.t_selStages[v].hidden == 0 then
			table.insert(main.t_selectableStages, v)
		end
	end
end
main.f_updateSelectableStages()
if gameOption('Config.BootLoadingMode') > 0 then
	main.f_queueAllPreloadsLow()
end

--add default maxmatches values if config is missing in select.def
if main.t_selOptions.arcademaxmatches == nil then main.t_selOptions.arcademaxmatches = {6, 1, 1, 0, 0, 0, 0, 0, 0, 0} end
if main.t_selOptions.teammaxmatches == nil then main.t_selOptions.teammaxmatches = {4, 1, 1, 0, 0, 0, 0, 0, 0, 0} end
if main.t_selOptions.timeattackmaxmatches == nil then main.t_selOptions.timeattackmaxmatches = {6, 1, 1, 0, 0, 0, 0, 0, 0, 0} end
if main.t_selOptions.survivalmaxmatches == nil then main.t_selOptions.survivalmaxmatches = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0} end

hook.run("main.selectDef.defaults", main.t_selOptions)

--uppercase title
function main.f_itemnameUpper(title, uppercase)
	if title == nil then
		return ''
	end
	if uppercase then
		return title:upper()
	end
	return title
end

--returns table storing menu window coordinates
function main.f_menuWindow(t, offset)
	local offset = offset or {0, 0}
	if t.window.margins.y[1] ~= 0 or t.window.margins.y[2] ~= 0 then
		return {
			0,
			math.max(0, t.pos[2] + offset[2] - t.window.margins.y[1]),
			motif.info.localcoord[1],
			t.pos[2] + offset[2] + (t.window.visibleitems - 1) * t.item.spacing[2] + t.window.margins.y[2]
		}
	end
	return {0, 0, motif.info.localcoord[1], motif.info.localcoord[2]}
end

function main.f_storyboard(path)
	local s = loadStoryboard(path)
	if s == nil then
		return false
	end
	if gameOption('Debug.DumpLuaTables') then
		-- get filename without extension from full path
		local name = path:match("([^/\\]+)$") or "unknown" -- last path segment
		name = name:gsub("%.[^%.]+$", "") -- strip last extension
		main.f_printTable(s, 'debug/loadStoryboard_' .. name .. '.txt')
	end
	while true do
		if not runStoryboard() then
			break
		end
		main.f_preloadTick(2)
		refresh()
	end
	return storyboardCanceled()
end

function main.f_hiscore(mode, place)
	while true do
		if not runHiscore(mode, place) then
			break
		end
		main.f_preloadTick(2)
		refresh()
	end
end

setPlayers()

--Load additional scripts
start = require('external.script.start')
options = require('external.script.options')
menu = require('external.script.menu')

if getCommandLineValue("-storyboard") ~= nil then
	main.f_storyboard(getCommandLineValue("-storyboard"))
	os.exit()
end

--;===========================================================
--; MENUS
--;===========================================================
if motif.attract_mode.enabled then
	main.group = 'attract_mode'
	main.background = 'attractbgdef'
else
	main.group = 'title_info'
	main.background = 'titlebgdef'
end

local function enterSyncedNetplayMenu()
	main.f_clearShuffleTables()
	main.f_menuSnap(motif[main.group])
	main.f_menuItemBgAnimReset(motif[main.group])
	fadeInInit(motif[main.group].fadein.FadeData)
	main.menu.submenu.server.loop()
end

local function isValidIp(address)
	local a, b, c, d = address:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
	if a ~= nil then
		a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
		return a <= 255 and b <= 255 and c <= 255 and d <= 255
	end
	if address:match('^[0-9A-Fa-f:]+$') and not address:match(':::') then
		local _, dbl = address:gsub('::', '')
		if dbl <= 1 then
			local parts, bad = 0, false
			for h in address:gmatch('[^:]+') do
				parts = parts + 1
				if #h > 4 then bad = true break end
			end
			return not bad and ((dbl == 1 and parts < 8) or (dbl == 0 and parts == 8))
		end
	end
	return false
end

function main.f_default()
	main.aiRamp = false --if AI ramping should be active
	main.charparam = { --which select.def charparam should be used
		ai = false,
		arcadepath = false,
		music = false,
		rounds = false,
		single = false,
		stage = false,
		time = false,
	}
	main.coop = false --if mode should be recognized as coop
	main.cpuSide = {false, true} --which side is controlled by CPU
	main.dropDefeated = false --if defeated turns members should be skipped in the next match
	main.elimination = false --if single lose should stop further lua execution
	main.exitSelect = false --if "clearing" the mode (matchno == -1) should go back to main menu
	main.forceChar = {nil, nil} --predefined P1/P2 characters
	main.forceRosterSize = false --if roster size should be enforced even if there are not enough characters to fill it (not used but may be useful for external modules)
	main.fightscreen = { --which fight screen elements should be rendered (these defaults are overwritten by fight.def, depending on game mode)
		active = true,
		bars = true,
		match = false,
		mode = true,
		p1ailevel = false,
		p1score = false,
		p1wincount = false,
		p2ailevel = false,
		p2score = false,
		p2wincount = false,
		timer = false,
		guardbar = gameOption('Options.GuardBreak'),
		stunbar = gameOption('Options.Dizzy'),
		redlifebar = gameOption('Options.RedLife'),
	}
	main.defaultLuaPath = 'external/script/default.lua'
	main.luaPath = main.defaultLuaPath
	main.pauseMenu = true
	main.makeRoster = false --if default roster for each match should be generated before first match
	main.matchWins = { --amount of rounds to win for each team side and team mode
		draw = {gameOption('Options.Match.MaxDrawGames'), gameOption('Options.Match.MaxDrawGames')},
		simul = {gameOption('Options.Simul.Match.Wins'), gameOption('Options.Simul.Match.Wins')},
		single = {gameOption('Options.Match.Wins'), gameOption('Options.Match.Wins')},
		tag = {gameOption('Options.Tag.Match.Wins'), gameOption('Options.Tag.Match.Wins')},
	}
	main.motif = { --which motif elements should be rendered
		challenger = false,
		continuescreen = false,
		demo = true,
		dialogue = true,
		hiscore = false,
		vsscreen = false,
		vsmatchno = false,
		victoryscreen = false,
		winscreen = false,
		losescreen = false,
		menu = true,
	}
	main.numSimul = {gameOption('Options.Simul.Min'), gameOption('Options.Simul.Max')} --min/max number of simul characters
	main.numTag = {gameOption('Options.Tag.Min'), gameOption('Options.Tag.Max')} --min/max number of tag characters
	main.numTurns = {gameOption('Options.Turns.Min'), gameOption('Options.Turns.Max')} --min/max number of turn characters
	main.orderSelect = {false, false} --if versus screen order selection should be active
	main.persistLife = false --if life should be maintained after match
	main.persistMusic = false --if the music that was playing previously should be stopped at the start of the match
	main.persistRounds = false --if fight screen should use consecutive wins for round numbers
	main.quickContinue = false --if by default continuing should skip player selection
	main.rankingCondition = false --if winning (clearing) whole mode is needed for rankings to be saved
	main.resetScore = false --if loosing should set score for the next match to lose count
	main.rotationChars = false --flags modes where gameOption('Arcade.AI.SurvivalColor') should be used instead of gameOption('Arcade.AI.RandomColor')
	main.roundTime = gameOption('Options.Time') --sets round time
	main.selectMenu = {true, false} --which team side should be allowed to select players
	main.stageMenu = false --if manual stage selection is allowed
	main.stageOrder = false --if select.def stage order param should be used
	main.storyboard = {intro = false, ending = false, credits = false, gameover = false} --which storyboards should be active
	main.teamMenu = {
		{simul = false, single = false, tag = false, turns = false}, --which team modes should be selectable by P1 side
		{simul = false, single = false, tag = false, turns = false}, --which team modes should be selectable by P2 side
	}
	resetAILevel()
	resetRemapInput()
	if not motif.attract_mode.enabled and start.challenger == 0 then
		setCredits(-1) --amount of credits from the start (-1 = disabled)
	end
	setConsecutiveWins(1, 0)
	setConsecutiveWins(2, 0)
	setGameMode('')
	setHomeTeam(2) --http://mugenguild.com/forum/topics/ishometeam-triggers-169132.0.html
	setFightScreenElements(main.fightscreen)
	setMotifElements(main.motif)
	setTimeFramesPerCount(fightScreenVar("time.framespercount"))
	setRoundTime(math.max(-1, main.roundTime * fightScreenVar("time.framespercount")))
	setWinCount(1, 0)
	setWinCount(2, 0)
	textImgReset(motif.select_info.title.TextSpriteData)
	demoFrameCounter = 0
	hook.run("main.f_default")
end

-- Associative elements table storing functions controlling behaviour of each
-- menu item (modes configuration). Can be appended via external module.
main.t_itemname = {
	--ARCADE / TEAM ARCADE
	['arcade'] = function(t, item)
		main.aiRamp = true
		main.charparam.ai = true
		main.charparam.arcadepath = true
		main.charparam.music = true
		main.charparam.rounds = true
		main.charparam.single = true
		main.charparam.stage = true
		main.charparam.time = true
		main.exitSelect = true
		--main.fightscreen.p1score = true
		--main.fightscreen.p2ailevel = true
		main.makeRoster = true
		main.motif.challenger = true
		main.motif.continuescreen = true
		main.motif.hiscore = true
		main.motif.vsscreen = true
		main.motif.vsmatchno = true
		main.motif.victoryscreen = true
		main.motif.winscreen = true
		main.orderSelect[1] = true
		main.orderSelect[2] = true
		main.resetScore = true
		main.stageOrder = true
		main.storyboard.credits = true
		main.storyboard.ending = true
		main.storyboard.gameover = true
		main.storyboard.intro = true
		if (t ~= nil and t[item].itemname == 'arcade') or (t == nil and not main.teamarcade) then
			main.teamMenu[1].single = true
			main.teamMenu[2].single = true
			textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.arcade)
			main.teamarcade = false
		else --teamarcade
			main.teamMenu[1].simul = true
			main.teamMenu[1].single = true
			main.teamMenu[1].tag = true
			main.teamMenu[1].turns = true
			main.teamMenu[2].simul = true
			main.teamMenu[2].single = true
			main.teamMenu[2].tag = true
			main.teamMenu[2].turns = true
			textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.teamarcade)
			main.teamarcade = true
		end
		main.f_setCredits()
		remapInput(1, getLastInputController())
		remapInput(getLastInputController(), 1)
		setGameMode('arcade')
		hook.run("main.t_itemname", t, item)
		if start.challenger == 0 then
			return start.f_selectMode
		end
		return nil
	end,
	--BONUS CHAR
	['bonus'] = function(t, item)
		main.charparam.ai = true
		main.charparam.music = true
		main.charparam.rounds = true
		main.charparam.single = true
		main.charparam.stage = true
		main.charparam.time = true
		main.forceChar[2] = {main.t_bonusChars[item]}
		main.selectMenu[2] = true
		main.teamMenu[1].single = true
		main.teamMenu[2].single = true
		textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.bonus)
		remapInput(1, getLastInputController())
		remapInput(getLastInputController(), 1)
		setGameMode('bonus')
		hook.run("main.t_itemname", t, item)
		return start.f_selectMode
	end,
	--DEMO
	['demo'] = function(t, item)
		hook.run("main.t_itemname", t, item)
		return main.f_demoStart
	end,
	--FREE BATTLE (QUICK VS)
	['freebattle'] = function(t, item)
		--main.fightscreen.p1score = true
		--main.fightscreen.p2ailevel = true
		main.motif.vsscreen = true
		main.motif.victoryscreen = true
		main.orderSelect[1] = true
		main.orderSelect[2] = true
		main.selectMenu[2] = true
		main.stageMenu = true
		main.teamMenu[1].simul = true
		main.teamMenu[1].single = true
		main.teamMenu[1].tag = true
		main.teamMenu[1].turns = true
		main.teamMenu[2].simul = true
		main.teamMenu[2].single = true
		main.teamMenu[2].tag = true
		main.teamMenu[2].turns = true
		textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.freebattle)
		remapInput(1, getLastInputController())
		remapInput(getLastInputController(), 1)
		setGameMode('freebattle')
		hook.run("main.t_itemname", t, item)
		return start.f_selectMode
	end,
	--JOIN (NEW ADDRESS)
	['joinadd'] = function(t, item)
		sndPlay(motif.Snd, motif[main.group].cursor.move.snd[1], motif[main.group].cursor.move.snd[2])
		local name = main.f_drawInput(
			motif[main.group].textinput.TextSpriteData,
			motif[main.group].textinput.text.name,
			motif[main.group],
			motif[main.background],
			motif[main.group].textinput.overlay.RectData
		)
		if name ~= '' then
			sndPlay(motif.Snd, motif[main.group].cursor.move.snd[1], motif[main.group].cursor.move.snd[2])
			local address = main.f_drawInput(
				motif[main.group].textinput.TextSpriteData,
				motif[main.group].textinput.text.address,
				motif[main.group],
				motif[main.background],
				motif[main.group].textinput.overlay.RectData
			)
			if isValidIp(address) then
				sndPlay(motif.Snd, motif[main.group].cursor.done.snd.default[1], motif[main.group].cursor.done.snd.default[2])
				modifyGameOption('Netplay.IP.' .. name, address)
				table.insert(t, #t, {itemname = 'ip_' .. name, displayname = name})
				saveGameOption(getCommandLineValue("-config"))
			else
				sndPlay(motif.Snd, motif[main.group].cancel.snd[1], motif[main.group].cancel.snd[2])
			end
		else
			sndPlay(motif.Snd, motif[main.group].cancel.snd[1], motif[main.group].cancel.snd[2])
		end
		hook.run("main.t_itemname", t, item)
		return t
	end,
	--NETPLAY SURVIVAL
	['netplaysurvivalcoop'] = function(t, item)
		main.aiRamp = true
		main.charparam.ai = true
		main.charparam.music = true
		main.charparam.single = true
		main.charparam.stage = true
		main.charparam.time = true
		main.coop = true
		main.elimination = true
		main.exitSelect = true
		--main.fightscreen.match = true
		--main.fightscreen.p2ailevel = true
		main.makeRoster = true
		main.motif.losescreen = true
		main.motif.winscreen = true
		main.matchWins.draw = {0, 0}
		main.matchWins.simul = {1, 1}
		main.matchWins.single = {1, 1}
		main.matchWins.tag = {1, 1}
		main.numSimul = {2, 2}
		main.numTag = {2, 2}
		main.pauseMenu = false
		main.persistLife = true
		main.persistMusic = true
		main.persistRounds = true
		main.stageMenu = true
		main.storyboard.credits = true
		main.storyboard.gameover = true
		main.teamMenu[1].simul = true
		main.teamMenu[1].tag = true
		main.teamMenu[2].simul = true
		main.teamMenu[2].single = true
		main.teamMenu[2].tag = true
		main.teamMenu[2].turns = true
		textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.netplaysurvivalcoop)
		setGameMode('netplaysurvivalcoop')
		hook.run("main.t_itemname", t, item)
		return start.f_selectMode
	end,
	--NETPLAY CO-OP
	['netplayteamcoop'] = function(t, item)
		main.aiRamp = true
		main.charparam.ai = true
		main.charparam.arcadepath = true
		main.charparam.music = true
		main.charparam.rounds = true
		main.charparam.single = true
		main.charparam.stage = true
		main.charparam.time = true
		main.coop = true
		main.exitSelect = true
		--main.fightscreen.p1score = true
		--main.fightscreen.p2ailevel = true
		main.makeRoster = true
		main.motif.continuescreen = true
		main.motif.vsscreen = true
		main.motif.vsmatchno = true
		main.motif.victoryscreen = true
		main.motif.winscreen = true
		main.numSimul = {2, 2}
		main.numTag = {2, 2}
		main.pauseMenu = false
		main.resetScore = true
		main.stageOrder = true
		main.storyboard.credits = true
		main.storyboard.ending = true
		main.storyboard.gameover = true
		main.storyboard.intro = true
		main.teamMenu[1].simul = true
		main.teamMenu[1].tag = true
		main.teamMenu[2].simul = true
		main.teamMenu[2].single = true
		main.teamMenu[2].tag = true
		main.teamMenu[2].turns = true
		main.f_setCredits()
		textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.netplayteamcoop)
		setGameMode('netplayteamcoop')
		hook.run("main.t_itemname", t, item)
		return start.f_selectMode
	end,
	--NETPLAY VERSUS
	['netplayversus'] = function(t, item)
		main.cpuSide[2] = false
		--main.fightscreen.p1wincount = true
		--main.fightscreen.p2wincount = true
		main.motif.vsscreen = true
		main.motif.victoryscreen = true
		main.orderSelect[1] = true
		main.orderSelect[2] = true
		main.pauseMenu = false
		main.selectMenu[2] = true
		main.stageMenu = true
		main.teamMenu[1].simul = true
		main.teamMenu[1].single = true
		main.teamMenu[1].tag = true
		main.teamMenu[1].turns = true
		main.teamMenu[2].simul = true
		main.teamMenu[2].single = true
		main.teamMenu[2].tag = true
		main.teamMenu[2].turns = true
		textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.netplayversus)
		setGameMode('netplayversus')
		setHomeTeam(1)
		hook.run("main.t_itemname", t, item)
		return start.f_selectMode
	end,
	--OPTIONS
	['options'] = function(t, item)
		hook.run("main.t_itemname", t, item)
		return options.menu.loop
	end,
	--RANDOMTEST
	['randomtest'] = function(t, item)
		main.pauseMenu = false
		setGameMode('randomtest')
		hook.run("main.t_itemname", t, item)
		return main.f_randomtest
	end,
	--REPLAY
	['replay'] = function(t, item)
		hook.run("main.t_itemname", t, item)
		return main.f_replay
	end,
	--SERVER CONNECT
	['serverconnect'] = function(t, item)
		main.f_waitForPreloads(true)
		local doneSnd = motif[main.group].cursor.done.snd.serverconnect or motif[main.group].cursor.done.snd.default
		sndPlay(motif.Snd, doneSnd[1], doneSnd[2])
		hook.run("main.t_itemname", t, item)
		if main.f_connect(gameOption('Netplay.IP.' .. t[item].itemname:gsub('^ip_', '')), t[item].displayname) then
			if synchronize() then
				enterSyncedNetplayMenu()
			end
			replayStop()
			exitNetPlay()
			exitReplay()
			showSessionWarning()
		end
		return nil
	end,
	--SERVER HOST
	['serverhost'] = function(t, item)
		main.f_waitForPreloads(true)
		local doneSnd = motif[main.group].cursor.done.snd.serverhost or motif[main.group].cursor.done.snd.default
		sndPlay(motif.Snd, doneSnd[1], doneSnd[2])
		hook.run("main.t_itemname", t, item)
		if main.f_connect("", gameOption('Netplay.ListenPort')) then
			if synchronize() then
				enterSyncedNetplayMenu()
			end
			replayStop()
			exitNetPlay()
			exitReplay()
			showSessionWarning()
		end
		return nil
	end,
	--STORY MODE ARC
	['storyarc'] = function(t, item)
		main.motif.continuescreen = true
		main.selectMenu[1] = false
		for _, v in ipairs(main.t_selStoryMode) do
			if v.name == t[item].itemname then
				main.luaPath = v.path
				break
			end
		end
		remapInput(1, getLastInputController())
		remapInput(getLastInputController(), 1)
		setGameMode(t[item].itemname)
		hook.run("main.t_itemname", t, item)
		return start.f_selectMode
	end,
	--SURVIVAL
	['survival'] = function(t, item)
		main.aiRamp = true
		main.charparam.ai = true
		main.charparam.music = true
		main.charparam.single = true
		main.charparam.stage = true
		main.charparam.time = true
		main.dropDefeated = true
		main.elimination = true
		main.exitSelect = true
		--main.fightscreen.match = true
		--main.fightscreen.p2ailevel = true
		main.makeRoster = true
		main.motif.hiscore = true
		main.motif.losescreen = true
		main.motif.winscreen = true
		main.matchWins.draw = {0, 0}
		main.matchWins.simul = {1, 1}
		main.matchWins.single = {1, 1}
		main.matchWins.tag = {1, 1}
		main.orderSelect[1] = true
		main.orderSelect[2] = true
		main.persistLife = true
		main.persistMusic = true
		main.persistRounds = true
		main.rotationChars = true
		main.stageMenu = true
		main.storyboard.credits = true
		main.storyboard.gameover = true
		main.teamMenu[1].simul = true
		main.teamMenu[1].single = true
		main.teamMenu[1].tag = true
		main.teamMenu[1].turns = true
		main.teamMenu[2].simul = true
		main.teamMenu[2].single = true
		main.teamMenu[2].tag = true
		main.teamMenu[2].turns = true
		textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.survival)
		remapInput(1, getLastInputController())
		remapInput(getLastInputController(), 1)
		setGameMode('survival')
		hook.run("main.t_itemname", t, item)
		return start.f_selectMode
	end,
	--SURVIVAL CO-OP
	['survivalcoop'] = function(t, item)
		main.aiRamp = true
		main.charparam.ai = true
		main.charparam.music = true
		main.charparam.single = true
		main.charparam.stage = true
		main.charparam.time = true
		main.coop = true
		main.elimination = true
		main.exitSelect = true
		--main.fightscreen.match = true
		--main.fightscreen.p2ailevel = true
		main.makeRoster = true
		main.motif.hiscore = true
		main.motif.losescreen = true
		main.motif.winscreen = true
		main.matchWins.draw = {0, 0}
		main.matchWins.simul = {1, 1}
		main.matchWins.single = {1, 1}
		main.matchWins.tag = {1, 1}
		main.numSimul = {2, math.min(4, gameOption('Config.Players'))}
		main.numTag = {2, math.min(4, gameOption('Config.Players'))}
		main.persistLife = true
		main.persistMusic = true
		main.persistRounds = true
		main.rotationChars = true
		main.stageMenu = true
		main.storyboard.credits = true
		main.storyboard.gameover = true
		main.teamMenu[1].simul = true
		main.teamMenu[1].tag = true
		main.teamMenu[2].simul = true
		main.teamMenu[2].single = true
		main.teamMenu[2].tag = true
		main.teamMenu[2].turns = true
		textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.survivalcoop)
		setGameMode('survivalcoop')
		hook.run("main.t_itemname", t, item)
		return start.f_selectMode
	end,
	--TEAM CO-OP
	['teamcoop'] = function(t, item)
		main.aiRamp = true
		main.charparam.ai = true
		main.charparam.arcadepath = true
		main.charparam.music = true
		main.charparam.rounds = true
		main.charparam.single = true
		main.charparam.stage = true
		main.charparam.time = true
		main.coop = true
		main.exitSelect = true
		--main.fightscreen.p1score = true
		--main.fightscreen.p2ailevel = true
		main.makeRoster = true
		main.motif.continuescreen = true
		main.motif.hiscore = true
		main.motif.vsscreen = true
		main.motif.vsmatchno = true
		main.motif.victoryscreen = true
		main.motif.winscreen = true
		main.numSimul = {2, math.min(4, gameOption('Config.Players'))}
		main.numTag = {2, math.min(4, gameOption('Config.Players'))}
		main.resetScore = true
		main.stageOrder = true
		main.storyboard.credits = true
		main.storyboard.ending = true
		main.storyboard.gameover = true
		main.storyboard.intro = true
		main.teamMenu[1].simul = true
		main.teamMenu[1].tag = true
		main.teamMenu[2].simul = true
		main.teamMenu[2].single = true
		main.teamMenu[2].tag = true
		main.teamMenu[2].turns = true
		main.f_setCredits()
		textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.teamcoop)
		setGameMode('teamcoop')
		hook.run("main.t_itemname", t, item)
		return start.f_selectMode
	end,
	--TIME ATTACK
	['timeattack'] = function(t, item)
		main.aiRamp = true
		main.charparam.ai = true
		main.charparam.music = true
		main.charparam.rounds = true
		main.charparam.single = true
		main.charparam.stage = true
		main.charparam.time = true
		main.exitSelect = true
		--main.fightscreen.p2ailevel = true
		--main.fightscreen.timer = true
		main.makeRoster = true
		main.motif.continuescreen = true
		main.motif.hiscore = true
		main.motif.vsscreen = true
		main.motif.vsmatchno = true
		main.motif.winscreen = true
		main.quickContinue = true
		main.orderSelect[1] = true
		main.orderSelect[2] = true
		main.resetScore = true
		main.stageOrder = true
		main.storyboard.credits = true
		main.storyboard.gameover = true
		main.teamMenu[1].simul = true
		main.teamMenu[1].single = true
		main.teamMenu[1].tag = true
		main.teamMenu[1].turns = true
		main.teamMenu[2].simul = true
		main.teamMenu[2].single = true
		main.teamMenu[2].tag = true
		main.teamMenu[2].turns = true
		main.f_setCredits()
		textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.timeattack)
		remapInput(1, getLastInputController())
		remapInput(getLastInputController(), 1)
		setGameMode('timeattack')
		hook.run("main.t_itemname", t, item)
		return start.f_selectMode
	end,
	--TRAINING
	['training'] = function(t, item)
		if main.t_charDef[gameOption('Config.TrainingChar'):lower()] ~= nil then
			main.forceChar[2] = {main.t_charDef[gameOption('Config.TrainingChar'):lower()]}
		end
		--main.fightscreen.p1score = true
		--main.fightscreen.p2ailevel = true
		main.roundTime = -1
		main.selectMenu[2] = true
		if gameOption('Config.TrainingStage') == '' then
			main.stageMenu = true
		end
		main.teamMenu[1].simul = true
		main.teamMenu[1].single = true
		main.teamMenu[1].tag = true
		main.teamMenu[1].turns = true
		main.teamMenu[2].single = true
		main.matchWins.draw = {0, 0}
		main.matchWins.simul = {0, 0}
		main.matchWins.single = {0, 0}
		main.matchWins.tag = {0, 0}
		textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.training)
		remapInput(1, getLastInputController())
		remapInput(getLastInputController(), 1)
		setGameMode('training')
		setHomeTeam(1)
		hook.run("main.t_itemname", t, item)
		return start.f_selectMode
	end,
	--VS MODE / TEAM VERSUS
	['versus'] = function(t, item)
		main.cpuSide[2] = false
		--main.fightscreen.p1wincount = true
		--main.fightscreen.p2wincount = true
		main.motif.vsscreen = true
		main.motif.victoryscreen = true
		main.orderSelect[1] = true
		main.orderSelect[2] = true
		main.selectMenu[2] = true
		main.stageMenu = true
		if (start.challenger == 0 and t[item].itemname == 'versus') or (start.challenger ~= 0 and not main.teamarcade) then
			main.teamMenu[1].single = true
			main.teamMenu[2].single = true
			textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.versus)
		else --teamversus
			main.teamMenu[1].simul = true
			main.teamMenu[1].single = true
			main.teamMenu[1].tag = true
			main.teamMenu[1].turns = true
			main.teamMenu[2].simul = true
			main.teamMenu[2].single = true
			main.teamMenu[2].tag = true
			main.teamMenu[2].turns = true
			textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.teamversus)
		end
		if start.challenger > 0 then
			setGameMode('challenger')
		else
			setGameMode('versus')
		end
		setHomeTeam(1)
		hook.run("main.t_itemname", t, item)
		if start.challenger == 0 then
			return start.f_selectMode
		end
		return nil
	end,
	--VERSUS CO-OP
	['versuscoop'] = function(t, item)
		main.coop = true
		main.cpuSide[2] = false
		--main.fightscreen.p1wincount = true
		--main.fightscreen.p2wincount = true
		main.motif.vsscreen = true
		main.motif.victoryscreen = true
		main.numSimul = {2, math.min(4, math.max(2, math.ceil(gameOption('Config.Players') / 2)))}
		main.numTag = {2, math.min(4, math.max(2, math.ceil(gameOption('Config.Players') / 2)))}
		main.selectMenu[2] = true
		main.stageMenu = true
		main.teamMenu[1].simul = true
		main.teamMenu[1].tag = true
		main.teamMenu[2].simul = true
		main.teamMenu[2].tag = true
		textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.versuscoop)
		setGameMode('versuscoop')
		setHomeTeam(1)
		hook.run("main.t_itemname", t, item)
		return start.f_selectMode
	end,
	--WATCH
	['watch'] = function(t, item)
		main.cpuSide[1] = true
		--main.fightscreen.p1ailevel = true
		--main.fightscreen.p2ailevel = true
		main.motif.vsscreen = true
		main.motif.victoryscreen = true
		main.selectMenu[2] = true
		main.stageMenu = true
		main.teamMenu[1].simul = true
		main.teamMenu[1].single = true
		main.teamMenu[1].tag = true
		main.teamMenu[1].turns = true
		main.teamMenu[2].simul = true
		main.teamMenu[2].single = true
		main.teamMenu[2].tag = true
		main.teamMenu[2].turns = true
		textImgSetText(motif.select_info.title.TextSpriteData, motif.select_info.title.text.watch)
		remapInput(1, getLastInputController())
		remapInput(getLastInputController(), 1)
		setGameMode('watch')
		setHomeTeam(1)
		hook.run("main.t_itemname", t, item)
		return start.f_selectMode
	end,
}
main.t_itemname.teamarcade = main.t_itemname.arcade
main.t_itemname.teamversus = main.t_itemname.versus
if gameOption('Debug.DumpLuaTables') then main.f_printTable(main.t_itemname, 'debug/t_mainItemname.txt') end

function main.f_deleteIP(item, t)
	if t[item].itemname:match('^ip_') then
		sndPlay(motif.Snd, motif.title_info.cancel.snd[1], motif.title_info.cancel.snd[2])
		resetKey()
		modifyGameOption('Netplay.IP.' .. t[item].itemname:gsub('^ip_', ''), nil)
		saveGameOption(getCommandLineValue("-config"))
		for i = 1, #t do
			if t[i].itemname == t[item].itemname then
				table.remove(t, i)
				break
			end
		end
	end
	return t
end

--return table without hidden modes (present in main.t_unlockLua.modes table)
function main.f_hiddenItems(t_items)
	local t = {}
	for _, v in ipairs(t_items) do
		if main.t_unlockLua.modes[v.itemname] == nil then
			table.insert(t, v)
		end
	end
	return t
end

local demoFrameCounter = 0
local introWaitCycles = 0

-- Returns the action function name and visible items table if the given menu table has exactly one actionable entry.
function main.f_getSingleMenuAction(tbl)
	if tbl == nil or tbl.items == nil then
		return nil
	end
	local cnt = 0
	local f = nil
	for _, v in ipairs(tbl.items) do
		if tbl.name == 'bonusgames' --[[or tbl.name == 'storymode']] or v.itemname == 'joinadd' then
			return nil
		elseif v.itemname ~= 'back' and main.t_unlockLua.modes[v.itemname] == nil then
			local fname = v.itemname
			if main.t_itemname[fname] == nil then
				if t_storyModeList[fname] then
					fname = 'storyarc'
				elseif fname:match('^bonus_') then
					fname = 'bonus'
				elseif fname:match('^ip_') then
					fname = 'serverconnect'
				end
			end
			cnt = cnt + 1
			f = fname
			if cnt > 1 then
				return nil
			end
		end
	end
	if f ~= nil and main.t_itemname[f] ~= nil and cnt == 1 then
		local t = main.f_hiddenItems(tbl.items)
		return f, t
	end
	return nil
end

-- Shared menu loop logic
function main.f_createMenu(tbl, bool_bgreset, bool_main, bool_f1, bool_del)
	return function()
		hook.run("main.menu.loop")
		local cursorPosY = 1
		local moveTxt = 0
		local item = 1
		local t = main.f_hiddenItems(tbl.items)
		local call_t_override = nil
		local call_item_override = nil
		--skip showing menu if there is only 1 valid item
		main.f_menuSnap(motif[main.group])
		-- Reset menu item background animations
		main.f_menuItemBgAnimReset(motif[main.group])
		-- Only auto-run here for menus that are entered directly (no parent submenu), so the fadeout is handled in the caller for submenus.
		local single_f, single_t = main.f_getSingleMenuAction(tbl)
		if single_f ~= nil and bool_bgreset then
			main.f_default()
			main.menu.f = main.t_itemname[single_f](single_t, item)
			main.f_unlock(false)
			if main.menu.f ~= nil then
				main.menu.f()
			end
			main.f_default()
			main.f_unlock(false)
			local itemNum = #t
			t = main.f_hiddenItems(tbl.items)
			main.menu.f = nil
			if itemNum == #t then
				return
			end
		end
		--more than 1 item (or newly unlocked ones), continue loop
		if bool_main then
			if motif.files.logo.storyboard ~= '' then
				main.f_storyboard(motif.files.logo.storyboard)
			end
			if motif.files.intro.storyboard ~= '' then
				main.f_storyboard(motif.files.intro.storyboard)
			end
		end
		if bool_bgreset then
			if not motif.attract_mode.enabled then
				bgReset(motif[main.background].BGDef)
				playBgm({source = "motif.title", interrupt = true})
			end
			fadeInInit(motif[main.group].fadein.FadeData)
		end
		main.menu.f = nil
		while true do
			if tbl.reset then
				tbl.reset = false
			else
				main.f_menuCommonDraw(t, item, cursorPosY, moveTxt, motif[main.group], motif[main.background], false)
			end
			-- While fading, ignore normal menu inputs, but still allow ESC / menu-cancel to skip the fade.
			if fadeActive() then
				if esc() or getInput(-1, motif[main.group].menu.cancel.key) then
					fadeSkip()
				end
			elseif main.menu.f ~= nil then
				main.f_unlock(false)
				main.menu.f()
				main.f_default()
				main.f_unlock(false)
				t = main.f_hiddenItems(tbl.items)
				main.menu.f = nil
			else
				if bool_main then
					main.f_demo()
				end
				local item_sav = item
				cursorPosY, moveTxt, item = main.f_menuCommonCalc(t, item, cursorPosY, moveTxt, motif[main.group], motif[main.group].cursor)
				textImgSetText(motif[main.group].title.TextSpriteData, tbl.title)
				if item_sav ~= item then
					demoFrameCounter = 0
					introWaitCycles = 0
				end
				local cancelInputTime = getInputTime(-1, motif[main.group].menu.cancel.key)
				if esc() or cancelInputTime > 0 then
					if not bool_main then
						sndPlay(motif.Snd, motif[main.group].cancel.snd[1], motif[main.group].cancel.snd[2])
					elseif not esc() and t[item].itemname ~= 'exit' then
						--menu key moves cursor to exit without exiting the game
						for i = 1, #t do
							if t[i].itemname == 'exit' then
								sndPlay(motif.Snd, motif[main.group].cancel.snd[1], motif[main.group].cancel.snd[2])
								item = i
								cursorPosY = math.min(item, motif[main.group].menu.window.visibleitems)
								if cursorPosY >= motif[main.group].menu.window.visibleitems then
									moveTxt = (item - motif[main.group].menu.window.visibleitems) * motif[main.group].menu.item.spacing[2]
								end
								break
							end
						end
					end
					-- If held for 30 frames or longer, show info text
					if cancelInputTime > 30 then
						main.f_warning(
							motif.infobox.text.text,
							motif[main.group],
							motif[main.background],
							motif.infobox.overlay.RectData,
							motif.infobox.title.TextSpriteData,
							motif.infobox.text.TextSpriteData
						)
					end
					if not bool_main or esc() then
						break
					end
				elseif bool_f1 and (getKey(motif.infobox.keycode) or gameOption('Config.FirstRun')) then
					if gameOption('Config.FirstRun') then
						modifyGameOption('Config.FirstRun', false)
						options.f_saveCfg(false)
					end
					main.f_warning(
						motif.infobox.text.text,
						motif[main.group],
						motif[main.background],
						motif.infobox.overlay.RectData,
						motif.infobox.title.TextSpriteData,
						motif.infobox.text.TextSpriteData
					)
				elseif motif.attract_mode.enabled and getKey(motif.attract_mode.options.keycode) then
					main.f_default()
					main.menu.f = main.t_itemname.options()
					sndPlay(motif.Snd, motif[main.group].cursor.done.snd.default[1], motif[main.group].cursor.done.snd.default[2])
					fadeOutInit(motif[main.group].fadeout.FadeData)
					resetKey()
				elseif bool_del and getKey(motif[main.group].menu.item.delete.keycode) then
					tbl.items = main.f_deleteIP(item, t)
				elseif main.f_hiscoreDisplay(t[item].itemname) then
					demoFrameCounter = 0
				elseif getInput(-1, motif[main.group].menu.done.key) then
					demoFrameCounter = 0
					local f = t[item].itemname
					if f == 'back' then
						sndPlay(motif.Snd, motif[main.group].cancel.snd[1], motif[main.group].cancel.snd[2])
						break
					elseif f == 'exit' then
						break
					elseif main.t_itemname[f] == nil then
						if t_storyModeList[f] then
							f = 'storyarc'
						elseif f:match('^bonus_') then
							f = 'bonus'
						elseif f:match('^ip_') then
							f = 'serverconnect'
						elseif tbl.submenu[f].loop ~= nil and #tbl.submenu[f].items > 0 then
							-- Check if the target submenu would immediately auto-run a single actionable item.
							-- If so, treat that as if it was selected directly here, so fadeout uses the current menu.
							local single_f2, single_t2 = main.f_getSingleMenuAction(tbl.submenu[f])
							if single_f2 ~= nil then
								f = single_f2
								call_t_override = single_t2
								call_item_override = 1
							else
								local doneSnd = motif[main.group].cursor.done.snd[f] or motif[main.group].cursor.done.snd.default
								sndPlay(motif.Snd, doneSnd[1], doneSnd[2])
								tbl.submenu[f].loop()
								f = ''
								main.f_menuSnap(motif[main.group])
								main.f_menuItemBgAnimReset(motif[main.group])
							end
						else
							break
						end
					end
					if f ~= '' then
						main.f_default()
						if f == 'joinadd' then
							tbl.items = main.t_itemname[f](t, item)
						elseif main.t_itemname[f] ~= nil then
							local call_t = call_t_override or t
							local call_item = call_item_override or item
							main.menu.f = main.t_itemname[f](call_t, call_item)
						end
						call_t_override = nil
						call_item_override = nil
						if main.menu.f ~= nil then
							local doneSnd = motif[main.group].cursor.done.snd[f] or motif[main.group].cursor.done.snd.default
							sndPlay(motif.Snd, doneSnd[1], doneSnd[2])
							fadeOutInit(motif[main.group].fadeout.FadeData)
						end
					end
				end
			end
		end
	end
end

-- Recursively remove pruned items/submenus.
function main.f_pruneMenu(tbl, excluded)
	if type(tbl) ~= 'table' or type(excluded) ~= 'table' then
		return
	end
	-- Remove items
	if type(tbl.items) == 'table' then
		for i = #tbl.items, 1, -1 do
			local it = tbl.items[i]
			if type(it) == 'table' and excluded[it.itemname] then
				table.remove(tbl.items, i)
			end
		end
	end
	-- Remove / recurse submenus
	if type(tbl.submenu) == 'table' then
		for k, sub in pairs(tbl.submenu) do
			if excluded[k] then
				tbl.submenu[k] = nil
			else
				main.f_pruneMenu(sub, excluded)
			end
		end
	end
end

-- Remove vardisplay pointer entries for items that were pruned from the menu.
function main.f_prunePointers(ptrs, excluded)
	if type(ptrs) ~= 'table' or type(excluded) ~= 'table' then
		return
	end
	for i = #ptrs, 1, -1 do
		local v = ptrs[i]
		if type(v) == 'table' and excluded[v.itemname] then
			table.remove(ptrs, i)
		end
	end
end

-- Dynamically generates all menus and submenus
function main.f_start()
	main.menu = {title = main.f_itemnameUpper(motif[main.group].title.text, motif[main.group].menu.title.uppercase), submenu = {}, items = {}}
	main.menu.loop = main.f_createMenu(main.menu, true, main.group == 'title_info', main.group == 'title_info', false)
	local w = main.f_menuWindow(motif[main.group].menu)
	local t_pos = {} --for storing current main.menu table position
	local t_skipGroup = {}
	local lastNum = 0
	local bonusUpper = true
	for i, suffix in ipairs(motif[main.group].menu.itemname_order) do
		for j, c in ipairs(main.f_strsplit('_', suffix)) do --split using "_" delimiter
			--exceptions for expanding the menu table
			if motif[main.group].menu.itemname[suffix] == '' and c ~= 'server' then --items and groups without displayname are skipped
				t_skipGroup[c] = true
				break
			elseif t_skipGroup[c] then --named item but inside a group without displayname
				break
			elseif c == 'bonusgames' and #main.t_bonusChars == 0 then --skip bonus mode if there are no characters with bonus param set to 1
				t_skipGroup[c] = true
				break
			elseif c == 'storymode' and #main.t_selStoryMode == 0 then --skip story mode if there are no story arc declared
				t_skipGroup[c] = true
				break
			elseif c == 'versuscoop' and gameOption('Config.Players') < 4 then --skip versus coop if there are not enough players
				t_skipGroup[c] = true
				break
			end
			--appending the menu table
			if j == 1 then --first string after menu.itemname (either reserved one or custom submenu assignment)
				if main.menu.submenu[c] == nil then
					main.menu.submenu[c] = {title = main.f_itemnameUpper(motif[main.group].menu.itemname[suffix], motif[main.group].menu.title.uppercase), submenu = {}, items = {}}
					main.menu.submenu[c].loop = main.f_createMenu(main.menu.submenu[c], false, false, true, c == 'serverjoin')
					if not suffix:match(c .. '_') then
						table.insert(main.menu.items, {
							itemname = c,
							displayname = motif[main.group].menu.itemname[suffix],
							paramname = suffix,
						})
						if c == 'bonusgames' then bonusUpper = main.menu.items[#main.menu.items].displayname == main.menu.items[#main.menu.items].displayname:upper() end
					end
				end
				t_pos = main.menu.submenu[c]
				t_pos.name = c
			else --following strings
				if t_pos.submenu[c] == nil then
					t_pos.submenu[c] = {title = main.f_itemnameUpper(motif[main.group].menu.itemname[suffix], motif[main.group].menu.title.uppercase), submenu = {}, items = {}}
					t_pos.submenu[c].loop = main.f_createMenu(t_pos.submenu[c], false, false, true, c == 'serverjoin')
					table.insert(t_pos.items, {
						itemname = c,
						displayname = motif[main.group].menu.itemname[suffix],
						paramname = suffix,
					})
					if c == 'bonusgames' then bonusUpper = t_pos.items[#t_pos.items].displayname == t_pos.items[#t_pos.items].displayname:upper() end
				end
				if j > lastNum then
					t_pos = t_pos.submenu[c]
					t_pos.name = c
				end
			end
			lastNum = j
			--add bonus character names to bonusgames submenu
			if suffix:match('bonusgames_back$') and c == 'bonusgames' then --j == main.f_countSubstring(suffix, '_') then
				for k = 1, #main.t_bonusChars do
					local name = start.f_getCharData(main.t_bonusChars[k]).name
					local itemname = 'bonus_' .. name:gsub('%s+', '_')
					table.insert(t_pos.items, {
						itemname = itemname,
						displayname = main.f_itemnameUpper(name, bonusUpper),
						paramname = suffix:gsub('back$', itemname),
					})
				end
			end
			--add story arcs to storymode submenu
			if suffix:match('storymode_back$') and c == 'storymode' then --j == main.f_countSubstring(suffix, '_') then
				for k, v in ipairs(main.t_selStoryMode) do
					local itemname = v.name:gsub('%s+', '_')
					table.insert(t_pos.items, {
						itemname = itemname,
						displayname = v.displayname,
						paramname = suffix:gsub('back$', itemname),
					})
				end
			end
			--add IP addresses for serverjoin submenu
			if suffix:match('_serverjoin_back$') and c == 'serverjoin' then --j == main.f_countSubstring(suffix, '_') then
				for k, v in pairs(gameOption('Netplay.IP')) do
					local itemname = 'ip_' .. k
					table.insert(t_pos.items, {
						itemname = itemname,
						displayname = k,
						paramname = suffix:gsub('back$', itemname),
					})
				end
			end
		end
	end
	textImgSetWindow(motif[main.group].menu.item.selected.active.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif[main.group].menu.item.active.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif[main.group].menu.item.value.active.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif[main.group].menu.item.selected.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif[main.group].menu.item.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif[main.group].menu.item.value.TextSpriteData, w[1], w[2], w[3], w[4])
	--for _, v in pairs(motif[main.group].menu.item.bg) do
	--	animSetWindow(v.AnimData, w[1], w[2], w[3], w[4])
	--end
	--for _, v in pairs(motif[main.group].menu.item.active.bg) do
	--	animSetWindow(v.AnimData, w[1], w[2], w[3], w[4])
	--end
	if gameOption('Debug.DumpLuaTables') then main.f_printTable(main.menu, 'debug/t_mainMenu.txt') end
end

function main.f_clearShuffleTables()
	start.shuffleChars = nil
	start.shuffleStages = nil
	start.shufflePals = nil
	start.lastRandomChar = nil
	start.lastRandomPal = nil
	start.lastStageIdx = nil
end

function main.f_deleteReplay(item, t)
	if t[item] == nil or t[item].itemname == 'back' or not t[item].itemname:match('%.replay$') then
		return t, item
	end

	local ok, err = os.remove(t[item].itemname)
	if not ok then
		print('Unable to delete replay: ' .. t[item].itemname .. (err and ' (' .. tostring(err) .. ')' or ''))
		return t, item
	end

	sndPlay(motif.Snd, motif.replay_info.cancel.snd[1], motif.replay_info.cancel.snd[2])
	resetKey()
	table.remove(t, item)
	item = math.max(1, math.min(item, #t))
	return t, item
end

function main.f_renameReplay(item, t)
	if t[item] == nil or t[item].itemname == 'back' or not t[item].itemname:match('%.replay$') then
		return t, item
	end
	local oldPath, oldName, ext = t[item].itemname:match('^(.-)([^\\/]+)%.([^%.\\/]-)$')
	if oldPath == nil or oldName == nil or ext == nil then
		return t, item
	end
	sndPlay(motif.Snd, motif.replay_info.cursor.move.snd[1], motif.replay_info.cursor.move.snd[2])
	local newName = main.f_drawInput(
		motif.title_info.textinput.TextSpriteData,
		motif.title_info.textinput.text.replay,
		motif.title_info,
		motif.replaybgdef,
		motif.title_info.textinput.overlay.RectData,
		oldName
	)
	newName = (newName or ''):match('^%s*(.-)%s*$')
	newName = newName:gsub('%.[Rr][Ee][Pp][Ll][Aa][Yy]$', '')
	if newName == '' or newName == oldName then
		sndPlay(motif.Snd, motif.replay_info.cancel.snd[1], motif.replay_info.cancel.snd[2])
		return t, item
	end
	if newName:match('[\\/:%*%?"<>|]') then
		sndPlay(motif.Snd, motif.replay_info.cancel.snd[1], motif.replay_info.cancel.snd[2])
		return t, item
	end
	local newFile = oldPath .. newName .. '.' .. ext
	if main.f_fileExists(newFile) then
		sndPlay(motif.Snd, motif.replay_info.cancel.snd[1], motif.replay_info.cancel.snd[2])
		return t, item
	end
	local ok, err = os.rename(t[item].itemname, newFile)
	if not ok then
		print('Unable to rename replay: ' .. t[item].itemname .. ' -> ' .. newFile .. (err and ' (' .. tostring(err) .. ')' or ''))
		sndPlay(motif.Snd, motif.replay_info.cancel.snd[1], motif.replay_info.cancel.snd[2])
		return t, item
	end
	sndPlay(motif.Snd, motif.replay_info.cursor.done.snd[1], motif.replay_info.cursor.done.snd[2])
	t[item].itemname = newFile
	t[item].displayname = newName
	return t, item
end

--replay menu
function main.f_replay()
	local w = main.f_menuWindow(motif.replay_info.menu)
	textImgSetWindow(motif.replay_info.menu.item.selected.active.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif.replay_info.menu.item.active.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif.replay_info.menu.item.value.active.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif.replay_info.menu.item.value.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif.replay_info.menu.item.selected.TextSpriteData, w[1], w[2], w[3], w[4])
	textImgSetWindow(motif.replay_info.menu.item.TextSpriteData, w[1], w[2], w[3], w[4])
	for _, v in pairs(motif.replay_info.menu.item.bg) do
		animSetWindow(v.AnimData, w[1], w[2], w[3], w[4])
	end
	for _, v in pairs(motif.replay_info.menu.item.active.bg) do
		animSetWindow(v.AnimData, w[1], w[2], w[3], w[4])
	end
	textImgReset(motif.replay_info.title.TextSpriteData)
	textImgSetText(motif.replay_info.title.TextSpriteData, main.f_itemnameUpper(motif.replay_info.title.text, motif.replay_info.menu.title.uppercase))
	local cursorPosY = 1
	local moveTxt = 0
	local item = 1
	local t = {}
	for k, v in ipairs(getDirectoryFiles('save/replays')) do
		v:gsub('^(.-)([^\\/]+)%.([^%.\\/]-)$', function(path, filename, ext)
			path = path:gsub('\\', '/')
			ext = ext:lower()
			if ext == 'replay' then
				table.insert(t, {itemname = path .. filename .. '.' .. ext, displayname = filename})
			end
		end)
	end
	table.insert(t, {itemname = 'back', displayname = motif.replay_info.menu.itemname.back})
	bgReset(motif.replaybgdef.BGDef)
	fadeInInit(motif.replay_info.fadein.FadeData)
	playBgm({source = "motif.replay"})
	main.close = false
	while true do
		main.f_menuCommonDraw(t, item, cursorPosY, moveTxt, motif.replay_info, motif.replaybgdef, false)
		cursorPosY, moveTxt, item = main.f_menuCommonCalc(t, item, cursorPosY, moveTxt, motif.replay_info, motif.replay_info.cursor)
		if main.close and not fadeActive() then
			bgReset(motif[main.background].BGDef)
			fadeInInit(motif[main.group].fadein.FadeData)
			playBgm({source = "motif.title", interrupt = true})
			main.close = false
			break
		elseif esc() or getInput(-1, motif[main.group].menu.cancel.key) or (t[item].itemname == 'back' and getInput(-1, motif[main.group].menu.done.key)) then
			sndPlay(motif.Snd, motif.replay_info.cancel.snd[1], motif.replay_info.cancel.snd[2])
			fadeOutInit(motif.replay_info.fadeout.FadeData)
			main.close = true
		elseif getKey(motif.replay_info.menu.item.delete.keycode) then
			t, item = main.f_deleteReplay(item, t)
			local visibleItems = motif.replay_info.menu.window.visibleitems
			if visibleItems == nil or visibleItems <= 0 then
				visibleItems = #t
			end
			cursorPosY = math.max(1, math.min(cursorPosY, item, visibleItems))
		elseif getKey(motif.replay_info.menu.item.rename.keycode) then
			t, item = main.f_renameReplay(item, t)
		elseif getInput(-1, motif[main.group].menu.done.key) then
			main.f_waitForPreloads(true)
			sndPlay(motif.Snd, motif[main.group].cursor.done.snd.default[1], motif[main.group].cursor.done.snd.default[2])
			if enterReplay(t[item].itemname) and synchronize() then
				main.replayActive = true
				enterSyncedNetplayMenu()
			end
			main.replayActive = false
			replayStop()
			exitNetPlay()
			exitReplay()
			showSessionWarning()
		end
	end
end

function main.f_connect(server, str)
	enterNetPlay(server)
	while not connected() do
		if esc() or getInput(-1, motif.title_info.menu.cancel.key) then
			sndPlay(motif.Snd, motif.title_info.cancel.snd[1], motif.title_info.cancel.snd[2])
			exitNetPlay()
			return false
		end
		--draw clearcolor
		clearColor(motif[main.background].bgclearcolor[1], motif[main.background].bgclearcolor[2], motif[main.background].bgclearcolor[3])
		--draw layerno = 0 backgrounds
		bgDraw(motif[main.background].BGDef, 0)
		--draw overlay
		rectDraw(motif.title_info.connecting.overlay.RectData)
		--draw text
		local txt = string.format(motif.title_info.connecting.text.default, str)
		if server ~= '' then
			txt = string.format(motif.title_info.connecting.text.join, server, str)
		end
		textImgReset(motif.title_info.connecting.TextSpriteData)
		textImgSetText(motif.title_info.connecting.TextSpriteData, txt)
		textImgDraw(motif.title_info.connecting.TextSpriteData)
		--draw layerno = 1 backgrounds
		bgDraw(motif[main.background].BGDef, 1)
		refresh()
	end
	replayRecord('save/replays/' .. os.date("%Y-%m-%d_%Hh%Mm%Ss") .. '.replay')
	return true
end

--asserts content unlock conditions
function main.f_unlock(permanent)
	local refreshRandom = false
	local stats = jsonDecode(getCommandLineValue("-stats")) or {}
	local env = setmetatable({stats = stats}, {__index = _G})
	for group, t in pairs(main.t_unlockLua) do
		local t_del = {}
		for k, v in pairs(t) do
			local func, err = loadstring('return ' .. v)
			if func == nil then
				panicError("\nmain.t_unlockLua." .. group .. "[" .. k .. "]\n" ..
					"Invalid Lua code: \n" .. v .. "\n" .. tostring(err) .. "\n")
			end
			setfenv(func, env)
			local bool = func()
			if type(bool) == 'boolean' then
				if group == 'chars' then
					if main.f_unlockChar(k, bool, false) then
						refreshRandom = true
					end
				elseif group == 'stages' then
					main.f_unlockStage(k, bool)
				elseif group == 'modes' then
					-- already handled via t_del cleaning
				end
				if bool and (permanent or group == 'modes') then
					table.insert(t_del, k)
				end
			else
				panicError("\nmain.t_unlockLua." .. group .. "[" .. k .. "]\n" ..
					"Following Lua code does not return boolean value: \n" .. v .. "\n")
			end
		end
		-- clean lua code that already returned true
		for _, v in ipairs(t_del) do
			t[v] = nil
		end
	end
	-- If any character visibility changed, rebuild random pool and clear shuffle bags so RandomSelect immediately reflects the updated roster.
	if refreshRandom then
		main.f_updateRandomChars()
		if start ~= nil then
			main.f_clearShuffleTables()
		end
	end
end

--unlock characters (select screen grid only)
function main.f_unlockChar(num, bool, reset)
	local changed = false
	if bool then
		if main.t_selChars[num].hidden ~= 0 then
			main.t_selChars[num].hidden_default = main.t_selChars[num].hidden
			main.t_selChars[num].hidden = 0
			for k, v in pairs(main.t_selChars[num]) do
				local mode = orderParamMode(k)
				local order = tonumber(v)
				if mode ~= nil and order ~= nil and order < 0 then
					main.t_selChars[num][k] = 0 - order
					addOrderChar(mode, main.t_selChars[num][k], main.t_selChars[num].char_ref)
				end
			end
			start.t_grid[main.t_selChars[num].row][main.t_selChars[num].col].hidden = main.t_selChars[num].hidden
			if reset then start.f_resetGrid() end
			changed = true
		end
	elseif main.t_selChars[num].hidden_default == nil then
		return false
	elseif main.t_selChars[num].hidden ~= main.t_selChars[num].hidden_default then
		main.t_selChars[num].hidden = main.t_selChars[num].hidden_default
		start.t_grid[main.t_selChars[num].row][main.t_selChars[num].col].hidden = main.t_selChars[num].hidden
		if reset then start.f_resetGrid() end
		changed = true
	end
	return changed
end

--unlock stages (stage selection menu only)
function main.f_unlockStage(num, bool)
	if bool then
		if main.t_selStages[num].hidden ~= 0 then
			main.t_selStages[num].hidden_default = main.t_selStages[num].hidden
			main.t_selStages[num].hidden = 0
			main.f_updateSelectableStages()
		end
	elseif main.t_selStages[num].hidden_default == nil then
		return
	elseif main.t_selStages[num].hidden ~= main.t_selStages[num].hidden_default then
		main.t_selStages[num].hidden = main.t_selStages[num].hidden_default
		main.f_updateSelectableStages()
	end
end

main.t_hiscoreMap = {
	teamarcade = 'arcade',
}
function main.f_hiscoreDisplay(itemname)
	local stats = jsonDecode(getCommandLineValue("-stats"))
	local mode = main.t_hiscoreMap[itemname] or itemname
	if not motif.hiscore_info.enabled or stats.modes == nil or stats.modes[mode] == nil or stats.modes[mode].ranking == nil then
		return false
	end
	if not getInput(-1, motif[main.group].menu.hiscore.key) then
		return false
	end
	sndPlay(motif.Snd, motif[main.group].cursor.done.snd.default[1], motif[main.group].cursor.done.snd.default[2])
	main.f_hiscore(mode, -1)
	--fadeInInit(motif[main.group].fadein.FadeData)
	playBgm({source = "motif.title", interrupt = true})
	return true
end

--attract mode start screen
function main.f_attractStart()
	local timerActive = getCredits() ~= 0
	local timer = 0
	local counter = 0 - motif.attract_mode.fadein.time
	local press_blinktime, insert_blinktime = 0, 0
	local press_switched, insert_switched = false, false
	local drawPress, drawInsert = true, true
	clearColor(motif.attractbgdef.bgclearcolor[1], motif.attractbgdef.bgclearcolor[2], motif.attractbgdef.bgclearcolor[3])
	bgReset(motif.attractbgdef.BGDef)
	fadeInInit(motif.attract_mode.fadein.FadeData)
	local fadeOutStarted = false
	playBgm({source = "motif.title", interrupt = true})
	local creditsCnt = getCredits()
	while true do
		counter = counter + 1
		--draw layerno = 0 backgrounds
		bgDraw(motif.attractbgdef.BGDef, 0)
		--draw text
		if getCredits() ~= 0 then
			if motif.attract_mode.start.press.blinktime > 0 and not fadeOutStarted then
				if press_blinktime < motif.attract_mode.start.press.blinktime then
					press_blinktime = press_blinktime + 1
				elseif press_switched then
					drawPress = true
					press_switched = false
					press_blinktime = 0
				else
					drawPress = false
					press_switched = true
					press_blinktime = 0
				end
			end
			if drawPress then
				textImgDraw(motif.attract_mode.start.press.TextSpriteData)
			end
		else
			if motif.attract_mode.start.insert.blinktime > 0 and not fadeOutStarted then
				if insert_blinktime < motif.attract_mode.start.insert.blinktime then
					insert_blinktime = insert_blinktime + 1
				elseif insert_switched then
					drawInsert = true
					insert_switched = false
					insert_blinktime = 0
				else
					drawInsert = false
					insert_switched = true
					insert_blinktime = 0
				end
			end
			if drawInsert then
				textImgDraw(motif.attract_mode.start.insert.TextSpriteData)
			end
		end
		--draw timer
		if motif.attract_mode.start.timer.count ~= -1 and timerActive then
			timer, timerActive = main.f_drawTimer(timer, motif.attract_mode.start.timer)
		end
		--draw credits text
		if getCredits() ~= -1 then
			textImgReset(motif.attract_mode.credits.TextSpriteData)
			textImgSetText(motif.attract_mode.credits.TextSpriteData, string.format(motif.attract_mode.credits.text, getCredits()))
			textImgDraw(motif.attract_mode.credits.TextSpriteData)
		end
		--credits
		if creditsCnt ~= getCredits() then
			timerActive = true
			timer = motif.attract_mode.start.timer.displaytime
			creditsCnt = getCredits()
		end
		--options
		if motif.attract_mode.enabled and getKey(motif.attract_mode.options.keycode) then
			main.f_default()
			main.menu.f = main.t_itemname.options()
			local doneSnd = motif[main.group].cursor.done.snd.options or motif[main.group].cursor.done.snd.default
			sndPlay(motif.Snd, doneSnd[1], doneSnd[2])
			fadeOutInit(motif[main.group].fadeout.FadeData)
			fadeOutStarted = true
			resetKey()
			main.menu.f()
			return false
		end
		--draw layerno = 1 backgrounds
		bgDraw(motif.attractbgdef.BGDef, 1)
		--draw fadein / fadeout
		if not fadeOutStarted and not fadeActive() and ((getCredits() ~= 0 and getInput(-1, motif.attract_mode.start.press.key)) or (not timerActive and counter >= motif.attract_mode.start.time)) then
			if getCredits() ~= 0 then
				sndPlay(motif.Snd, motif.attract_mode.start.done.snd[1], motif.attract_mode.start.done.snd[2])
			end
			fadeOutInit(motif.attract_mode.fadeout.FadeData)
			fadeOutStarted = true
		end
		--frame transition
		if esc() --[[or getInput(-1, motif.attract_mode.menu.cancel.key)]] then
			esc(false)
			return false
		end
		if fadeOutStarted and not fadeActive() then
			return getCredits() ~= 0
		end
		main.f_preloadTick(2)
		refresh()
	end
end

--attract mode loop
function main.f_attractMode()
	setCredits(0)
	while true do --outer loop
		local startScreen = false
		while true do --inner loop (attract mode)
			--logo storyboard
			if motif.attract_mode.logo.storyboard ~= '' and main.f_storyboard(motif.attract_mode.logo.storyboard) then
				break
			end
			--intro storyboard
			if motif.attract_mode.intro.storyboard ~= '' and main.f_storyboard(motif.attract_mode.intro.storyboard) then
				break
			end
			--demo
			main.f_demoStart()
			if getCredits() > 0 then break end
			--hiscores
			main.f_hiscore("arcade", -1)
			if getCredits() > 0 then break end
			--start
			if main.f_attractStart() then
				startScreen = true
				break
			end
			--demo
			main.f_demoStart()
			if getCredits() > 0 then break end
			--hiscores
			main.f_hiscore("arcade", -1)
			if getCredits() > 0 then break end
		end
		if startScreen or main.f_attractStart() then
			--attract storyboard
			if motif.attract_mode.start.storyboard ~= '' then
				main.f_storyboard(motif.attract_mode.start.storyboard)
			end
			--eat credit
			if getCredits() > 0 then
				setCredits(getCredits() - 1)
			end
			--enter menu
			main.menu.loop()
		elseif getCredits() > 0 then
			setCredits(getCredits() - 1)
		end
	end
end

setCredits(-1)
function main.f_setCredits()
	if motif.attract_mode.enabled or start.challenger ~= 0 then
		return
	end
	setCredits(gameOption('Options.Credits') - 1)
end

--demo mode
function main.f_demo()
	if #main.t_randomChars == 0 then
		return
	end
	if fadeActive() or not motif.demo_mode.enabled then
		demoFrameCounter = 0
		return
	end
	demoFrameCounter = demoFrameCounter + 1
	if demoFrameCounter < motif.demo_mode.title.waittime then
		return
	end
	demoFrameCounter = 0
	fadeOutInit(motif[main.group].fadeout.FadeData)
	main.menu.f = main.t_itemname.demo()
end

-- prevents mirrored palette in demo mode / randomtest mirror matches
function main.f_getUniquePalette(ch, state)
	local charData = start.f_getCharData(ch)
	local pals = charData and charData.pal or {1}
	state = state or {}
	state.used = state.used or {}
	state.used[ch] = state.used[ch] or {}
	local used = state.used[ch]

	-- build list of palettes not yet used for this character
	local available = {}
	for _, p in ipairs(pals) do
		if not used[p] then
			table.insert(available, p)
		end
	end

	-- If we've exhausted all palettes, start cycling again for this character
	if #available == 0 then
		used = {}
		state.used[ch] = used
		for _, p in ipairs(pals) do
			table.insert(available, p)
		end
	end

	local pal = available[math.random(#available)]
	used[pal] = true
	state.last = {ch = ch, pal = pal}
	return pal
end

function main.f_demoStart()
	main.f_default()
	main.pauseMenu = false
	local palState = {}
	setFightScreenElements({bars = motif.demo_mode.fight.bars.display})
	setGameMode('demo')
	for side = 1, 2 do
		setTeamMode(side, 0, 1)
		setCom(side, 8)
		local ch = main.t_randomChars[math.random(1, #main.t_randomChars)]
		local pal = main.f_getUniquePalette(ch, palState)
		selectChar(side, ch, pal)
	end
	start.f_setStage()
	if motif.demo_mode.fight.stopbgm then
		stopBgm()
	end
	hook.run("main.t_itemname", t, item)
	--clearColor(motif[main.background].bgclearcolor[1], motif[main.background].bgclearcolor[2], motif[main.background].bgclearcolor[3])
	loadStart(start.f_buildLoadStartParams())
	game()
	if not motif.attract_mode.enabled then
		if introWaitCycles >= motif.demo_mode.intro.waitcycles then
			main.f_hiscore("arcade", -1)
			if motif.files.intro.storyboard ~= '' then
				main.f_storyboard(motif.files.intro.storyboard)
			end
			introWaitCycles = 0
		else
			introWaitCycles = introWaitCycles + 1
		end
		bgReset(motif[main.background].BGDef)
		--start title BGM only if it has been interrupted
		if motif.demo_mode.fight.stopbgm or motif.demo_mode.fight.playbgm or (introWaitCycles == 0 and motif.files.intro.storyboard ~= '') then
			playBgm({source = "motif.title", interrupt = true})
		end
	end
	fadeInInit(motif[main.group].fadein.FadeData)
end

--randomtest
function main.f_randomtest()
	while true do
		clearSelected()
		resetGameParams()
		local palState = {}
		local teamMode = math.random(0, 3)
		local numChars = 1
		if teamMode == 1 then
			numChars = math.random(gameOption('Options.Simul.Min'), gameOption('Options.Simul.Max'))
		elseif teamMode == 2 then
			numChars = math.random(gameOption('Options.Turns.Min'), gameOption('Options.Turns.Max'))
		elseif teamMode == 3 then
			numChars = math.random(gameOption('Options.Tag.Min'), gameOption('Options.Tag.Max'))
		end
		for side = 1, 2 do
			start.p[side].teamMode = teamMode
			start.p[side].numChars = numChars
			start.p[side].turnsOffset = 0
			start.p[side].t_selected = {}
			start.p[side].t_selTemp = {}
			setTeamMode(side, teamMode, numChars)
			for i = 1, numChars do
				local pn = (i - 1) * 2 + side
				if pn <= 12 then
					setCom(pn, 8)
				end
				local ch = main.t_randomChars[math.random(1, #main.t_randomChars)]
				local pal = main.f_getUniquePalette(ch, palState)
				selectChar(side, ch, pal)
				table.insert(start.p[side].t_selected, {
					ref = ch,
					pal = pal,
					pn = start.f_getPlayerNo(side, i),
				})
			end
		end
		start.f_setRounds(nil, {})
		start.f_setStage()
		loadStart(start.f_buildLoadStartParams())
		game()
		refresh()
		if getWinnerTeam() == -1 then
			bgReset(motif[main.background].BGDef)
			playBgm({source = "motif.title", interrupt = true})
			fadeInInit(motif[main.group].fadein.FadeData)
			break
		end
	end
end

--calculate menu.tween and boxcursor.tween
local function f_tweenStep(val, target, factor)
	if not factor or factor <= 0 then
		return target
	end
	local newVal = val + (target - val) * math.min(factor, 1)
	if math.abs(newVal - target) < 1 then
		return target
	end
	return newVal
end

--common menu calculations
function main.f_menuCommonCalc(t, item, cursorPosY, moveTxt, sec, cursorParams, forcedDir)
	local m = sec.menu or sec
	-- persistent scroll tween per section
	if not sec.menuTweenData then
		sec.menuTweenData = {
			currentPos = 0,
			targetPos = 0,
			slideOffset = 0
		}
	end
	local item_before = item
	local startItem = 1
	for _, v in ipairs(t) do
		if not v.itemname:match("^spacer%d*$") then
			break
		end
		startItem = startItem + 1
	end
	-- effective visible-items: treat 0 / nil as "all items"
	local visible = #t
	if m.window and m.window.visibleitems ~= nil then
		if m.window.visibleitems > 0 then
			visible = m.window.visibleitems
		end
	end
	-- movement: forcedDir: 1 = next (down), -1 = previous (up), 0/nil = no forced move
	local moveDir = 0
	if forcedDir ~= nil then
		moveDir = forcedDir
	elseif getInput(-1, m.next.key) then
		moveDir = 1
	elseif getInput(-1, m.previous.key) then
		moveDir = -1
	end
	if moveDir == 1 then
		if forcedDir == nil then
			sndPlay(motif.Snd, cursorParams.move.snd[1], cursorParams.move.snd[2])
		end
		while true do
			item = item + 1
			if cursorPosY < visible then
				cursorPosY = cursorPosY + 1
			end
			if t[item] == nil or not t[item].itemname:match("^spacer%d*$") then
				break
			end
		end
	elseif moveDir == -1 then
		if forcedDir == nil then
			sndPlay(motif.Snd, cursorParams.move.snd[1], cursorParams.move.snd[2])
		end
		while true do
			item = item - 1
			if cursorPosY > startItem then
				cursorPosY = cursorPosY - 1
			end
			if t[item] == nil or not t[item].itemname:match("^spacer%d*$") then
				break
			end
		end
	end
	main.menuWrapped = false
	if item > #t or (item == 1 and t[item].itemname:match("^spacer%d*$")) then
		item = 1
		while true do
			if not t[item].itemname:match("^spacer%d*$") or item >= #t then break end
			item = item + 1
		end
		cursorPosY = item
		if m.tween.wrap.snap then
			main.menuSnap = true
		end
		main.menuWrapped = true
	elseif item < 1 then
		item = #t
		while true do
			if not t[item].itemname:match("^spacer%d*$") or item <= 1 then break end
			item = item - 1
		end
		if item > visible then
			cursorPosY = visible
		else
			cursorPosY = item
		end
		if m.tween.wrap.snap then
			main.menuSnap = true
		end
		main.menuWrapped = true
	end
	-- Reset active background animation when cursor selection changes
	if item_before ~= item and t ~= nil and t[item] ~= nil then
		local bgTable = m.item and m.item.active and m.item.active.bg
		if bgTable ~= nil then
			local params = bgTable[t[item].paramname] or bgTable.default
			if params ~= nil and params.AnimData ~= nil then
				animReset(params.AnimData)
				animUpdate(params.AnimData)
			end
		end
	end
	-- compute target: determine first visible item to keep cursor at row `cursorPosY`, clamp to valid range, and convert to pixel offset
	local spacing = m.item.spacing[2]
	-- max index that can appear at the top of the window
	local maxFirst = math.max(1, #t - visible + 1)
	local t_factor = m.tween.factor

	-- which list index should be drawn on the very first row
	local desiredFirst = item - cursorPosY + 1
	-- clamp so we never scroll before the first row or past the end
	if desiredFirst < 1 then
		desiredFirst = 1
	elseif desiredFirst > maxFirst then
		desiredFirst = maxFirst
	end

	-- Measure scroll offset from the first drawn row.
	local targetMove = (desiredFirst - 1) * spacing
	-- update target and offset if changed, snap immediately if requested, otherwise apply tween or direct move
	if sec.menuTweenData.targetPos ~= targetMove then
		sec.menuTweenData.targetPos = targetMove
		sec.menuTweenData.slideOffset = sec.menuTweenData.currentPos - sec.menuTweenData.targetPos
	end

	if main.menuSnap then
		sec.menuTweenData.currentPos = sec.menuTweenData.targetPos
		sec.menuTweenData.slideOffset = 0
		main.menuSnap = false
		moveTxt = sec.menuTweenData.currentPos
		return cursorPosY, moveTxt, item
	end

	if t_factor[1] > 0 then
		sec.menuTweenData.slideOffset = f_tweenStep(sec.menuTweenData.slideOffset, 0, t_factor[1])
		sec.menuTweenData.currentPos = sec.menuTweenData.targetPos + sec.menuTweenData.slideOffset
	else
		sec.menuTweenData.currentPos = sec.menuTweenData.targetPos
		sec.menuTweenData.slideOffset = 0
	end
	moveTxt = sec.menuTweenData.currentPos
	return cursorPosY, moveTxt, item
end

--common menu draw
function main.f_menuCommonDraw(t, item, cursorPosY, moveTxt, sec, bg, skipClear, opts)
	main.f_preloadTick(2)
	local m = sec.menu or sec
	-- opts:
	--   offx, offy               : per-call offsets
	--   skipBG0, skipBG1         : skip bg layer 0 / 1
	--   skipTitle                : skip drawing the title
	--   forceInactive            : treat "selected" row as inactive (no highlight, no cursor)
	opts = opts or {}
	local offx = opts.offx or 0
	local offy = opts.offy or 0
	local forceInactive = (opts.forceInactive == true)

	-- effective visible-items: treat 0 or 'unlimitedItems' as "all"
	local visible = (m.window and m.window.visibleitems) or #t
	if not visible or visible <= 0 then
		visible = #t
	end

	if not skipClear then
		clearColor(bg.bgclearcolor[1], bg.bgclearcolor[2], bg.bgclearcolor[3])
	end
	--draw layerno = 0 backgrounds
	if not opts.skipBG0 then
		bgDraw(bg.BGDef, 0)
	end

	--draw menu box
	if m.boxbg.visible then
		local x1 = offx + m.pos[1] + m.boxcursor.coords[1]
		local y1 = offy + m.pos[2] + m.boxcursor.coords[2]
		local w  = m.boxcursor.coords[3] - m.boxcursor.coords[1] + 1
		local h  = m.boxcursor.coords[4] - m.boxcursor.coords[2] + 1
			+ (math.min(#t, visible) - 1) * m.item.spacing[2]
		rectSetWindow(m.boxbg.RectData, x1, y1, x1 + w, y1 + h)
		rectUpdate(m.boxbg.RectData)
		rectDraw(m.boxbg.RectData)
	end
	--draw title
	if not opts.skipTitle and sec.title and sec.title.TextSpriteData then
		textImgDraw(sec.title.TextSpriteData)
	end
	--draw menu items
	local cur = moveTxt
	local tgt = moveTxt
	if sec.menuTweenData then
		cur = sec.menuTweenData.currentPos or sec.menuTweenData.slideOffset or cur
		tgt = sec.menuTweenData.targetPos or tgt
	end
	local tweenDone = math.abs((cur or 0) - (tgt or 0)) < 1

	local items_shown = item + visible - cursorPosY
	if items_shown > #t or (visible > 0 and items_shown < #t and (m.window.margins.y[1] ~= 0 or m.window.margins.y[2] ~= 0)) then
		items_shown = #t
	end

	-- helper that draws a single item either as active or inactive
	local function drawItem(i, isActive)
		local itemData = t[i]
		-- display name
		local displayname = main.f_itemnameUpper(itemData.displayname, m.item.uppercase)
		if itemData.itemname:match("^spacer%d*$") then
			displayname = ""
		end
		-- shared position
		local posX = offx + (i - 1) * m.item.spacing[1]
		local posY = offy + (i - 1) * m.item.spacing[2] - moveTxt
		-- background params
		local bgTable = isActive and m.item.active.bg or m.item.bg
		local params = bgTable[itemData.paramname] or bgTable.default
		-- draw background
		local bgPosX = offx 
		local bgPosY = offy
		if bgTable.default.spacing[1] ~= 0 or bgTable.default.spacing[2] ~= 0 then
			bgPosX = bgPosX + (i - 1) * bgTable.default.spacing[1]
			bgPosY = bgPosY + (i - 1) * bgTable.default.spacing[2] - moveTxt
		end
		main.f_animPosDraw(params.AnimData, bgPosX, bgPosY)
		-- text sprite for label
		local labelSprite
		if itemData.selected then
			labelSprite = isActive and m.item.selected.active.TextSpriteData or m.item.selected.TextSpriteData
		else
			labelSprite = isActive and m.item.active.TextSpriteData or m.item.TextSpriteData
		end
		textImgReset(labelSprite)
		textImgAddPos(labelSprite, posX, posY)
		textImgSetText(labelSprite, displayname)
		textImgDraw(labelSprite)
		-- value / info sprites
		if itemData.vardisplay ~= nil then
			if itemData.conflict and m.item.value.conflict and m.item.value.conflict.TextSpriteData then
				local spr = m.item.value.conflict.TextSpriteData
				textImgReset(spr)
				textImgAddPos(spr, posX, posY)
				textImgSetText(spr, itemData.vardisplay)
				textImgDraw(spr)
			else
				local spr = isActive and m.item.value.active.TextSpriteData or m.item.value.TextSpriteData
				textImgReset(spr)
				textImgAddPos(spr, posX, posY)
				textImgSetText(spr, itemData.vardisplay)
				textImgDraw(spr)
			end
		elseif itemData.infodisplay ~= nil then
			local spr = isActive and m.item.info.active.TextSpriteData or m.item.info.TextSpriteData
			textImgReset(spr)
			textImgAddPos(spr, posX, posY)
			textImgSetText(spr, itemData.infodisplay)
			textImgDraw(spr)
		end
	end
	-- draw not active items
	for i = 1, items_shown do
		if i > item - cursorPosY or not tweenDone then
			local isSelected = (i == item) and (not forceInactive)
			if not isSelected then
				drawItem(i, false)
			end
		end
	end
	-- draw active items
	for i = 1, items_shown do
		if i > item - cursorPosY or not tweenDone then
			local isSelected = (i == item) and (not forceInactive)
			if isSelected then
				drawItem(i, true)
			end
		end
	end
	--initialize storage for boxcursor per section if missing
	if not sec.boxCursorData then
		sec.boxCursorData = {
			offsetY = 0, 
			snap = 0, 
			init = false
		}
	end
	--calculate target Y position for cursor
	local targetY = offy + m.pos[2] + m.boxcursor.coords[2] + (cursorPosY - 1) * m.item.spacing[2]
	local t_factor = m.boxcursor.tween.factor
	--snap cursor immediately if first use or snap enabled
	if sec.boxCursorData.snap == 1 or not sec.boxCursorData.init then
		sec.boxCursorData.offsetY = targetY
		sec.boxCursorData.init = true
		sec.boxCursorData.snap = -1
	end
	if m.boxcursor.tween.wrap.snap and main.menuWrapped then
		sec.boxCursorData.offsetY = targetY
	end
	--apply tween if enabled, otherwise snap to target
	if t_factor[1] > 0 then
		sec.boxCursorData.offsetY = f_tweenStep(sec.boxCursorData.offsetY, targetY, t_factor[1])
	else
		sec.boxCursorData.offsetY = targetY
	end
	--draw menu cursor
	if m.boxcursor.visible and not fadeActive() and not forceInactive then
		local x1 = offx + m.pos[1] + m.boxcursor.coords[1] + (cursorPosY - 1) * m.item.spacing[1]
		local y1 = sec.boxCursorData.offsetY
		local w  = m.boxcursor.coords[3] - m.boxcursor.coords[1] + 1
		local h  = m.boxcursor.coords[4] - m.boxcursor.coords[2] + 1
		rectSetWindow(m.boxcursor.RectData, x1, y1, x1 + w, y1 + h)
		rectUpdate(m.boxcursor.RectData)
		rectDraw(m.boxcursor.RectData)
	end
	--draw scroll arrows
	if #t > visible then
		if item > cursorPosY then
			animReset(m.arrow.up.AnimData, {'pos'})
			animAddPos(m.arrow.up.AnimData, offx, offy)
			animUpdate(m.arrow.up.AnimData)
			animDraw(m.arrow.up.AnimData)
		end
		if item >= cursorPosY and item + visible - cursorPosY < #t then
			animReset(m.arrow.down.AnimData, {'pos'})
			animAddPos(m.arrow.down.AnimData, offx, offy)
			animUpdate(m.arrow.down.AnimData)
			animDraw(m.arrow.down.AnimData)
		end
	end
	--draw credits text
	if motif.attract_mode.enabled and getCredits() ~= -1 then
		textImgReset(motif.attract_mode.credits.TextSpriteData)
		textImgSetText(motif.attract_mode.credits.TextSpriteData, string.format(motif.attract_mode.credits.text, getCredits()))
		textImgDraw(motif.attract_mode.credits.TextSpriteData)
	end
	--draw layerno = 1 backgrounds
	if not opts.skipBG1 then
		bgDraw(bg.BGDef, 1)
	end
	--draw footer
	if sec.footer ~= nil then
		rectDraw(sec.footer.overlay.RectData)
		textImgDraw(sec.footer.title.TextSpriteData)
		textImgDraw(sec.footer.info.TextSpriteData)
		textImgDraw(sec.footer.version.TextSpriteData)
	end
	--frame transition
	if not skipClear then
		refresh()
	end
end

--force menu to snap, boxcursor snaps if enabled
function main.f_menuSnap(sec)
	main.menuSnap = true
	if sec.boxCursorData then
		sec.boxCursorData.snap = sec.menu.boxcursor.tween.snap
	end
end

-- Reset all menu item background animations
function main.f_menuItemBgAnimReset(sec)
	if sec == nil or sec.menu == nil or sec.menu.item == nil then
		return
	end
	local function resetBgTable(bgTable)
		if type(bgTable) ~= 'table' then return end
		for _, params in pairs(bgTable) do
			if type(params) == 'table' and params.AnimData ~= nil then
				animReset(params.AnimData)
				animUpdate(params.AnimData)
			end
		end
	end
	-- reset both inactive and active item backgrounds
	if sec.menu.item.bg ~= nil then
		resetBgTable(sec.menu.item.bg)
	end
	if sec.menu.item.active ~= nil and sec.menu.item.active.bg ~= nil then
		resetBgTable(sec.menu.item.active.bg)
	end
end

--common timer draw code
function main.f_drawTimer(timer, params)
	local num = main.f_round((params.count * params.framespercount - timer + params.displaytime) / params.framespercount)
	local active = true
	if num <= -1 then
		active = false
		timer = -1
		textImgReset(params.TextSpriteData)
		textImgSetText(params.TextSpriteData, string.format(params.text, 0))		
	elseif timer ~= -1 then
		timer = timer + 1
		textImgReset(params.TextSpriteData)
		textImgSetText(params.TextSpriteData, string.format(params.text, math.max(0, num)))
	end
	if timer == -1 or timer >= params.displaytime then
		textImgDraw(params.TextSpriteData)
	end
	return timer, active
end

--;===========================================================
--; EXTERNAL LUA CODE
--;===========================================================
local t_modules = {}
for _, v in ipairs(getDirectoryFiles('external/mods')) do
	if v:lower():match('%.([^%.\\/]-)$') == 'lua' then
		local fileName = v:match("[^/\\]+$") or v
		-- Lua files prefixed with '-' are excluded from autoloading
		if not fileName:match("^%-") then
			table.insert(t_modules, v)
		end
	end
end

for _, v in ipairs(gameOption('Common.Modules')) do
	table.insert(t_modules, v)
end
if motif.files.module ~= '' then table.insert(t_modules, motif.files.module) end
for _, v in ipairs(t_modules) do
	print('Loading module: ' .. v)
	v = v:gsub('^%s*[%./\\]*', '')
	v = v:gsub('%.[^%.]+$', '')
	require(v:gsub('[/\\]+', '.'))
end

main.f_unlock(false)

--;===========================================================
--; INITIALIZE LOOPS
--;===========================================================
if gameOption('Debug.DumpLuaTables') then
	main.f_printTable(main.t_selChars, "debug/t_selChars.txt")
	main.f_printTable(main.t_selStages, "debug/t_selStages.txt")
	main.f_printTable(main.t_selOptions, "debug/t_selOptions.txt")
	main.f_printTable(main.t_selStoryMode, "debug/t_selStoryMode.txt")
	main.f_printTable(main.t_orderChars, "debug/t_orderChars.txt")
	main.f_printTable(main.t_orderStages, "debug/t_orderStages.txt")
	main.f_printTable(main.t_randomChars, "debug/t_randomChars.txt")
	main.f_printTable(main.t_bonusChars, "debug/t_bonusChars.txt")
	main.f_printTable(main.t_stageDef, "debug/t_stageDef.txt")
	main.f_printTable(main.t_charDef, "debug/t_charDef.txt")
	main.f_printTable(main.t_includeStage, "debug/t_includeStage.txt")
	main.f_printTable(main.t_selectableStages, "debug/t_selectableStages.txt")
	main.f_printTable(main.t_selGrid, "debug/t_selGrid.txt")
	main.f_printTable(main.t_unlockLua, "debug/t_unlockLua.txt")
	main.f_printTable(loadGameOption(), "debug/config.txt")
end

main.f_start()
menu.f_start()
options.f_start()

if getCommandLineValue("-p1") ~= nil and getCommandLineValue("-p2") ~= nil and getCommandLineValue("-loadmotif") ~= nil then
	main.f_commandLine()
end

main.f_loadingRefresh()

if motif.attract_mode.enabled then
	main.f_attractMode()
else
	main.menu.loop()
end

-- Debug Info
--if gameOption('Debug.DumpLuaTables') then main.f_printTable(main, "debug/t_main.txt") end
