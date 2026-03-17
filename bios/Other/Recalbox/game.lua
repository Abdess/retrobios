-- DirkSimple; a dirt-simple player for FMV games.
--
-- Please see the file LICENSE.txt in the source's root directory.
--
--  This file written by Ryan C. Gordon.
--

DirkSimple.gametitle = "Cliff Hanger"

-- CVARS
local starting_lives = 6  -- number of lives player gets at startup. Six was the maximum that arcade cabinet dip switches allowed.
local infinite_lives = false  -- set to true to not lose a life on failure.
local show_lives_and_score = true  -- if true, overlay current lives and score at top of laserdisc video during scenes. This is usually enabled in arcade cabinets' dip switches.
local show_hints = true  -- if true, overlay hints about the expected move at the bottom of the laserdisc video during scenes. This is often enabled in arcade cabinets' dip switches.
local show_full_hints = false  -- if true, instead of "ACTION" or "STICK" it tells you the exact necessary move. The real version doesn't do this!
local show_hanging_scene = false  -- They show Cliff getting hanged (get it, CLIFF HANGER?!?) after each failure and it takes forever and it is kinda disturbing. There's a dip switch to disable it. Set it to false to disable it here, too.
local show_should_have_hint = 3  -- show "SHOULD HAVE USED FEET" etc after X failures in a row (zero to disable, 1 shows on every failure).
local allow_buy_in = true  -- allow player to continue on game over?
local god_mode = false  -- if true, game plays correct moves automatically, so you never fail.

DirkSimple.cvars = {
    { name="starting_lives", desc="Number of lives player starts with", values="6|5|4|3|2|1", setter=function(name, value) starting_lives = DirkSimple.to_int(value) end },
    { name="infinite_lives", desc="Don't lose a life when failing", values="false|true", setter=function(name, value) infinite_lives = DirkSimple.to_bool(value) end },
    { name="show_lives_and_score", desc="Show score and lives remaining at top of screen", values="true|false", setter=function(name, value) show_lives_and_score = DirkSimple.to_bool(value) end },
    { name="show_hints", desc="Show hints at bottom of screen about expected moves", values="true|false", setter=function(name, value) show_hints = DirkSimple.to_bool(value) end },
    { name="show_full_hints", desc="Show exact required moves on the HUD", values="false|true", setter=function(name, value) show_full_hints = DirkSimple.to_bool(value) end },
    { name="show_hanging_scene", desc="Show Cliff being hanged after each failure", values="false|true", setter=function(name, value) show_hanging_scene = DirkSimple.to_bool(value) end },
    { name="show_should_have_hint", desc="Show the correct choice after X failures in a row", values="3|2|always|never", setter=function(name, value) if value == "always" then value = 1 elseif value == "never" then value = 0 else value = DirkSimple.to_int(value) end show_should_have_hint = value end },
    { name="allow_buy_in", desc="Allow player to continue on game over", values="true|false", setter=function(name, value) allow_buy_in = DirkSimple.to_bool(value) end },
    { name="god_mode", desc="Game plays itself perfectly, never failing", values="false|true", setter=function(name, value) god_mode = DirkSimple.to_bool(value) end }
}

-- SOME INITIAL SETUP STUFF
local scenes = nil  -- gets set up later in the file.
local test_scene = nil  -- set to index of scene to test. nil otherwise!
local test_sequence_num = nil  -- set to index of sequence to test. nil otherwise!
--test_scene = 5 ; test_sequence = 1

-- GAME STATE
local scene_manager = {}
local alltime_highscores = nil  -- set up later in the file
local today_highscores = nil  -- set up later in the file


-- FUNCTIONS

-- Cliff Hanger counts frames at 29.97fps, not 23.976fps like Dragon's Lair.
local function laserdisc_frame_to_ms(frame)
    return (frame / 29.97) * 1000.0
end

local function seek_laserdisc_to(frame)
    -- will suspend ticking until the seek completes and reset sequence tick count
    scene_manager.last_seek = laserdisc_frame_to_ms(frame - 6)
    scene_manager.unserialize_offset = 0
    DirkSimple.start_clip(scene_manager.last_seek)
end

local function halt_laserdisc()
    -- will suspend ticking until the seek completes and reset sequence tick count
    scene_manager.last_seek = -1
    scene_manager.unserialize_offset = 0
    DirkSimple.halt_video()
end

local function setup_scene_manager()
    scene_manager.initialized = true
    scene_manager.accepted_input = nil
    scene_manager.attract_mode_state = 0
    scene_manager.death_mode_state = 0
    scene_manager.scene_start_state = 0
    scene_manager.scene_start_tick_offset = 0
    scene_manager.game_over_state = 0
    scene_manager.player_initials = { ' ', ' ', ' ' }
    scene_manager.player_initials_entered = 0
    scene_manager.player_initials_selected_glyph = 0
    scene_manager.lives_left = starting_lives
    scene_manager.current_score = 0
    scene_manager.last_failed_scene = 0
    scene_manager.last_failed_sequence = 0
    scene_manager.failures_in_a_row = 0
    scene_manager.last_seek = 0
    scene_manager.current_scene = nil
    scene_manager.current_scene_num = 0
    scene_manager.current_sequence = nil
    scene_manager.current_sequence_num = 0
    scene_manager.current_scene_ticks = 0
    scene_manager.laserdisc_frame = 0
    scene_manager.unserialize_offset = 0
end

-- Cliff Hanger only draws "characters" to a grid on the screen. It could not
-- draw outside the grid (one character filled a cell, you couldn't draw
-- in the middle to straddle two cells, which means you could not position
-- anything by pixel position if it didn't align to the grid. Think of it
-- as a fancy text terminal.
-- Coordinates and sizes are in character blocks (8x8 pixels). The logical
-- screen here is 40x24 blocks, so we'll scale as appropriate to match the
-- laserdisc video resolution.
local function draw_sprite_chars(name, sx, sy, sw, sh, dx, dy, modr, modg, modb)
    -- scale dest coords for the screen resolution.
    -- some percentage of the laserdisc video height is letterboxing, don't count that part.
    local blockh = (DirkSimple.video_height - (DirkSimple.video_height * 0.216666)) / 24.0
    local blockw = DirkSimple.video_width / 40.0
    dx = DirkSimple.truncate(DirkSimple.truncate(dx) * blockw)
    dy = DirkSimple.truncate((DirkSimple.truncate(dy) * blockh) + (DirkSimple.video_height * 0.10))
    local dw = DirkSimple.truncate((sw * blockw) + 0.5)
    local dh = DirkSimple.truncate((sh * blockh) + 0.5)

    -- convert from source blocks to pixels
    sx = DirkSimple.truncate(sx) * 8
    sy = DirkSimple.truncate(sy) * 8
    sw = DirkSimple.truncate(sw) * 8
    sh = DirkSimple.truncate(sh) * 8

    --DirkSimple.log("draw_sprite(" .. sx .. ", " .. sy .. ", " .. sw .. ", " .. sh .. ", " .. dx .. ", " .. dy .. ", " .. dw .. ", " .. dh .. ")")
    DirkSimple.draw_sprite(name, sx, sy, sw, sh, dx, dy, dw, dh, modr, modg, modb)
end

local chartable = nil
local function draw_text(str, x, y, modr, modg, modb)
    if chartable == nil then
        local x = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[~]^~`abcdefghijklmnopqrstuvwxyz{|}"
        local bytelist = { x:byte(1, #x) }
        chartable = {}
        for i,ch in ipairs(bytelist) do
            chartable[ch] = i
        end
    end

    local bytes = { str:byte(1, #str) }
    for i,ch in ipairs(bytes) do
        local idx = chartable[ch]
        if idx == nil then
            idx = 1
        end
        draw_sprite_chars("cliffglyphs", idx - 1, 0, 1, 1, x, y, modr, modg, modb)
        x = x + 1
    end
end

local function draw_rectangle(x, y, w, h, r, g, b)
    draw_sprite_chars("cliffglyphs", 99, 0, 1, 1, x, y, r, g, b)
    draw_sprite_chars("cliffglyphs", 98, 0, 1, 1, x+w+1, y, r, g, b)
    draw_sprite_chars("cliffglyphs", 101, 0, 1, 1, x, y+h+1, r, g, b)
    draw_sprite_chars("cliffglyphs", 100, 0, 1, 1, x+w+1, y+h+1, r, g, b)
    for i = 1,w,1 do
        draw_sprite_chars("cliffglyphs", 96, 0, 1, 1, x+i, y, r, g, b)
        draw_sprite_chars("cliffglyphs", 96, 0, 1, 1, x+i, y+h+1, r, g, b)
    end
    for i = 1,h,1 do
        draw_sprite_chars("cliffglyphs", 97, 0, 1, 1, x, y+i, r, g, b)
        draw_sprite_chars("cliffglyphs", 97, 0, 1, 1, x+w+1, y+i, r, g, b)
    end
end

local function draw_standard_rectangle(idx, r, g, b)
    draw_rectangle(idx, idx, 38 - (idx * 2), 21 - (idx * 2), r, g, b)
end

-- these color values come from Daphne's TMS9128NL code.
local colortable = {  -- red, blue, green triplets.
    black = { 0, 0, 0 },
    medium_green = { 26, 219, 36 },
    light_green = { 109, 255, 109 },
    dark_blue = { 36, 36, 255 },
    light_blue = { 73, 109, 255 },
    dark_red = { 182, 36, 36 },
    purple = { 125, 0, 128 },  -- daphne uses this for Cliff Hanger's move prompts, looks more accurate to the arcade than dark_red.
    light_cyan = { 73, 219, 255 },
    medium_red = { 255, 36, 36 },
	light_red = { 255, 109, 109 },
    dark_yellow = { 219, 219, 36 },
    light_yellow = { 219, 219, 146 },
	dark_green = { 36, 146, 36 },
    magenta = { 219, 73, 182 },
    grey = { 182, 182, 182 },
    white = { 255, 255, 255 }
}

local function mapcolor(name)
    if colortable[name] == nil then
        name = "black"
    end
    local triplet = colortable[name]
    return triplet[1], triplet[2], triplet[3]
end


local start_attract_mode = nil -- predeclare

local attract_mode_flash_colors = {   -- just foreground
    "white", "light_yellow", "medium_red", "dark_yellow", "dark_blue", "dark_green", "light_green"
}

local function start_scene(scenenum, sequencenum)
    if test_scene ~= nil then
        scenenum = test_scene
        sequencenum = test_sequence
        if sequencenum == nil then
            sequencenum = 0
        end
    end

    local start_of_scene = (sequencenum == 0)
    if start_of_scene then
        sequencenum = 1
    end

    local seqname = nil
    if (scenes[scenenum] ~= nil) and (scenes[scenenum].moves ~= nil) and (scenes[scenenum].moves[sequencenum] ~= nil) then
        seqname = scenes[scenenum].moves[sequencenum].name
    end
    if seqname ~= nil then
        seqname = " (" .. seqname .. ")"
    else
        seqname = ''
    end

    DirkSimple.log("Starting scene " .. scenenum .. " (" .. scenes[scenenum].scene_name .. "), sequence " .. sequencenum .. seqname)
    scene_manager.current_scene_num = scenenum
    scene_manager.current_scene = scenes[scenenum]
    scene_manager.current_sequence_num = sequencenum
    scene_manager.current_sequence = scene_manager.current_scene.moves[sequencenum]
    scene_manager.accepted_input = nil

    scene_manager.scene_start_state = 1
    if not start_of_scene then
        scene_manager.scene_start_state = 2
    end
end

local function start_game()
    DirkSimple.log("Start game!")
    setup_scene_manager()
    halt_laserdisc()
    start_scene(1, 0)
end

local function draw_high_scores(ticks)
    DirkSimple.clear_screen(mapcolor("magenta"))

    draw_rectangle(0, 0, 19, 22, mapcolor("white"))
    draw_rectangle(20, 0, 18, 22, mapcolor("white"))
    draw_text("The Highest Scores", 2, 1, mapcolor("white"))

    -- this only shows the default scores for now. We could manage actual scores, though!
    for i,v in ipairs(alltime_highscores) do
        if ticks >= (i * 100) then
            local score = "" .. v[2]
            local y = 2 + (i * 2)
            draw_text(v[1], 2, y, mapcolor("white"))
            draw_text(score, 19 - #score, y, mapcolor("white"))
        end
    end

    if ticks >= 1100 then
        draw_text("High Scores Today", 22, 1, mapcolor("white"))
        for i,v in ipairs(today_highscores) do
            if ticks >= (1100 + (i * 100)) then
                local score = "" .. v[2]
                local y = 2 + (i * 2)
                draw_text(v[1], 22, y, mapcolor("white"))
                draw_text(score, 39 - #score, y, mapcolor("white"))
            end
        end
    end
end

local function tick_attract_mode(inputs)
    -- !!! FIXME: if someone wants to make this frame-perfect, feel free to adjust all the magic tick values in this function.
    local ticks = scene_manager.current_scene_ticks
    if scene_manager.attract_mode_state == 1 then  -- state == 1? Showing initial intro before laserdisc starts playing.
        if ticks <= 2000 then  -- Sliding in initial logo.
            DirkSimple.clear_screen(mapcolor("black"))
            draw_sprite_chars("logo", 0, 0, 20, 10, 31 - (31 * (ticks / 2000)), 0, mapcolor("light_blue"))
        elseif ticks <= 3000 then  -- waiting to flash
            DirkSimple.clear_screen(mapcolor("black"))
            draw_sprite_chars("logo", 0, 0, 20, 10, 0, 0, mapcolor("light_blue"))
        elseif ticks <= 3128 then  -- flash
            DirkSimple.clear_screen(mapcolor("light_blue"))
            draw_sprite_chars("logo", 0, 0, 20, 10, 0, 0, mapcolor("dark_red"))
        elseif ticks <= 3256 then  -- flash2
            DirkSimple.clear_screen(mapcolor("light_blue"))
            draw_sprite_chars("logo", 0, 0, 20, 10, 0, 0, mapcolor("white"))
        else  -- into the main graphics screen, before laserdisc kicks in.
            local flashticks = ticks - 8384
            local fg = "black"
            local bg = "light_blue"

            if flashticks > 0 then
                local flashidx = DirkSimple.truncate(flashticks / 128.0)
                if flashidx > #attract_mode_flash_colors then
                    flashidx = #attract_mode_flash_colors   -- moving on to next mode, but do this one more time for this last frame.
                    scene_manager.attract_mode_state = scene_manager.attract_mode_state + 1
                    seek_laserdisc_to(6)  -- start the laserdisc attract mode video playing.
                end

                fg = attract_mode_flash_colors[flashidx]
                if flashidx == #attract_mode_flash_colors then  -- last one chooses a black background.
                    bg = "black"
                end
            end

            DirkSimple.clear_screen(mapcolor(bg))
            draw_sprite_chars("logo", 0, 0, 20, 10, 0, 0, mapcolor(fg))
            if ticks > 4256 then
                draw_text("A Laser Disc Video Game", 8, 16, mapcolor(fg))
            end
            if ticks > 5256 then  -- show byline
                draw_text("BY STERN ELECTRONICS, INC.", 7, 18, mapcolor(fg))
            end
            if ticks > 6256 then  -- show number of credits
                draw_text("FREE PLAY", 15, 23, mapcolor(fg))
            end
        end
    elseif scene_manager.attract_mode_state == 2 then  -- state == 2? Started actual laserdisc attract mode video playing.
        if scene_manager.laserdisc_frame >= 1546 then
            DirkSimple.clear_screen(mapcolor("dark_blue"))
            halt_laserdisc()
            scene_manager.attract_mode_state = scene_manager.attract_mode_state + 1  -- move on to original game's credits page.
            return
        end
    elseif scene_manager.attract_mode_state == 3 then  -- state == 3? Show developer credits.
        -- ticks were reset by the halt_laserdisc call that ended state 2.
        DirkSimple.clear_screen(mapcolor("dark_blue"))
        draw_text("Designed & Programmed By", 8, 7, mapcolor("white"))
        if ticks >= 1000 then
            draw_text("PAUL M. RUBENSTEIN", 11, 10, mapcolor("white"))
        end
        if ticks >= 1100 then
            draw_text("BOB KOWALSKI", 13, 12, mapcolor("white"))
        end
        if ticks >= 1200 then
            draw_text("JON MICHAEL HOGAN", 11, 14, mapcolor("white"))
        end
        if ticks >= 1300 then
            draw_text("EDWARD J. MARCH JR.", 10, 16, mapcolor("white"))
        end
        if ticks >= 1400 then
            local total = DirkSimple.truncate((ticks - 1400) / 128)
            if total > 5 then
                total = 5
            end
            for i = 1,total,1 do
                draw_standard_rectangle(i-1, mapcolor("white"))
            end
        end

        if ticks >= 6300 then -- move on to next state.
            halt_laserdisc()  -- just reset ticks for next state
            scene_manager.attract_mode_state = scene_manager.attract_mode_state + 1  -- move on to DirkSimple credits page.
        end
    elseif scene_manager.attract_mode_state == 4 then  -- state == 4? Added a DirkSimple credits page.
        DirkSimple.clear_screen(mapcolor("medium_red"))
        draw_text("Rebuilt for DirkSimple By", 7, 7, mapcolor("white"))
        if ticks >= 1000 then
            draw_text("RYAN C. GORDON", 13, 12, mapcolor("white"))
        end
        if ticks >= 1500 then
            draw_text("https://icculus.org/dirksimple", 5, 17, mapcolor("light_yellow"))
        end
        if ticks >= 1600 then
            local total = DirkSimple.truncate((ticks - 1600) / 128)
            if total > 3 then
                total = 3
            end
            for i = 1,total,1 do
                draw_standard_rectangle(i-1, mapcolor("white"))
            end
        end
        if ticks >= 4000 then -- move on to next state.
            halt_laserdisc()  -- just reset ticks for next state
            scene_manager.attract_mode_state = scene_manager.attract_mode_state + 1  -- move on to high scores.
        end
    elseif scene_manager.attract_mode_state == 5 then  -- state == 5? High scores list.
        draw_high_scores(ticks)
        if ticks >= 5000 then -- move on to next state.
            halt_laserdisc()  -- just reset ticks for next state
            scene_manager.attract_mode_state = scene_manager.attract_mode_state + 1  -- move on to instructions
        end
    elseif scene_manager.attract_mode_state == 6 then  -- state == 6? Instructions.
        DirkSimple.clear_screen(mapcolor("dark_blue"))
        if ticks >= 128 then
            draw_text("Move the joystick in the", 8, 3, mapcolor("white"))
        end
        if ticks >= 256 then
            draw_text("direction Cliff or his car", 7, 4, mapcolor("white"))
        end
        if ticks >= 386 then
            draw_text("moves on the screen", 10, 5, mapcolor("white"))
        end
        if ticks >= 770 then
            draw_text("Stick right if object moves", 6, 9, mapcolor("white"))
        end
        if ticks >= 898 then
            draw_text("toward right edge of screen", 6, 10, mapcolor("white"))
        end
        if ticks >= 1226 then
            draw_text("Stick left if object moves", 7, 12, mapcolor("white"))
        end
        if ticks >= 1354 then
            draw_text("toward left edge of screen", 7, 13, mapcolor("white"))
        end
        if ticks >= 1682 then
            draw_text("Stick up if object moves", 8, 15, mapcolor("white"))
        end
        if ticks >= 1810 then
            draw_text("toward upper edge of screen", 6, 16, mapcolor("white"))
        end
        if ticks >= 2138 then
            draw_text("Stick down if object moves", 7, 18, mapcolor("white"))
        end
        if ticks >= 2266 then
            draw_text("toward bottom edge of screen", 6, 19, mapcolor("white"))
        end
        if ticks >= 2366 then
            draw_standard_rectangle(0, mapcolor("white"))
        end
        if ticks >= 2466 then
            draw_standard_rectangle(1, mapcolor("white"))
        end
        if ticks >= 12522 then
            scene_manager.attract_mode_state = 1  -- restart attract mode.
            halt_laserdisc()  -- just reset ticks for next state
        end
    end

    if inputs ~= nil and inputs.pressed["start"] then
        start_game()
    end
end

start_attract_mode = function()
    DirkSimple.log("Starting attract mode")
    setup_scene_manager()
    scene_manager.attract_mode_state = 1
    halt_laserdisc()
    tick_attract_mode(nil)  -- start right now.
end

local function game_over(won)
    DirkSimple.log("Game over!")
    scene_manager.accepted_input = nil
    halt_laserdisc()  -- blank laserdisc frame, reset ticks.
    if won then
        scene_manager.game_over_state = 1
    elseif allow_buy_in then
        scene_manager.game_over_state = 2
    else
        scene_manager.game_over_state = 3
    end
end

local failure_flash_colors = {  -- { foreground, background }
    { "white", "dark_blue" },
    { "white", "dark_red" },
    { "dark_blue", "white" },
    { "dark_red", "white" },
    { "white", "dark_blue" },
    { "white", "dark_red" },
    { "white", "dark_blue" },
    { "white", "dark_red" }
}

local function draw_failure_screen(ticks)
    local actions = scene_manager.current_sequence.correct_moves
    local msg = "Y O U ' V E   B L O W N   I T  !"
    if (#actions > 0) and (show_should_have_hint > 0) and (scene_manager.failures_in_a_row >= show_should_have_hint) then
        local input = actions[1]
        if input == "up" then
            msg = "      SHOULD HAVE GONE UP  !"
        elseif input == "down" then
            msg = "      SHOULD HAVE GONE DOWN  !"
        elseif input == "left" then
            msg = "      SHOULD HAVE GONE LEFT  !"
        elseif input == "right" then
            msg = "      SHOULD HAVE GONE RIGHT  !"
        elseif input == "hands" then
            msg = "   SHOULD HAVE USED YOUR HAND  !"
        elseif input == "feet" then
            msg = "   SHOULD HAVE USED YOUR FEET  !"
        end
    end

    local flashidx = DirkSimple.truncate(ticks / 96) + 1
    if flashidx > #failure_flash_colors then
        flashidx = #failure_flash_colors
    end
    local flashcolor = failure_flash_colors[flashidx]
    local fg = flashcolor[1]
    local bg = flashcolor[2]

    DirkSimple.clear_screen(mapcolor(bg))
    for i = 1,40,1 do
        draw_sprite_chars("cliffglyphs", 96, 0, 1, 1, i-1, 6, mapcolor(fg))
        draw_sprite_chars("cliffglyphs", 96, 0, 1, 1, i-1, 16, mapcolor(fg))
    end
    draw_text("PLAYER #  1", 15, 9, mapcolor(fg))
    draw_text(msg, 4, 13, mapcolor(fg))
end

local function tick_death_scene()
    local ticks = scene_manager.current_scene_ticks

    if scene_manager.death_mode_state == 0 then  -- not showing a death sequence.
        return
    elseif scene_manager.death_mode_state == 1 then  -- the "YOU'VE BLOWN IT" screen
        draw_failure_screen(ticks)
        if ticks >= 2000 then
            scene_manager.death_mode_state = scene_manager.death_mode_state + 1  -- show laserdisc death video
            seek_laserdisc_to(scene_manager.current_sequence.death_start_frame)
        end
    elseif scene_manager.death_mode_state == 2 then  -- showing the laserdisc death video clip.
        local end_frame = scene_manager.current_sequence.death_end_frame
        if not show_hanging_scene then
            end_frame = end_frame - 260
        end
        if scene_manager.laserdisc_frame >= end_frame then
            scene_manager.death_mode_state = 0  -- done.
            if scene_manager.lives_left == 0 then
                game_over(false)
            else
                -- In Cliff Hanger, you have to complete each scene in order, before you can do a different one.
                -- don't halt the laserdisc here, the audio from the death scene plays over the start screen.
                start_scene(scene_manager.current_scene_num, scene_manager.current_sequence.restart_move)  -- move back to where the sequence prescribes.
                scene_manager.scene_start_tick_offset = ticks
            end
        end
    end
end

local function kill_player()
    if (not infinite_lives) and (test_scene == nil) then
        scene_manager.lives_left = scene_manager.lives_left - 1
    end

    DirkSimple.log("Killing player (lives now left=" .. scene_manager.lives_left .. ")")

    if (scene_manager.last_failed_scene == scene_manager.current_scene_num) and (scene_manager.last_failed_sequence == scene_manager.current_sequence_num) then
        scene_manager.failures_in_a_row = scene_manager.failures_in_a_row + 1
    else
        scene_manager.failures_in_a_row = 1
        scene_manager.last_failed_scene = scene_manager.current_scene_num
        scene_manager.last_failed_sequence = scene_manager.current_sequence_num
    end

    scene_manager.death_mode_state = 1
    halt_laserdisc()  -- set the scene tick count back to zero; ticking the death scene will start the disc once the initial message is done.
    draw_failure_screen(0)
end

local function move_was_made(inputs, actions)
    if actions ~= nil then
        for i,v in ipairs(actions) do
            local input = v
            if input == "hands" then
                input = "action"
            elseif input == "feet" then
                input = "action2"
            end

            if inputs.pressed[input] then  -- we got one!
                DirkSimple.log("accepted action '" .. v .. "' at " .. tostring(scene_manager.current_scene_ticks / 1000.0))
                return v
            end
        end
    end
    return nil
end

local function draw_hud_lives_left()
    local lives = scene_manager.lives_left
    if lives > 6 then
        lives = 6
    end
    draw_sprite_chars("cliffglyphs", 95, 0, 1, 1, 21, 0, mapcolor("black"))
    draw_sprite_chars("cliffglyphs", 95, 0, 1, 1, 20, 0, mapcolor("black"))
    draw_sprite_chars("cliffglyphs", 94, 0, 1, 1, 20, 0, mapcolor("purple"))
    for i = 1,lives,1 do
        draw_sprite_chars("cliffglyphs", 95, 0, 1, 1, 20-i, 0, mapcolor("black"))
        draw_sprite_chars("cliffglyphs", 112, 0, 1, 1, 20-i, 0, mapcolor("purple"))
    end
    draw_sprite_chars("cliffglyphs", 95, 0, 1, 1, 20-(lives+1), 0, mapcolor("black"))
    draw_sprite_chars("cliffglyphs", 60, 0, 1, 1, 20-(lives+1), 0, mapcolor("purple"))
end

local function draw_hud_current_score()
    local score = "" .. scene_manager.current_score
    local scorex = 10 - #score
    for i = 1,#score+3,1 do  -- draw black background for text
        draw_sprite_chars("cliffglyphs", 95, 0, 1, 1, (scorex-2) + i, 0, mapcolor("black"))
    end
    draw_text(score, scorex, y, mapcolor("purple"))
    draw_sprite_chars("cliffglyphs", 60, 0, 1, 1, scorex - 1, 0, mapcolor("purple"))
    draw_sprite_chars("cliffglyphs", 94, 0, 1, 1, scorex + #score, 0, mapcolor("purple"))
end

local function draw_hud_action_hint(actions)
    if (actions == nil) or (#actions == 0) then
        return
    end

    local hint = nil
    local hintx = nil
    if show_full_hints then
        hint = ""
        local comma = ""
        for i,v in ipairs(actions) do
            hint = hint .. comma .. v
            comma = ", "
        end
        hintx = (40 - (#hint + 5)) / 2
    else
        for i,v in ipairs(actions) do
            local input = v
            if input == "up" or input == "down" or input == "left" or input == "right" then
                hint = "STICK"
                hintx = 15
                break
            elseif input == "hands" or input == "feet" then
                hint = "ACTION"
                hintx = 14
                break
            end
        end
    end

    if hint ~= nil then
        for i = 1,(#hint+5),1 do  -- draw black background for text
            draw_sprite_chars("cliffglyphs", 95, 0, 1, 1, (hintx - 1) + i, 23, mapcolor("black"))
        end
        draw_sprite_chars("cliffglyphs", 60, 0, 1, 1, hintx, 23, mapcolor("purple"))
        draw_text(hint, hintx + 2, 23, mapcolor("purple"))
        draw_sprite_chars("cliffglyphs", 94, 0, 1, 1, hintx + #hint + 4, 23, mapcolor("purple"))
    end
end

local function tick_game(inputs)
    -- if sequence is nil, we've run through all the moves for the scene and are just waiting on the scene to finish playing.
    local sequence = scene_manager.current_sequence
    local laserdisc_frame = scene_manager.laserdisc_frame
    local ticks = scene_manager.current_scene_ticks

    --DirkSimple.log("TICK GAME: ticks=" .. ticks .. ", laserdisc_frame=" .. laserdisc_frame)

    if show_lives_and_score then
        draw_hud_lives_left()
        draw_hud_current_score()
    end

    -- see if it's time to shift to the next sequence.
    if (sequence ~= nil) and (laserdisc_frame >= sequence.end_frame) then
        if (scene_manager.accepted_input == nil) and (sequence.correct_moves ~= nil) and (#sequence.correct_moves ~= 0) and (not god_mode) then
            -- uhoh, player did nothing, they blew it.
            kill_player()
            return
        end

        -- ok, you survived this sequence, moving on to the next!
        scene_manager.accepted_input = nil
        scene_manager.current_sequence_num = scene_manager.current_sequence_num + 1
        scene_manager.current_sequence = scene_manager.current_scene.moves[scene_manager.current_sequence_num]
        sequence = scene_manager.current_sequence

        if sequence == nil then  -- did we run out of sequences?
            DirkSimple.log("Finished all sequences in this scene!")
        else
            local seqname = sequence.name
            if seqname ~= nil then
                seqname = " (" .. seqname .. ")"
            else
                seqname = ''
            end
            DirkSimple.log("Moving on to sequence " .. scene_manager.current_sequence_num .. seqname)
        end
    end

    -- are we in the window for moves in this sequence?
    if (sequence ~= nil) and (scene_manager.accepted_input == nil) and (laserdisc_frame >= sequence.start_frame) then
        if move_was_made(inputs, sequence.incorrect_moves) and (not god_mode) then
            kill_player()
            return
        else
            if show_hints then
                draw_hud_action_hint(sequence.correct_moves)
            end
            if #sequence.correct_moves > 0 then
                if god_mode then
                    scene_manager.accepted_input = sequence.correct_moves[1]
                else
                    scene_manager.accepted_input = move_was_made(inputs, sequence.correct_moves)
                end
                if scene_manager.accepted_input ~= nil then  -- correct move was just made!
                    scene_manager.current_score = scene_manager.current_score + 5000
                end
            end
        end
    end

    -- see if the entire scene has ended.
    if laserdisc_frame >= scene_manager.current_scene.end_frame then
        scene_manager.current_score = scene_manager.current_score + 10000
        if scene_manager.current_scene_num >= #scenes then  -- out of scenes? You won the game!
            game_over(true)
        else
            halt_laserdisc()
            start_scene(scene_manager.current_scene_num + 1, 0)
        end
    end
end

local function draw_start_play_screen(ticks)
    DirkSimple.clear_screen(mapcolor("dark_blue"))
    draw_text("PLAYER #  1", 15, 9, mapcolor("white"))
    local lives_left = scene_manager.lives_left
    if lives_left == starting_lives then
        draw_text("G O O D   L U C K  ! ! !", 8, 13, mapcolor("white"))
    else
        local scorestr = "" .. scene_manager.current_score
        draw_text("YOUR SCORE IS", 7, 12, mapcolor("white"))
        draw_text(scorestr, 21 + (8 - #scorestr), 12, mapcolor("white"))
        local lives_left_msg = "You have   1 life left."
        if lives_left > 1 then
            lives_left_msg = "You have   " .. lives_left .. " lives left."
        end
        draw_text(lives_left_msg, 7, 14, mapcolor("white"))
    end

    local total = DirkSimple.truncate(ticks / 64) + 1
    if total > 5 then
        total = 5
    end
    for i = 1,total,1 do
        draw_standard_rectangle(i-1, mapcolor("white"))
    end
end

local function tick_scene_start()
    if scene_manager.scene_start_state > 0 then
        local ticks = scene_manager.current_scene_ticks - scene_manager.scene_start_tick_offset
        draw_start_play_screen(ticks)
        if ticks > 2000 then
            halt_laserdisc()  -- this just makes the engine replace the current frame of video with black
            if scene_manager.scene_start_state == 1 then
                seek_laserdisc_to(scene_manager.current_scene.start_frame)
            else
                seek_laserdisc_to(scene_manager.current_sequence.start_frame)
            end
            scene_manager.scene_start_state = 0
            scene_manager.scene_start_tick_offset = 0
        end
    end
end

local function draw_buy_in_screen(ticks, timeleft)
    DirkSimple.clear_screen(mapcolor("magenta"))

    local total = DirkSimple.truncate(ticks / 64) + 1
    if total > 5 then
        total = 5
    end
    for i = 1,total,1 do
        draw_standard_rectangle(i-1, mapcolor("white"))
    end

    if ticks > 320 then
        draw_text("PLAYER #  1", 15, 7, mapcolor("white"))
        draw_text("If you wish to continue", 8, 9, mapcolor("white"))
        draw_text("playing this level", 11, 10, mapcolor("white"))
        draw_text("Press Player 1 button", 9, 14, mapcolor("white"))
        draw_text("Time left to buy-in :  " .. timeleft, 8, 17, mapcolor("white"))
    end
end

local function draw_congrats_screen(ticks)
    if ticks < (96 * 64) then
        local fg = "light_blue"
        local bg = "light_red"
        DirkSimple.clear_screen(mapcolor(bg))
        local segment = DirkSimple.truncate(ticks / 96) % 3
        if segment == 0 then
            draw_text("*  *  *  *  *  *  *  *  *", 7, 9, mapcolor(fg))
            draw_text("                         ", 7, 10, mapcolor(fg))
            draw_text("*    CONGRATULATIONS     ", 7, 11, mapcolor(fg))
            draw_text("                        *", 7, 12, mapcolor(fg))
            draw_text("    YOU HAVE COMPLETED   ", 7, 13, mapcolor(fg))
            draw_text("*     THIS CHALLENGE     ", 7, 14, mapcolor(fg))
            draw_text("                        *", 7, 15, mapcolor(fg))
            draw_text("  *  *  *  *  *  *  *    ", 7, 16, mapcolor(fg))
        elseif segment == 1 then
            draw_text(" *  *  *  *  *  *  *  *  ", 7, 9, mapcolor(fg))
            draw_text("*                       *", 7, 10, mapcolor(fg))
            draw_text("     CONGRATULATIONS     ", 7, 11, mapcolor(fg))
            draw_text("                         ", 7, 12, mapcolor(fg))
            draw_text("*   YOU HAVE COMPLETED  *", 7, 13, mapcolor(fg))
            draw_text("      THIS CHALLENGE     ", 7, 14, mapcolor(fg))
            draw_text("                         ", 7, 15, mapcolor(fg))
            draw_text("*  *  *  *  *  *  *  *  *", 7, 16, mapcolor(fg))
        elseif segment == 2 then
            draw_text("  *  *  *  *  *  *  *  * ", 7, 9, mapcolor(fg))
            draw_text("                         ", 7, 10, mapcolor(fg))
            draw_text("     CONGRATULATIONS    *", 7, 11, mapcolor(fg))
            draw_text("*                        ", 7, 12, mapcolor(fg))
            draw_text("    YOU HAVE COMPLETED   ", 7, 13, mapcolor(fg))
            draw_text("      THIS CHALLENGE    *", 7, 14, mapcolor(fg))
            draw_text("*                        ", 7, 15, mapcolor(fg))
            draw_text("*  *  *  *  *  *  *  *   ", 7, 16, mapcolor(fg))
        end
    else
        local fg = "white"
        local bg = "dark_blue"
        if ticks < ((96 * 64) + (32 * 30)) then
            if (DirkSimple.truncate(ticks  / 32) % 2) == 1 then
                bg = "dark_red"
            end
        end
        draw_text("*************************", 7, 9, mapcolor(fg))
        draw_text("*                       *", 7, 10, mapcolor(fg))
        draw_text("*    CONGRATULATIONS    *", 7, 11, mapcolor(fg))
        draw_text("*                       *", 7, 12, mapcolor(fg))
        draw_text("*   YOU HAVE COMPLETED  *", 7, 13, mapcolor(fg))
        draw_text("*     THIS CHALLENGE    *", 7, 14, mapcolor(fg))
        draw_text("*                       *", 7, 15, mapcolor(fg))
        draw_text("*************************", 7, 16, mapcolor(fg))
    end
end

local game_over_flash_colors = {  -- { foreground, background }
    { "black", "black" },
    { "medium_green", "black" },
    { "light_green", "black" },
    { "dark_blue", "black" },
    { "light_blue", "black" },
    { "dark_red", "black" },
    { "light_cyan", "black" },
    { "medium_red", "black" },
    { "light_red", "black" },
    { "dark_yellow", "black" },
    { "light_yellow", "black" },
    { "dark_green", "black" },
    { "magenta", "black" },
    { "grey", "dark_blue" },
    { "white", "dark_red" },
    { "white", "dark_blue" },
    { "white", "black" },
    { "white", "black" },
}

local function draw_game_over_screen(ticks)
    local flashidx = DirkSimple.truncate(ticks / 160) + 1
    if flashidx > #game_over_flash_colors then
        flashidx = #game_over_flash_colors
    end
    local flashcolor = game_over_flash_colors[flashidx]
    local fg = flashcolor[1]
    local bg = flashcolor[2]

    DirkSimple.clear_screen(mapcolor(bg))
    draw_text("******************", 12, 9, mapcolor(fg))
    draw_text("*                *", 12, 10, mapcolor(fg))
    draw_text("*  YOUR  GAME    *", 12, 11, mapcolor(fg))
    draw_text("*                *", 12, 12, mapcolor(fg))
    draw_text("* IS  NOW  OVER  *", 12, 13, mapcolor(fg))
    draw_text("*                *", 12, 14, mapcolor(fg))
    draw_text("******************", 12, 15, mapcolor(fg))
end

local initial_entry_string = "abcdefghijklmnopqrstuvwxyz *?";  -- everything but the backspace at the end
local function draw_highscore_entry_screen()
    local scorestr = "" .. scene_manager.current_score
    local fg = "dark_red"
    local selected = scene_manager.player_initials_selected_glyph
    local backspace = 63  -- glyph index
    local caret = 62  -- glyph index

    DirkSimple.clear_screen(mapcolor("black"))
    draw_text("CONGRATULATIONS PLAYER 1", 8, 1, mapcolor(fg))
    draw_text("YOUR SCORE", 9, 3, mapcolor(fg))
    draw_text(scorestr, 20 + (8 - #scorestr), 3, mapcolor(fg))
    draw_text("IS IN THE TOP TEN SCORES", 8, 5, mapcolor(fg))
    draw_text("PLEASE ENTER YOUR INITIALS", 7, 8, mapcolor(fg))
    draw_text(initial_entry_string, 5, 11, mapcolor(fg))
    draw_sprite_chars("cliffglyphs", backspace, 0, 1, 1, 34, 11, mapcolor(fg))
    draw_sprite_chars("cliffglyphs", caret, 0, 1, 1, 5 + selected, 12, mapcolor(fg))
    draw_rectangle(18, 13, 3, 1, mapcolor(fg))

    for i = 1,scene_manager.player_initials_entered,1 do
        draw_text(scene_manager.player_initials[i], 18+i, 14, mapcolor(fg))
    end

    if scene_manager.player_initials_entered < 3 then
        local x = 18+scene_manager.player_initials_entered+1
        if selected == 29 then  -- backspace?
            draw_sprite_chars("cliffglyphs", backspace, 0, 1, 1, x, 14, mapcolor(fg))
        else
            draw_text(initial_entry_string:sub(selected + 1, selected + 1), x, 14, mapcolor(fg))
        end
    end

    draw_text("YOU CAN USE", 14, 17, mapcolor(fg))
    draw_text("THE JOYSTICK TO SELECT LETTERS", 5, 19, mapcolor(fg))
    draw_text("BUT YOU MUST USE", 12, 21, mapcolor(fg))
    draw_text("YOUR HANDS TO ENTER THEM.", 7, 23, mapcolor(fg))
end

local function insert_highscore(list, name, score)
    for i,v in ipairs(list) do
        if score > v[2] then
            table.insert(list, i, { name, score })
            table.remove(list)
            break
        end
    end
end

local function tick_game_over(inputs)
    local ticks = scene_manager.current_scene_ticks
    if scene_manager.game_over_state == 1 then  -- game_over_state == 1? You won!
        draw_congrats_screen(ticks)
        if ticks >= (((96 * 64) + (32 * 30)) + 2000) then
            halt_laserdisc()  -- this just makes the tick count go back to zero.
            scene_manager.game_over_state = scene_manager.game_over_state + 2  -- skip over buy-in, there's no game left to continue.
        end
    elseif scene_manager.game_over_state == 2 then  -- game_over_state == 2? "Buy in" mode, where they let you continue (for more money in the arcade, of course).
        local timeleft = 9 - DirkSimple.truncate((ticks - 320) / 1000)

        local showtimeleft = timeleft
        if showtimeleft <= 0 then
            showtimeleft = 1  -- bump so the last frame doesn't render to zero.
        end
        draw_buy_in_screen(ticks, showtimeleft)

        if inputs ~= nil and inputs.pressed["start"] then  -- user decided to continue current game
            scene_manager.lives_left = starting_lives
            scene_manager.game_over_state = 0
            start_scene(scene_manager.current_scene_num, scene_manager.current_sequence.restart_move)  -- move back to where the sequence prescribes.
            scene_manager.scene_start_tick_offset = 0
        elseif timeleft == 0 then
            halt_laserdisc()  -- this just makes the tick count go back to zero.
            scene_manager.game_over_state = scene_manager.game_over_state + 1  -- move on to actual game over screen.
        end
    elseif scene_manager.game_over_state == 3 then  -- game_over_state == 3? Decide if this was a high score.
        scene_manager.game_over_state = scene_manager.game_over_state + 1  -- Maybe move on to entering player initials.
        if scene_manager.current_score < today_highscores[#today_highscores][2] then  -- today's lowest highscore must be lower than any alltime high score, so we don't check that.
            scene_manager.game_over_state = scene_manager.game_over_state + 1  -- skip initial entry, go right to game over.
        end
        return tick_game_over(inputs)  -- do it right now.
    elseif scene_manager.game_over_state == 4 then  -- game_over_state == 4? User is entering initials.
        if inputs.pressed["left"] then
            if scene_manager.player_initials_selected_glyph == 0 then
                scene_manager.player_initials_selected_glyph = 29
            else
                scene_manager.player_initials_selected_glyph = scene_manager.player_initials_selected_glyph - 1
            end
        end
        if inputs.pressed["right"] then
            scene_manager.player_initials_selected_glyph = (scene_manager.player_initials_selected_glyph + 1) % 30
        end
        if inputs.pressed["action"] then
            local selected = scene_manager.player_initials_selected_glyph
            if selected == 29 then  -- backspace?
                if scene_manager.player_initials_entered > 0 then
                    scene_manager.player_initials[scene_manager.player_initials_entered] = ' '
                    scene_manager.player_initials_entered = scene_manager.player_initials_entered - 1
                end
            else
                scene_manager.player_initials_entered = scene_manager.player_initials_entered + 1
                scene_manager.player_initials[scene_manager.player_initials_entered] = initial_entry_string:sub(selected + 1, selected + 1);
                if scene_manager.player_initials_entered == 3 then
                    local finalstr = scene_manager.player_initials[1] .. scene_manager.player_initials[2] .. scene_manager.player_initials[3]
                    finalstr = finalstr:upper()
                    DirkSimple.log("Player entered high score initials '" .. finalstr .. "' for a score of " .. scene_manager.current_score)
                    insert_highscore(alltime_highscores, finalstr, scene_manager.current_score)
                    insert_highscore(today_highscores, finalstr, scene_manager.current_score)
                    halt_laserdisc()  -- this just makes the tick count go back to zero.
                    scene_manager.game_over_state = scene_manager.game_over_state + 1  -- move on to actual Game Over.
                end
            end
        end
        draw_highscore_entry_screen()
    elseif scene_manager.game_over_state == 5 then  -- game_over_state == 5? Actual game over screen.
        draw_game_over_screen(ticks)
        if ticks >= ((160 * #game_over_flash_colors) + 2000) then
            halt_laserdisc()  -- this just makes the tick count go back to zero.
            scene_manager.game_over_state = scene_manager.game_over_state + 1  -- move on to high score list
        end
    elseif scene_manager.game_over_state == 6 then  -- game_over_state == 6? Show high scores.
        draw_high_scores(ticks)
        if ticks >= 5000 then  -- we're done, go back to attract mode.
            start_attract_mode()
        end
    end
end

DirkSimple.tick = function(ticks, sequenceticks, inputs)
    scene_manager.current_scene_ticks = sequenceticks + scene_manager.unserialize_offset
    if scene_manager.last_seek == -1 then
        scene_manager.laserdisc_frame = -1
    else
        scene_manager.laserdisc_frame = ((scene_manager.last_seek + scene_manager.current_scene_ticks) / (1000.0 / 29.97)) + 6
    end

    if scene_manager.attract_mode_state ~= 0 then
        tick_attract_mode(inputs)
    elseif scene_manager.death_mode_state ~= 0 then
        tick_death_scene()
    elseif scene_manager.scene_start_state ~= 0 then
        tick_scene_start()
    elseif scene_manager.game_over_state ~= 0 then
        tick_game_over(inputs)
    elseif scene_manager.current_scene == nil then
        start_attract_mode()
    else
        tick_game(inputs)
    end
end

DirkSimple.serialize = function()
    if not scene_manager.initialized then
        setup_scene_manager()   -- just so we can serialize a default state.
    end

    local state = {}
    state[#state + 1] = 2   -- current serialization version
    state[#state + 1] = scene_manager.lives_left
    state[#state + 1] = scene_manager.current_score
    state[#state + 1] = scene_manager.last_failed_scene
    state[#state + 1] = scene_manager.last_failed_sequence
    state[#state + 1] = scene_manager.failures_in_a_row
    state[#state + 1] = scene_manager.attract_mode_state
    state[#state + 1] = scene_manager.death_mode_state
    state[#state + 1] = scene_manager.game_over_state
    state[#state + 1] = scene_manager.player_initials[1]:byte()
    state[#state + 1] = scene_manager.player_initials[2]:byte()
    state[#state + 1] = scene_manager.player_initials[3]:byte()
    state[#state + 1] = scene_manager.player_initials_entered
    state[#state + 1] = scene_manager.player_initials_selected_glyph
    state[#state + 1] = scene_manager.scene_start_state
    state[#state + 1] = scene_manager.scene_start_tick_offset
    state[#state + 1] = scene_manager.last_seek
    state[#state + 1] = scene_manager.current_scene_num
    state[#state + 1] = scene_manager.current_sequence_num
    state[#state + 1] = scene_manager.current_scene_ticks
    state[#state + 1] = scene_manager.accepted_input

    return state
end


DirkSimple.unserialize = function(state)
    -- !!! FIXME: this function assumes that `state` is completely valid. It doesn't check array length or data types.
    setup_scene_manager()

    local idx = 1
    local version = state[idx] ; idx = idx + 1
    if version == 1 then idx = idx + 1 end  -- this was scene_manager.infinite_lives, but that's a cvar now.
    scene_manager.lives_left = state[idx] ; idx = idx + 1
    scene_manager.current_score = state[idx] ; idx = idx + 1
    scene_manager.last_failed_scene = state[idx] ; idx = idx + 1
    scene_manager.last_failed_sequence = state[idx] ; idx = idx + 1
    scene_manager.failures_in_a_row = state[idx] ; idx = idx + 1
    scene_manager.attract_mode_state = state[idx] ; idx = idx + 1
    scene_manager.death_mode_state = state[idx] ; idx = idx + 1
    scene_manager.game_over_state = state[idx] ; idx = idx + 1
    scene_manager.player_initials[1] = string.char(state[idx]) ; idx = idx + 1
    scene_manager.player_initials[2] = string.char(state[idx]) ; idx = idx + 1
    scene_manager.player_initials[3] = string.char(state[idx]) ; idx = idx + 1
    scene_manager.player_initials_entered = state[idx] ; idx = idx + 1
    scene_manager.player_initials_selected_glyph = state[idx] ; idx = idx + 1
    scene_manager.scene_start_state = state[idx] ; idx = idx + 1
    scene_manager.scene_start_tick_offset = state[idx] ; idx = idx + 1
    scene_manager.last_seek = state[idx] ; idx = idx + 1
    scene_manager.current_scene_num = state[idx] ; idx = idx + 1
    scene_manager.current_sequence_num = state[idx] ; idx = idx + 1
    scene_manager.current_scene_ticks = state[idx] ; idx = idx + 1
    scene_manager.accepted_input = state[idx] ; idx = idx + 1

    scene_manager.unserialize_offset = scene_manager.current_scene_ticks

    if scene_manager.current_scene_num ~= 0 then
        scene_manager.current_scene = scenes[scene_manager.current_scene_num]
        if scene_manager.current_sequence_num ~= 0 then
            scene_manager.current_sequence = scene_manager.current_scene[scene_manager.current_sequence_num]
        end
    end

    if last_seek == -1 then
        scene_manager.laserdisc_frame = -1
        halt_laserdisc()
    else
        scene_manager.laserdisc_frame = ((scene_manager.last_seek + scene_manager.current_scene_ticks) / (1000.0 / 29.97)) + 6
        DirkSimple.start_clip(scene_manager.last_seek + scene_manager.unserialize_offset)
    end

    return true
end


setup_scene_manager()  -- Call this during initial load to make sure the table is ready to go.

local default_highscores = {
    { "JMH", 1000000 },
    { "PMR", 90000 },
    { "EMJ", 80000 },
    { "APH", 70000 },
    { "VAV", 60000 },
    { "MAS", 50000 },
    { "JON", 40000 },
    { "WHO", 30000 },
    { "HP?", 20000 },
    { "JIM", 10000 }
}

local function initialize_highscore()
    local retval = {}
    for i,v in ipairs(default_highscores) do
        retval[i] = {}
        retval[i][1] = default_highscores[i][1]
        retval[i][2] = default_highscores[i][2]
    end
    return retval
end

alltime_highscores = initialize_highscore()
today_highscores = initialize_highscore()



-- The scene table!
-- https://www.jeffsromhack.com/code/cliffhanger.htm
scenes = {

    -- scene 1
    {
        scene_name = "Casino Heist",
        start_frame = 1547,
        end_frame = 3160,
        dunno1_frame = 0,
        dunno2_frame = 0,
        moves = {
            {
                name = "Running from the casino",
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 1800,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                name = "Jump first hurdle",
                correct_moves = { "feet" },
                incorrect_moves = { "hands" },
                start_frame = 1928,
                end_frame = 1987,
                death_start_frame = 3930,
                death_end_frame = 4234,
                restart_move = 1
            },
            {
                name = "Jump second hurdle",
                correct_moves = { "feet" },
                incorrect_moves = { "hands" },
                start_frame = 1990,
                end_frame = 2040,
                death_start_frame = 3930,
                death_end_frame = 4234,
                restart_move = 2
            },
            {
                name = "Get in the car, loser.",
                correct_moves = { "hands" },
                incorrect_moves = { "feet" },
                start_frame = 2120,
                end_frame = 2160,
                death_start_frame = 3930,
                death_end_frame = 4234,
                restart_move = 2
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "down" },
                start_frame = 2186,
                end_frame = 2226,
                death_start_frame = 3930,
                death_end_frame = 4234,
                restart_move = 2
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 2276,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 7
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet", "right" },
                start_frame = 2419,
                end_frame = 2459,
                death_start_frame = 3214,
                death_end_frame = 3500,
                restart_move = 7
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet", "left" },
                start_frame = 2447,
                end_frame = 2487,
                death_start_frame = 3214,
                death_end_frame = 3500,
                restart_move = 7
            },
            {
                correct_moves = { "down" },
                incorrect_moves = { "hands", "feet", "up" },
                start_frame = 2464,
                end_frame = 2504,
                death_start_frame = 3214,
                death_end_frame = 3500,
                restart_move = 7
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet", "up", "down", "right" },
                start_frame = 2513,
                end_frame = 2553,
                death_start_frame = 3214,
                death_end_frame = 3500,
                restart_move = 7
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet", "left" },
                start_frame = 2549,
                end_frame = 2589,
                death_start_frame = 3214,
                death_end_frame = 3500,
                restart_move = 7
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "feet", "left", "right" },
                start_frame = 2640,
                end_frame = 2680,
                death_start_frame = 3214,
                death_end_frame = 3500,
                restart_move = 7
            },
        }
    },

    -- scene 2
    {
        scene_name = "The Getaway",
        start_frame = 4776,
        end_frame = 8074,
        dunno1_frame = 4592,
        dunno2_frame = 0,
        moves = {
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 5186,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "down" },
                incorrect_moves = { "feet", "hands" },
                start_frame = 5388,
                end_frame = 5428,
                death_start_frame = 8120,
                death_end_frame = 8409,
                restart_move = 2
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "right", "down", "up" },
                start_frame = 5418,
                end_frame = 5458,
                death_start_frame = 8120,
                death_end_frame = 8409,
                restart_move = 2
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 5484,
                end_frame = 5524,
                death_start_frame = 8120,
                death_end_frame = 8409,
                restart_move = 2
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "feet", "hands" },
                start_frame = 5516,
                end_frame = 5556,
                death_start_frame = 8120,
                death_end_frame = 8409,
                restart_move = 2
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 5560,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "feet", "hands" },
                start_frame = 5600,
                end_frame = 5640,
                death_start_frame = 8120,
                death_end_frame = 8409,
                restart_move = 7
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "feet", "hands" },
                start_frame = 5680,
                end_frame = 5720,
                death_start_frame = 8439,
                death_end_frame = 8732,
                restart_move = 7
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "feet", "hands" },
                start_frame = 5710,
                end_frame = 5750,
                death_start_frame = 8439,
                death_end_frame = 8732,
                restart_move = 7
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "feet", "hands" },
                start_frame = 5752,
                end_frame = 5792,
                death_start_frame = 8439,
                death_end_frame = 8732,
                restart_move = 7
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "feet", "hands", "left", "up", "down" },
                start_frame = 5802,
                end_frame = 5842,
                death_start_frame = 8439,
                death_end_frame = 8732,
                restart_move = 7
            },
            {
                correct_moves = { "down" },
                incorrect_moves = { "feet", "hands" },
                start_frame = 5874,
                end_frame = 5914,
                death_start_frame = 8439,
                death_end_frame = 8732,
                restart_move = 7
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 5920,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet", "right", "up", "down" },
                start_frame = 6000,
                end_frame = 6040,
                death_start_frame = 9794,
                death_end_frame = 10081,
                restart_move = 14
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 6108,
                end_frame = 6148,
                death_start_frame = 9794,
                death_end_frame = 10081,
                restart_move = 14
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet", "right", "up", "down" },
                start_frame = 6278,
                end_frame = 6318,
                death_start_frame = 9794,
                death_end_frame = 10081,
                restart_move = 14
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 6342,
                end_frame = 6382,
                death_start_frame = 8439,
                death_end_frame = 8732,
                restart_move = 14
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet", "left", "down" },
                start_frame = 6496,
                end_frame = 6536,
                death_start_frame = 8439,
                death_end_frame = 8732,
                restart_move = 14
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 6694,
                end_frame = 6734,
                death_start_frame = 10105,
                death_end_frame = 10427,
                restart_move = 14
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet", "right", "up", "down" },
                start_frame = 6904,
                end_frame = 6944,
                death_start_frame = 10105,
                death_end_frame = 10427,
                restart_move = 14
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 6974,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "down" },
                incorrect_moves = { "hands", "feet", "left", "right", "up" },
                start_frame = 7015,
                end_frame = 7055,
                death_start_frame = 10105,
                death_end_frame = 10427,
                restart_move = 22
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet", "right", "up", "down" },
                start_frame = 7114,
                end_frame = 7154,
                death_start_frame = 10105,
                death_end_frame = 10427,
                restart_move = 22
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 7202,
                end_frame = 7242,
                death_start_frame = 8120,
                death_end_frame = 8409,
                restart_move = 22
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 7239,
                end_frame = 7279,
                death_start_frame = 8120,
                death_end_frame = 8409,
                restart_move = 22
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 7284,
                end_frame = 7324,
                death_start_frame = 8120,
                death_end_frame = 8409,
                restart_move = 22
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "hands", "left", "right", "up", "down" },
                start_frame = 7403,
                end_frame = 7443,
                death_start_frame = 8439,
                death_end_frame = 8732,
                restart_move = 22
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 7470,
                end_frame = 7510,
                death_start_frame = 8439,
                death_end_frame = 8732,
                restart_move = 22
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 7958,
                end_frame = 7998,
                death_start_frame = 11753,
                death_end_frame = 12215,
                restart_move = 22
            },
        }
    },

    -- scene 3
    {
        scene_name = "Rooftops",
        start_frame = 12397,
        end_frame = 17248,
        dunno1_frame = 12247,
        dunno2_frame = 0,
        moves = {
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 12460,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 12702,
                end_frame = 12742,
                death_start_frame = 17251,
                death_end_frame = 17820,
                restart_move = 2
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 12725,
                end_frame = 12765,
                death_start_frame = 17251,
                death_end_frame = 17820,
                restart_move = 2
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 13601,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 13866,
                end_frame = 13906,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 5
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 13888,
                end_frame = 13918,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 5
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 13898,
                end_frame = 13928,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 5
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 13944,
                end_frame = 13984,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 5
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 14044,
                end_frame = 14084,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 5
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 14256,
                end_frame = 14296,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 5
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 14343,
                end_frame = 14383,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 5
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 14569,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 14668,
                end_frame = 14708,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 13
            },
            {
                correct_moves = { "down" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 14694,
                end_frame = 14734,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 13
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 14788,
                end_frame = 14818,
                death_start_frame = 19596,
                death_end_frame = 19889,
                restart_move = 13
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 14818,
                end_frame = 14858,
                death_start_frame = 19596,
                death_end_frame = 19889,
                restart_move = 13
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 15014,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 15143,
                end_frame = 15183,
                death_start_frame = 18596,
                death_end_frame = 19889,
                restart_move = 18
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet", "up" },
                start_frame = 15221,
                end_frame = 15261,
                death_start_frame = 19596,
                death_end_frame = 19889,
                restart_move = 18
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet", "right" },
                start_frame = 15232,
                end_frame = 15272,
                death_start_frame = 19596,
                death_end_frame = 19889,
                restart_move = 18
            },
            {
                correct_moves = { "down" },
                incorrect_moves = { "hands", "feet", "right" },
                start_frame = 15253,
                end_frame = 15293,
                death_start_frame = 19596,
                death_end_frame = 19889,
                restart_move = 18
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet", "left" },
                start_frame = 15270,
                end_frame = 15310,
                death_start_frame = 19596,
                death_end_frame = 19889,
                restart_move = 18
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet", "down" },
                start_frame = 15296,
                end_frame = 15336,
                death_start_frame = 19596,
                death_end_frame = 19889,
                restart_move = 18
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 15750,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet", "down" },
                start_frame = 15884,
                end_frame = 15914,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 25
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet", "right" },
                start_frame = 16054,
                end_frame = 16094,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 25
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet", "left" },
                start_frame = 16094,
                end_frame = 16134,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 25
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet", "right" },
                start_frame = 16137,
                end_frame = 16177,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 25
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet", "left" },
                start_frame = 16170,
                end_frame = 16210,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 25
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet", "right" },
                start_frame = 16222,
                end_frame = 16262,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 25
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet", "left" },
                start_frame = 16254,
                end_frame = 16294,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 25
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet", "right" },
                start_frame = 16307,
                end_frame = 16347,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 25
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet", "left" },
                start_frame = 16339,
                end_frame = 16379,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 25
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 16392,
                end_frame = 16432,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 25
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 16424,
                end_frame = 16464,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 25
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 16998,
                end_frame = 17038,
                death_start_frame = 18235,
                death_end_frame = 18577,
                restart_move = 25
            },
        }
    },

    -- scene 4
    {
        scene_name = "Highway",
        start_frame = 20891,
        end_frame = 23321,
        dunno1_frame = 20741,
        dunno2_frame = 0,
        moves = {
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 21240,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 21553,
                end_frame = 21583,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 2
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 21570,
                end_frame = 21600,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 2
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 21594,
                end_frame = 21614,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 2
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 21640,
                end_frame = 21670,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 2
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 21669,
                end_frame = 21699,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 2
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 21698,
                end_frame = 21728,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 2
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 21727,
                end_frame = 21757,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 2
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 21826,
                end_frame = 21856,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 2
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 21897,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22004,
                end_frame = 22034,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 11
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 22050,
                end_frame = 22080,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 11
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 22065,
                end_frame = 22095,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 11
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22097,
                end_frame = 22117,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 11
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22102,
                end_frame = 22132,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 11
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22146,
                end_frame = 22176,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 11
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22160,
                end_frame = 22190,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 11
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 22224,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22237,
                end_frame = 22267,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 19
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 22250,
                end_frame = 22280,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 19
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22264,
                end_frame = 22294,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 19
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 22326,
                end_frame = 22356,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 19
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 22345,
                end_frame = 22375,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 19
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 22384,
                end_frame = 22404,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 19
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 22403,
                end_frame = 22433,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 19
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22424,
                end_frame = 22454,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 19
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 22492,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet", "left", "right", "down" },
                start_frame = 22494,
                end_frame = 22524,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 28
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22500,
                end_frame = 22530,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 28
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 22538,
                end_frame = 22568,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 28
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 22556,
                end_frame = 22586,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 28
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22580,
                end_frame = 22610,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 28
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22592,
                end_frame = 22622,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 28
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22610,
                end_frame = 22640,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 28
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 22683,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 22689,
                end_frame = 22719,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 36
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22702,
                end_frame = 22732,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 36
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22730,
                end_frame = 22760,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 36
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 22750,
                end_frame = 22780,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 36
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 22784,
                end_frame = 22814,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 36
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22794,
                end_frame = 22824,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 36
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22845,
                end_frame = 22875,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 36
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 22925,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet", "left", "right", "down" },
                start_frame = 22941,
                end_frame = 22971,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 44
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 22955,
                end_frame = 22985,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 44
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 22995,
                end_frame = 23025,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 44
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 23010,
                end_frame = 23040,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 44
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 23035,
                end_frame = 23065,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 44
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 23046,
                end_frame = 23076,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 44
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 23058,
                end_frame = 23088,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 44
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 23148,
                end_frame = 23178,
                death_start_frame = 23358,
                death_end_frame = 23640,
                restart_move = 44
            },
        }
    },

    -- scene 5
    {
        scene_name = "The Castle Battle",
        start_frame = 25728,
        end_frame = 26387,
        dunno1_frame = 25579,
        dunno2_frame = 25727,
        moves = {
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 25729,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 25715,
                end_frame = 25745,
                death_start_frame = 26423,
                death_end_frame = 26705,
                restart_move = 2
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 25765,
                end_frame = 25795,
                death_start_frame = 26423,
                death_end_frame = 26705,
                restart_move = 2
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 25795,
                end_frame = 25825,
                death_start_frame = 26423,
                death_end_frame = 26705,
                restart_move = 2
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 25800,
                end_frame = 25830,
                death_start_frame = 26423,
                death_end_frame = 26705,
                restart_move = 2
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 25808,
                end_frame = 25838,
                death_start_frame = 26423,
                death_end_frame = 26705,
                restart_move = 2
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 25824,
                end_frame = 25854,
                death_start_frame = 26423,
                death_end_frame = 26705,
                restart_move = 2
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 25931,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 25944,
                end_frame = 25974,
                death_start_frame = 27725,
                death_end_frame = 28014,
                restart_move = 9
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 25996,
                end_frame = 26026,
                death_start_frame = 27725,
                death_end_frame = 28014,
                restart_move = 9
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 26146,
                end_frame = 26176,
                death_start_frame = 27725,
                death_end_frame = 28014,
                restart_move = 9
            },
        }
    },

    -- scene 6
    {
        scene_name = "Finale",
        start_frame = 28514,
        end_frame = 31212,
        dunno1_frame = 28363,
        dunno2_frame = 28510,
        moves = {
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 28836,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 28900,
                end_frame = 28930,
                death_start_frame = 31275,
                death_end_frame = 31619,
                restart_move = 2
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 29422,
                end_frame = 29452,
                death_start_frame = 31275,
                death_end_frame = 31619,
                restart_move = 2
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 29622,
                end_frame = 29652,
                death_start_frame = 31275,
                death_end_frame = 31619,
                restart_move = 2
            },
            {
                correct_moves = { "hands", "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 30098,
                end_frame = 30128,
                death_start_frame = 31999,
                death_end_frame = 32379,
                restart_move = 2
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 30460,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 30794,
                end_frame = 30814,
                death_start_frame = 31999,
                death_end_frame = 32379,
                restart_move = 7
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 30804,
                end_frame = 30834,
                death_start_frame = 31999,
                death_end_frame = 32379,
                restart_move = 7
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 30834,
                end_frame = 30864,
                death_start_frame = 31999,
                death_end_frame = 32379,
                restart_move = 7
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 30890,
                end_frame = 30920,
                death_start_frame = 32399,
                death_end_frame = 32692,
                restart_move = 7
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 30954,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 31063,
                end_frame = 31093,
                death_start_frame = 32797,
                death_end_frame = 33102,
                restart_move = 12
            },
        }
    },

    -- scene 7
    {
        scene_name = "Finale II",
        start_frame = 33255,
        end_frame = 37138,
        dunno1_frame = 33105,
        dunno2_frame = 33252,
        moves = {
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 31063,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 33668,
                end_frame = 33698,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 2
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 33704,
                end_frame = 33734,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 2
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 33710,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 2
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 33720,
                end_frame = 33750,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 2
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 33733,
                end_frame = 33763,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 2
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 33760,
                end_frame = 33790,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 2
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 33824,
                end_frame = 33854,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 2
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 33830,
                end_frame = 33860,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 2
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 33840,
                end_frame = 33870,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 2
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 33922,
                end_frame = 33952,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 2
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 33938,
                end_frame = 33968,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 2
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 33990,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 34030,
                end_frame = 34060,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 14
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 34100,
                end_frame = 34130,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 14
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 34130,
                end_frame = 34160,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 14
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 34286,
                end_frame = 34316,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 14
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 34402,
                end_frame = 34432,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 14
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 34620,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 35012,
                end_frame = 35042,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 20
            },
            {
                correct_moves = { "down" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 35170,
                end_frame = 35200,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 20
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 35374,
                end_frame = 35404,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 20
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 35785,
                end_frame = 35815,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 20
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 35873,
                end_frame = 35903,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 20
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 35889,
                end_frame = 35919,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 20
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 35955,
                end_frame = 35985,
                death_start_frame = 39727,
                death_end_frame = 40184,
                restart_move = 20
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 36020,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 36164,
                end_frame = 36194,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 28
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 36327,
                end_frame = 36357,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 28
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 36477,
                end_frame = 36507,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 28
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 36593,
                end_frame = 36623,
                death_start_frame = 37192,
                death_end_frame = 37511,
                restart_move = 28
            },
        }
    },

    -- scene 8
    {
        scene_name = "Ending",
        start_frame = 41587,
        end_frame = 46880,
        dunno1_frame = 41436,
        dunno2_frame = 41584,
        moves = {
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 41587,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 41574,
                end_frame = 41604,
                death_start_frame = 46960,
                death_end_frame = 47256,
                restart_move = 2
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 41662,
                end_frame = 41692,
                death_start_frame = 46960,
                death_end_frame = 47256,
                restart_move = 2
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 41713,
                end_frame = 41743,
                death_start_frame = 46960,
                death_end_frame = 47256,
                restart_move = 2
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 42550,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 42676,
                end_frame = 42706,
                death_start_frame = 47289,
                death_end_frame = 47578,
                restart_move = 6
            },
            {
                correct_moves = { "up" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 42827,
                end_frame = 42857,
                death_start_frame = 47289,
                death_end_frame = 47578,
                restart_move = 6
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 42860,
                end_frame = 42890,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 6
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 42902,
                end_frame = 42932,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 6
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43068,
                end_frame = 43098,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 6
            },
            {
                correct_moves = { "right" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 43092,
                end_frame = 43102,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 6
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 43163,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43261,
                end_frame = 43291,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43286,
                end_frame = 43306,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43295,
                end_frame = 43325,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43307,
                end_frame = 43337,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43320,
                end_frame = 43350,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43345,
                end_frame = 43375,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43367,
                end_frame = 43397,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43434,
                end_frame = 43464,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43449,
                end_frame = 43479,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43476,
                end_frame = 43506,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43515,
                end_frame = 43545,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43531,
                end_frame = 43561,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43541,
                end_frame = 43571,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43556,
                end_frame = 43586,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43580,
                end_frame = 43610,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43603,
                end_frame = 43633,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43670,
                end_frame = 43700,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43685,
                end_frame = 43715,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43712,
                end_frame = 43742,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43756,
                end_frame = 43786,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43771,
                end_frame = 43801,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43789,
                end_frame = 43819,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43816,
                end_frame = 43846,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43863,
                end_frame = 43893,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43888,
                end_frame = 43908,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43899,
                end_frame = 43929,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 43926,
                end_frame = 43956,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 44151,
                end_frame = 44181,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 44304,
                end_frame = 44334,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 44437,
                end_frame = 44467,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 44530,
                end_frame = 44560,
                death_start_frame = 47607,
                death_end_frame = 47969,
                restart_move = 13
            },
            {
                correct_moves = {},
                incorrect_moves = {},
                start_frame = 45030,
                end_frame = 0,
                death_start_frame = 0,
                death_end_frame = 0,
                restart_move = 1
            },
            {
                correct_moves = { "left" },
                incorrect_moves = { "hands", "feet" },
                start_frame = 45298,
                end_frame = 45328,
                death_start_frame = 48768,
                death_end_frame = 49050,
                restart_move = 45
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 45394,
                end_frame = 45414,
                death_start_frame = 46960,
                death_end_frame = 47256,
                restart_move = 45
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 45525,
                end_frame = 45555,
                death_start_frame = 46960,
                death_end_frame = 47256,
                restart_move = 45
            },
            {
                correct_moves = { "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 45591,
                end_frame = 45621,
                death_start_frame = 49225,
                death_end_frame = 49634,
                restart_move = 45
            },
            {
                correct_moves = { "hands", "feet" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 45618,
                end_frame = 45648,
                death_start_frame = 49225,
                death_end_frame = 49634,
                restart_move = 45
            },
            {
                correct_moves = { "hands" },
                incorrect_moves = { "left", "right", "up", "down" },
                start_frame = 45685,
                end_frame = 45715,
                death_start_frame = 49225,
                death_end_frame = 49634,
                restart_move = 45
            },
        }
    }
}

-- end of cliff.lua ...

