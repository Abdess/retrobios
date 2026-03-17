-- DirkSimple; a dirt-simple player for FMV games.
--
-- Please see the file LICENSE.txt in the source's root directory.
--
--  This file written by Ryan C. Gordon.
--

DirkSimple.gametitle = "Dragon's Lair"

-- CVARS
local starting_lives = 5
local infinite_lives = false  -- set to true to not lose a life on failure.
local god_mode = false  -- if true, game plays correct moves automatically, so you never fail.
local play_sounds = true  -- if true, beeps and buzzes play when appropriate, otherwise, skipped.

DirkSimple.cvars = {
    { name="starting_lives", desc="Number of lives player starts with", values="5|4|3|2|1", setter=function(name, value) starting_lives = DirkSimple.to_int(value) end },
    { name="infinite_lives", desc="Don't lose a life when failing", values="false|true", setter=function(name, value) infinite_lives = DirkSimple.to_bool(value) end },
    { name="god_mode", desc="Game plays itself perfectly, never failing", values="false|true", setter=function(name, value) god_mode = DirkSimple.to_bool(value) end },
    { name="play_sounds", desc="Play input sounds", values="true|false", setter=function(name, value) play_sounds = DirkSimple.to_bool(value) end }
}


-- SOME INITIAL SETUP STUFF
local scenes = nil  -- gets set up later in the file.
local test_scene_name = nil  -- set to name of scene to test. nil otherwise!
--test_scene_name = "the_dragons_lair"

-- GAME STATE
local current_ticks = 0
local current_inputs = nil
local accepted_input = nil
local play_sound_cooldown = 0
local scene_manager = nil


-- FUNCTIONS

local function play_sound(name)
    if not play_sounds then
        return  -- beeps and buzzes disabled.
    end

    -- Don't let a sound play more than once every 200ms. I don't know if
    -- this is what Dragon's Lair actually does, but this prevents it from
    -- getting totally annoying.
    if play_sound_cooldown < current_ticks then  -- eligible to play again?
        play_sound_cooldown = current_ticks + 200
        DirkSimple.play_sound(name)
    end
end

local function laserdisc_frame_to_ms(frame)
    return ((frame / 23.976) * 1000.0)
end

local function time_laserdisc_frame(frame)
    -- 6297 is the magic millsecond offset between the ROM test screens and the actual game content, I think,
    --  When the ROM would ask for a frame, we have to adjust by this number.
    --  Since we're filling in the timings from the original ROM's data table,
    --  we make this adjustment ourselves.
    return laserdisc_frame_to_ms(frame) - 6297.0
end

local function time_laserdisc_noseek()
    return -1
end

local function time_to_ms(seconds, ms)
    return (seconds * 1000) + ms
end

local function start_sequence(sequencename)
    DirkSimple.log("Starting sequence '" .. sequencename .. "'")
    scene_manager.current_sequence_name = sequencename
    scene_manager.current_sequence = scene_manager.current_scene[sequencename]
    accepted_input = nil

    local start_time = scene_manager.current_sequence.start_time
    if start_time < 0 then  -- if negative, no seek desired (just keep playing from current location)
        scene_manager.current_sequence_tick_offset = scene_manager.current_sequence_tick_offset + scene_manager.current_sequence_ticks
    else
        -- will suspend ticking until the seek completes and reset sequence tick count
        if scene_manager.current_sequence.is_single_frame then
            DirkSimple.show_single_frame(start_time)
        else
            DirkSimple.start_clip(start_time)
        end
        scene_manager.last_seek = start_time
        scene_manager.current_sequence_tick_offset = 0
        scene_manager.unserialize_offset = 0
    end
end

local function start_scene(scenename, is_resurrection)
    DirkSimple.log("Starting scene '" .. scenename .. "'")

    local sequencename
    if is_resurrection then
        sequencename = "start_dead"
    else
        sequencename = "start_alive"
    end

    scene_manager.current_scene_name = scenename
    scene_manager.current_scene = scenes[scenename]
    start_sequence(sequencename)
end

local function start_attract_mode(after_losing_game_over)
    start_scene('attract_mode', after_losing_game_over)
end

local function game_over(won)
    DirkSimple.log("Game over! won=" .. tostring(won))

    if (won) then
        -- The arcade version, at least as far as I can see on DAPHNE runs on YouTube,
        -- puts up a frame of Dirk+Daphne in a heart, a few frames from the end
        -- of the video, for about 10 seconds. Then it drops directly into attract mode.
        -- I've added this single frame of animation to the scene data (where
        -- maybe it was already in the original ROM?), so all we need to do here
        -- is kick out to attract mode and call it a day.
        start_attract_mode(false)
    else
        if (scene_manager.current_scene ~= nil) and (scene_manager.current_scene.game_over ~= nil) then
            start_sequence("game_over")
        else
            start_attract_mode(true)
        end
    end
end

local function choose_next_scene(is_resurrection)
    if test_scene_name ~= nil then
        start_scene(test_scene_name, is_resurrection)
        return
    end

    -- Mark current scene as a success or failure.
    if scene_manager.current_scene ~= nil then
        if scene_manager.current_scene_name == "the_dragons_lair" then

        -- Intro just needs to be marked as done.
        elseif scene_manager.current_scene_name == "introduction" then
            scene_manager.completed_introduction = true

        -- have we been through all the scenes except the_dragons_lair? You have to go back and survive the ones you previously failed.
        elseif scene_manager.rerunning_failures then
            -- beat the scene? Take it out of the failed list.
            if not is_resurrection then
                for i = 1, scene_manager.total_failed-1, 1 do
                    scene_manager.failed[i] = scene_manager.failed[i + 1]
                end
                scene_manager.failed[scene_manager.total_failed] = nil
                scene_manager.total_failed = scene_manager.total_failed - 1
            end

            if scene_manager.total_failed == 0 then
                scene_manager.rerunning_failures = false
            end

        elseif scene_manager.current_scene_name ~= "the_dragons_lair" then  -- normal scene selection logic only applies until you reach the lair.
            if is_resurrection then
                if scene_manager.total_failed < 8 then   -- the arcade version only queues up to 8 failed levels, which is only a limit if you have it set to infinite lives.
                    scene_manager.total_failed = scene_manager.total_failed + 1
                    scene_manager.failed[scene_manager.total_failed] = scene_manager.current_scene_name
                end
            end

            -- bump to the next row (or, if at the end of the rows, bump to the next cycle).
            scene_manager.current_row = scene_manager.current_row + 1
            if scene_manager.current_row > #scene_manager.rows then
                scene_manager.current_row = 1
                if scene_manager.current_cycle < #scene_manager.rows[1] then
                    scene_manager.current_cycle = scene_manager.current_cycle + 1
                end
            end
        end
    end

    -- intro must be played first.
    --  (!!! FIXME: if we add back in the drawbridge, do we want this to require it be _completed_ first?
    if not scene_manager.completed_introduction then
        start_scene("introduction", is_resurrection)

    -- If rerunning failures, always pick the start of the list to play next.
    -- This means that if you fail during the rerunning phase, you _must_ retry that room immediately.
    elseif (scene_manager.rerunning_failures) and (scene_manager.total_failed > 0) then
        start_scene(scene_manager.failed[1], is_resurrection)

    -- did we beat the game?
    elseif scene_manager.current_scene_name == "the_dragons_lair" then
        if is_resurrection then
            start_scene("the_dragons_lair", true)  -- once you get there, you have to replay the dragon's lair until you beat it.
        else
            game_over(true)  -- Didn't die in the lair? You beat the game!
        end

    -- The normal scene choosing logic for everything else.
    else
        -- if we're at the last row of the cycle, there are special rules: you _must_ play
        --  falling_platform_long in the first cycle, falling_platform_long_reverse in the
        --  second, and the_dragons_lair third (and that, only once all other levels are survived).
        if scene_manager.current_row == #scene_manager.rows then
            -- are we at the final level? Make sure everything else was beaten before we let the player in.
            if (scene_manager.current_cycle == #scene_manager.rows[scene_manager.current_row]) and (scene_manager.total_failed > 0) then
                scene_manager.rerunning_failures = true
                start_scene(scene_manager.failed[1], is_resurrection)
            else
                start_scene(scene_manager.rows[scene_manager.current_row][scene_manager.current_cycle], is_resurrection)
            end
        else
            -- choose from scenes in the current row that have not been run before.
            local eligible = {}
            local eligible_columns = {}
            for i,name in ipairs(scene_manager.rows[scene_manager.current_row]) do
                if not scene_manager.chosen[scene_manager.current_row][i] then
                    eligible[#eligible+1] = name
                    eligible_columns[#eligible_columns+1] = i;
                end
            end

            local choice = (current_ticks % #eligible) + 1
            scene_manager.chosen[scene_manager.current_row][eligible_columns[choice]] = true
            start_scene(eligible[choice], is_resurrection)
        end
    end
end

local function game_over_complete()
    start_attract_mode(true)
end

local function setup_scene_manager()
    scene_manager.initialized = true
    scene_manager.infinite_lives = false
    scene_manager.lives_left = starting_lives
    scene_manager.current_score = 0
    scene_manager.last_seek = 0
    scene_manager.completed_introduction = false
    scene_manager.current_scene = nil
    scene_manager.current_scene_name = nil
    scene_manager.current_sequence = nil
    scene_manager.current_sequence_name = nil
    scene_manager.current_sequence_ticks = 0
    scene_manager.current_sequence_tick_offset = 0
    scene_manager.unserialize_offset = 0
    scene_manager.current_row = 1
    scene_manager.current_cycle = 1
    scene_manager.chosen = {}
    scene_manager.total_failed = 0
    scene_manager.failed = {}

    for i,v in ipairs(scene_manager.rows) do
        scene_manager.chosen[i] = {}
        for j,v2 in ipairs(v) do
            scene_manager.chosen[i][j] = false
        end
    end
end

local function start_game()
    DirkSimple.log("Start game!")
    setup_scene_manager()

    -- Did you know this gives you infinite lives on any Dragon's Lair arcade
    -- cabinet, regardless of dip switch settings? Would have been nice to
    -- know when this cost a dollar per run!
    scene_manager.infinite_lives = (current_inputs.held["up"] and current_inputs.held["left"])

    choose_next_scene(false)
end

local function kill_player()
    if (not infinite_lives) and (not scene_manager.infinite_lives) and (test_scene == nil) then
        scene_manager.lives_left = scene_manager.lives_left - 1
    end

    DirkSimple.log("Killing player (lives now left=" .. scene_manager.lives_left .. ")")

    if scene_manager.lives_left == 0 then
        game_over(false)
    else
        choose_next_scene(true)
    end
end

local function check_actions(inputs)
    -- we don't care about inserting coins, but we'll play the sound if you
    -- hit the coinslot button.
    if inputs.pressed["coinslot"] then
        play_sound("coinslot")
    end

    if accepted_input ~= nil then
        return true  -- ignore all input until end of sequence.
    end

    local actions = scene_manager.current_sequence.actions
    if actions ~= nil then
        for i,v in ipairs(actions) do
            -- ignore if not in the time window for this input.
            if (scene_manager.current_sequence_ticks >= v.from) and (scene_manager.current_sequence_ticks <= v.to) then
                local input = v.input
                if god_mode and (v.nextsequence ~= nil) and (scene_manager.current_scene ~= nil) and (not scene_manager.current_scene[v.nextsequence].kills_player) then
                    DirkSimple.log("(god mode) accepted action '" .. input .. "' at " .. tostring(scene_manager.current_sequence_ticks / 1000.0))
                    accepted_input = v
                    return true
                elseif inputs.pressed[input] then  -- we got one!
                    DirkSimple.log("accepted action '" .. input .. "' at " .. tostring(scene_manager.current_sequence_ticks / 1000.0))
                    accepted_input = v
                    if input ~= "start" then
                        play_sound("accept")
                    end
                    return true
                end
            end
        end
    end

    -- if we don't have an accepted input but something was pressed,
    --  play the rejection buzz sound. Wrong inputs that lead to death
    --  still play the accepted sound, even though the input results in
    --  a failure state.
    if accepted_input == nil then
        if inputs.pressed["up"] or inputs.pressed["down"] or inputs.pressed["left"] or inputs.pressed["right"] or inputs.pressed["action"] then
            if scene_manager.current_scene_name ~= "attract_mode" then  -- don't buzz in attract mode.
                play_sound("reject")
            end
        end
    end

    return false
end

local function check_timeout()
    local done_with_sequence = false
    if scene_manager.current_sequence_ticks >= scene_manager.current_sequence.timeout.when then  -- whole sequence has run to completion.
        done_with_sequence = true
    elseif (accepted_input ~= nil) and accepted_input.interrupt ~= nil then  -- If interrupting, forego the timeout.
        done_with_sequence = true
    elseif (accepted_input ~= nil) and (accepted_input.nextsequence ~= nil) and (scene_manager.current_scene[accepted_input.nextsequence].start_time ~= time_laserdisc_noseek()) then  -- If action leads to a laserdisc seek, forego the timeout.
        done_with_sequence = true
    end

    if not done_with_sequence then
        return  -- sequence is not complete yet.
    end

    DirkSimple.log("Done with current sequence")

    local outcome
    if accepted_input ~= nil then
        outcome = accepted_input
    else
        outcome = scene_manager.current_sequence.timeout
    end

    if outcome.points ~= nil then
        scene_manager.current_score = scene_manager.current_score + outcome.points
    end

    if outcome.interrupt ~= nil then
        outcome.interrupt()
    elseif outcome.nextsequence ~= nil then  -- end of scene?
        start_sequence(outcome.nextsequence)
    else
        if scene_manager.current_sequence.kills_player then
            kill_player()  -- will update state, start new scene.
        else
            choose_next_scene(false)
        end
    end

    -- as a special hack, if the new sequence has a timeout of 0, we process it immediately without
    -- waiting for the next tick, since it's just trying to set up some state before an actual
    -- sequence and we don't want the video to move ahead in a completed sequence or progress
    -- before the actual sequence is ticking.
    if scene_manager.current_sequence.timeout.when == 0 then
        check_timeout()
    end
end

DirkSimple.serialize = function()
    if not scene_manager.initialized then
        setup_scene_manager()   -- just so we can serialize a default state.
    end

    local state = {}
    state[#state + 1] = 1   -- current serialization version
    state[#state + 1] = scene_manager.infinite_lives
    state[#state + 1] = scene_manager.lives_left
    state[#state + 1] = scene_manager.current_score
    state[#state + 1] = scene_manager.last_seek
    state[#state + 1] = scene_manager.completed_introduction
    state[#state + 1] = scene_manager.current_scene_name
    state[#state + 1] = scene_manager.current_sequence_name
    state[#state + 1] = scene_manager.current_sequence_ticks
    state[#state + 1] = scene_manager.current_sequence_tick_offset
    state[#state + 1] = scene_manager.current_row
    state[#state + 1] = scene_manager.current_cycle
    state[#state + 1] = scene_manager.total_failed

    for i,v in ipairs(scene_manager.failed) do
        state[#state + 1] = v
    end

    for i,v in ipairs(scene_manager.rows) do
        for j,v2 in ipairs(v) do
            state[#state + 1] = scene_manager.chosen[i][j]
        end
    end

    return state
end


DirkSimple.unserialize = function(state)
    -- !!! FIXME: this function assumes that `state` is completely valid. It doesn't check array length or data types.
    setup_scene_manager()

    local idx = 1
    local version = state[idx] ; idx = idx + 1
    scene_manager.infinite_lives = state[idx] ; idx = idx + 1
    scene_manager.lives_left = state[idx] ; idx = idx + 1
    scene_manager.current_score = state[idx] ; idx = idx + 1
    scene_manager.last_seek = state[idx] ; idx = idx + 1
    scene_manager.completed_introduction = state[idx] ; idx = idx + 1
    scene_manager.current_scene_name = state[idx] ; idx = idx + 1
    scene_manager.current_sequence_name = state[idx] ; idx = idx + 1
    scene_manager.current_sequence_ticks = state[idx] ; idx = idx + 1
    scene_manager.current_sequence_tick_offset = state[idx] ; idx = idx + 1
    scene_manager.current_row = state[idx] ; idx = idx + 1
    scene_manager.current_cycle = state[idx] ; idx = idx + 1
    scene_manager.total_failed = state[idx] ; idx = idx + 1
    scene_manager.unserialize_offset = scene_manager.current_sequence_ticks + scene_manager.current_sequence_tick_offset
    scene_manager.current_sequence_tick_offset = 0  -- unserialize_offset will handle everything up until now, until the next sequence starts.

    for i = 1, scene_manager.total_failed, 1 do
        scene_manager.failed[#scene_manager.failed + 1] = state[idx] ; idx = idx + 1
    end

    for i,v in ipairs(scene_manager.rows) do
        for j,v2 in ipairs(v) do
            scene_manager.chosen[i][j] = state[idx] ; idx = idx + 1
        end
    end

    if scene_manager.current_scene_name ~= nil then
        scene_manager.current_scene = scenes[scene_manager.current_scene_name]
        if scene_manager.current_sequence_name ~= nil then
            scene_manager.current_sequence = scene_manager.current_scene[scene_manager.current_sequence_name]
            local start_time = scene_manager.last_seek
            if scene_manager.current_sequence.is_single_frame then
                DirkSimple.show_single_frame(start_time)
            else
                DirkSimple.start_clip(start_time + scene_manager.unserialize_offset)
            end
        end
    end

    -- We don't (currently) serialize wave playback state (but we could,
    --  if DirkSimple.play_sound took a starting offset). So just reset the
    --  cooldown clock to allow a new buzz to play right away, for now.
    play_sound_cooldown = 0

    return true
end

DirkSimple.tick = function(ticks, sequenceticks, inputs)
    current_ticks = ticks
    current_inputs = inputs

    if not scene_manager.initialized then
        setup_scene_manager()
    end

    scene_manager.current_sequence_ticks = (sequenceticks + scene_manager.unserialize_offset) - scene_manager.current_sequence_tick_offset
    --DirkSimple.log("LUA TICK(ticks=" .. tostring(current_ticks) .. ", sequenceticks=" .. tostring(scene_manager.current_sequence_ticks) .. ", tick_offset=" .. tostring(scene_manager.current_sequence_tick_offset) .. ", unserialize_offset=" .. tostring(scene_manager.unserialize_offset) .. ")")

    if scene_manager.current_sequence == nil then
        start_attract_mode(false)
    end

    check_actions(inputs)   -- check inputs before timeout, in case an input came through at the last possible moment, even if we're over time.
    check_timeout()
end


-- The scene table!
-- http://www.dragons-lair-project.com/games/related/walkthru/lair/easy.asp
scenes = {
    attract_mode = {
        start_alive = {
            timeout = { when=0, nextsequence="attract_movie" },
            start_time = time_laserdisc_noseek(),
        },
        start_dead = {
            start_time = time_to_ms(5, 830),
            is_single_frame = true,
            timeout = { when=time_to_ms(3, 0), nextsequence="attract_movie" },
        },
        attract_movie = {
            start_time = time_to_ms(7, 0),
            timeout = { when=time_to_ms(43, 0), nextsequence="insert_coins" },
            actions = {
                -- Player hit start to start the game
                { input="start", from=time_to_ms(0, 0), to=time_to_ms(60, 0, 0), interrupt=start_game, nextsequence=nil },
            }
        },
        insert_coins = {
            start_time = time_to_ms(6, 200),
            is_single_frame = true,
            timeout = { when=time_to_ms(5, 0), nextsequence="attract_movie" },
            actions = {
                -- Player hit start to start the game
                { input="start", from=time_to_ms(0, 0), to=time_to_ms(60, 0, 0), interrupt=start_game, nextsequence=nil },
            }
        },
    },

    -- Intro level, no gameplay in the arcade version.
    introduction = {
        start_dead = {
            start_time = time_laserdisc_frame(1367),
            timeout = { when=time_to_ms(2, 32), nextsequence="castle_exterior" }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="castle_exterior" }
        },

        castle_exterior = {  -- exterior shot of the castle
            start_time = time_laserdisc_frame(1424),
            timeout = { when=time_to_ms(5, 767), nextsequence="exit_room" },
        },

        -- this skips the drawbridge itself, like the arcade does.
        exit_room = {  -- player runs through the gates.
            start_time = time_laserdisc_frame(1823) - laserdisc_frame_to_ms(2),
            timeout = { when=time_to_ms(2, 359) + laserdisc_frame_to_ms(10), nextsequence=nil },
        },
    },

    -- Swinging ropes, burning over a fiery pit.
    flaming_ropes = {
        game_over = {
            start_time = time_laserdisc_frame(3999),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(3505),
            timeout = { when=time_to_ms(2, 167), nextsequence="enter_room" }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {
            start_time = time_laserdisc_frame(3561),
            timeout = { when=time_to_ms(2, 228), nextsequence="platform_sliding" },
            actions = {
                -- Player grabs rope too soon
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 245), nextsequence="fall_to_death" },
                -- Player grabs rope correctly
                { input="right", from=time_to_ms(1, 245), to=time_to_ms(2, 130), nextsequence="rope1", points=251 },
                -- Player grabs rope too late
                { input="right", from=time_to_ms(2, 130), to=time_to_ms(4, 260), nextsequence="fall_to_death" },
                -- Player tries to fly
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 490), nextsequence="fall_to_death" },
                -- Player tries to dive
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 490), nextsequence="fall_to_death" },
            }
        },

        platform_sliding = {  -- Player hesitated, platform starts pulling back
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 621), nextsequence="fall_to_death" },  -- player hesitated, platform is gone, player falls
            actions = {
                -- Player grabs rope too soon
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="fall_to_death" },
                -- Player grabs rope correctly
                { input="right", from=time_to_ms(1, 835), to=time_to_ms(2, 884), nextsequence="rope1", points=251 },
                -- Player tries to flee
                { input="left", from=time_to_ms(1, 835), to=time_to_ms(2, 884), nextsequence="fall_to_death" },
                -- Player tries to fly
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 884), nextsequence="fall_to_death" },
                -- Player tries to dive
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 884), nextsequence="fall_to_death" },
            }
        },

        rope1 = {  -- player grabbed first rope
            start_time = time_laserdisc_frame(3693),
            timeout = { when=time_to_ms(2, 228), nextsequence="burns_hands" },
            actions = {
                -- Player grabs rope too soon
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 81), nextsequence="fall_to_death" },
                -- Player grabs rope correctly
                { input="right", from=time_to_ms(1, 81), to=time_to_ms(1, 835), nextsequence="rope2", points=379 },
                -- Player tries to fly
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="fall_to_death" },
                -- Player tries to dive
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="fall_to_death" },
                -- Player tries to flee
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="fall_to_death" },
            }
        },

        rope2 = {  -- player grabbed second rope
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 228), nextsequence="burns_hands" },
            actions = {
                -- Player grabs rope too soon
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 81), nextsequence="fall_to_death" },
                -- Player grabs rope correctly
                { input="right", from=time_to_ms(1, 81), to=time_to_ms(1, 835), nextsequence="rope3", points=495 },
                -- Player tries to fly
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="fall_to_death"  },
                -- Player tries to dive
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="fall_to_death" },
                -- Player tries to flee
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="fall_to_death" },
            }
        },

        rope3 = {  -- player grabbed third rope
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 507), nextsequence="misses_landing" },
            actions = {
                -- Player grabs rope too soon
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(0, 852), nextsequence="fall_to_death" },
                -- Player grabs rope correctly
                { input="right", from=time_to_ms(0, 852), to=time_to_ms(1, 704), nextsequence="exit_room", points=915 },
                -- Player tries to fly
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 769), nextsequence="fall_to_death" },
                -- Player tries to dive
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 769), nextsequence="fall_to_death" },
                -- Player tries to flee
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 769), nextsequence="fall_to_death" },
            }
        },

        exit_room = {  -- player reaches exit platform
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(0, 792), nextsequence=nil },
        },

        misses_landing = {  -- player landed on exit platform, but fell backwards
            start_time = time_laserdisc_frame(3879),
            kills_player = true,
            timeout = { when=time_to_ms(1, 917), nextsequence=nil },
        },

        burns_hands = {  -- rope burns up to hands, making player fall
            start_time = time_laserdisc_frame(3925),
            timeout = { when=time_to_ms(1, 583), nextsequence="fall_to_death" }
        },

        fall_to_death = {  -- player falls into the flames
            start_time = time_laserdisc_frame(3963),
            kills_player = true,
            timeout = { when=time_to_ms(1, 417), nextsequence=nil }
        }
    },

    -- Bedroom where brick wall appears in front of you to be jumped through.
    bower = {
        game_over = {
            start_time = time_laserdisc_frame(9387),
            timeout = { when=time_to_ms(3, 650), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(9093),
            timeout = { when=time_to_ms(2, 366), nextsequence="enter_room", points = 49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {
            start_time = time_laserdisc_frame(9181) - laserdisc_frame_to_ms(15),
            timeout = { when=time_to_ms(1, 147) + laserdisc_frame_to_ms(15), nextsequence="trapped_in_wall" },
            actions = {
                -- Player jumps through the hole in the wall
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 409) + laserdisc_frame_to_ms(15), nextsequence="exit_room", points=379 },
            }
        },

        trapped_in_wall = {  -- player fails to climb through.
            start_time = time_laserdisc_frame(9301) - laserdisc_frame_to_ms(15),
            kills_player = true,
            timeout = { when=time_to_ms(1, 792), nextsequence=nil }
        },

        exit_room = {  -- player reaches the door
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 425) + laserdisc_frame_to_ms(15), nextsequence=nil },
        },
    },

    -- Room with the "DRINK ME" sign.
    alice_room = {
        game_over = {
            start_time = time_laserdisc_frame(18522),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(18226),
            timeout = { when=time_to_ms(2, 334), nextsequence="enter_room", points = 49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {
            start_time = time_laserdisc_frame(18282) + laserdisc_frame_to_ms(1),
            timeout = { when=time_to_ms(2, 64) - laserdisc_frame_to_ms(1), nextsequence="burned_to_death" },
            actions = {
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 64), nextsequence="exit_room", points=379 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 64), nextsequence="drinks_potion" },
                { input="down", from=time_to_ms(1, 131), to=time_to_ms(2, 32), nextsequence="burned_to_death" },
                { input="left", from=time_to_ms(1, 131), to=time_to_ms(2, 32), nextsequence="burned_to_death" },
            }
        },

        drinks_potion = {  -- player drinks potion, dies
            start_time = time_laserdisc_frame(18378),
            kills_player = true,
            timeout = { when=time_to_ms(4, 86), nextsequence=nil }
        },

        burned_to_death = {  -- player dies in a fire
            start_time = time_laserdisc_frame(18486),
            kills_player = true,
            timeout = { when=time_to_ms(1, 375), nextsequence=nil }
        },

        exit_room = {  -- player reaches the door
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 442) + laserdisc_frame_to_ms(12), nextsequence=nil },
        },
    },

    -- Room with the wind blowing you and a diamond you shouldn't reach for.
    wind_room = {
        game_over = {
            start_time = time_laserdisc_frame(9010),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(8653),
            timeout = { when=time_to_ms(2, 376), nextsequence="enter_room", points = 49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {
            start_time = time_laserdisc_frame(8709),
            timeout = { when=time_to_ms(8, 159), nextsequence="sucked_in" },
            actions = {
                { input="right", from=time_to_ms(7, 406), to=time_to_ms(8, 126), nextsequence="exit_room", points=379 },
                { input="up", from=time_to_ms(5, 964), to=time_to_ms(8, 126), nextsequence="sucked_in" },
            }
        },

        sucked_in = {  -- player sucked into hole, falls to death
            start_time = time_laserdisc_frame(8938),
            kills_player = true,
            timeout = { when=time_to_ms(3, 2), nextsequence=nil }
        },

        exit_room = {  -- player reaches the door
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(0, 557), nextsequence=nil },
        },
    },

    -- Room that crumbles on three sides and then the ceiling caves in
    vestibule = {
        game_over = {
            start_time = time_laserdisc_frame(2214),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(4083),
            timeout = { when=time_to_ms(2, 84), nextsequence="enter_room", points = 49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {
            start_time = time_laserdisc_frame(1887),
            timeout = { when=time_to_ms(3, 998), nextsequence="fell_to_death" },
            actions = {
                { input="right", from=time_to_ms(1, 966), to=time_to_ms(3, 998), nextsequence="stagger", points=251 },
                { input="down", from=time_to_ms(1, 966), to=time_to_ms(3, 998), nextsequence="stagger", points=251 },
                { input="up", from=time_to_ms(1, 966), to=time_to_ms(3, 998), nextsequence="fell_to_death" },
                { input="left", from=time_to_ms(2, 490), to=time_to_ms(3, 965), nextsequence="fell_to_death" },
            }
        },

        stagger = {  -- player staggers in the rumble, room is about to collapse
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(0, 668), nextsequence="fell_to_death" },
            actions = {
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(0, 950), nextsequence="exit_room", points=251 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(0, 950), nextsequence="fell_to_death" },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(0, 950), nextsequence="fell_to_death" },
            }
        },

        fell_to_death = {  -- player fell through floor.
            start_time = time_laserdisc_frame(2085),
            kills_player = true,
            timeout = { when=time_to_ms(2, 42), nextsequence=nil }
        },

        exit_room = {  -- player reaches the door
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 922), nextsequence=nil },
        }
    },

    -- the one with three chances to jump.
    falling_platform_short = {
        game_over = {
            start_time = time_laserdisc_frame(15487),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(14791),
            timeout = { when=time_to_ms(2, 376), nextsequence="enter_room", points = 49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {
            start_time = time_laserdisc_frame(14847) + laserdisc_frame_to_ms(1),
            timeout = { when=time_to_ms(6, 881), nextsequence="crash_landing" },
            actions = {
                { input="left", from=time_to_ms(2, 818), to=time_to_ms(5, 14), nextsequence="fell_to_death" },
                { input="left", from=time_to_ms(5, 14), to=time_to_ms(5, 341), nextsequence="exit_room", points=3255 },
                { input="left", from=time_to_ms(5, 341), to=time_to_ms(5, 669), nextsequence="missed_jump" },
                { input="left", from=time_to_ms(5, 702), to=time_to_ms(6, 29), nextsequence="exit_room", points=3255 },
                { input="left", from=time_to_ms(6, 29), to=time_to_ms(6, 357), nextsequence="fell_to_death" },
                { input="left", from=time_to_ms(6, 357), to=time_to_ms(6, 685), nextsequence="exit_room", points=3255 },
                { input="right", from=time_to_ms(2, 818), to=time_to_ms(7, 209), nextsequence="fell_to_death" },
                { input="up", from=time_to_ms(2, 818), to=time_to_ms(7, 209), nextsequence="fell_to_death" },
                { input="down", from=time_to_ms(2, 818), to=time_to_ms(7, 209), nextsequence="fell_to_death" },
            }
        },

        crash_landing = {  -- platform crashes into the floor at the bottom of the pit.
            start_time = time_laserdisc_frame(15226),
            kills_player = true,
            timeout = { when=time_to_ms(3, 335), nextsequence=nil }
        },

        missed_jump = {  -- player tried the jump but missed
            start_time = time_laserdisc_frame(15306),
            kills_player = true,
            timeout = { when=time_to_ms(2, 501), nextsequence=nil }
        },

        fell_to_death = {  -- player fell off the platform without jumping
            start_time = time_laserdisc_frame(15338),
            kills_player = true,
            timeout = { when=time_to_ms(1, 166), nextsequence=nil }
        },

        exit_room = {  -- player successfully makes the jump
            start_time = time_laserdisc_frame(15366),
            timeout = { when=time_to_ms(4, 586) + laserdisc_frame_to_ms(10), nextsequence=nil },
        }
    },

    -- the one with nine chances to jump.
    falling_platform_long = {
        game_over = {
            start_time = time_laserdisc_frame(15487),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(14791),
            timeout = { when=time_to_ms(2, 376), nextsequence="enter_room", points = 49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {
            start_time = time_laserdisc_frame(14847) + laserdisc_frame_to_ms(1),
            timeout = { when=time_to_ms(6, 816), nextsequence="second_jump_set", points = 49 },
            actions = {
                { input="left", from=time_to_ms(2, 818), to=time_to_ms(5, 14), nextsequence="fell_to_death" },
                { input="left", from=time_to_ms(5, 14), to=time_to_ms(5, 341), nextsequence="exit_room", points=3255 },
                { input="left", from=time_to_ms(5, 341), to=time_to_ms(5, 669), nextsequence="fell_to_death" },
                { input="left", from=time_to_ms(5, 702), to=time_to_ms(6, 29), nextsequence="exit_room", points=3255 },
                { input="left", from=time_to_ms(6, 29), to=time_to_ms(6, 357), nextsequence="missed_jump" },
                { input="left", from=time_to_ms(6, 357), to=time_to_ms(6, 685), nextsequence="exit_room", points=3255 },
                { input="right", from=time_to_ms(2, 818), to=time_to_ms(6, 750), nextsequence="fell_to_death" },
                { input="up", from=time_to_ms(2, 818), to=time_to_ms(6, 750), nextsequence="fell_to_death" },
                { input="down", from=time_to_ms(2, 818), to=time_to_ms(6, 750), nextsequence="fell_to_death" },
            }
        },

        second_jump_set = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(4, 293), nextsequence="third_jump_set", points = 1939 },
            actions = {
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 458), nextsequence="fell_to_death" },
                { input="right", from=time_to_ms(2, 458), to=time_to_ms(2, 785), nextsequence="exit_room", points=3255 },
                { input="right", from=time_to_ms(2, 785), to=time_to_ms(3, 113), nextsequence="missed_jump" },
                { input="right", from=time_to_ms(3, 146), to=time_to_ms(3, 473), nextsequence="exit_room", points=3255 },
                { input="right", from=time_to_ms(3, 473), to=time_to_ms(3, 801), nextsequence="missed_jump" },
                { input="right", from=time_to_ms(3, 801), to=time_to_ms(4, 129), nextsequence="exit_room", points=3255 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(4, 293), nextsequence="fell_to_death" },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(4, 293), nextsequence="fell_to_death" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(4, 293), nextsequence="fell_to_death" },
            }
        },

        third_jump_set = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(4, 293), nextsequence="crash_landing" },
            actions = {
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 458), nextsequence="missed_jump" },
                { input="left", from=time_to_ms(2, 458), to=time_to_ms(2, 785), nextsequence="exit_room", points=3255 },
                { input="left", from=time_to_ms(2, 785), to=time_to_ms(3, 113), nextsequence="missed_jump" },
                { input="left", from=time_to_ms(3, 146), to=time_to_ms(3, 473), nextsequence="exit_room", points=3255 },
                { input="left", from=time_to_ms(3, 473), to=time_to_ms(3, 801), nextsequence="missed_jump" },
                { input="left", from=time_to_ms(3, 801), to=time_to_ms(4, 129), nextsequence="exit_room", points=3255 },
                { input="left", from=time_to_ms(4, 162), to=time_to_ms(5, 571), nextsequence="fell_to_death" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(5, 571), nextsequence="fell_to_death" },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(5, 571), nextsequence="fell_to_death" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(5, 571), nextsequence="fell_to_death" },
            }
        },

        crash_landing = {  -- platform crashes into the floor at the bottom of the pit.
            start_time = time_laserdisc_noseek(),
            kills_player = true,
            timeout = { when=time_to_ms(2, 32), nextsequence=nil }
        },

        missed_jump = {  -- player tried the jump but missed
            start_time = time_laserdisc_frame(15306),
            kills_player = true,
            timeout = { when=time_to_ms(2, 501), nextsequence=nil }
        },

        fell_to_death = {  -- player fell off the platform without jumping
            start_time = time_laserdisc_frame(15338),
            kills_player = true,
            timeout = { when=time_to_ms(1, 166), nextsequence=nil }
        },

        exit_room = {  -- player successfully makes the jump
            start_time = time_laserdisc_frame(15366),
            timeout = { when=time_to_ms(4, 653) + laserdisc_frame_to_ms(10), nextsequence=nil },
        }
    },

    -- The tomb with the skulls, slime, skeletal hands, and ghouls
    crypt_creeps = {
        game_over = {
            start_time = time_laserdisc_frame(12039),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(11433),
            timeout = { when=time_to_ms(2, 334), nextsequence="enter_room", points = 49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {  -- skulls roll in
            start_time = time_laserdisc_frame(11489),
            timeout = { when=time_to_ms(3, 244), nextsequence="eaten_by_skulls" },
            actions = {
                { input="up", from=time_to_ms(2, 228), to=time_to_ms(3, 244), nextsequence="jumped_skulls", points=495 },
                { input="action", from=time_to_ms(2, 228), to=time_to_ms(3, 178), nextsequence="overpowered_by_skulls" },
                { input="down", from=time_to_ms(2, 228), to=time_to_ms(3, 178), nextsequence="eaten_by_skulls" },
                { input="right", from=time_to_ms(2, 228), to=time_to_ms(3, 178), nextsequence="eaten_by_skulls" },
                { input="left", from=time_to_ms(2, 228), to=time_to_ms(3, 178), nextsequence="eaten_by_skulls" },
            }
        },

        jumped_skulls = {   -- player jumped down the hall when skulls rolled in, first hand attacks
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 311), nextsequence="crushed_by_hand" },
            actions = {
                { input="action", from=time_to_ms(0, 688), to=time_to_ms(1, 278), nextsequence="attacked_first_hand", points=915 },
                { input="up", from=time_to_ms(0, 918), to=time_to_ms(1, 278), nextsequence="crushed_by_hand" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 311), nextsequence="eaten_by_skulls" },
                { input="left", from=time_to_ms(0, 668), to=time_to_ms(1, 278), nextsequence="crushed_by_hand" },
            }
        },

        attacked_first_hand = {   -- player drew sword and attacked the first skeletal hand, slime rolls in
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 195), nextsequence="eaten_by_slime" },
            actions = {
                { input="up", from=time_to_ms(1, 49), to=time_to_ms(2, 195), nextsequence="jumped_slime", points=495 },
                { input="down", from=time_to_ms(1, 49), to=time_to_ms(2, 163), nextsequence="eaten_by_skulls" },
                { input="right", from=time_to_ms(1, 49), to=time_to_ms(2, 163), nextsequence="eaten_by_slime" },
                { input="left", from=time_to_ms(1, 49), to=time_to_ms(2, 163), nextsequence="eaten_by_slime" },
            }
        },

        jumped_slime = {   -- player jumped down the hall when black slime rolled in, second hand attacks
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 212), nextsequence="crushed_by_hand" },
            actions = {
                { input="action", from=time_to_ms(0, 590), to=time_to_ms(1, 180), nextsequence="attacked_second_hand", points=915 },
                { input="up", from=time_to_ms(0, 590), to=time_to_ms(1, 147), nextsequence="crushed_by_hand" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 212), nextsequence="eaten_by_slime" },
                { input="right", from=time_to_ms(0, 590), to=time_to_ms(1, 147), nextsequence="crushed_by_hand" },
            }
        },

        attacked_second_hand = {   -- player drew sword and attacked the second skeletal hand, more slime rolls in
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 835), nextsequence="eaten_by_slime" },
            actions = {
                { input="left", from=time_to_ms(0, 426), to=time_to_ms(1, 835), nextsequence="enter_crypt", points=495 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="eaten_by_slime" },
                { input="right", from=time_to_ms(0, 360), to=time_to_ms(1, 835), nextsequence="eaten_by_slime" },
            }
        },

        enter_crypt = {   -- player fled hallway, entered actual crypt
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 835), nextsequence="captured_by_ghouls" },
            actions = {
                { input="action", from=time_to_ms(0, 688), to=time_to_ms(1, 835), nextsequence="exit_room", points=495 },
                { input="up", from=time_to_ms(1, 81), to=time_to_ms(1, 835), nextsequence="captured_by_ghouls" },
                { input="down", from=time_to_ms(0, 688), to=time_to_ms(1, 835), nextsequence="captured_by_ghouls" },
                { input="right", from=time_to_ms(1, 81), to=time_to_ms(1, 835), nextsequence="captured_by_ghouls" },
                { input="left", from=time_to_ms(1, 81), to=time_to_ms(1, 835), nextsequence="captured_by_ghouls" },
            }
        },

        exit_room = {  -- player kills ghouls, heads through the exit
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(4, 257), nextsequence=nil },
        },

        overpowered_by_skulls = {  -- skulls got the player while drawing sword
            start_time = time_laserdisc_frame(11881),
            kills_player = true,
            timeout = { when=time_to_ms(1, 83) + laserdisc_frame_to_ms(10), nextsequence=nil }
        },

        eaten_by_skulls = {  -- skulls got the player
            start_time = time_laserdisc_frame(11904),
            kills_player = true,
            timeout = { when=time_to_ms(0, 124) + laserdisc_frame_to_ms(10), nextsequence=nil }
        },

        crushed_by_hand = {  -- giant skeletal hand got the player
            start_time = time_laserdisc_frame(11917),
            kills_player = true,
            timeout = { when=time_to_ms(0, 874), nextsequence=nil }
        },

        eaten_by_slime = {  -- black slime got the player
            start_time = time_laserdisc_frame(11940),
            kills_player = true,
            timeout = { when=time_to_ms(1, 375), nextsequence=nil }
        },

        captured_by_ghouls = {  -- ghouls got the player
            start_time = time_laserdisc_frame(11983),
            kills_player = true,
            timeout = { when=time_to_ms(2, 292), nextsequence=nil }
        }
    },

    -- The flying horse machine that rides you past fires and other obstacles
    flying_horse = {
        game_over = {
            start_time = time_laserdisc_frame(10600),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(9965),
            timeout = { when=time_to_ms(2, 84), nextsequence="enter_room", points = 49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {  -- Player mounts the horse, starts the wild ride, dodge first fire
            start_time = time_laserdisc_frame(10021) + laserdisc_frame_to_ms(1),
            timeout = { when=time_to_ms(4, 522), nextsequence="hit_pillar" },
            actions = {
                -- The ROM checks for UpRight here, but also an identical entry for Right which comes to the same result.
                { input="right", from=time_to_ms(3, 801), to=time_to_ms(4, 522), nextsequence="second_fire", points=495 },
                { input="up", from=time_to_ms(3, 801), to=time_to_ms(4, 522), nextsequence="hit_pillar" },
                { input="left", from=time_to_ms(3, 801), to=time_to_ms(4, 522), nextsequence="burned_to_death" },
            }
        },

        second_fire = {  -- dodge second fire
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 376), nextsequence="hit_pillar" },
            actions = {
                { input="left", from=time_to_ms(0, 721), to=time_to_ms(1, 343), nextsequence="third_fire", points=495 },
                { input="up", from=time_to_ms(0, 721), to=time_to_ms(1, 343), nextsequence="hit_pillar" },
                { input="right", from=time_to_ms(0, 721), to=time_to_ms(1, 343), nextsequence="burned_to_death" },
            }
        },

        third_fire = {  -- dodge third fire
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 835), nextsequence="hit_pillar" },
            actions = {
                { input="right", from=time_to_ms(1, 212), to=time_to_ms(1, 835), nextsequence="fourth_fire", points=495 },
                { input="up", from=time_to_ms(0, 852), to=time_to_ms(1, 802), nextsequence="hit_pillar" },
                { input="left", from=time_to_ms(1, 212), to=time_to_ms(1, 835), nextsequence="burned_to_death" },
            }
        },

        fourth_fire = {  -- dodge fourth fire
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 966), nextsequence="hit_pillar" },
            actions = {
                { input="left", from=time_to_ms(1, 311), to=time_to_ms(1, 966), nextsequence="brick_wall", points=495 },
                { input="up", from=time_to_ms(1, 49), to=time_to_ms(1, 966), nextsequence="hit_pillar" },
                { input="right", from=time_to_ms(1, 311), to=time_to_ms(1, 966), nextsequence="burned_to_death" },
            }
        },

        brick_wall = {  -- dodge a brick wall
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 868), nextsequence="hit_brick_wall" },
            actions = {
                { input="left", from=time_to_ms(1, 311), to=time_to_ms(1, 868), nextsequence="fifth_fire", points=1326 },
                { input="up", from=time_to_ms(0, 950), to=time_to_ms(1, 835), nextsequence="hit_brick_wall" },
                { input="right", from=time_to_ms(0, 950), to=time_to_ms(1, 835), nextsequence="hit_brick_wall" },
            }
        },

        fifth_fire = {  -- dodge fifth fire
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 409), nextsequence="hit_pillar" },
            actions = {
                { input="left", from=time_to_ms(0, 721), to=time_to_ms(1, 376), nextsequence="exit_room", points=495 },
                { input="up", from=time_to_ms(0, 393), to=time_to_ms(1, 409), nextsequence="hit_pillar" },
                { input="right", from=time_to_ms(0, 721), to=time_to_ms(1, 376), nextsequence="burned_to_death" },
            }
        },

        exit_room = {  -- player crash lands safely, exits room.
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(5, 41), nextsequence=nil },
        },

        burned_to_death = {  -- player ran into the wall of flames
            start_time = time_laserdisc_frame(10565),
            kills_player = true,
            timeout = { when=time_to_ms(1, 500), nextsequence=nil }
        },

        hit_pillar = {  -- player ran into the pillar
            start_time = time_laserdisc_frame(10453),
            kills_player = true,
            timeout = { when=time_to_ms(2, 1), nextsequence=nil }
        },

        hit_brick_wall = {  -- player ran into the brick wall
            start_time = time_laserdisc_frame(10501),
            kills_player = true,
            timeout = { when=time_to_ms(2, 292), nextsequence=nil }
        }
    },

    -- The giddy goons!
    giddy_goons = {
        game_over = {
            start_time = time_laserdisc_frame(6198),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(5627),
            timeout = { when=time_to_ms(2, 84), nextsequence="enter_room", points = 49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {  -- Player runs into the goons!!
            start_time = time_laserdisc_frame(5683),
            timeout = { when=time_to_ms(3, 146), nextsequence="knife_in_back" },
            actions = {
                { input="action", from=time_to_ms(2, 392), to=time_to_ms(3, 113), nextsequence="kills_first_goon", points=379 },
                { input="up", from=time_to_ms(1, 507), to=time_to_ms(2, 392), nextsequence="fall_to_death" },
                { input="right", from=time_to_ms(2, 392), to=time_to_ms(3, 113), nextsequence="knife_in_back" },
                { input="left", from=time_to_ms(2, 392), to=time_to_ms(3, 113), nextsequence="swarm_of_goons" },
            }
        },

        kills_first_goon = {  -- player kills first goon, moves towards stairs.
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 835), nextsequence="knife_in_back" },
            actions = {
                -- the ROM has an "UpRight" action that matches the successful "Right" (but "Up" by itself is a fail), so we just check "Right" first so the player will pass if they're hitting both.
                { input="right", from=time_to_ms(1, 114), to=time_to_ms(1, 835), nextsequence="climbs_stairs", points=1326 },
                { input="up", from=time_to_ms(0, 885), to=time_to_ms(1, 802), nextsequence="fall_to_death" },
                { input="left", from=time_to_ms(1, 114), to=time_to_ms(1, 835), nextsequence="shoves_off_edge" },
                { input="action", from=time_to_ms(1, 114), to=time_to_ms(1, 835), nextsequence="shoves_off_edge" },
            }
        },

        climbs_stairs = {  -- Player climbs the stairs, meets more resistance
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 163), nextsequence="swarm_of_goons" },
            actions = {
                { input="action", from=time_to_ms(1, 475), to=time_to_ms(2, 130), nextsequence="kill_upper_goons", points=3255 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 130), nextsequence="kill_upper_goons", points=3255 },
                { input="up", from=time_to_ms(1, 475), to=time_to_ms(2, 130), nextsequence="fight_off_one_before_swarm" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 163), nextsequence="fight_off_one_before_swarm" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 163), nextsequence="fall_to_death" },
            }
        },

        -- the original ROM gives no points for passing this sequence, probably because you can do nothing and win on autopilot.
        -- Interestingly, Digital Leisure's current version on Steam doesn't have goons to kill at the top of the stairs, either. Not sure what happened there.
        kill_upper_goons = {  -- Player kills the goons at the top of the stairs.
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 606), nextsequence="exit_room", points=0 },
            actions = {
                -- The ROM has an "UpLeft" action here, but it matches its separate "Up" and "Left" entries.
                { input="up", from=time_to_ms(0, 852), to=time_to_ms(1, 540), nextsequence="exit_room", points=0 },
                { input="left", from=time_to_ms(0, 852), to=time_to_ms(1, 540), nextsequence="exit_room", points=0 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 606), nextsequence="fight_off_one_before_swarm" },
                { input="action", from=time_to_ms(0, 786), to=time_to_ms(1, 573), nextsequence="fight_off_one_before_swarm" },
            }
        },

        exit_room = {  -- player heads for the door
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 842), nextsequence=nil },
        },

        knife_in_back = {  -- player gets a knife in the back
            start_time = time_laserdisc_frame(6039),
            kills_player = true,
            timeout = { when=time_to_ms(2, 84), nextsequence=nil }
        },

        shoves_off_edge = {  -- goons push player off edge
            start_time = time_laserdisc_frame(6091),
            kills_player = true,
            timeout = { when=time_to_ms(2, 720), nextsequence=nil }
        },

        fall_to_death = {  -- player falls down into pit
            start_time = time_laserdisc_frame(6163),
            kills_player = true,
            timeout = { when=time_to_ms(1, 41), nextsequence=nil }
        },

        fight_off_one_before_swarm = {  -- Player kills one, then swarm takes him down.
            start_time = time_laserdisc_frame(5947),
            kills_player = true,
            timeout = { when=time_to_ms(3, 544), nextsequence=nil }
        },

        swarm_of_goons = {  -- giddy goons swarm dirk.
            start_time = time_laserdisc_frame(6015),
            kills_player = true,
            timeout = { when=time_to_ms(0, 708), nextsequence=nil }
        }
    },

    -- Green tentacles flood in to the room.
    tentacle_room = {
        game_over = {
            start_time = time_laserdisc_frame(2954),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(2297),
            timeout = { when=time_to_ms(2, 84), nextsequence="enter_room", points = 49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {
            start_time = time_laserdisc_frame(2353),
            timeout = { when=time_to_ms(3, 965), nextsequence="left_tentacle_grabs" },
            actions = {
                { input="action", from=time_to_ms(2, 687), to=time_to_ms(3, 965), nextsequence="kills_first_tentacle", points=49 }
            }
        },

        kills_first_tentacle = {  -- player slashes first tentacle
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 359), nextsequence="squeeze_to_death" },
            actions = {
                { input="up", from=time_to_ms(1, 409), to=time_to_ms(2, 327), nextsequence="jump_to_weapon_rack", points=379 }
            }
        },

        jump_to_weapon_rack = {  -- player jumps to weapon rack on far wall
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 901), nextsequence="squeeze_to_death" },
            actions = {
                { input="right", from=time_to_ms(1, 180), to=time_to_ms(1, 933), nextsequence="jump_to_door", points=495 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 901), nextsequence="squeeze_to_death" },
                { input="action", from=time_to_ms(0, 0), to=time_to_ms(1, 901), nextsequence="squeeze_to_death" },
                { input="left", from=time_to_ms(1, 180), to=time_to_ms(1, 933), nextsequence="squeeze_to_death" },
            }
        },

        jump_to_door = {  -- player jumps to door far wall
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 442), nextsequence="squeeze_to_death_by_door" },
            actions = {
                -- ROM has "DownRight" with identical "Down" and "Right" entries, so this is fine.
                { input="down", from=time_to_ms(0, 492), to=time_to_ms(1, 409), nextsequence="jump_to_stairs", points=915 },
                { input="right", from=time_to_ms(0, 492), to=time_to_ms(1, 409), nextsequence="jump_to_stairs", points=915 },
                { input="up", from=time_to_ms(0, 492), to=time_to_ms(1, 409), nextsequence="squeeze_to_death_by_door" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 442), nextsequence="squeeze_to_death" },
                { input="action", from=time_to_ms(0, 0), to=time_to_ms(1, 475), nextsequence="squeeze_to_death" },
            }
        },

        jump_to_stairs = {  -- player jumps to base of staircase, starts to climb
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 720), nextsequence="two_front_war" },
            actions = {
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 966), nextsequence="squeeze_to_death" },
                { input="left", from=time_to_ms(1, 966), to=time_to_ms(2, 720), nextsequence="jump_to_table", points=1326 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 720), nextsequence="two_front_war" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 720), nextsequence="squeeze_to_death" },
                { input="action", from=time_to_ms(0, 0), to=time_to_ms(2, 720), nextsequence="two_front_war" },
            }
        },

        jump_to_table = {  -- player jumps back down the stairs to the table
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 228), nextsequence="squeeze_to_death" },
            actions = {
                -- ROM has "UpRight" with identical "Up" and "Right" entries, so this is fine.
                { input="up", from=time_to_ms(0, 360), to=time_to_ms(2, 195), nextsequence="exit_room", points=1939 },
                { input="right", from=time_to_ms(0, 360), to=time_to_ms(2, 195), nextsequence="exit_room", points=1939 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 228), nextsequence="squeeze_to_death" },
                { input="action", from=time_to_ms(0, 0), to=time_to_ms(2, 228), nextsequence="squeeze_to_death" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 228), nextsequence="squeeze_to_death" },
            }
        },

        exit_room = {  -- player heads for the door
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 66), nextsequence=nil },
        },

        left_tentacle_grabs = {  -- player gets grabbed by first tentacle in the room.
            start_time = time_laserdisc_frame(2729),
            kills_player = true,
            timeout = { when=time_to_ms(2, 918), nextsequence=nil }
        },

        squeeze_to_death = {  -- tentacles wrap around player in close-up and squeeze him to death
            start_time = time_laserdisc_frame(2801),
            kills_player = true,
            timeout = { when=time_to_ms(2, 42), nextsequence=nil }
        },

        two_front_war = {  -- player slashes tentacle on the right, but left tentacle sneaks up on him
            start_time = time_laserdisc_frame(2849),
            kills_player = true,
            timeout = { when=time_to_ms(3, 2), nextsequence=nil }
        },

        squeeze_to_death_by_door = {  -- tentacles wrap around player in close-up and squeeze him to death, door in background.
            start_time = time_laserdisc_frame(2933),
            kills_player = true,
            timeout = { when=time_to_ms(0, 874), nextsequence=nil }
        },
    },

    tilting_room = {
        game_over = {
            start_time = time_laserdisc_frame(20535),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(20130),
            timeout = { when=time_to_ms(2, 251), nextsequence="enter_room", points = 49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {
            start_time = time_laserdisc_frame(20187),
            timeout = { when=time_to_ms(4, 456), nextsequence="catches_fire" },
            actions = {
                { input="down", from=time_to_ms(3, 768), to=time_to_ms(4, 489), nextsequence="jumps_back", points=1939 },
                { input="left", from=time_to_ms(2, 785), to=time_to_ms(4, 489), nextsequence="catches_fire" },
                { input="right", from=time_to_ms(3, 768), to=time_to_ms(4, 489), nextsequence="falls_to_death" }
            }
        },

        jumps_back = {  -- player jumps back towards the camera
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 573), nextsequence="falls_to_death" },
            actions = {
                { input="up", from=time_to_ms(0, 328), to=time_to_ms(0, 885), nextsequence="catches_fire" },
                { input="up", from=time_to_ms(0, 885), to=time_to_ms(1, 540), nextsequence="jumps_forward", points=2675  },
                { input="left", from=time_to_ms(0, 328), to=time_to_ms(1, 573), nextsequence="catches_fire" },
                { input="down", from=time_to_ms(0, 328), to=time_to_ms(1, 573), nextsequence="falls_to_death" },
            }
        },

        jumps_forward = {  -- player jumps forward again towards the far wall.
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(0, 786), nextsequence="falls_to_death" },
            actions = {
                { input="left", from=time_to_ms(0, 492), to=time_to_ms(1, 49), nextsequence="exit_room", points=1939  },
                { input="up", from=time_to_ms(0, 492), to=time_to_ms(1, 49), nextsequence="wrong_door" },
                { input="down", from=time_to_ms(0, 328), to=time_to_ms(1, 49), nextsequence="falls_to_death" },
                { input="right", from=time_to_ms(0, 328), to=time_to_ms(1, 49), nextsequence="falls_to_death" },
            }
        },

        exit_room = {  -- player heads for the door
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 400), nextsequence=nil },
        },

        catches_fire = {  -- player catches fire
            start_time = time_laserdisc_frame(20450),
            kills_player = true,
            timeout = { when=time_to_ms(1, 500), nextsequence=nil }
        },

        falls_to_death = {  -- player falls in pit
            start_time = time_laserdisc_frame(20486),
            kills_player = true,
            timeout = { when=time_to_ms(2, 1), nextsequence=nil }
        },

        wrong_door = {  -- player jumps for the wrong door, hits gate
            start_time = time_laserdisc_frame(20384),
            kills_player = true,
            timeout = { when=time_to_ms(2, 710), nextsequence=nil }
        },
    },

    throne_room = {
        game_over = {
            start_time = time_laserdisc_frame(21073),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(20618),
            timeout = { when=time_to_ms(2, 334), nextsequence="enter_room", points = 49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {  -- player's sword and helmut are pulled to magnet in middle of room, floor starts to electrify.
            start_time = time_laserdisc_frame(20674) + laserdisc_frame_to_ms(1),
            timeout = { when=time_to_ms(2, 753), nextsequence="electrified_floor" },
            actions = {
                { input="right", from=time_to_ms(1, 966), to=time_to_ms(2, 720), nextsequence="first_jump", points=1326 },
                { input="up", from=time_to_ms(1, 606), to=time_to_ms(3, 834), nextsequence="electrified_floor" },
                { input="down", from=time_to_ms(1, 606), to=time_to_ms(3, 834), nextsequence="electrified_floor" },
                { input="left", from=time_to_ms(1, 606), to=time_to_ms(3, 834), nextsequence="electrified_floor" },
            }
        },

        first_jump = {  -- player jumps away from electrified floor
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(0, 688), nextsequence="electrified_floor" },
            actions = {
                -- The ROM has "UpRight" here that matches "Up" and "Right", so we're good to go here.
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(0, 688), nextsequence="second_jump", points=3255 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(0, 688), nextsequence="second_jump", points=3255 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(0, 688), nextsequence="electrified_floor" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(0, 688), nextsequence="electrified_floor" },
            }
        },

        second_jump = {  -- player jumps away from still-moving electrified floor, again.
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(0, 885), nextsequence="electrified_floor" },
            actions = {
                { input="right", from=time_to_ms(0, 131), to=time_to_ms(0, 885), nextsequence="on_throne", points=2675 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(0, 885), nextsequence="electrified_sword" },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(0, 885), nextsequence="electrified_floor" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(0, 885), nextsequence="electrified_floor" },
            }
        },

        on_throne = {  -- player jumps on throne, throne rotates around to secret room
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(4, 293), nextsequence="electrified_throne" },
            actions = {
                { input="right", from=time_to_ms(3, 408), to=time_to_ms(4, 358), nextsequence="exit_room", points=1939 },
                { input="left", from=time_to_ms(3, 408), to=time_to_ms(4, 358), nextsequence="electrified_floor" },
                { input="left", from=time_to_ms(3, 408), to=time_to_ms(4, 96), nextsequence="electrified_floor" },
            }
        },

        exit_room = {  -- player heads for the door
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 932), nextsequence=nil },
        },

        electrified_sword = {   -- player grabs sword, gets zapped
            start_time = time_laserdisc_frame(20928),
            kills_player = true,
            timeout = { when=time_to_ms(2, 835), nextsequence=nil }
        },

        electrified_floor = {  -- player touched wrong part of floor, gets zapped
            start_time = time_laserdisc_frame(21000),
            kills_player = true,
            timeout = { when=time_to_ms(1, 41), nextsequence=nil }
        },

        electrified_throne = {  -- player doesn't leave throne, gets zapped.
            start_time = time_laserdisc_frame(21030),
            kills_player = true,
            timeout = { when=time_to_ms(1, 750), nextsequence=nil }
        },
    },

    underground_river = {
        game_over = {
            start_time = time_laserdisc_frame(24239),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(22682),
            timeout = { when=time_to_ms(2, 334), nextsequence="enter_room", points = 49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {  -- player is walking along, falls through floor into barrel
            start_time = time_laserdisc_frame(22738),
            timeout = { when=time_to_ms(2, 654), nextsequence="first_boulders" }
        },

        -- the arcade skips the "YE BOULDERS" intro footage here--hence the laserdisc seek--presumably to shorten this pretty-long scene.
        first_boulders = {  -- the first part of YE BOULDERS sequence
            start_time = time_laserdisc_frame(22936),
            timeout = { when=time_to_ms(1, 16), nextsequence="boulders_crash" },
            actions = {
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 16), nextsequence="second_boulders", points=379 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 16), nextsequence="boulders_crash" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 16), nextsequence="boulders_crash" },
            }
        },

        second_boulders = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 933), nextsequence="boulders_crash2" },
            actions = {
                { input="right", from=time_to_ms(0, 950), to=time_to_ms(1, 901), nextsequence="third_boulders", points=379 },
                { input="up", from=time_to_ms(0, 950), to=time_to_ms(1, 901), nextsequence="boulders_crash2" },
                { input="left", from=time_to_ms(0, 950), to=time_to_ms(1, 901), nextsequence="boulders_crash2" },
            }
        },

        third_boulders = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 32), nextsequence="boulders_crash3" },
            actions = {
                { input="left", from=time_to_ms(1, 49), to=time_to_ms(1, 999), nextsequence="fourth_boulders", points=379 },
                { input="up", from=time_to_ms(1, 49), to=time_to_ms(1, 999), nextsequence="boulders_crash3" },
                { input="right", from=time_to_ms(1, 49), to=time_to_ms(1, 999), nextsequence="boulders_crash3" },
            }
        },

        fourth_boulders = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 966), nextsequence="boulders_crash4" },
            actions = {
                { input="right", from=time_to_ms(0, 950), to=time_to_ms(1, 966), nextsequence="first_rapids", points=379 },
                { input="up", from=time_to_ms(0, 950), to=time_to_ms(1, 966), nextsequence="boulders_crash4" },
                { input="left", from=time_to_ms(0, 950), to=time_to_ms(1, 966), nextsequence="boulders_crash4" },
            }
        },

        first_rapids = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(5, 210), nextsequence="rapids_crash" },
            actions = {
                { input="up", from=time_to_ms(3, 932), to=time_to_ms(4, 522), nextsequence="rapids_crash" },
                { input="up", from=time_to_ms(4, 522), to=time_to_ms(5, 145), nextsequence="second_rapids", points=495 },
                { input="right", from=time_to_ms(3, 736), to=time_to_ms(4, 555), nextsequence="second_rapids", points=495 },
                { input="right", from=time_to_ms(4, 555), to=time_to_ms(5, 145), nextsequence="rapids_crash" },
                { input="left", from=time_to_ms(4, 391), to=time_to_ms(5, 177), nextsequence="rapids_crash" },
            }
        },

        second_rapids = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 523), nextsequence="rapids_crash" },
            actions = {
                { input="up", from=time_to_ms(1, 212), to=time_to_ms(1, 835), nextsequence="rapids_crash" },
                { input="up", from=time_to_ms(1, 835), to=time_to_ms(2, 490), nextsequence="third_rapids", points=495 },
                { input="right", from=time_to_ms(1, 212), to=time_to_ms(2, 613), nextsequence="rapids_crash" },
                { input="left", from=time_to_ms(1, 81), to=time_to_ms(1, 901), nextsequence="third_rapids", points=495 },
                { input="left", from=time_to_ms(1, 901), to=time_to_ms(2, 490), nextsequence="rapids_crash" },
            }
        },

        third_rapids = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 490), nextsequence="rapids_crash" },
            actions = {
                { input="up", from=time_to_ms(1, 311), to=time_to_ms(1, 802), nextsequence="rapids_crash" },
                { input="up", from=time_to_ms(1, 802), to=time_to_ms(2, 458), nextsequence="fourth_rapids", points=495 },
                { input="right", from=time_to_ms(1, 16), to=time_to_ms(1, 868), nextsequence="fourth_rapids", points=495 },
                { input="right", from=time_to_ms(1, 868), to=time_to_ms(2, 458), nextsequence="rapids_crash" },
                { input="left", from=time_to_ms(1, 147), to=time_to_ms(2, 490), nextsequence="rapids_crash" },
            }
        },

        fourth_rapids = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 818), nextsequence="rapids_crash" },
            actions = {
                { input="up", from=time_to_ms(1, 343), to=time_to_ms(2, 163), nextsequence="rapids_crash" },
                { input="up", from=time_to_ms(2, 163), to=time_to_ms(2, 785), nextsequence="first_whirlpools", points=495 },
                { input="right", from=time_to_ms(1, 606), to=time_to_ms(2, 818), nextsequence="rapids_crash" },
                { input="left", from=time_to_ms(1, 343), to=time_to_ms(2, 163), nextsequence="first_whirlpools", points=495 },
                { input="left", from=time_to_ms(2, 163), to=time_to_ms(2, 785), nextsequence="rapids_crash" },
            }
        },

        first_whirlpools = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(5, 505), nextsequence="whirlpools_crash" },
            actions = {
                -- !!! FIXME: The ROM has an "UpRight" entry that matches "Right" for success, but "Up" has the same timing and is a fail!
                { input="right", from=time_to_ms(3, 834), to=time_to_ms(5, 472), nextsequence="second_whirlpools", points=251 },
                { input="up", from=time_to_ms(3, 834), to=time_to_ms(5, 472), nextsequence="whirlpools_crash" },
                { input="left", from=time_to_ms(3, 834), to=time_to_ms(5, 472), nextsequence="whirlpools_crash" },
            }
        },

        second_whirlpools = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 720), nextsequence="whirlpools_crash" },
            actions = {
                -- !!! FIXME: The ROM has an "UpLeft" entry that matches "Left" for success, but "Up" has the same timing and is a fail!
                { input="left", from=time_to_ms(1, 409), to=time_to_ms(2, 720), nextsequence="third_whirlpools", points=251 },
                { input="up", from=time_to_ms(1, 409), to=time_to_ms(2, 720), nextsequence="whirlpools_crash" },
                { input="right", from=time_to_ms(1, 409), to=time_to_ms(2, 720), nextsequence="whirlpools_crash" },
            }
        },

        third_whirlpools = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 490), nextsequence="whirlpools_crash" },
            actions = {
                -- !!! FIXME: The ROM has an "UpRight" entry that matches "Right" for success, but "Up" has the same timing and is a fail!
                { input="right", from=time_to_ms(1, 343), to=time_to_ms(2, 490), nextsequence="fourth_whirlpools", points=251 },
                { input="up", from=time_to_ms(1, 343), to=time_to_ms(2, 490), nextsequence="whirlpools_crash" },
                { input="left", from=time_to_ms(1, 343), to=time_to_ms(2, 490), nextsequence="whirlpools_crash" },
            }
        },

        fourth_whirlpools = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 720), nextsequence="whirlpools_crash" },
            actions = {
                -- !!! FIXME: The ROM has an "UpLeft" entry that matches "Left" for success, but "Up" has the same timing and is a fail!
                { input="left", from=time_to_ms(1, 442), to=time_to_ms(2, 720), nextsequence="bounce_to_chain", points=251 },
                { input="up", from=time_to_ms(1, 442), to=time_to_ms(2, 720), nextsequence="whirlpools_crash" },
                { input="right", from=time_to_ms(1, 442), to=time_to_ms(2, 720), nextsequence="whirlpools_crash" },
            }
        },

        bounce_to_chain = {  -- player bounces out of boat, to a chain he must grab
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(5, 177), nextsequence="miss_chain" },
            actions = {
                -- The ROM has an "UpRight" entry that matches "Right"  and "Up", so we're okay here
                { input="up", from=time_to_ms(3, 867), to=time_to_ms(5, 145), nextsequence="exit_room", points=495 },
                { input="down", from=time_to_ms(3, 867), to=time_to_ms(5, 145), nextsequence="miss_chain" },
                { input="right", from=time_to_ms(3, 867), to=time_to_ms(5, 145), nextsequence="exit_room", points=495 },
                { input="left", from=time_to_ms(3, 867), to=time_to_ms(5, 145), nextsequence="miss_chain" },
            }
        },

        exit_room = {  -- player heads for the door
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(3, 65), nextsequence=nil },
        },

        boulders_crash = {
            start_time = time_laserdisc_frame(23938),
            kills_player = true,
            timeout = { when=time_to_ms(1, 0), nextsequence=nil }
        },

        boulders_crash2 = {
            start_time = time_laserdisc_frame(23962),
            kills_player = true,
            timeout = { when=time_to_ms(0, 541), nextsequence=nil }
        },

        boulders_crash3 = {
            start_time = time_laserdisc_frame(23986),
            kills_player = true,
            timeout = { when=time_to_ms(1, 542), nextsequence=nil }
        },

        boulders_crash4 = {
            start_time = time_laserdisc_frame(24010),
            kills_player = true,
            timeout = { when=time_to_ms(0, 541), nextsequence=nil }
        },

        rapids_crash = {
            start_time = time_laserdisc_frame(24034),
            kills_player = true,
            timeout = { when=time_to_ms(2, 376), nextsequence=nil }
        },

        whirlpools_crash = {
            start_time = time_laserdisc_frame(24094),
            kills_player = true,
            timeout = { when=time_to_ms(2, 668), nextsequence=nil }
        },

        miss_chain = {
            start_time = time_laserdisc_frame(24187),
            kills_player = true,
            timeout = { when=time_to_ms(2, 1), nextsequence=nil }
        },
    },

    rolling_balls = {
        game_over = {
            start_time = time_laserdisc_frame(26638),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(26042),
            timeout = { when=time_to_ms(2, 334), nextsequence="enter_room", points = 49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
        },

        enter_room = {  -- Player has reached the yellow segment of the tunnel, big black balls starts chasing
            start_time = time_laserdisc_frame(26098) + laserdisc_frame_to_ms(1),
            timeout = { when=time_to_ms(5, 964), nextsequence="big_ball_crushes" },
            actions = {
                { input="down", from=time_to_ms(4, 882), to=time_to_ms(5, 145), nextsequence="small_ball_crushes" },
                { input="down", from=time_to_ms(5, 145), to=time_to_ms(5, 931), nextsequence="red_ball", points=251 },
                { input="up", from=time_to_ms(5, 177), to=time_to_ms(5, 964), nextsequence="big_ball_crushes" },
            }
        },

        red_ball = { -- Player has reached the red segment of the tunnel
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 868), nextsequence="big_ball_crushes" },
            actions = {
                { input="down", from=time_to_ms(0, 852), to=time_to_ms(1, 81), nextsequence="small_ball_crushes" },
                { input="down", from=time_to_ms(1, 81), to=time_to_ms(1, 835), nextsequence="blue_ball", points=379 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 868), nextsequence="big_ball_crushes" },
            }
        },

        blue_ball = {  -- Player has reached the blue segment of the tunnel
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 966), nextsequence="big_ball_crushes" },
            actions = {
                { input="down", from=time_to_ms(0, 885), to=time_to_ms(1, 212), nextsequence="small_ball_crushes" },
                { input="down", from=time_to_ms(1, 212), to=time_to_ms(1, 933), nextsequence="green_ball", points=379 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 966), nextsequence="big_ball_crushes" },
            }
        },

        green_ball = {  -- Player has reached the green segment of the tunnel
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 966), nextsequence="big_ball_crushes" },
            actions = {
                { input="down", from=time_to_ms(0, 885), to=time_to_ms(1, 147), nextsequence="small_ball_crushes" },
                { input="down", from=time_to_ms(1, 147), to=time_to_ms(1, 933), nextsequence="orange_ball", points=379 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 966), nextsequence="big_ball_crushes" },
            }
        },

        orange_ball = {  -- Player has reached the orange segment of the tunnel
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 966), nextsequence="big_ball_crushes" },
            actions = {
                { input="down", from=time_to_ms(0, 885), to=time_to_ms(1, 147), nextsequence="small_ball_crushes" },
                { input="down", from=time_to_ms(1, 147), to=time_to_ms(1, 933), nextsequence="purple_ball", points=379 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 966), nextsequence="big_ball_crushes" },
            }
        },

        purple_ball = {  -- Player has reached the purple segment of the tunnel
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 901), nextsequence="big_ball_crushes" },
            actions = {
                { input="down", from=time_to_ms(0, 885), to=time_to_ms(1, 114), nextsequence="small_ball_crushes" },
                { input="down", from=time_to_ms(1, 114), to=time_to_ms(1, 868), nextsequence="pit_in_ground", points=379 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 901), nextsequence="big_ball_crushes" },
            }
        },

        pit_in_ground = {  -- There's a hole in the ground at the end of the tunnel! Jump it!
            -- !!! FIXME: RomSpinner reported bogus data for this, so check these timings.
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 901), nextsequence="big_ball_crushes" },
            actions = {
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 414), nextsequence="exit_room", points=379 },
            }
        },

        exit_room = {  -- player heads for the door
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 320), nextsequence=nil },
        },

        small_ball_crushes = {  -- player gets sideswiped by a smaller, colorful ball
            start_time = time_laserdisc_frame(26613),
            kills_player = true,
            timeout = { when=time_to_ms(1, 41), nextsequence=nil }
        },

        big_ball_crushes = {  -- player gets bowled over by the big black ball
            start_time = time_laserdisc_frame(26596),
            kills_player = true,
            timeout = { when=time_to_ms(0, 749), nextsequence=nil }
        },
    },

    black_knight = {
        game_over = {
            start_time = time_laserdisc_frame(25956),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(25480),
            timeout = { when=time_to_ms(2, 42), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(25536),
            timeout = { when=time_to_ms(3, 539), nextsequence="seq7" },
            actions = {
                { input="left", from=time_to_ms(2, 687), to=time_to_ms(3, 506), nextsequence="seq3", points=1939 },
                { input="right", from=time_to_ms(3, 146), to=time_to_ms(3, 539), nextsequence="seq6" },
                { input="up", from=time_to_ms(2, 687), to=time_to_ms(3, 572), nextsequence="seq7" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(25536),
            timeout = { when=time_to_ms(3, 539), nextsequence="seq7" },
            actions = {
                { input="left", from=time_to_ms(2, 687), to=time_to_ms(3, 506), nextsequence="seq3", points=1939 },
                { input="right", from=time_to_ms(3, 146), to=time_to_ms(3, 539), nextsequence="seq6" },
                { input="up", from=time_to_ms(2, 687), to=time_to_ms(3, 572), nextsequence="seq7" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(3, 867), nextsequence="seq9" },
            actions = {
                { input="left", from=time_to_ms(3, 113), to=time_to_ms(3, 867), nextsequence="seq4", points=1939 },
                { input="up", from=time_to_ms(3, 113), to=time_to_ms(3, 801), nextsequence="seq9" },
                { input="right", from=time_to_ms(3, 473), to=time_to_ms(6, 849), nextsequence="seq6" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(3, 244), nextsequence="seq9" },
            actions = {
                { input="right", from=time_to_ms(2, 458), to=time_to_ms(3, 211), nextsequence="seq5", points=2675 },
                { input="left", from=time_to_ms(2, 458), to=time_to_ms(3, 178), nextsequence="seq6" },
                { input="up", from=time_to_ms(2, 458), to=time_to_ms(3, 178), nextsequence="seq9" },
                { input="down", from=time_to_ms(1, 966), to=time_to_ms(2, 687), nextsequence="seq6" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 445), nextsequence=nil }
        },

        seq6 = {
            start_time = time_laserdisc_frame(25850),
            kills_player = true,
            timeout = { when=time_to_ms(1, 417), nextsequence=nil }
        },

        seq7 = {
            start_time = time_laserdisc_frame(25898),
            kills_player = true,
            timeout = { when=time_to_ms(2, 376), nextsequence=nil }
        },

        seq9 = {
            start_time = time_laserdisc_frame(25918),
            kills_player = true,
            timeout = { when=time_to_ms(1, 542), nextsequence=nil }
        },
    },

    bubbling_cauldron = {
        game_over = {
            start_time = time_laserdisc_frame(5541),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(5067),
            timeout = { when=time_to_ms(2, 84), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(5123),
            timeout = { when=time_to_ms(2, 753), nextsequence="seq9" },
            actions = {
                { input="up", from=time_to_ms(1, 966), to=time_to_ms(2, 720), nextsequence="seq3", points=2191 },
                { input="down", from=time_to_ms(1, 966), to=time_to_ms(2, 720), nextsequence="seq9" },
                { input="right", from=time_to_ms(1, 966), to=time_to_ms(2, 720), nextsequence="seq9" },
                { input="left", from=time_to_ms(1, 966), to=time_to_ms(2, 720), nextsequence="seq9" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(5123),
            timeout = { when=time_to_ms(2, 753), nextsequence="seq9" },
            actions = {
                { input="up", from=time_to_ms(1, 966), to=time_to_ms(2, 720), nextsequence="seq3", points=2191 },
                { input="down", from=time_to_ms(1, 966), to=time_to_ms(2, 720), nextsequence="seq9" },
                { input="right", from=time_to_ms(1, 966), to=time_to_ms(2, 720), nextsequence="seq9" },
                { input="left", from=time_to_ms(1, 966), to=time_to_ms(2, 720), nextsequence="seq9" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 523), nextsequence="seq8" },
            actions = {
                { input="action", from=time_to_ms(1, 638), to=time_to_ms(2, 490), nextsequence="seq4", points=3255 },
                { input="up", from=time_to_ms(1, 638), to=time_to_ms(2, 490), nextsequence="seq8" },
                { input="down", from=time_to_ms(1, 638), to=time_to_ms(2, 490), nextsequence="seq9" },
                { input="right", from=time_to_ms(1, 835), to=time_to_ms(2, 720), nextsequence="seq9" },
                { input="left", from=time_to_ms(1, 638), to=time_to_ms(2, 490), nextsequence="seq8" },
                { input="left", from=time_to_ms(1, 638), to=time_to_ms(2, 490), nextsequence="seq8" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 409), nextsequence="seq9" },
            actions = {
                { input="down", from=time_to_ms(0, 557), to=time_to_ms(1, 376), nextsequence="seq5", points=3255 },
                { input="downright", from=time_to_ms(0, 557), to=time_to_ms(1, 376), nextsequence="seq5", points=3255 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 409), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 409), nextsequence="seq9" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 409), nextsequence="seq9" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 737), nextsequence="seq10" },
            actions = {
                { input="action", from=time_to_ms(0, 655), to=time_to_ms(1, 737), nextsequence="seq6", points=2191 },
                { input="up", from=time_to_ms(0, 655), to=time_to_ms(1, 737), nextsequence="seq10" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(0, 262), nextsequence="seq10" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 737), nextsequence="seq9" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 949), nextsequence="seq9" },
            actions = {
                { input="right", from=time_to_ms(1, 802), to=time_to_ms(2, 916), nextsequence="seq7", points=1326 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 949), nextsequence="seq9" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 949), nextsequence="seq9" },
            }
        },

        seq7 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 140), nextsequence=nil }
        },

        seq8 = {
            start_time = time_laserdisc_frame(5423),
            kills_player = true,
            timeout = { when=time_to_ms(1, 417), nextsequence=nil }
        },

        seq9 = {
            start_time = time_laserdisc_frame(5459),
            kills_player = true,
            timeout = { when=time_to_ms(1, 417), nextsequence=nil }
        },

        seq10 = {
            start_time = time_laserdisc_frame(5513),
            kills_player = true,
            timeout = { when=time_to_ms(1, 125), nextsequence=nil }
        },

    },

    catwalk_bats = {
        game_over = {
            start_time = time_laserdisc_frame(12586),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(12133),
            timeout = { when=time_to_ms(2, 42), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(12190),
            timeout = { when=time_to_ms(2, 687), nextsequence="seq9" },
            actions = {
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 687), nextsequence="seq3", points=915 },
                { input="down", from=time_to_ms(2, 64), to=time_to_ms(2, 687), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 687), nextsequence="seq9" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(12190),
            timeout = { when=time_to_ms(2, 687), nextsequence="seq9" },
            actions = {
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 687), nextsequence="seq3", points=915 },
                { input="down", from=time_to_ms(2, 64), to=time_to_ms(2, 687), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 687), nextsequence="seq9" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 147), nextsequence="seq9" },
            actions = {
                { input="upleft", from=time_to_ms(0, 0), to=time_to_ms(1, 147), nextsequence="seq4", points=915 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 147), nextsequence="seq4", points=915 },
                { input="left", from=time_to_ms(0, 950), to=time_to_ms(2, 97), nextsequence="seq4", points=915 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 147), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 147), nextsequence="seq9" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 490), nextsequence="seq8" },
            actions = {
                { input="action", from=time_to_ms(1, 737), to=time_to_ms(2, 458), nextsequence="seq5", points=2675 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 490), nextsequence="seq9" },
                { input="up", from=time_to_ms(1, 737), to=time_to_ms(2, 458), nextsequence="seq8" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(0, 360), nextsequence="seq9" },
                { input="left", from=time_to_ms(0, 328), to=time_to_ms(2, 785), nextsequence="seq9" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 475), nextsequence="seq9" },
            actions = {
                { input="right", from=time_to_ms(0, 360), to=time_to_ms(1, 442), nextsequence="seq6", points=915 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 49), nextsequence="seq9" },
                { input="upright", from=time_to_ms(0, 360), to=time_to_ms(1, 409), nextsequence="seq6", points=915 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 442), nextsequence="seq9" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 147), nextsequence="seq9" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 212), nextsequence="seq9" },
            actions = {
                { input="right", from=time_to_ms(0, 885), to=time_to_ms(1, 442), nextsequence="seq7", points=3551 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 475), nextsequence="seq9" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 475), nextsequence="seq9" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 475), nextsequence="seq9" },
            }
        },

        seq7 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 958), nextsequence=nil }
        },

        seq8 = {
            start_time = time_laserdisc_frame(12537),
            kills_player = true,
            timeout = { when=time_to_ms(2, 42), nextsequence=nil }
        },

        seq9 = {
            start_time = time_laserdisc_frame(12477),
            kills_player = true,
            timeout = { when=time_to_ms(2, 501), nextsequence=nil }
        },
    },

    crypt_creeps_reversed = {
        game_over = {
            start_time = time_laserdisc_frame(19223),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(18606),
            timeout = { when=time_to_ms(2, 334), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(18662),
            timeout = { when=time_to_ms(3, 473), nextsequence="seq10" },
            actions = {
                { input="up", from=time_to_ms(2, 458), to=time_to_ms(3, 473), nextsequence="seq3", points=495 },
                { input="action", from=time_to_ms(2, 458), to=time_to_ms(3, 408), nextsequence="seq9" },
                { input="down", from=time_to_ms(2, 458), to=time_to_ms(3, 408), nextsequence="seq10" },
                { input="right", from=time_to_ms(2, 458), to=time_to_ms(3, 408), nextsequence="seq10" },
                { input="left", from=time_to_ms(2, 458), to=time_to_ms(3, 408), nextsequence="seq10" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(18662),
            timeout = { when=time_to_ms(3, 473), nextsequence="seq10" },
            actions = {
                { input="up", from=time_to_ms(2, 458), to=time_to_ms(3, 473), nextsequence="seq3", points=495 },
                { input="action", from=time_to_ms(2, 458), to=time_to_ms(3, 408), nextsequence="seq9" },
                { input="down", from=time_to_ms(2, 458), to=time_to_ms(3, 408), nextsequence="seq10" },
                { input="right", from=time_to_ms(2, 458), to=time_to_ms(3, 408), nextsequence="seq10" },
                { input="left", from=time_to_ms(2, 458), to=time_to_ms(3, 408), nextsequence="seq10" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(0, 918), nextsequence="seq11" },
            actions = {
                { input="action", from=time_to_ms(0, 492), to=time_to_ms(0, 918), nextsequence="seq4", points=2191 },
                { input="up", from=time_to_ms(0, 557), to=time_to_ms(0, 918), nextsequence="seq11" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 278), nextsequence="seq10" },
                { input="right", from=time_to_ms(0, 492), to=time_to_ms(0, 918), nextsequence="seq11" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 228), nextsequence="seq12" },
            actions = {
                { input="up", from=time_to_ms(1, 147), to=time_to_ms(2, 228), nextsequence="seq5", points=495 },
                { input="down", from=time_to_ms(1, 147), to=time_to_ms(2, 261), nextsequence="seq10" },
                { input="right", from=time_to_ms(1, 147), to=time_to_ms(2, 228), nextsequence="seq12" },
                { input="left", from=time_to_ms(1, 147), to=time_to_ms(2, 228), nextsequence="seq12" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 147), nextsequence="seq11" },
            actions = {
                { input="action", from=time_to_ms(0, 688), to=time_to_ms(1, 114), nextsequence="seq6", points=2191 },
                { input="up", from=time_to_ms(0, 688), to=time_to_ms(1, 114), nextsequence="seq11" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 180), nextsequence="seq12" },
                { input="left", from=time_to_ms(0, 688), to=time_to_ms(1, 114), nextsequence="seq11" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 835), nextsequence="seq12" },
            actions = {
                { input="right", from=time_to_ms(0, 492), to=time_to_ms(1, 835), nextsequence="seq7", points=495 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="seq12" },
                { input="left", from=time_to_ms(0, 492), to=time_to_ms(2, 327), nextsequence="seq12" },
            }
        },

        seq7 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 835), nextsequence="seq13" },
            actions = {
                { input="action", from=time_to_ms(0, 754), to=time_to_ms(1, 835), nextsequence="seq8", points=495 },
                { input="right", from=time_to_ms(0, 754), to=time_to_ms(1, 835), nextsequence="seq13" },
                { input="left", from=time_to_ms(0, 754), to=time_to_ms(1, 835), nextsequence="seq13" },
                { input="down", from=time_to_ms(0, 754), to=time_to_ms(1, 835), nextsequence="seq13" },
            }
        },

        seq8 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(4, 453), nextsequence=nil }
        },

        seq9 = {
            start_time = time_laserdisc_frame(19054),
            kills_player = true,
            timeout = { when=time_to_ms(1, 83) + laserdisc_frame_to_ms(10), nextsequence=nil }
        },

        seq10 = {
            start_time = time_laserdisc_frame(19077),
            kills_player = true,
            timeout = { when=time_to_ms(0, 124) + laserdisc_frame_to_ms(10), nextsequence=nil }
        },

        seq11 = {
            start_time = time_laserdisc_frame(19090),
            kills_player = true,
            timeout = { when=time_to_ms(0, 582), nextsequence=nil }
        },

        seq12 = {
            start_time = time_laserdisc_frame(19114),
            kills_player = true,
            timeout = { when=time_to_ms(1, 333), nextsequence=nil }
        },

        seq13 = {
            start_time = time_laserdisc_frame(19150),
            kills_player = true,
            timeout = { when=time_to_ms(2, 543), nextsequence=nil }
        },
    },

    electric_cage_and_geyser = {
        game_over = {
            start_time = time_laserdisc_frame(27158),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(26723),
            timeout = { when=time_to_ms(2, 292), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(26778),
            timeout = { when=time_to_ms(2, 916), nextsequence="seq7" },
            actions = {
                { input="up", from=time_to_ms(0, 557), to=time_to_ms(2, 916), nextsequence="seq3", points=915 },
                { input="down", from=time_to_ms(2, 490), to=time_to_ms(2, 916), nextsequence="seq7" },
                { input="right", from=time_to_ms(2, 327), to=time_to_ms(2, 916), nextsequence="seq7" },
                { input="left", from=time_to_ms(2, 327), to=time_to_ms(2, 916), nextsequence="seq7" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(26778),
            timeout = { when=time_to_ms(2, 916), nextsequence="seq7" },
            actions = {
                { input="up", from=time_to_ms(0, 557), to=time_to_ms(2, 916), nextsequence="seq3", points=915 },
                { input="down", from=time_to_ms(2, 490), to=time_to_ms(2, 916), nextsequence="seq7" },
                { input="right", from=time_to_ms(2, 327), to=time_to_ms(2, 916), nextsequence="seq7" },
                { input="left", from=time_to_ms(2, 327), to=time_to_ms(2, 916), nextsequence="seq7" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 507), nextsequence="seq7" },
            actions = {
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(0, 393), nextsequence="seq4", points=1326 },
                { input="up", from=time_to_ms(0, 393), to=time_to_ms(0, 623), nextsequence="seq6" },
                { input="up", from=time_to_ms(0, 623), to=time_to_ms(1, 49), nextsequence="seq4", points=1326 },
                { input="up", from=time_to_ms(1, 81), to=time_to_ms(1, 311), nextsequence="seq6" },
                { input="up", from=time_to_ms(1, 311), to=time_to_ms(1, 769), nextsequence="seq4", points=1326 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 769), nextsequence="seq7" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 769), nextsequence="seq7" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 769), nextsequence="seq7" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_frame(26893),
            timeout = { when=time_to_ms(5, 374), nextsequence="seq8" },
            actions = {
                { input="left", from=time_to_ms(3, 113), to=time_to_ms(3, 506), nextsequence="seq5", points=2191 },
                { input="left", from=time_to_ms(3, 506), to=time_to_ms(3, 998), nextsequence="seq8" },
                { input="left", from=time_to_ms(3, 998), to=time_to_ms(4, 391), nextsequence="seq5", points=2191 },
                { input="left", from=time_to_ms(4, 424), to=time_to_ms(4, 915), nextsequence="seq8" },
                { input="left", from=time_to_ms(4, 915), to=time_to_ms(5, 341), nextsequence="seq5", points=2191 },
                { input="right", from=time_to_ms(1, 933), to=time_to_ms(5, 341), nextsequence="seq7" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_frame(27025),
            timeout = { when=time_to_ms(0, 714), nextsequence=nil }
        },

        seq6 = {
            start_time = time_laserdisc_frame(27050),
            kills_player = true,
            timeout = { when=time_to_ms(1, 500), nextsequence=nil }
        },

        seq7 = {
            start_time = time_laserdisc_frame(27085),
            kills_player = true,
            timeout = { when=time_to_ms(1, 542), nextsequence=nil }
        },

        seq8 = {
            start_time = time_laserdisc_frame(27122),
            kills_player = true,
            timeout = { when=time_to_ms(1, 500), nextsequence=nil }
        },
    },

    falling_platform_long_reversed = {
        game_over = {
            start_time = time_laserdisc_frame(22588),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(21904),
            timeout = { when=time_to_ms(2, 334), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(21959),
            timeout = { when=time_to_ms(9, 241), nextsequence="seq3", points=124 },
            actions = {
                { input="right", from=time_to_ms(2, 785), to=time_to_ms(5, 14), nextsequence="seq6" },
                { input="right", from=time_to_ms(5, 14), to=time_to_ms(5, 341), nextsequence="seq7", points=3255 },
                { input="right", from=time_to_ms(5, 374), to=time_to_ms(5, 702), nextsequence="seq8" },
                { input="right", from=time_to_ms(5, 702), to=time_to_ms(6, 29), nextsequence="seq7", points=3255 },
                { input="right", from=time_to_ms(6, 29), to=time_to_ms(6, 357), nextsequence="seq8" },
                { input="right", from=time_to_ms(6, 390), to=time_to_ms(6, 717), nextsequence="seq7", points=3255 },
                { input="right", from=time_to_ms(6, 717), to=time_to_ms(9, 208), nextsequence="seq6" },
                { input="left", from=time_to_ms(2, 785), to=time_to_ms(4, 915), nextsequence="seq6" },
                { input="left", from=time_to_ms(4, 915), to=time_to_ms(6, 750), nextsequence="seq8" },
                { input="left", from=time_to_ms(6, 783), to=time_to_ms(9, 208), nextsequence="seq6" },
                { input="up", from=time_to_ms(2, 785), to=time_to_ms(4, 915), nextsequence="seq6" },
                { input="up", from=time_to_ms(4, 915), to=time_to_ms(6, 750), nextsequence="seq8" },
                { input="up", from=time_to_ms(6, 783), to=time_to_ms(9, 208), nextsequence="seq6" },
                { input="down", from=time_to_ms(2, 785), to=time_to_ms(4, 915), nextsequence="seq6" },
                { input="down", from=time_to_ms(4, 915), to=time_to_ms(6, 750), nextsequence="seq8" },
                { input="down", from=time_to_ms(6, 783), to=time_to_ms(9, 208), nextsequence="seq6" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(21959),
            timeout = { when=time_to_ms(9, 241), nextsequence="seq3", points=124 },
            actions = {
                { input="right", from=time_to_ms(2, 785), to=time_to_ms(5, 14), nextsequence="seq6" },
                { input="right", from=time_to_ms(5, 14), to=time_to_ms(5, 341), nextsequence="seq7", points=3255 },
                { input="right", from=time_to_ms(5, 374), to=time_to_ms(5, 702), nextsequence="seq8" },
                { input="right", from=time_to_ms(5, 702), to=time_to_ms(6, 29), nextsequence="seq7", points=3255 },
                { input="right", from=time_to_ms(6, 29), to=time_to_ms(6, 357), nextsequence="seq8" },
                { input="right", from=time_to_ms(6, 390), to=time_to_ms(6, 717), nextsequence="seq7", points=3255 },
                { input="right", from=time_to_ms(6, 717), to=time_to_ms(9, 208), nextsequence="seq6" },
                { input="left", from=time_to_ms(2, 785), to=time_to_ms(4, 915), nextsequence="seq6" },
                { input="left", from=time_to_ms(4, 915), to=time_to_ms(6, 750), nextsequence="seq8" },
                { input="left", from=time_to_ms(6, 783), to=time_to_ms(9, 208), nextsequence="seq6" },
                { input="up", from=time_to_ms(2, 785), to=time_to_ms(4, 915), nextsequence="seq6" },
                { input="up", from=time_to_ms(4, 915), to=time_to_ms(6, 750), nextsequence="seq8" },
                { input="up", from=time_to_ms(6, 783), to=time_to_ms(9, 208), nextsequence="seq6" },
                { input="down", from=time_to_ms(2, 785), to=time_to_ms(4, 915), nextsequence="seq6" },
                { input="down", from=time_to_ms(4, 915), to=time_to_ms(6, 750), nextsequence="seq8" },
                { input="down", from=time_to_ms(6, 783), to=time_to_ms(9, 208), nextsequence="seq6" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 802), nextsequence="seq4", points=2191 },
            actions = {
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(0, 360), nextsequence="seq7", points=3255 },
                { input="left", from=time_to_ms(0, 360), to=time_to_ms(0, 688), nextsequence="seq8" },
                { input="left", from=time_to_ms(0, 688), to=time_to_ms(1, 16), nextsequence="seq7", points=3255 },
                { input="left", from=time_to_ms(1, 49), to=time_to_ms(1, 376), nextsequence="seq8" },
                { input="left", from=time_to_ms(1, 376), to=time_to_ms(1, 704), nextsequence="seq7", points=3255 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 802), nextsequence="seq8" },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 802), nextsequence="seq8" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 802), nextsequence="seq8" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(5, 702), nextsequence="seq5" },
            actions = {
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 523), nextsequence="seq6" },
                { input="right", from=time_to_ms(2, 523), to=time_to_ms(2, 851), nextsequence="seq7", points=3255 },
                { input="right", from=time_to_ms(2, 851), to=time_to_ms(3, 178), nextsequence="seq8" },
                { input="right", from=time_to_ms(3, 211), to=time_to_ms(3, 539), nextsequence="seq7", points=3255 },
                { input="right", from=time_to_ms(3, 539), to=time_to_ms(3, 867), nextsequence="seq8" },
                { input="right", from=time_to_ms(3, 867), to=time_to_ms(4, 194), nextsequence="seq7", points=3255 },
                { input="right", from=time_to_ms(4, 227), to=time_to_ms(4, 719), nextsequence="seq8" },
                { input="right", from=time_to_ms(4, 719), to=time_to_ms(5, 669), nextsequence="seq6" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 949), nextsequence="seq6" },
                { input="left", from=time_to_ms(2, 949), to=time_to_ms(4, 719), nextsequence="seq8" },
                { input="left", from=time_to_ms(4, 719), to=time_to_ms(5, 636), nextsequence="seq6" },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 949), nextsequence="seq6" },
                { input="up", from=time_to_ms(2, 949), to=time_to_ms(4, 719), nextsequence="seq8" },
                { input="up", from=time_to_ms(4, 719), to=time_to_ms(5, 636), nextsequence="seq6" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 949), nextsequence="seq6" },
                { input="down", from=time_to_ms(2, 949), to=time_to_ms(4, 719), nextsequence="seq8" },
                { input="down", from=time_to_ms(4, 719), to=time_to_ms(5, 636), nextsequence="seq6" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            kills_player = true,
            timeout = { when=time_to_ms(1, 671), nextsequence=nil }
        },

        seq6 = {
            start_time = time_laserdisc_frame(22450),
            kills_player = true,
            timeout = { when=time_to_ms(0, 819), nextsequence=nil }
        },

        seq7 = {
            start_time = time_laserdisc_frame(22478),
            timeout = { when=time_to_ms(4, 653) + laserdisc_frame_to_ms(10), nextsequence=nil },
        },

        seq8 = {
            start_time = time_laserdisc_frame(22418),
            kills_player = true,
            timeout = { when=time_to_ms(1, 41), nextsequence="seq6" }
        },

    },

    flaming_ropes_reversed = {
        game_over = {
            start_time = time_laserdisc_frame(13164),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(12669),
            timeout = { when=time_to_ms(2, 84), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(12725),
            timeout = { when=time_to_ms(2, 523), nextsequence="seq10" },
            actions = {
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 245), nextsequence="seq9" },
                { input="left", from=time_to_ms(1, 245), to=time_to_ms(2, 130), nextsequence="seq3", points=379 },
                { input="left", from=time_to_ms(2, 130), to=time_to_ms(4, 260), nextsequence="seq9" },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 490), nextsequence="seq9" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 490), nextsequence="seq9" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(12725),
            timeout = { when=time_to_ms(2, 523), nextsequence="seq10" },
            actions = {
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 245), nextsequence="seq9" },
                { input="left", from=time_to_ms(1, 245), to=time_to_ms(2, 130), nextsequence="seq3", points=379 },
                { input="left", from=time_to_ms(2, 130), to=time_to_ms(4, 260), nextsequence="seq9" },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 490), nextsequence="seq9" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 490), nextsequence="seq9" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_frame(12857),
            timeout = { when=time_to_ms(1, 583), nextsequence="seq8" },
            actions = {
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 114), nextsequence="seq9" },
                { input="left", from=time_to_ms(1, 114), to=time_to_ms(1, 835), nextsequence="seq4", points=495 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="seq9" },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="seq9" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="seq9" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 573), nextsequence="seq8" },
            actions = {
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 81), nextsequence="seq9" },
                { input="left", from=time_to_ms(1, 81), to=time_to_ms(1, 835), nextsequence="seq5", points=0 },  -- I assume this is a bug in the original ROM, but this correct move gets you no points!
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="seq9" },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="seq9" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="seq9" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 501), nextsequence="seq7" },
            actions = {
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(0, 852), nextsequence="seq9" },
                { input="left", from=time_to_ms(0, 852), to=time_to_ms(1, 704), nextsequence="seq6", points=0 },  -- I assume this is a bug in the original ROM, but this correct move gets you no points!
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 737), nextsequence="seq9" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 737), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 737), nextsequence="seq9" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 57), nextsequence=nil }
        },

        seq7 = {
            start_time = time_laserdisc_frame(13041),
            kills_player = true,
            timeout = { when=time_to_ms(2, 42), nextsequence=nil }
        },

        seq8 = {
            start_time = time_laserdisc_frame(13089),
            kills_player = true,
            timeout = { when=time_to_ms(3, 85), nextsequence=nil }
        },

        seq9 = {
            start_time = time_laserdisc_frame(13127),
            kills_player = true,
            timeout = { when=time_to_ms(1, 500), nextsequence=nil }
        },

        seq10 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 621), nextsequence="seq9" },
            actions = {
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="seq9" },
                { input="left", from=time_to_ms(1, 835), to=time_to_ms(2, 884), nextsequence="seq3", points=379 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 884), nextsequence="seq9" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 884), nextsequence="seq9" },
            }
        },

    },

    flattening_staircase = {
        game_over = {
            start_time = time_laserdisc_frame(6825),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(6283),
            timeout = { when=time_to_ms(2, 334), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(6375),
            timeout = { when=time_to_ms(2, 425), nextsequence="seq7" },
            actions = {
                { input="left", from=time_to_ms(2, 32), to=time_to_ms(2, 753), nextsequence="seq3", points=495 },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(6375),
            timeout = { when=time_to_ms(2, 425), nextsequence="seq7" },
            actions = {
                { input="left", from=time_to_ms(2, 32), to=time_to_ms(2, 753), nextsequence="seq3", points=495 },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 228), nextsequence="seq8" },
            actions = {
                { input="action", from=time_to_ms(1, 475), to=time_to_ms(2, 195), nextsequence="seq4", points=1939 },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 507), nextsequence="seq5", points=915 },
            actions = {
                { input="left", from=time_to_ms(0, 754), to=time_to_ms(1, 475), nextsequence="seq5", points=915 },
                { input="upleft", from=time_to_ms(0, 754), to=time_to_ms(1, 475), nextsequence="seq5", points=915 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 507), nextsequence="seq8" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 507), nextsequence="seq8" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(3, 211), nextsequence="seq7" },
            actions = {
                { input="left", from=time_to_ms(1, 966), to=time_to_ms(3, 178), nextsequence="seq6", points=1326 },
                { input="right", from=time_to_ms(1, 966), to=time_to_ms(3, 178), nextsequence="seq9" },
                { input="up", from=time_to_ms(1, 966), to=time_to_ms(3, 178), nextsequence="seq9" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 278), nextsequence="seq11" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 14), nextsequence=nil }
        },

        seq7 = {
            start_time = time_laserdisc_frame(6647),
            kills_player = true,
            timeout = { when=time_to_ms(2, 42), nextsequence=nil }
        },

        seq8 = {
            start_time = time_laserdisc_frame(6695),
            kills_player = true,
            timeout = { when=time_to_ms(1, 166), nextsequence=nil }
        },

        seq9 = {
            start_time = time_laserdisc_frame(6731),
            kills_player = true,
            timeout = { when=time_to_ms(4, 44), nextsequence=nil }
        },

        -- !!! FIXME: this was corrupt data in RomSpinner, go figure this one out.
        seq11 = {
            start_time = time_laserdisc_frame(6731),
            kills_player = true,
            timeout = { when=time_to_ms(4, 44), nextsequence=nil }
        },

    },

    flying_horse_reversed = {
        game_over = {
            start_time = time_laserdisc_frame(17124),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(16488),
            timeout = { when=time_to_ms(2, 209), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(16544),
            timeout = { when=time_to_ms(4, 522), nextsequence="seq9" },
            actions = {
                { input="upleft", from=time_to_ms(3, 441), to=time_to_ms(3, 768), nextsequence="seq9" },
                { input="upleft", from=time_to_ms(3, 768), to=time_to_ms(4, 489), nextsequence="seq3", points=915 },
                { input="left", from=time_to_ms(3, 441), to=time_to_ms(3, 768), nextsequence="seq9" },
                { input="left", from=time_to_ms(3, 768), to=time_to_ms(4, 489), nextsequence="seq3", points=915 },
                { input="up", from=time_to_ms(3, 801), to=time_to_ms(4, 489), nextsequence="seq9" },
                { input="right", from=time_to_ms(3, 441), to=time_to_ms(3, 768), nextsequence="seq9" },
                { input="right", from=time_to_ms(3, 768), to=time_to_ms(4, 456), nextsequence="seq11" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(16544),
            timeout = { when=time_to_ms(4, 522), nextsequence="seq9" },
            actions = {
                { input="upleft", from=time_to_ms(3, 441), to=time_to_ms(3, 768), nextsequence="seq9" },
                { input="upleft", from=time_to_ms(3, 768), to=time_to_ms(4, 489), nextsequence="seq3", points=915 },
                { input="left", from=time_to_ms(3, 441), to=time_to_ms(3, 768), nextsequence="seq9" },
                { input="left", from=time_to_ms(3, 768), to=time_to_ms(4, 489), nextsequence="seq3", points=915 },
                { input="up", from=time_to_ms(3, 801), to=time_to_ms(4, 489), nextsequence="seq9" },
                { input="right", from=time_to_ms(3, 441), to=time_to_ms(3, 768), nextsequence="seq9" },
                { input="right", from=time_to_ms(3, 768), to=time_to_ms(4, 456), nextsequence="seq11" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 278), nextsequence="seq9" },
            actions = {
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(0, 721), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 721), to=time_to_ms(1, 245), nextsequence="seq4", points=915 },
                { input="up", from=time_to_ms(0, 721), to=time_to_ms(1, 278), nextsequence="seq9" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(0, 721), nextsequence="seq9" },
                { input="left", from=time_to_ms(0, 721), to=time_to_ms(1, 278), nextsequence="seq11" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 966), nextsequence="seq9" },
            actions = {
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 311), nextsequence="seq9" },
                { input="left", from=time_to_ms(1, 311), to=time_to_ms(1, 966), nextsequence="seq5", points=495 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 311), nextsequence="seq9" },
                { input="right", from=time_to_ms(1, 311), to=time_to_ms(1, 966), nextsequence="seq11" },
                { input="up", from=time_to_ms(0, 852), to=time_to_ms(1, 966), nextsequence="seq9" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 966), nextsequence="seq9" },
            actions = {
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 311), nextsequence="seq9" },
                { input="right", from=time_to_ms(1, 311), to=time_to_ms(1, 966), nextsequence="seq6", points=495 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 311), nextsequence="seq9" },
                { input="left", from=time_to_ms(1, 311), to=time_to_ms(1, 966), nextsequence="seq11" },
                { input="up", from=time_to_ms(1, 49), to=time_to_ms(1, 966), nextsequence="seq9" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 802), nextsequence="seq10" },
            actions = {
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 245), nextsequence="seq9" },
                { input="right", from=time_to_ms(1, 245), to=time_to_ms(1, 802), nextsequence="seq7", points=1939 },
                { input="up", from=time_to_ms(0, 950), to=time_to_ms(1, 769), nextsequence="seq10" },
                { input="left", from=time_to_ms(0, 950), to=time_to_ms(1, 769), nextsequence="seq10" },
            }
        },

        seq7 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 475), nextsequence="seq9" },
            actions = {
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(0, 786), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 786), to=time_to_ms(1, 442), nextsequence="seq8", points=495 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(0, 786), nextsequence="seq9" },
                { input="left", from=time_to_ms(0, 786), to=time_to_ms(1, 442), nextsequence="seq11" },
                { input="up", from=time_to_ms(0, 393), to=time_to_ms(1, 475), nextsequence="seq9" },
            }
        },

        seq8 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(5, 8), nextsequence=nil },
        },

        seq9 = {
            start_time = time_laserdisc_frame(16976),
            kills_player = true,
            timeout = { when=time_to_ms(1, 834), nextsequence=nil }
        },

        seq10 = {
            start_time = time_laserdisc_frame(17024),
            kills_player = true,
            timeout = { when=time_to_ms(2, 692), nextsequence=nil }
        },

        seq11 = {
            start_time = time_laserdisc_frame(17088),
            kills_player = true,
            timeout = { when=time_to_ms(1, 542), nextsequence=nil }
        },
    },

    giant_bat = {
        game_over = {
            start_time = time_laserdisc_frame(14708),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(14231),
            timeout = { when=time_to_ms(2, 334), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(14327),
            timeout = { when=time_to_ms(1, 16), nextsequence="seq8" },
            actions = {
                { input="action", from=time_to_ms(0, 0), to=time_to_ms(1, 16), nextsequence="seq3", points=1326 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 16), nextsequence="seq10" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(14327),
            timeout = { when=time_to_ms(1, 16), nextsequence="seq8" },
            actions = {
                { input="action", from=time_to_ms(0, 0), to=time_to_ms(1, 16), nextsequence="seq3", points=1326 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 16), nextsequence="seq10" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 409), nextsequence="seq10" },
            actions = {
                { input="left", from=time_to_ms(0, 819), to=time_to_ms(1, 376), nextsequence="seq4", points=2191 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 409), nextsequence="seq10" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 359), nextsequence="seq9" },
            actions = {
                { input="upleft", from=time_to_ms(1, 704), to=time_to_ms(2, 327), nextsequence="seq5", points=1326 },
                { input="up", from=time_to_ms(1, 704), to=time_to_ms(2, 327), nextsequence="seq5", points=1326 },
                { input="left", from=time_to_ms(1, 704), to=time_to_ms(2, 327), nextsequence="seq5", points=1326 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 359), nextsequence="seq10" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 359), nextsequence="seq8" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 359), nextsequence="seq11" },
            actions = {
                { input="action", from=time_to_ms(1, 737), to=time_to_ms(2, 327), nextsequence="seq6", points=3551 },
                { input="down", from=time_to_ms(0, 590), to=time_to_ms(1, 147), nextsequence="seq10" },
                { input="left", from=time_to_ms(1, 737), to=time_to_ms(2, 327), nextsequence="seq11" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 442), nextsequence="seq7", points=49 }
        },

        seq7 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 757), nextsequence=nil }
        },

        seq8 = {
            start_time = time_laserdisc_frame(14611),
            kills_player = true,
            timeout = { when=time_to_ms(2, 42), nextsequence=nil }
        },

        seq9 = {
            start_time = time_laserdisc_frame(14659),
            timeout = { when=time_to_ms(0, 754), nextsequence="seq10" }
        },

        seq10 = {
            start_time = time_laserdisc_frame(14679),
            kills_player = true,
            timeout = { when=time_to_ms(1, 208), nextsequence=nil }
        },

        seq11 = {
            start_time = time_laserdisc_frame(14575),
            kills_player = true,
            timeout = { when=time_to_ms(1, 542), nextsequence=nil }
        },
    },

    grim_reaper = {
        game_over = {
            start_time = time_laserdisc_frame(8569),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(7829),
            timeout = { when=time_to_ms(2, 334), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(8004),
            timeout = { when=time_to_ms(5, 800), nextsequence="seq7" },
            actions = {
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 573), nextsequence="seq7" },
                { input="up", from=time_to_ms(1, 573), to=time_to_ms(1, 933), nextsequence="seq3", points=4026 },
                { input="up", from=time_to_ms(1, 933), to=time_to_ms(3, 47), nextsequence="seq7" },
                { input="up", from=time_to_ms(3, 47), to=time_to_ms(3, 408), nextsequence="seq3", points=4026 },
                { input="up", from=time_to_ms(3, 408), to=time_to_ms(4, 522), nextsequence="seq7" },
                { input="up", from=time_to_ms(4, 555), to=time_to_ms(4, 915), nextsequence="seq3", points=4026 },
                { input="up", from=time_to_ms(4, 915), to=time_to_ms(6, 29), nextsequence="seq7" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(6, 95), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(6, 95), nextsequence="seq9" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(8004),
            timeout = { when=time_to_ms(5, 800), nextsequence="seq7" },
            actions = {
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 573), nextsequence="seq7" },
                { input="up", from=time_to_ms(1, 573), to=time_to_ms(1, 933), nextsequence="seq3", points=4026 },
                { input="up", from=time_to_ms(1, 933), to=time_to_ms(3, 47), nextsequence="seq7" },
                { input="up", from=time_to_ms(3, 47), to=time_to_ms(3, 408), nextsequence="seq3", points=4026 },
                { input="up", from=time_to_ms(3, 408), to=time_to_ms(4, 522), nextsequence="seq7" },
                { input="up", from=time_to_ms(4, 555), to=time_to_ms(4, 915), nextsequence="seq3", points=4026 },
                { input="up", from=time_to_ms(4, 915), to=time_to_ms(6, 29), nextsequence="seq7" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(6, 95), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(6, 95), nextsequence="seq9" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_frame(8151),
            timeout = { when=time_to_ms(3, 604), nextsequence="seq8" },
            actions = {
                { input="action", from=time_to_ms(2, 982), to=time_to_ms(3, 572), nextsequence="seq4", points=2191 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(3, 572), nextsequence="seq9" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(3, 473), nextsequence="seq9" },
                { input="down", from=time_to_ms(3, 244), to=time_to_ms(3, 604), nextsequence="seq9" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 916), nextsequence="seq9" },
            actions = {
                { input="down", from=time_to_ms(1, 573), to=time_to_ms(2, 916), nextsequence="seq5", points=1326 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 916), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 916), nextsequence="seq9" },
                { input="left", from=time_to_ms(2, 261), to=time_to_ms(2, 916), nextsequence="seq9" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 982), nextsequence="seq9" },
            actions = {
                { input="up", from=time_to_ms(1, 475), to=time_to_ms(2, 982), nextsequence="seq6", points=915 },
                { input="down", from=time_to_ms(1, 671), to=time_to_ms(2, 982), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 982), nextsequence="seq9" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 982), nextsequence="seq9" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(0, 673), nextsequence=nil }
        },

        seq7 = {
            start_time = time_laserdisc_frame(8395),
            kills_player = true,
            timeout = { when=time_to_ms(2, 292), nextsequence=nil }
        },

        seq8 = {
            start_time = time_laserdisc_frame(8475),
            kills_player = true,
            timeout = { when=time_to_ms(2, 418), nextsequence=nil }
        },

        seq9 = {
            start_time = time_laserdisc_frame(8533),
            kills_player = true,
            timeout = { when=time_to_ms(1, 458), nextsequence=nil }
        },
    },

    grim_reaper_reversed = {
        game_over = {
            start_time = time_laserdisc_frame(20046),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(19306),
            timeout = { when=time_to_ms(2, 334), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(19520),
            timeout = { when=time_to_ms(4, 227), nextsequence="seq7" },
            actions = {
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(0, 721), nextsequence="seq7" },
                { input="up", from=time_to_ms(0, 721), to=time_to_ms(1, 16), nextsequence="seq3", points=4750 },
                { input="up", from=time_to_ms(1, 16), to=time_to_ms(2, 195), nextsequence="seq7" },
                { input="up", from=time_to_ms(2, 228), to=time_to_ms(2, 523), nextsequence="seq3", points=4750 },
                { input="up", from=time_to_ms(2, 523), to=time_to_ms(3, 703), nextsequence="seq7" },
                { input="up", from=time_to_ms(3, 703), to=time_to_ms(3, 998), nextsequence="seq3", points=4750 },
                { input="up", from=time_to_ms(3, 998), to=time_to_ms(4, 391), nextsequence="seq7" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(4, 489), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(4, 489), nextsequence="seq9" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(19520),
            timeout = { when=time_to_ms(4, 227), nextsequence="seq7" },
            actions = {
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(0, 721), nextsequence="seq7" },
                { input="up", from=time_to_ms(0, 721), to=time_to_ms(1, 16), nextsequence="seq3", points=4750 },
                { input="up", from=time_to_ms(1, 16), to=time_to_ms(2, 195), nextsequence="seq7" },
                { input="up", from=time_to_ms(2, 228), to=time_to_ms(2, 523), nextsequence="seq3", points=4750 },
                { input="up", from=time_to_ms(2, 523), to=time_to_ms(3, 703), nextsequence="seq7" },
                { input="up", from=time_to_ms(3, 703), to=time_to_ms(3, 998), nextsequence="seq3", points=4750 },
                { input="up", from=time_to_ms(3, 998), to=time_to_ms(4, 391), nextsequence="seq7" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(4, 489), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(4, 489), nextsequence="seq9" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_frame(19628),
            timeout = { when=time_to_ms(3, 604), nextsequence="seq8" },
            actions = {
                { input="action", from=time_to_ms(3, 47), to=time_to_ms(3, 604), nextsequence="seq4", points=2191 },
                { input="down", from=time_to_ms(3, 47), to=time_to_ms(3, 637), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 720), nextsequence="seq9" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 720), nextsequence="seq9" },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(3, 604), nextsequence="seq8" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 982), nextsequence="seq9" },
            actions = {
                { input="down", from=time_to_ms(2, 163), to=time_to_ms(2, 982), nextsequence="seq5", points=1326 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 982), nextsequence="seq9" },
                { input="right", from=time_to_ms(2, 163), to=time_to_ms(2, 982), nextsequence="seq9" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 982), nextsequence="seq9" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 589), nextsequence="seq9" },
            actions = {
                { input="up", from=time_to_ms(1, 606), to=time_to_ms(2, 556), nextsequence="seq6", points=915 },
                { input="down", from=time_to_ms(1, 606), to=time_to_ms(3, 15), nextsequence="seq9" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(3, 47), nextsequence="seq9" },
                { input="left", from=time_to_ms(1, 606), to=time_to_ms(3, 15), nextsequence="seq9" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(0, 875), nextsequence=nil }
        },

        seq7 = {
            start_time = time_laserdisc_frame(19872),
            kills_player = true,
            timeout = { when=time_to_ms(2, 292), nextsequence=nil }
        },

        seq8 = {
            start_time = time_laserdisc_frame(19950),
            kills_player = true,
            timeout = { when=time_to_ms(2, 459), nextsequence=nil }
        },

        seq9 = {
            start_time = time_laserdisc_frame(20010),
            kills_player = true,
            timeout = { when=time_to_ms(1, 458), nextsequence=nil }
        },
    },

    lizard_king = {
        game_over = {
            start_time = time_laserdisc_frame(18142),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(17208),
            timeout = { when=time_to_ms(2, 334), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(17264),
            timeout = { when=time_to_ms(2, 163), nextsequence="seq15" },
            actions = {
                { input="left", from=time_to_ms(0, 459), to=time_to_ms(2, 130), nextsequence="seq3", points=1939 },
                { input="up", from=time_to_ms(0, 459), to=time_to_ms(2, 130), nextsequence="seq3", points=1939 },
                { input="upleft", from=time_to_ms(0, 459), to=time_to_ms(2, 130), nextsequence="seq3", points=1939 },
                { input="down", from=time_to_ms(0, 459), to=time_to_ms(2, 130), nextsequence="seq17" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 163), nextsequence="seq16" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(17264),
            timeout = { when=time_to_ms(2, 163), nextsequence="seq15" },
            actions = {
                { input="left", from=time_to_ms(0, 459), to=time_to_ms(2, 130), nextsequence="seq3", points=1939 },
                { input="up", from=time_to_ms(0, 459), to=time_to_ms(2, 130), nextsequence="seq3", points=1939 },
                { input="upleft", from=time_to_ms(0, 459), to=time_to_ms(2, 130), nextsequence="seq3", points=1939 },
                { input="down", from=time_to_ms(0, 459), to=time_to_ms(2, 130), nextsequence="seq17" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 163), nextsequence="seq16" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(4, 456), nextsequence="seq17" },
            actions = {
                { input="right", from=time_to_ms(3, 572), to=time_to_ms(4, 424), nextsequence="seq4", points=1326 },
                { input="left", from=time_to_ms(3, 572), to=time_to_ms(4, 424), nextsequence="seq16" },
                { input="down", from=time_to_ms(3, 572), to=time_to_ms(4, 424), nextsequence="seq15" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(3, 506), nextsequence="seq17" },
            actions = {
                { input="right", from=time_to_ms(2, 654), to=time_to_ms(3, 473), nextsequence="seq5", points=1326 },
                { input="left", from=time_to_ms(2, 654), to=time_to_ms(3, 473), nextsequence="seq16" },
                { input="down", from=time_to_ms(2, 654), to=time_to_ms(3, 473), nextsequence="seq15" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 97), nextsequence="seq17" },
            actions = {
                { input="right", from=time_to_ms(1, 212), to=time_to_ms(2, 64), nextsequence="seq6", points=1326 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 97), nextsequence="seq16" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 97), nextsequence="seq15" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(4, 817), nextsequence="seq17" },
            actions = {
                { input="right", from=time_to_ms(3, 834), to=time_to_ms(4, 784), nextsequence="seq7", points=1326 },
                { input="left", from=time_to_ms(3, 834), to=time_to_ms(4, 784), nextsequence="seq16" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(4, 817), nextsequence="seq15" },
            }
        },

        seq7 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 163), nextsequence="seq17" },
            actions = {
                { input="right", from=time_to_ms(1, 409), to=time_to_ms(2, 130), nextsequence="seq8", points=2191 },
                { input="left", from=time_to_ms(1, 409), to=time_to_ms(2, 130), nextsequence="seq16" },
                { input="down", from=time_to_ms(1, 409), to=time_to_ms(2, 130), nextsequence="seq15" },
            }
        },

        seq8 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 228), nextsequence="seq17" },
            actions = {
                { input="up", from=time_to_ms(0, 459), to=time_to_ms(2, 195), nextsequence="seq9", points=3255 },
                { input="action", from=time_to_ms(0, 459), to=time_to_ms(2, 195), nextsequence="seq9", points=3255 },
            }
        },

        -- once you recover your sword and attack, no more points are awarded in this level in the original ROM,
        --  probably because after this sequence there are still right and wrong moves, but just not touching
        --  anything will let you survive the level on autopilot.
        seq9 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 573), nextsequence="seq15" },
            actions = {
                { input="action", from=time_to_ms(0, 819), to=time_to_ms(1, 540), nextsequence="seq10", points=0 },
                { input="down", from=time_to_ms(0, 819), to=time_to_ms(1, 540), nextsequence="seq15" },
            }
        },

        seq10 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(0, 950), nextsequence="seq11", points=0 },
            actions = {
                { input="action", from=time_to_ms(0, 328), to=time_to_ms(0, 950), nextsequence="seq11", points=0 },
                { input="down", from=time_to_ms(0, 328), to=time_to_ms(0, 950), nextsequence="seq11", points=0 },
            }
        },

        seq11 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 16), nextsequence="seq12", points=0 },
            actions = {
                { input="action", from=time_to_ms(0, 164), to=time_to_ms(0, 983), nextsequence="seq12", points=0 },
            }
        },

        seq12 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(0, 918), nextsequence="seq13", points=0 },
            actions = {
                { input="action", from=time_to_ms(0, 492), to=time_to_ms(0, 918), nextsequence="seq13", points=0 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(0, 918), nextsequence="seq17" },
                { input="down", from=time_to_ms(0, 492), to=time_to_ms(0, 918), nextsequence="seq13", points=0 },
                { input="left", from=time_to_ms(0, 492), to=time_to_ms(0, 918), nextsequence="seq15" },
            }
        },

        seq13 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 114), nextsequence="seq14", points=0 },
            actions = {
                { input="action", from=time_to_ms(0, 557), to=time_to_ms(1, 81), nextsequence="seq14", points=0 },
            }
        },

        seq14 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(5, 238) - laserdisc_frame_to_ms(3), nextsequence=nil }
        },

        seq15 = {
            start_time = time_laserdisc_frame(18036),
            kills_player = true,
            timeout = { when=time_to_ms(1, 0), nextsequence=nil }
        },

        seq16 = {
            start_time = time_laserdisc_frame(18060),
            kills_player = true,
            timeout = { when=time_to_ms(3, 419), nextsequence=nil }
        },

        seq17 = {
            start_time = time_laserdisc_frame(18082),
            kills_player = true,
            timeout = { when=time_to_ms(2, 501), nextsequence=nil }
        },
    },

    mudmen = {
        game_over = {
            start_time = time_laserdisc_frame(25396),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(24322),
            timeout = { when=time_to_ms(2, 334), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(24378),
            timeout = { when=time_to_ms(5, 964), nextsequence="seq15" },
            actions = {
                { input="action", from=time_to_ms(3, 965), to=time_to_ms(5, 931), nextsequence="seq3", points=1326 },
                { input="up", from=time_to_ms(4, 260), to=time_to_ms(5, 931), nextsequence="seq13" },
                { input="down", from=time_to_ms(3, 539), to=time_to_ms(5, 833), nextsequence="seq14" },
                { input="down", from=time_to_ms(5, 833), to=time_to_ms(5, 931), nextsequence="seq15" },
                { input="right", from=time_to_ms(3, 965), to=time_to_ms(5, 931), nextsequence="seq15" },
                { input="left", from=time_to_ms(3, 965), to=time_to_ms(5, 931), nextsequence="seq15" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(24378),
            timeout = { when=time_to_ms(5, 964), nextsequence="seq15" },
            actions = {
                { input="action", from=time_to_ms(3, 965), to=time_to_ms(5, 931), nextsequence="seq3", points=1326 },
                { input="up", from=time_to_ms(4, 260), to=time_to_ms(5, 931), nextsequence="seq13" },
                { input="down", from=time_to_ms(3, 539), to=time_to_ms(5, 833), nextsequence="seq14" },
                { input="down", from=time_to_ms(5, 833), to=time_to_ms(5, 931), nextsequence="seq15" },
                { input="right", from=time_to_ms(3, 965), to=time_to_ms(5, 931), nextsequence="seq15" },
                { input="left", from=time_to_ms(3, 965), to=time_to_ms(5, 931), nextsequence="seq15" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(3, 703), nextsequence="seq4", points=1326 },
            actions = {
                { input="right", from=time_to_ms(2, 720), to=time_to_ms(3, 670), nextsequence="seq15" },
                { input="down", from=time_to_ms(2, 720), to=time_to_ms(3, 670), nextsequence="seq15" },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(2, 720), nextsequence="seq15" },
                { input="up", from=time_to_ms(2, 720), to=time_to_ms(3, 670), nextsequence="seq4", points=1326 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(3, 703), nextsequence="seq15" },
                { input="action", from=time_to_ms(0, 0), to=time_to_ms(3, 703), nextsequence="seq15" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 606), nextsequence="seq15" },
            actions = {
                { input="up", from=time_to_ms(0, 295), to=time_to_ms(1, 606), nextsequence="seq5", points=2191 },
                { input="upleft", from=time_to_ms(0, 295), to=time_to_ms(1, 606), nextsequence="seq5", points=2191 },
                { input="action", from=time_to_ms(0, 295), to=time_to_ms(1, 573), nextsequence="seq15" },
                { input="left", from=time_to_ms(0, 295), to=time_to_ms(1, 573), nextsequence="seq12" },
                { input="right", from=time_to_ms(0, 295), to=time_to_ms(1, 573), nextsequence="seq14" },
                { input="down", from=time_to_ms(0, 295), to=time_to_ms(1, 573), nextsequence="seq15" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 540), nextsequence="seq15" },
            actions = {
                { input="up", from=time_to_ms(1, 16), to=time_to_ms(1, 540), nextsequence="seq6", points=2675 },
                { input="right", from=time_to_ms(1, 16), to=time_to_ms(1, 540), nextsequence="seq6", points=2675 },
                { input="upright", from=time_to_ms(1, 16), to=time_to_ms(1, 540), nextsequence="seq6", points=2675 },
                { input="down", from=time_to_ms(1, 16), to=time_to_ms(1, 540), nextsequence="seq15" },
                { input="left", from=time_to_ms(1, 16), to=time_to_ms(1, 540), nextsequence="seq14" },
                { input="action", from=time_to_ms(1, 16), to=time_to_ms(1, 540), nextsequence="seq15" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 933), nextsequence="seq15" },
            actions = {
                { input="up", from=time_to_ms(0, 852), to=time_to_ms(1, 933), nextsequence="seq7", points=1326 },
                { input="left", from=time_to_ms(0, 852), to=time_to_ms(1, 933), nextsequence="seq12" },
                { input="down", from=time_to_ms(0, 852), to=time_to_ms(1, 933), nextsequence="seq13" },
                { input="right", from=time_to_ms(1, 278), to=time_to_ms(1, 933), nextsequence="seq15" },
                { input="action", from=time_to_ms(1, 278), to=time_to_ms(1, 933), nextsequence="seq15" },
            }
        },

        seq7 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 638), nextsequence="seq15" },
            actions = {
                { input="up", from=time_to_ms(0, 655), to=time_to_ms(1, 606), nextsequence="seq8", points=1326 },
                { input="left", from=time_to_ms(0, 655), to=time_to_ms(1, 573), nextsequence="seq12" },
                { input="right", from=time_to_ms(0, 655), to=time_to_ms(1, 573), nextsequence="seq14" },
                { input="down", from=time_to_ms(0, 655), to=time_to_ms(1, 573), nextsequence="seq15" },
                { input="action", from=time_to_ms(0, 655), to=time_to_ms(1, 573), nextsequence="seq15" },
            }
        },

        seq8 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 654), nextsequence="seq16" },
            actions = {
                { input="upleft", from=time_to_ms(1, 475), to=time_to_ms(1, 933), nextsequence="seq16" },
                { input="upleft", from=time_to_ms(1, 933), to=time_to_ms(2, 621), nextsequence="seq9", points=1326 },
                { input="up", from=time_to_ms(1, 475), to=time_to_ms(1, 933), nextsequence="seq16" },
                { input="up", from=time_to_ms(1, 933), to=time_to_ms(2, 621), nextsequence="seq9", points=1326 },
                { input="left", from=time_to_ms(1, 475), to=time_to_ms(2, 621), nextsequence="seq16" },
                { input="right", from=time_to_ms(1, 475), to=time_to_ms(2, 621), nextsequence="seq16" },
                { input="down", from=time_to_ms(1, 475), to=time_to_ms(2, 621), nextsequence="seq15" },
            }
        },

        seq9 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 720), nextsequence="seq15" },
            actions = {
                { input="up", from=time_to_ms(1, 114), to=time_to_ms(2, 720), nextsequence="seq10", points=1326 },
                { input="right", from=time_to_ms(1, 114), to=time_to_ms(2, 753), nextsequence="seq16" },
                { input="left", from=time_to_ms(1, 114), to=time_to_ms(2, 753), nextsequence="seq16" },
                { input="down", from=time_to_ms(1, 114), to=time_to_ms(2, 753), nextsequence="seq15" },
                { input="action", from=time_to_ms(1, 114), to=time_to_ms(2, 753), nextsequence="seq15" },
            }
        },

        seq10 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(4, 391), nextsequence="seq15" },
            actions = {
                { input="up", from=time_to_ms(2, 818), to=time_to_ms(4, 686), nextsequence="seq11", points=1326 },
                { input="right", from=time_to_ms(2, 818), to=time_to_ms(4, 686), nextsequence="seq11", points=1326 },
                { input="down", from=time_to_ms(2, 818), to=time_to_ms(3, 998), nextsequence="seq15" },
                { input="down", from=time_to_ms(3, 998), to=time_to_ms(7, 897), nextsequence="seq14" },
                { input="left", from=time_to_ms(3, 998), to=time_to_ms(7, 897), nextsequence="seq15" },
                { input="action", from=time_to_ms(3, 310), to=time_to_ms(7, 209), nextsequence="seq15" },
            }
        },

        seq11 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(3, 421), nextsequence=nil }
        },

        seq12 = {
            start_time = time_laserdisc_frame(25194),
            kills_player = true,
            timeout = { when=time_to_ms(4, 420), nextsequence=nil }
        },

        seq13 = {
            start_time = time_laserdisc_frame(25098),
            kills_player = true,
            timeout = { when=time_to_ms(0, 874), nextsequence=nil }
        },

        seq14 = {
            start_time = time_laserdisc_frame(25360),
            kills_player = true,
            timeout = { when=time_to_ms(1, 500), nextsequence=nil }
        },

        seq15 = {
            start_time = time_laserdisc_frame(25300),
            kills_player = true,
            timeout = { when=time_to_ms(2, 42), nextsequence=nil }
        },

        seq16 = {
            start_time = time_laserdisc_frame(25146),
            kills_player = true,
            timeout = { when=time_to_ms(2, 1), nextsequence=nil }
        },
    },

    yellow_brick_road = {
        game_over = {
            start_time = time_laserdisc_frame(4981),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(4083),
            timeout = { when=time_to_ms(2, 84), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(4139),
            timeout = { when=time_to_ms(1, 868), nextsequence="seq14" },
            actions = {
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="seq3", points=1326 },
                { input="up", from=time_to_ms(1, 606), to=time_to_ms(1, 999), nextsequence="seq14" },
                { input="down", from=time_to_ms(1, 606), to=time_to_ms(1, 999), nextsequence="seq14" },
                { input="right", from=time_to_ms(1, 606), to=time_to_ms(1, 999), nextsequence="seq14" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(4139),
            timeout = { when=time_to_ms(1, 868), nextsequence="seq14" },
            actions = {
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="seq3", points=1326 },
                { input="up", from=time_to_ms(1, 606), to=time_to_ms(1, 999), nextsequence="seq14" },
                { input="down", from=time_to_ms(1, 606), to=time_to_ms(1, 999), nextsequence="seq14" },
                { input="right", from=time_to_ms(1, 606), to=time_to_ms(1, 999), nextsequence="seq14" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 64), nextsequence="seq12" },
            actions = {
                { input="up", from=time_to_ms(0, 885), to=time_to_ms(2, 32), nextsequence="seq4", points=1939 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 64), nextsequence="seq14" },
                { input="left", from=time_to_ms(0, 885), to=time_to_ms(2, 32), nextsequence="seq12" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 458), nextsequence="seq14" },
            actions = {
                { input="right", from=time_to_ms(1, 81), to=time_to_ms(2, 458), nextsequence="seq5", points=2191 },
                { input="left", from=time_to_ms(1, 507), to=time_to_ms(2, 425), nextsequence="seq14" },
                { input="up", from=time_to_ms(1, 81), to=time_to_ms(2, 458), nextsequence="seq14" },
                { input="down", from=time_to_ms(1, 343), to=time_to_ms(2, 458), nextsequence="seq14" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 835), nextsequence="seq14" },
            actions = {
                { input="up", from=time_to_ms(0, 492), to=time_to_ms(1, 769), nextsequence="seq6", points=2675 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="seq14" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="seq14" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 835), nextsequence="seq14" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 130), nextsequence="seq15" },
            actions = {
                { input="left", from=time_to_ms(0, 655), to=time_to_ms(2, 97), nextsequence="seq7", points=3255 },
                { input="right", from=time_to_ms(1, 114), to=time_to_ms(2, 130), nextsequence="seq15" },
                { input="action", from=time_to_ms(1, 114), to=time_to_ms(2, 130), nextsequence="seq15" },
                { input="up", from=time_to_ms(1, 114), to=time_to_ms(2, 130), nextsequence="seq15" },
                { input="down", from=time_to_ms(1, 114), to=time_to_ms(2, 130), nextsequence="seq15" },
            }
        },

        seq7 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 933), nextsequence="seq16" },
            actions = {
                { input="up", from=time_to_ms(1, 245), to=time_to_ms(1, 933), nextsequence="seq8", points=3551 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 933), nextsequence="seq15" },
                { input="left", from=time_to_ms(1, 245), to=time_to_ms(1, 933), nextsequence="seq16" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 933), nextsequence="seq14" },
            }
        },

        seq8 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(3, 244), nextsequence="seq17" },
            actions = {
                { input="action", from=time_to_ms(2, 490), to=time_to_ms(3, 211), nextsequence="seq9", points=4026 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(3, 244), nextsequence="seq14" },
                { input="left", from=time_to_ms(2, 490), to=time_to_ms(3, 211), nextsequence="seq17" },
            }
        },

        seq9 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 540), nextsequence="seq14" },
            actions = {
                { input="right", from=time_to_ms(0, 721), to=time_to_ms(1, 475), nextsequence="seq10", points=5000 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 540), nextsequence="seq14" },
                { input="left", from=time_to_ms(0, 885), to=time_to_ms(1, 507), nextsequence="seq14" },
            }
        },

        seq10 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 97), nextsequence="seq18" },
            actions = {
                { input="up", from=time_to_ms(0, 754), to=time_to_ms(2, 64), nextsequence="seq11", points=4750 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 97), nextsequence="seq14" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 97), nextsequence="seq14" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 97), nextsequence="seq15" },
            }
        },

        seq11 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 225), nextsequence=nil }
        },

        seq12 = {
            start_time = time_laserdisc_frame(4639),
            kills_player = true,
            timeout = { when=time_to_ms(1, 41), nextsequence=nil }
        },

        seq14 = {
            start_time = time_laserdisc_frame(4711),
            kills_player = true,
            timeout = { when=time_to_ms(2, 42), nextsequence=nil }
        },

        seq15 = {
            start_time = time_laserdisc_frame(4759),
            kills_player = true,
            timeout = { when=time_to_ms(3, 335), nextsequence=nil }
        },

        seq16 = {
            start_time = time_laserdisc_frame(4839),
            kills_player = true,
            timeout = { when=time_to_ms(1, 83), nextsequence=nil }
        },

        seq17 = {
            start_time = time_laserdisc_frame(4875),
            kills_player = true,
            timeout = { when=time_to_ms(1, 834), nextsequence=nil }
        },

        seq18 = {
            start_time = time_laserdisc_frame(4923),
            kills_player = true,
            timeout = { when=time_to_ms(2, 543), nextsequence=nil }
        },
    },

    yellow_brick_road_reversed = {
        game_over = {
            start_time = time_laserdisc_frame(14148),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(13247),
            timeout = { when=time_to_ms(2, 334), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(13303),
            timeout = { when=time_to_ms(1, 868), nextsequence="seq14" },
            actions = {
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 868), nextsequence="seq3", points=1939 },
                { input="up", from=time_to_ms(1, 606), to=time_to_ms(1, 999), nextsequence="seq14" },
                { input="left", from=time_to_ms(1, 606), to=time_to_ms(1, 999), nextsequence="seq14" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(13303),
            timeout = { when=time_to_ms(1, 868), nextsequence="seq14" },
            actions = {
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 868), nextsequence="seq3", points=1939 },
                { input="up", from=time_to_ms(1, 606), to=time_to_ms(1, 999), nextsequence="seq14" },
                { input="left", from=time_to_ms(1, 606), to=time_to_ms(1, 999), nextsequence="seq14" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 64), nextsequence="seq12" },
            actions = {
                { input="up", from=time_to_ms(0, 885), to=time_to_ms(2, 32), nextsequence="seq4", points=2191 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 64), nextsequence="seq14" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 163), nextsequence="seq14" },
            actions = {
                { input="left", from=time_to_ms(1, 81), to=time_to_ms(2, 425), nextsequence="seq5", points=2675 },
                { input="right", from=time_to_ms(1, 507), to=time_to_ms(2, 392), nextsequence="seq14" },
                { input="up", from=time_to_ms(1, 81), to=time_to_ms(2, 425), nextsequence="seq14" },
                { input="down", from=time_to_ms(1, 81), to=time_to_ms(2, 425), nextsequence="seq14" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 737), nextsequence="seq14" },
            actions = {
                { input="up", from=time_to_ms(0, 492), to=time_to_ms(1, 737), nextsequence="seq6", points=3255 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 737), nextsequence="seq14" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 737), nextsequence="seq14" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 737), nextsequence="seq14" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 97), nextsequence="seq15" },
            actions = {
                { input="right", from=time_to_ms(0, 655), to=time_to_ms(2, 64), nextsequence="seq7", points=3551 },
                { input="left", from=time_to_ms(1, 114), to=time_to_ms(2, 130), nextsequence="seq15" },
                { input="up", from=time_to_ms(1, 81), to=time_to_ms(2, 97), nextsequence="seq15" },
                { input="down", from=time_to_ms(1, 81), to=time_to_ms(2, 97), nextsequence="seq15" },
                { input="action", from=time_to_ms(1, 81), to=time_to_ms(2, 97), nextsequence="seq15" },
            }
        },

        seq7 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 933), nextsequence="seq16" },
            actions = {
                { input="up", from=time_to_ms(1, 212), to=time_to_ms(1, 933), nextsequence="seq8", points=4026 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(1, 933), nextsequence="seq15" },
                { input="right", from=time_to_ms(1, 212), to=time_to_ms(1, 901), nextsequence="seq16" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 933), nextsequence="seq14" },
            }
        },

        seq8 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(3, 244), nextsequence="seq17" },
            actions = {
                { input="action", from=time_to_ms(2, 490), to=time_to_ms(3, 211), nextsequence="seq9", points=4026 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(3, 342), nextsequence="seq14" },
                { input="right", from=time_to_ms(2, 490), to=time_to_ms(3, 310), nextsequence="seq17" },
            }
        },

        seq9 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 540), nextsequence="seq14" },
            actions = {
                { input="left", from=time_to_ms(0, 721), to=time_to_ms(1, 507), nextsequence="seq10", points=5000 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 311), nextsequence="seq14" },
                { input="right", from=time_to_ms(0, 885), to=time_to_ms(1, 507), nextsequence="seq14" },
            }
        },

        seq10 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 97), nextsequence="seq18" },
            actions = {
                { input="up", from=time_to_ms(0, 754), to=time_to_ms(2, 64), nextsequence="seq11", points=4750 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 97), nextsequence="seq14" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 97), nextsequence="seq14" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 97), nextsequence="seq15" },
            }
        },

        seq11 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 693), nextsequence=nil }
        },

        seq12 = {
            start_time = time_laserdisc_frame(13803),
            kills_player = true,
            timeout = { when=time_to_ms(0, 874), nextsequence=nil }
        },

        seq14 = {
            start_time = time_laserdisc_frame(13875),
            kills_player = true,
            timeout = { when=time_to_ms(2, 1), nextsequence=nil }
        },

        seq15 = {
            start_time = time_laserdisc_frame(13923),
            kills_player = true,
            timeout = { when=time_to_ms(3, 293), nextsequence=nil }
        },

        seq16 = {
            start_time = time_laserdisc_frame(14003),
            kills_player = true,
            timeout = { when=time_to_ms(1, 83), nextsequence=nil }
        },

        seq17 = {
            start_time = time_laserdisc_frame(14039),
            kills_player = true,
            timeout = { when=time_to_ms(2, 1), nextsequence=nil }
        },

        seq18 = {
            start_time = time_laserdisc_frame(14087),
            kills_player = true,
            timeout = { when=time_to_ms(2, 376), nextsequence=nil }
        },
    },

    robot_knight = {
        game_over = {
            start_time = time_laserdisc_frame(11340),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(10685),
            timeout = { when=time_to_ms(2, 167), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(10741),
            timeout = { when=time_to_ms(4, 293), nextsequence="seq11" },
            actions = {
                { input="right", from=time_to_ms(2, 884), to=time_to_ms(4, 260), nextsequence="seq3", points=1939 },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(10741),
            timeout = { when=time_to_ms(4, 293), nextsequence="seq11" },
            actions = {
                { input="right", from=time_to_ms(2, 884), to=time_to_ms(4, 260), nextsequence="seq3", points=1939 },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 311), nextsequence="seq11" },
            actions = {
                { input="left", from=time_to_ms(0, 426), to=time_to_ms(1, 278), nextsequence="seq4", points=1939 },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 540), nextsequence="seq11" },
            actions = {
                { input="up", from=time_to_ms(0, 950), to=time_to_ms(1, 507), nextsequence="seq5", points=2191 },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 163), nextsequence="seq11" },
            actions = {
                { input="left", from=time_to_ms(1, 147), to=time_to_ms(2, 163), nextsequence="seq6", points=1939 },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 130), nextsequence="seq11" },
            actions = {
                { input="right", from=time_to_ms(1, 212), to=time_to_ms(2, 97), nextsequence="seq7", points=1939 },
            }
        },

        seq7 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 49), nextsequence="seq11" },
            actions = {
                { input="left", from=time_to_ms(0, 393), to=time_to_ms(1, 16), nextsequence="seq8", points=1939 },
            }
        },

        seq8 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(0, 754), nextsequence="seq11" },
            actions = {
                { input="right", from=time_to_ms(0, 197), to=time_to_ms(0, 754), nextsequence="seq9", points=4026 },
            }
        },

        seq9 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 687), nextsequence="seq12" },
            actions = {
                { input="up", from=time_to_ms(1, 606), to=time_to_ms(2, 687), nextsequence="seq12" },
                { input="action", from=time_to_ms(1, 606), to=time_to_ms(2, 687), nextsequence="seq10", points=2191 },
            }
        },

        seq10 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(5, 676), nextsequence=nil }
        },

        seq11 = {
            start_time = time_laserdisc_frame(11269),
            kills_player = true,
            timeout = { when=time_to_ms(1, 875), nextsequence=nil }
        },

        seq12 = {
            start_time = time_laserdisc_frame(11317),
            kills_player = true,
            timeout = { when=time_to_ms(0, 874), nextsequence=nil }
        },
    },

    robot_knight_reversed = {
        game_over = {
            start_time = time_laserdisc_frame(21820),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(21156),
            timeout = { when=time_to_ms(2, 334), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(21212),
            timeout = { when=time_to_ms(4, 391), nextsequence="seq11" },
            actions = {
                { input="left", from=time_to_ms(3, 473), to=time_to_ms(4, 358), nextsequence="seq3", points=2191 },
                { input="up", from=time_to_ms(3, 473), to=time_to_ms(7, 766), nextsequence="seq11" },
                { input="down", from=time_to_ms(3, 473), to=time_to_ms(4, 358), nextsequence="seq11" },
                { input="right", from=time_to_ms(3, 473), to=time_to_ms(4, 358), nextsequence="seq11" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(21212),
            timeout = { when=time_to_ms(4, 391), nextsequence="seq11" },
            actions = {
                { input="left", from=time_to_ms(3, 473), to=time_to_ms(4, 358), nextsequence="seq3", points=2191 },
                { input="up", from=time_to_ms(3, 473), to=time_to_ms(7, 766), nextsequence="seq11" },
                { input="down", from=time_to_ms(3, 473), to=time_to_ms(4, 358), nextsequence="seq11" },
                { input="right", from=time_to_ms(3, 473), to=time_to_ms(4, 358), nextsequence="seq11" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 311), nextsequence="seq11" },
            actions = {
                { input="right", from=time_to_ms(0, 557), to=time_to_ms(1, 278), nextsequence="seq4", points=2191 },
                { input="up", from=time_to_ms(0, 557), to=time_to_ms(1, 278), nextsequence="seq11" },
                { input="down", from=time_to_ms(0, 557), to=time_to_ms(1, 278), nextsequence="seq11" },
                { input="left", from=time_to_ms(0, 557), to=time_to_ms(1, 278), nextsequence="seq11" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 606), nextsequence="seq11" },
            actions = {
                { input="up", from=time_to_ms(0, 950), to=time_to_ms(1, 573), nextsequence="seq5", points=2675 },
                { input="down", from=time_to_ms(0, 950), to=time_to_ms(1, 573), nextsequence="seq11" },
                { input="right", from=time_to_ms(0, 950), to=time_to_ms(1, 573), nextsequence="seq11" },
                { input="left", from=time_to_ms(0, 950), to=time_to_ms(1, 573), nextsequence="seq11" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 163), nextsequence="seq11" },
            actions = {
                { input="right", from=time_to_ms(1, 245), to=time_to_ms(2, 130), nextsequence="seq6", points=2191 },
                { input="up", from=time_to_ms(1, 245), to=time_to_ms(2, 130), nextsequence="seq11" },
                { input="down", from=time_to_ms(1, 245), to=time_to_ms(2, 130), nextsequence="seq11" },
                { input="left", from=time_to_ms(1, 245), to=time_to_ms(2, 130), nextsequence="seq11" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 130), nextsequence="seq11" },
            actions = {
                { input="left", from=time_to_ms(1, 212), to=time_to_ms(2, 97), nextsequence="seq7", points=2191 },
                { input="up", from=time_to_ms(1, 212), to=time_to_ms(2, 97), nextsequence="seq11" },
                { input="down", from=time_to_ms(1, 212), to=time_to_ms(2, 97), nextsequence="seq11" },
                { input="right", from=time_to_ms(1, 212), to=time_to_ms(2, 97), nextsequence="seq11" },
            }
        },

        seq7 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 49), nextsequence="seq11" },
            actions = {
                { input="right", from=time_to_ms(0, 393), to=time_to_ms(1, 16), nextsequence="seq8", points=2191 },
                { input="up", from=time_to_ms(0, 393), to=time_to_ms(1, 16), nextsequence="seq11" },
                { input="down", from=time_to_ms(0, 393), to=time_to_ms(1, 16), nextsequence="seq11" },
                { input="left", from=time_to_ms(0, 393), to=time_to_ms(1, 16), nextsequence="seq11" },
            }
        },

        seq8 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(0, 754), nextsequence="seq11" },
            actions = {
                { input="left", from=time_to_ms(0, 197), to=time_to_ms(0, 754), nextsequence="seq9", points=4750 },
                { input="up", from=time_to_ms(0, 197), to=time_to_ms(0, 754), nextsequence="seq11" },
                { input="right", from=time_to_ms(0, 197), to=time_to_ms(0, 754), nextsequence="seq11" },
                { input="down", from=time_to_ms(0, 197), to=time_to_ms(0, 754), nextsequence="seq11" },
            }
        },

        seq9 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 720), nextsequence="seq12" },
            actions = {
                { input="up", from=time_to_ms(1, 835), to=time_to_ms(2, 687), nextsequence="seq12" },
                { input="action", from=time_to_ms(1, 835), to=time_to_ms(2, 687), nextsequence="seq10", points=2675 },
            }
        },

        seq10 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(5, 438), nextsequence=nil }
        },

        seq11 = {
            start_time = time_laserdisc_frame(21740),
            kills_player = true,
            timeout = { when=time_to_ms(2, 1), nextsequence=nil }
        },

        seq12 = {
            start_time = time_laserdisc_frame(21788),
            kills_player = true,
            timeout = { when=time_to_ms(0, 874), nextsequence=nil }
        },
    },

    fire_room = {
        game_over = {
            start_time = time_laserdisc_frame(9880),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(9473),
            timeout = { when=time_to_ms(2, 167), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(9529),
            timeout = { when=time_to_ms(3, 539), nextsequence="seq8" },
            actions = {
                { input="right", from=time_to_ms(2, 884), to=time_to_ms(3, 506), nextsequence="seq3", points=915 },
                { input="left", from=time_to_ms(2, 884), to=time_to_ms(3, 473), nextsequence="seq8" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(9529),
            timeout = { when=time_to_ms(3, 539), nextsequence="seq8" },
            actions = {
                { input="right", from=time_to_ms(2, 884), to=time_to_ms(3, 506), nextsequence="seq3", points=915 },
                { input="left", from=time_to_ms(2, 884), to=time_to_ms(3, 473), nextsequence="seq8" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 163), nextsequence="seq8" },
            actions = {
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(0, 328), nextsequence="seq7" },
                { input="up", from=time_to_ms(1, 147), to=time_to_ms(2, 97), nextsequence="seq4", points=1326 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(0, 328), nextsequence="seq7" },
                { input="left", from=time_to_ms(1, 147), to=time_to_ms(2, 97), nextsequence="seq4", points=1326 },
                { input="down", from=time_to_ms(1, 147), to=time_to_ms(2, 195), nextsequence="seq8" },
                { input="right", from=time_to_ms(1, 147), to=time_to_ms(2, 195), nextsequence="seq8" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 966), nextsequence="seq8" },
            actions = {
                { input="left", from=time_to_ms(0, 655), to=time_to_ms(1, 966), nextsequence="seq5", points=915 },
                { input="up", from=time_to_ms(0, 655), to=time_to_ms(1, 966), nextsequence="seq7" },
                { input="down", from=time_to_ms(0, 655), to=time_to_ms(1, 966), nextsequence="seq5", points=915 },
                { input="downleft", from=time_to_ms(0, 655), to=time_to_ms(1, 966), nextsequence="seq5", points=915 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 966), nextsequence="seq7" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 638), nextsequence="seq8" },
            actions = {
                { input="left", from=time_to_ms(0, 197), to=time_to_ms(1, 638), nextsequence="seq6", points=1326 },
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(1, 638), nextsequence="seq7" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 638), nextsequence="seq8" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(1, 638), nextsequence="seq8" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 913), nextsequence=nil }
        },

        seq7 = {
            start_time = time_laserdisc_frame(9821),
            kills_player = true,
            timeout = { when=time_to_ms(1, 180), nextsequence="seq8" }
        },

        seq8 = {
            start_time = time_laserdisc_frame(9857),
            kills_player = true,
            timeout = { when=time_to_ms(1, 0), nextsequence=nil }
        },
    },

    smithee = {
        game_over = {
            start_time = time_laserdisc_frame(7745),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(6911),
            timeout = { when=time_to_ms(2, 376), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(6994),
            timeout = { when=time_to_ms(3, 113), nextsequence="seq9" },
            actions = {
                { input="action", from=time_to_ms(2, 228), to=time_to_ms(3, 80), nextsequence="seq3", points=915 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(3, 113), nextsequence="seq8" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(3, 113), nextsequence="seq8" },
                { input="up", from=time_to_ms(1, 507), to=time_to_ms(3, 178), nextsequence="seq8" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 654), nextsequence="seq8" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(6994),
            timeout = { when=time_to_ms(3, 113), nextsequence="seq9" },
            actions = {
                { input="action", from=time_to_ms(2, 228), to=time_to_ms(3, 80), nextsequence="seq3", points=915 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(3, 113), nextsequence="seq8" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(3, 113), nextsequence="seq8" },
                { input="up", from=time_to_ms(1, 507), to=time_to_ms(3, 178), nextsequence="seq8" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 654), nextsequence="seq8" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 490), nextsequence="seq10" },
            actions = {
                { input="action", from=time_to_ms(1, 933), to=time_to_ms(2, 458), nextsequence="seq4", points=1939 },
                { input="up", from=time_to_ms(1, 147), to=time_to_ms(2, 425), nextsequence="seq8" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 147), nextsequence="seq8" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 490), nextsequence="seq8" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 490), nextsequence="seq8" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 720), nextsequence="seq11" },
            actions = {
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(0, 950), nextsequence="seq8" },
                { input="left", from=time_to_ms(0, 950), to=time_to_ms(2, 687), nextsequence="seq5", points=1326 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 720), nextsequence="seq8" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 720), nextsequence="seq8" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 835), nextsequence="seq12" },
            actions = {
                { input="action", from=time_to_ms(1, 49), to=time_to_ms(1, 835), nextsequence="seq6", points=1326 },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(6, 259), nextsequence="seq13" },
            actions = {
                { input="action", from=time_to_ms(5, 210), to=time_to_ms(6, 259), nextsequence="seq7", points=915 },
                { input="right", from=time_to_ms(5, 210), to=time_to_ms(6, 259), nextsequence="seq13" },
            }
        },

        seq7 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(4, 269), nextsequence=nil }
        },

        seq8 = {
            start_time = time_laserdisc_frame(7489),
            kills_player = true,
            timeout = { when=time_to_ms(1, 458), nextsequence=nil }
        },

        seq9 = {
            start_time = time_laserdisc_frame(7525),
            kills_player = true,
            timeout = { when=time_to_ms(0, 833), nextsequence=nil }
        },

        seq10 = {
            start_time = time_laserdisc_frame(7549),
            kills_player = true,
            timeout = { when=time_to_ms(1, 875), nextsequence=nil }
        },

        seq11 = {
            start_time = time_laserdisc_frame(7623),
            kills_player = true,
            timeout = { when=time_to_ms(1, 83), nextsequence=nil }
        },

        seq12 = {
            start_time = time_laserdisc_frame(7649),
            kills_player = true,
            timeout = { when=time_to_ms(0, 958), nextsequence=nil }
        },

        seq13 = {
            start_time = time_laserdisc_frame(7681),
            kills_player = true,
            timeout = { when=time_to_ms(2, 626), nextsequence=nil }
        },
    },

    smithee_reversed = {
        game_over = {
            start_time = time_laserdisc_frame(16405),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(15570),
            timeout = { when=time_to_ms(2, 84), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(15653),
            timeout = { when=time_to_ms(3, 178), nextsequence="seq9" },
            actions = {
                { input="action", from=time_to_ms(1, 475), to=time_to_ms(2, 195), nextsequence="seq9" },
                { input="action", from=time_to_ms(2, 195), to=time_to_ms(3, 113), nextsequence="seq3", points=1326 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(3, 113), nextsequence="seq8" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(3, 113), nextsequence="seq8" },
                { input="up", from=time_to_ms(1, 507), to=time_to_ms(3, 178), nextsequence="seq8" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 654), nextsequence="seq8" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(15653),
            timeout = { when=time_to_ms(3, 178), nextsequence="seq9" },
            actions = {
                { input="action", from=time_to_ms(1, 475), to=time_to_ms(2, 195), nextsequence="seq9" },
                { input="action", from=time_to_ms(2, 195), to=time_to_ms(3, 113), nextsequence="seq3", points=1326 },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(3, 113), nextsequence="seq8" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(3, 113), nextsequence="seq8" },
                { input="up", from=time_to_ms(1, 507), to=time_to_ms(3, 178), nextsequence="seq8" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 654), nextsequence="seq8" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 490), nextsequence="seq10" },
            actions = {
                { input="action", from=time_to_ms(0, 852), to=time_to_ms(1, 933), nextsequence="seq10" },
                { input="action", from=time_to_ms(1, 933), to=time_to_ms(2, 458), nextsequence="seq4", points=2191 },
                { input="up", from=time_to_ms(1, 147), to=time_to_ms(2, 425), nextsequence="seq8" },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(1, 147), nextsequence="seq8" },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(2, 490), nextsequence="seq8" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 490), nextsequence="seq8" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 753), nextsequence="seq11" },
            actions = {
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(0, 950), nextsequence="seq8" },
                { input="right", from=time_to_ms(0, 950), to=time_to_ms(2, 720), nextsequence="seq5", points=1326 },
                { input="down", from=time_to_ms(0, 0), to=time_to_ms(2, 753), nextsequence="seq8" },
                { input="left", from=time_to_ms(0, 0), to=time_to_ms(2, 753), nextsequence="seq8" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 802), nextsequence="seq12" },
            actions = {
                { input="action", from=time_to_ms(0, 229), to=time_to_ms(0, 983), nextsequence="seq12" },
                { input="action", from=time_to_ms(0, 983), to=time_to_ms(1, 802), nextsequence="seq6", points=1326 },
                { input="up", from=time_to_ms(1, 49), to=time_to_ms(1, 868), nextsequence="seq12" },
                { input="down", from=time_to_ms(1, 49), to=time_to_ms(1, 868), nextsequence="seq12" },
                { input="left", from=time_to_ms(1, 49), to=time_to_ms(1, 868), nextsequence="seq12" },
                { input="right", from=time_to_ms(1, 49), to=time_to_ms(1, 868), nextsequence="seq12" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(6, 226), nextsequence="seq13" },
            actions = {
                { input="action", from=time_to_ms(5, 177), to=time_to_ms(6, 226), nextsequence="seq7", points=915 },
                { input="right", from=time_to_ms(5, 210), to=time_to_ms(6, 259), nextsequence="seq13" },
                { input="left", from=time_to_ms(5, 210), to=time_to_ms(6, 259), nextsequence="seq13" },
            }
        },

        seq7 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(3, 987), nextsequence=nil }
        },

        seq8 = {
            start_time = time_laserdisc_frame(16148),
            kills_player = true,
            timeout = { when=time_to_ms(1, 417), nextsequence=nil }
        },

        seq9 = {
            start_time = time_laserdisc_frame(16184),
            kills_player = true,
            timeout = { when=time_to_ms(0, 791), nextsequence=nil }
        },

        seq10 = {
            start_time = time_laserdisc_frame(16208),
            kills_player = true,
            timeout = { when=time_to_ms(1, 542), nextsequence=nil }
        },

        seq11 = {
            start_time = time_laserdisc_frame(16282),
            kills_player = true,
            timeout = { when=time_to_ms(1, 125), nextsequence=nil }
        },

        seq12 = {
            start_time = time_laserdisc_frame(16308),
            kills_player = true,
            timeout = { when=time_to_ms(1, 41), nextsequence=nil }
        },

        seq13 = {
            start_time = time_laserdisc_frame(16341),
            kills_player = true,
            timeout = { when=time_to_ms(2, 668), nextsequence=nil }
        },
    },

    snake_room = {
        game_over = {
            start_time = time_laserdisc_frame(3411),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(3041),
            timeout = { when=time_to_ms(2, 376), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(3097),
            timeout = { when=time_to_ms(2, 720), nextsequence="seq7" },
            actions = {
                { input="action", from=time_to_ms(1, 966), to=time_to_ms(2, 687), nextsequence="seq3", points=495 },
                { input="left", from=time_to_ms(1, 966), to=time_to_ms(2, 687), nextsequence="seq7" },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(3097),
            timeout = { when=time_to_ms(2, 720), nextsequence="seq7" },
            actions = {
                { input="action", from=time_to_ms(1, 966), to=time_to_ms(2, 687), nextsequence="seq3", points=495 },
                { input="left", from=time_to_ms(1, 966), to=time_to_ms(2, 687), nextsequence="seq7" },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 671), nextsequence="seq7" },
            actions = {
                { input="action", from=time_to_ms(0, 918), to=time_to_ms(1, 638), nextsequence="seq4", points=2675 },
                { input="right", from=time_to_ms(0, 918), to=time_to_ms(1, 638), nextsequence="seq7" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 835), nextsequence="seq9", points=49 },
            actions = {
                { input="action", from=time_to_ms(1, 49), to=time_to_ms(1, 868), nextsequence="seq9", points=49 },
                { input="left", from=time_to_ms(1, 16), to=time_to_ms(1, 835), nextsequence="seq7" },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(3, 145), nextsequence=nil }
        },

        seq6 = {
            start_time = time_laserdisc_frame(3349),
            timeout = { when=time_to_ms(1, 671), nextsequence="seq7" }
        },

        seq7 = {
            start_time = time_laserdisc_frame(3397),
            kills_player = true,
            timeout = { when=time_to_ms(0, 874), nextsequence=nil }
        },

        seq9 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(0, 721), nextsequence="seq6" },
            actions = {
                { input="up", from=time_to_ms(0, 0), to=time_to_ms(0, 721), nextsequence="seq5", points=1939 },
                { input="upright", from=time_to_ms(0, 0), to=time_to_ms(0, 721), nextsequence="seq5", points=1939 },
                { input="right", from=time_to_ms(0, 0), to=time_to_ms(0, 721), nextsequence="seq5", points=1939 },
            }
        },
    },

    the_dragons_lair = {
        game_over = {
            start_time = time_laserdisc_frame(31503),
            timeout = { when=time_to_ms(3, 503), interrupt=game_over_complete }
        },

        start_dead = {
            start_time = time_laserdisc_frame(28882),
            timeout = { when=time_to_ms(2, 334), nextsequence="seq2", points=49 }
        },

        start_alive = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=0, nextsequence="enter_room", points = 49 }
         },

        enter_room = {
            start_time = time_laserdisc_frame(28938),
            timeout = { when=time_to_ms(4, 882), nextsequence="seq19" },
            actions = {
                { input="left", from=time_to_ms(3, 932), to=time_to_ms(4, 850), nextsequence="seq3", points=1326 },
            }
        },

        seq2 = {
            start_time = time_laserdisc_frame(28938),
            timeout = { when=time_to_ms(4, 882), nextsequence="seq19" },
            actions = {
                { input="left", from=time_to_ms(3, 932), to=time_to_ms(4, 850), nextsequence="seq3", points=1326 },
            }
        },

        seq3 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(11, 207), nextsequence="seq19" },
            actions = {
                { input="left", from=time_to_ms(10, 584), to=time_to_ms(11, 141), nextsequence="seq4", points=1939 },
                { input="up", from=time_to_ms(10, 584), to=time_to_ms(11, 141), nextsequence="seq19" },
                { input="right", from=time_to_ms(10, 584), to=time_to_ms(11, 141), nextsequence="seq19" },
                { input="action", from=time_to_ms(10, 584), to=time_to_ms(11, 141), nextsequence="seq19" },
            }
        },

        seq4 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(8, 618), nextsequence="seq19" },
            actions = {
                { input="left", from=time_to_ms(6, 980), to=time_to_ms(8, 585), nextsequence="seq5", points=1326 },
            }
        },

        seq5 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(22, 872), nextsequence="seq14" },
            actions = {
                { input="downleft", from=time_to_ms(22, 20), to=time_to_ms(22, 807), nextsequence="seq6", points=2191 },
                { input="left", from=time_to_ms(22, 20), to=time_to_ms(22, 807), nextsequence="seq6", points=2191 },
                { input="down", from=time_to_ms(22, 20), to=time_to_ms(22, 807), nextsequence="seq6", points=2191 },
                { input="action", from=time_to_ms(22, 20), to=time_to_ms(22, 807), nextsequence="seq14" },
            }
        },

        seq6 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(7, 406), nextsequence="seq17" },
            actions = {
                { input="up", from=time_to_ms(6, 554), to=time_to_ms(7, 373), nextsequence="seq16" },
                { input="down", from=time_to_ms(6, 554), to=time_to_ms(7, 373), nextsequence="seq7", points=2191 },
                { input="right", from=time_to_ms(6, 554), to=time_to_ms(7, 373), nextsequence="seq17" },
                { input="left", from=time_to_ms(6, 554), to=time_to_ms(7, 373), nextsequence="seq7", points=2191 },
                { input="downleft", from=time_to_ms(6, 554), to=time_to_ms(7, 373), nextsequence="seq7", points=2191 },
                { input="action", from=time_to_ms(6, 554), to=time_to_ms(7, 373), nextsequence="seq17" },
            }
        },

        seq7 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(5, 341), nextsequence="seq19" },
            actions = {
                { input="down", from=time_to_ms(4, 653), to=time_to_ms(5, 308), nextsequence="seq19" },
                { input="right", from=time_to_ms(4, 653), to=time_to_ms(5, 308), nextsequence="seq8", points=3255 },
                { input="left", from=time_to_ms(4, 653), to=time_to_ms(5, 308), nextsequence="seq19" },
            }
        },

        seq8 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(3, 670), nextsequence="seq19" },
            actions = {
                { input="right", from=time_to_ms(2, 654), to=time_to_ms(3, 670), nextsequence="seq9", points=2191 },
                { input="up", from=time_to_ms(2, 654), to=time_to_ms(3, 670), nextsequence="seq9", points=2191 },
                { input="upright", from=time_to_ms(2, 654), to=time_to_ms(3, 670), nextsequence="seq9", points=2191 },
            }
        },

        seq9 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(1, 475), nextsequence="seq15" },
            actions = {
                { input="action", from=time_to_ms(0, 393), to=time_to_ms(1, 475), nextsequence="seq10", points=3551 },
                { input="right", from=time_to_ms(0, 393), to=time_to_ms(1, 475), nextsequence="seq10", points=3551 },
            }
        },

        seq10 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(3, 768), nextsequence="seq16" },
            actions = {
                { input="action", from=time_to_ms(2, 687), to=time_to_ms(3, 768), nextsequence="seq11", points=4026 },
                { input="up", from=time_to_ms(2, 687), to=time_to_ms(3, 768), nextsequence="seq16" },
                { input="down", from=time_to_ms(2, 687), to=time_to_ms(3, 768), nextsequence="seq16" },
                { input="right", from=time_to_ms(2, 687), to=time_to_ms(3, 768), nextsequence="seq16" },
                { input="left", from=time_to_ms(2, 687), to=time_to_ms(3, 768), nextsequence="seq16" },
            }
        },

        seq11 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(3, 899), nextsequence="seq18" },
            actions = {
                { input="left", from=time_to_ms(2, 425), to=time_to_ms(3, 899), nextsequence="seq12", points=4750 },
                { input="up", from=time_to_ms(2, 425), to=time_to_ms(3, 899), nextsequence="seq12", points=4750 },
                { input="upleft", from=time_to_ms(2, 425), to=time_to_ms(3, 899), nextsequence="seq12", points=4750 },
                { input="right", from=time_to_ms(2, 425), to=time_to_ms(3, 899), nextsequence="seq18" },
            }
        },

        seq12 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(2, 228), nextsequence="seq16" },
            actions = {
                { input="action", from=time_to_ms(1, 114), to=time_to_ms(2, 228), nextsequence="seq13", points=5000 },
            }
        },

        seq13 = {
            start_time = time_laserdisc_noseek(),
            timeout = { when=time_to_ms(18, 501), nextsequence="endgame" }
        },

        endgame = {  -- show dirk and daphne in a heart for ten seconds before ending the game.
            start_time = time_laserdisc_frame(31178),
            is_single_frame = true,
            timeout = { when=time_to_ms(10, 0), nextsequence=nil },
        },

        seq14 = {
            start_time = time_laserdisc_frame(31238),
            kills_player = true,
            timeout = { when=time_to_ms(2, 501), nextsequence=nil }
        },

        seq15 = {
            start_time = time_laserdisc_frame(31298),
            kills_player = true,
            timeout = { when=time_to_ms(2, 1), nextsequence=nil }
        },

        seq16 = {
            start_time = time_laserdisc_frame(31354),
            kills_player = true,
            timeout = { when=time_to_ms(1, 583), nextsequence=nil }
        },

        seq17 = {
            start_time = time_laserdisc_frame(31394),
            kills_player = true,
            timeout = { when=time_to_ms(2, 543), nextsequence=nil }
        },

        seq18 = {
            start_time = time_laserdisc_frame(31454),
            kills_player = true,
            timeout = { when=time_to_ms(2, 42), nextsequence=nil }
        },

        seq19 = {
            start_time = time_laserdisc_noseek(),
            kills_player = true,
            timeout = { when=time_to_ms(1, 638), nextsequence=nil }
        },
    }
}


-- http://www.dragons-lair-project.com/games/related/sequence.asp
scene_manager = {
    -- there are thirteen rows of three scenes each.
    rows = {
        { 'flaming_ropes', 'flaming_ropes_reversed', 'bower' },
        { 'flying_horse', 'flying_horse_reversed', 'alice_room' },
        { 'crypt_creeps', 'crypt_creeps_reversed', 'underground_river' },
        { 'falling_platform_short', 'falling_platform_short', 'vestibule' },
        { 'rolling_balls', 'electric_cage_and_geyser', 'black_knight' },
        { 'grim_reaper', 'grim_reaper_reversed', 'lizard_king' },
        { 'smithee', 'smithee_reversed', 'wind_room' },
        { 'tentacle_room', 'snake_room', 'bubbling_cauldron' },
        { 'flattening_staircase', 'giddy_goons', 'fire_room' },
        { 'yellow_brick_road', 'yellow_brick_road_reversed', 'catwalk_bats' },
        { 'robot_knight', 'robot_knight_reversed', 'giant_bat' },
        { 'throne_room', 'tilting_room', 'mudmen' },
        { 'falling_platform_long', 'falling_platform_long_reversed', 'the_dragons_lair' }
    }
}

-- end of lair.lua ...

