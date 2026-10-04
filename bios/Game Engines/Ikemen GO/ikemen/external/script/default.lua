if not main.makeRoster then
	launchFight{}
	setMatchNo(-1)
	return
end

if main.storyboard.intro and matchNo() == 1 and not continued() then
	launchStoryboard(start.f_getCharData(start.p[1].t_selected[1].ref).intro)
end

for i = matchNo(), #start.t_roster do
	if start.t_roster[i][1] == -1 then --infinite matches flag detected
		return --restart lua script after appending new entries
	end
	local t_p2char = {}
	for _, v in ipairs(start.t_roster[i]) do
		table.insert(t_p2char, start.f_getCharData(v).char)
	end
	main.f_tableShuffle(t_p2char)
	if not launchFight{p2char = t_p2char, p2numchars = #t_p2char} then return end
end

if main.storyboard.ending then
	if not launchStoryboard(start.f_getCharData(start.p[1].t_selected[1].ref).ending) and motif.default_ending.enabled then
		launchStoryboard(motif.default_ending.storyboard)
	end
end

setMatchNo(-1)