{
	"Version": {
		"Target": "Jazz² Resurrection"
	},

	"Animations": {
		"Walk": {
			"Path": "Turtle/xmas_walk.aura",
			"FrameRate": 4,
			"States": [ 0, 1, 2, 8, 9, 10 ]
		},
		"WithdrawStart": {
			"Path": "Turtle/xmas_turn_start.aura",
			"FrameRate": 7,
			"States": [ 20 ]
		},
		"WithdrawStartFast": {
			"Path": "Turtle/xmas_turn_start.aura",
			"FrameRate": 20,
			"States": [ 21 ]
		},
		"WithdrawInProgress": {
			"Path": "Turtle/xmas_turn_start.aura",
			"FrameOffset": 6,
			"FrameCount": 1,
			"States": [ 22 ]
		},
		"WithdrawEnd": {
			"Path": "Turtle/xmas_turn_end.aura",
			"FrameRate": 7,
			"States": [ 23 ]
		},
		"Attack": {
			"Path": "Turtle/xmas_attack.aura",
			"FrameRate": 7,
			"States": [ 1325400065 ]
		}
	},

	"Sounds": {
		"Withdraw": {
			"Paths": [ "Turtle/xmas_turn_start.wav" ]
		},
		"WithdrawEnd": {
			"Paths": [ "Turtle/xmas_turn_end.wav" ]
		},
		"Attack": {
			"Paths": [ "Turtle/xmas_attack_neck.wav" ]
		},
		"Attack2": {
			"Paths": [ "Turtle/xmas_attack_bite.wav" ]
		}
	}
}