{
	"Version": {
		"Target": "Jazz² Resurrection"
	},

	"Animations": {
		"Walk": {
			"Path": "Turtle/walk.aura",
			"FrameRate": 4,
			"States": [ 0, 1, 2, 8, 9, 10 ]
		},
		"WithdrawStart": {
			"Path": "Turtle/turn_start.aura",
			"FrameRate": 7,
			"States": [ 20 ]
		},
		"WithdrawStartFast": {
			"Path": "Turtle/turn_start.aura",
			"FrameRate": 20,
			"States": [ 21 ]
		},
		"WithdrawInProgress": {
			"Path": "Turtle/turn_start.aura",
			"FrameOffset": 6,
			"FrameCount": 1,
			"States": [ 22 ]
		},
		"WithdrawEnd": {
			"Path": "Turtle/turn_end.aura",
			"FrameRate": 7,
			"States": [ 23 ]
		},
		"Attack": {
			"Path": "Turtle/attack.aura",
			"FrameRate": 7,
			"States": [ 1325400065 ]
		}
	},

	"Sounds": {
		"Withdraw": {
			"Paths": [ "Turtle/turn_start.wav" ]
		},
		"WithdrawEnd": {
			"Paths": [ "Turtle/turn_end.wav" ]
		},
		"Attack": {
			"Paths": [ "Turtle/attack_neck.wav" ]
		},
		"Attack2": {
			"Paths": [ "Turtle/attack_bite.wav" ]
		}
	}
}