{
	"Version": {
		"Target": "Jazz² Resurrection"
	},

	"Animations": {
		"Idle": {
			"Path": "TurtleBoss/idle.aura",
			"States": [ 0 ],
			"FrameRate": 8
		},
		"Walk": {
			"Path": "TurtleBoss/walk.aura",
			"States": [ 1 ],
			"FrameRate": 5
		},

		"AttackStart": {
			"Path": "TurtleBoss/attack_start.aura",
			"States": [ 1073741824 ],
			"FrameRate": 6,
			"FrameCount": 15
		},
		"AttackStart2": {
			"Path": "TurtleBoss/attack_start.aura",
			"States": [ 1073741825 ],
			"FrameRate": 10,
			"FrameOffset": 15,
			"FrameCount": 4
		},
		"AttackEnd": {
			"Path": "TurtleBoss/attack_end.aura",
			"States": [ 1073741826 ],
			"FrameRate": 7
		},
		
		"Mace": {
			"Path": "TurtleBoss/mace.aura",
			"States": [ 1073741827 ],
			"FrameRate": 12
		}
	},

	"Sounds": {
		"AttackStart": {
			"Paths": [ "TurtleBoss/attack_start.wav" ]
		},
		"AttackEnd": {
			"Paths": [ "TurtleBoss/attack_end.wav" ]
		},
		"Mace": {
			"Paths": [ "TurtleBoss/mace.wav" ]
		}
	}
}