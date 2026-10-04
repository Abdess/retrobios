{
	"Version": {
		"Target": "Jazz² Resurrection"
	},

	"Animations": {
		"Walk": {
			"Path": "Monkey/walk.aura",
			"FrameRate": 5,
			"States": [ 1 ]
		},
		"Jump": {
			"Path": "Monkey/jump.aura",
			"FrameRate": 5,
			"States": [ 4 ]
		},
		
		"WalkStart": {
			"Path": "Monkey/walk_start.aura",
			"FrameRate": 17,
			"States": [ 1073741824 ]
		},
		"WalkEnd": {
			"Path": "Monkey/walk_end.aura",
			"FrameRate": 17,
			"States": [ 1073741825 ]
		},
		
		"AttackStart": {
			"Path": "Monkey/attack.aura",
			"FrameCount": 8,
			"FrameRate": 8,
			"States": [ 1073741826 ]
		},
		"AttackEnd": {
			"Path": "Monkey/attack.aura",
			"FrameOffset": 8,
			"FrameRate": 10,
			"States": [ 1073741827 ]
		},
		
		"Banana": {
			"Path": "Monkey/banana.aura",
			"States": [ 1073741828 ]
		},
		"BananaSplat": {
			"Path": "Monkey/banana_splat.aura",
			"FrameRate": 12,
			"States": [ 1073741829 ]
		}
	},

	"Sounds": {
		"BananaThrow": {
			"Paths": [ "Monkey/banana_throw.wav" ]
		},
		"BananaSplat": {
			"Paths": [ "Monkey/banana_splat.wav" ]
		}
	}
}