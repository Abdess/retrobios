{
	"Version": {
		"Target": "Jazz² Resurrection"
	},

	"Animations": {
		"Idle": {
			"Path": "Lizard/xmas_copter_idle.aura",
			"States": [ 0 ]
		},
		"Attack": {
			"Path": "Lizard/xmas_copter_attack.aura",
			"FrameCount": 12,
			"FrameRate": 6,
			"States": [ 1325400065 ]
		},
		"AttackEnd": {
			"Path": "Lizard/xmas_copter_attack.aura",
			"FrameOffset": 12,
			"FrameRate": 40,
			"States": [ 1325400066 ]
		},
		"Copter": {
			"Path": "Lizard/xmas_copter.aura",
			"FrameRate": 20,
			"States": [ 1 ]
		},
		
		"Bomb": {
			"Path": "Lizard/xmas_bomb.aura",
			"FrameRate": 8,
			"States": [ 2 ]
		}
	},
	
	"Sounds": {
		"Copter": {
			"Paths": [ "Object/copter.wav" ]
		},
		"CopterPre": {
			"Paths": [ "Common/copter_pre.wav" ]
		}
	}
}