{
	"Version": {
		"Target": "Jazz² Resurrection"
	},

	"Animations": {
		"Idle": {
			"Path": "Devan/idle.aura",
			"States": [ 0 ]
		},
		"Run": {
			"Path": "Devan/run.aura",
			"States": [ 2 ]
		},	
		"WarpIn": {
			"Path": "Devan/warp_in.aura",
			"States": [ 1073741843 ]
		},
		"WarpOut": {
			"Path": "Devan/warp_out.aura",
			"States": [ 1073741844 ]
		},
		
		"RunEnd": {
			"Path": "Devan/run_end.aura",
			"FrameRate": 20,
			"States": [ 1073741824 ]
		},
		"ShootStart": {
			"Path": "Devan/shoot.aura",
			"FrameCount": 3,
			"FrameRate": 20,
			"States": [ 10 ]
		},
		"ShootInProgress": {
			"Path": "Devan/shoot.aura",
			"FrameOffset": 3,
			"FrameCount": 3,
			"FrameRate": 40,
			"States": [ 11 ]
		},
		"ShootEnd": {
			"Path": "Devan/shoot.aura",
			"FrameOffset": 6,
			"FrameCount": 1,
			"FrameRate": 50,
			"States": [ 12 ]
		},
		"ShootEnd2": {
			"Path": "Devan/shoot.aura",
			"FrameOffset": 7,
			"FrameRate": 28,
			"States": [ 13 ]
		},
		"CrouchStart": {
			"Path": "Devan/crouch.aura",
			"FrameCount": 4,
			"FrameRate": 20,
			"States": [ 14 ]
		},
		"CrouchInProgress": {
			"Path": "Devan/crouch.aura",
			"FrameOffset": 4,
			"FrameCount": 1,
			"States": [ 15 ]
		},
		"CrouchEnd": {
			"Path": "Devan/crouch.aura",
			"FrameOffset": 5,
			"FrameCount": 4,
			"FrameRate": 20,
			"States": [ 16 ]
		},
		
		"JumpStart": {
			"Path": "Devan/jump.aura",
			"FrameCount": 14,
			"FrameRate": 20,
			"States": [ 17 ]
		},
		"JumpInProgress": {
			"Path": "Devan/jump.aura",
			"FrameOffset": 14,
			"FrameCount": 1,
			"States": [ 18 ]
		},
		"JumpEnd": {
			"Path": "Devan/jump.aura",
			"FrameOffset": 15,
			"FrameCount": 11,
			"FrameRate": 20,
			"States": [ 19 ]
		},
		"JumpEnd2": {
			"Path": "Devan/jump_end.aura",
			"States": [ 20 ]
		},
		
		"Freefall": {
			"Path": "Devan/freefall.aura",
			"FrameRate": 30,
			"States": [ 65536 ]
		},
			
		"DisarmedStart": {
			"Path": "Devan/disarmed.aura",
			"States": [ 22 ]
		},
		"DisarmedGunDecor": {
			"Path": "Devan/disarmed_gun.aura",
			"States": [ 23 ]
		},

		"DisorientedStart": {
			"Path": "Devan/disoriented_start.aura",
			"FrameRate": 30,
			"States": [ 24 ]
		},
		"Disoriented": {
			"Path": "Devan/disoriented.aura",
			"States": [ 25 ]
		},
		"DisorientedWarpOut": {
			"Path": "Devan/disoriented_warp_out.aura",
			"States": [ 26 ]
		},

		"DevanBullet": {
			"Path": "Devan/bullet.aura",
			"States": [ 27 ]
		},
		
		"DemonFly": {
			"Path": "Devan/demon_fly.aura",
			"FrameRate": 5,
			"States": [ 30 ]
		},
		"DemonTransformStart": {
			"Path": "Devan/demon_transform_start.aura",
			"FrameRate": 2,
			"States": [ 31 ]
		},
		"DemonTransformEnd": {
			"Path": "Devan/demon_transform_end.aura",
			"FrameRate": 4,
			"States": [ 32 ]
		},
		"DemonTurn": {
			"Path": "Devan/demon_turn.aura",
			"FrameRate": 16,
			"States": [ 33 ]
		},
		"DemonSpewFireball": {
			"Path": "Devan/demon_spew_fireball.aura",
			"FrameCount": 9,
			"States": [ 34 ]
		},
		"DemonSpewFireballEnd": {
			"Path": "Devan/demon_spew_fireball.aura",
			"FrameOffset": 9,
			"FrameRate": 20,
			"States": [ 35 ]
		},
		
		"DemonFireball": {
			"Path": "Devan/demon_fireball.aura",
			"States": [ 36 ]
		}
	},

	"Sounds": {
		"Shoot": {
			"Paths": [ "Devan/shoot.wav" ]
		},
		"SpitFireball": {
			"Paths": [ "Devan/spit_fireball.wav" ]
		},
		"Flap": {
			"Paths": [ "Devan/flap.wav" ]
		},
		"WallPoof": {
			"Paths": [ "Weapon/wall_poof.wav" ]
		}
	}
}