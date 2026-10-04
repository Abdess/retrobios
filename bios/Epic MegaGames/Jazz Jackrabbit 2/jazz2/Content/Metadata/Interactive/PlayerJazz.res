{
	"Version": {
		"Target": "Jazz² Resurrection"
	},

	"Animations": {
		"Idle": {
			"Path": "Jazz/idle.aura",
			"States": [ 0 ]
		},
		"Walk": {
			"Path": "Jazz/run.aura",
			"FrameRate": 8,
			"States": [ 1, 17 ]
		},
		"Run": {
			"Path": "Jazz/dash_start.aura",
			"FrameRate": 12,
			"States": [ 2, 18 ]
		},
		"Jump": {
			"Path": "Jazz/jump.aura",
			"States": [ 4 ]
		},
		"RunJump": {
			"Path": "Jazz/jump_diag.aura",
			"Flags": 1,
			"States": [ 5, 6 ]
		},
		"Fall": {
			"Path": "Jazz/fall.aura",
			"FrameRate": 12.97,
			"States": [ 8 ]
		},
		"FallDiag": {
			"Path": "Jazz/fall_diag.aura",
			"States": [ 9, 10, 11 ]
		},
		"Freefall": {
			"Path": "Jazz/freefall.aura",
			"States": [ 65536, 65537, 65538, 65539 ]
		},
		"Dash": {
			"Path": "Jazz/dash.aura",
			"FrameRate": 20,
			"States": [ 3, 19 ]
		},
		"DashJump": {
			"Path": "Jazz/ball.aura",
			"States": [ 7 ]
		},
		"Lookup": {
			"Path": "Jazz/lookup_start.aura",
			"Flags": 1,
			"FrameRate": 34,
			"States": [ 64 ]
		},
		"Crouch": {
			"Path": "Jazz/crouch_start.aura",
			"Flags": 1,
			"FrameRate": 40,
			"States": [ 32 ]
		},
		"DizzyIdle": {
			"Path": "Jazz/dizzy.aura",
			"FrameRate": 7,
			"States": [ 128 ]
		},
		"DizzyWalk": {
			"Path": "Jazz/dizzy_walk.aura",
			"FrameRate": 6,
			"States": [ 129, 145 ]
		},
		"Shoot": {
			"Path": "Jazz/shoot.aura",
			"States": [ 16, 144 ],
			"Flags": 1
		},
		"CrouchShoot": {
			"Path": "Jazz/crouch_shoot.aura",
			"States": [ 48 ],
			"Flags": 1
		},
		"LookupShoot": {
			"Path": "Jazz/shoot_ver.aura",
			"States": [ 80 ],
			"Flags": 1
		},
		"Hurt": {
			"Path": "Jazz/hurt.aura",
			"FrameRate": 6,
			"States": [ 2048 ]
		},
		"Uppercut": {
			"Path": "Jazz/uppercut.aura",
			"States": [ 512 ]
		},
		"Buttstomp": {
			"Path": "Jazz/buttstomp.aura",
			"States": [ 256 ]
		},
		"HookIdleFlavor": {
			"Path": "Jazz/vine_idle_flavor.aura",
			"FrameRate": 8.75,
			"States": [ 1073741866 ]
		},
		"Hook": {
			"Path": "Jazz/vine_idle.aura",
			"States": [ 12 ]
		},
		"HookLookup": {
			"Path": "Jazz/vine_shoot_up_end.aura",
			"States": [ 76 ]
		},
		"HookMove": {
			"Path": "Jazz/vine_walk.aura",
			"States": [ 13, 14, 15 ]
		},
		"Copter": {
			"Path": "Jazz/copter.aura",
			"FrameRate": 8,
			"States": [ 8192, 8193, 8194, 8195 ]
		},
		"CopterShoot": {
			"Path": "Jazz/copter_shoot.aura",
			"FrameRate": 22,
			"States": [ 8208, 8209, 8210, 8211 ]
		},
		"AerialShoot": {
			"Path": "Jazz/fall_shoot.aura",
			"FrameRate": 14,
			"States": [ 20, 21, 22, 23, 24, 25, 26, 27, 262160, 262161, 262162, 262163 ]
		},
		"HookShoot": {
			"Path": "Jazz/vine_shoot.aura",
			"States": [ 28, 29, 30, 31 ],
			"Flags": 1
		},
		"HookLookupShoot": {
			"Path": "Jazz/vine_shoot_up.aura",
			"States": [ 92 ],
			"Flags": 1
		},
		"RunToIdle": {
			"Path": "Jazz/run_stop.aura",
			"FrameRate": 10.9,
			"States": [ 1073741824 ]
		},
		"WalkToIdle": {
			"Path": "Jazz/walk_stop.aura",
			"FrameRate": 29.2,
			"States": [ 1073741865 ]
		},
		"RevUpSpark": {
			"Path": "Common/explosion_tiny.aura",
			"States": [ 1325400080 ]
		},
		"RevUp": {
			"Path": "Jazz/revup.aura",
			"FrameRate": 5,
			"States": [ 524288 ]
		},
		"RevUpStart": {
			"Path": "Jazz/revup_start.aura",
			"FrameRate": 80,
			"States": [ 1073741863 ]
		},
		"RevUpEnd": {
			"Path": "Jazz/revup_end.aura",
			"FrameRate": 23,
			"States": [ 1073741864 ]
		},
		"RunToDash": {
			"Path": "Jazz/dash_start.aura",
			"States": [ 1073741825 ]
		},
		"DashToIdle": {
			"Path": "Jazz/dash_stop.aura",
			"FrameRate": 16.7,
			"States": [ 1073741856 ]
		},
		"FallToIdle": {
			"Path": "Jazz/fall_end.aura",
			"States": [ 1073741826 ],
			"FrameRate": 14.29
		},
		"ShootToIdle": {
			"Path": "Jazz/shoot_end.aura",
			"FrameRate": 20,
			"States": [ 1073741828 ]
		},
		"HookShootToHook": {
			"Path": "Jazz/vine_shoot_end.aura",
			"FrameRate": 20,
			"States": [ 1073741829 ]
		},
		"CopterShootToCopter": {
			"Path": "Jazz/copter_shoot_start.aura",
			"FrameRate": 27,
			"States": [ 1073741830 ]
		},
		"FallShootToFall": {
			"Path": "Jazz/jump_shoot_end.aura",
			"FrameOffset": 1,
			"FrameCount": 2,
			"FrameRate": 29.2,
			"States": [ 1073741872 ]
		},
		"UppercutA": {
			"Path": "Jazz/uppercut_start.aura",
			"FrameCount": 3,
			"FrameRate": 20,
			"States": [ 1073741831 ]
		},
		"UppercutB": {
			"Path": "Jazz/uppercut_start.aura",
			"FrameOffset": 3,
			"FrameRate": 20,
			"States": [ 1073741832 ]
		},
		"UppercutC": {
			"Path": "Jazz/uppercut_end.aura",
			"FrameRate": 20,
			"States": [ 1073741833 ]
		},
		"ButtstompStart": {
			"Path": "Jazz/spring.aura",
			"States": [ 1073741834 ]
		},
		"ButtstompEnd": {
			"Path": "Jazz/buttstomp_end.aura",
			"States": [ 1073741858 ]
		},
		"PoleH": {
			"Path": "Jazz/pole_h.aura",
			"FrameRate": 20,
			"States": [ 1073741835 ]
		},
		"PoleHSlow": {
			"Path": "Jazz/pole_h.aura",
			"States": [ 1073741837 ]
		},
		"PoleV": {
			"Path": "Jazz/pole_v.aura",
			"FrameRate": 20,
			"States": [ 1073741836 ]
		},
		"PoleVSlow": {
			"Path": "Jazz/pole_v.aura",
			"States": [ 1073741838 ]
		},
		"Death": {
			"Path": "Jazz/die.aura",
			"FrameRate": 3,
			"States": [ 1073741839 ]
		},
		"WarpIn": {
			"Path": "Jazz/warp_in.aura",
			"States": [ 1073741843 ]
		},
		"WarpOut": {
			"Path": "Jazz/warp_out.aura",
			"States": [ 1073741844 ]
		},
		"WarpInFreefall": {
			"Path": "Jazz/warp_in_freefall.aura",
			"States": [ 1073741847 ]
		},
		"WarpOutFreefall": {
			"Path": "Jazz/warp_out_freefall.aura",
			"States": [ 1073741848 ]
		},
		"Spring": {
			"Path": "Jazz/spring.aura",
			"States": [ 262144, 262145, 262146, 262147 ]
		},
		"Push": {
			"Path": "Jazz/push.aura",
			"FrameRate": 6,
			"States": [ 16384, 16385 ]
		},
		"EndOfLevel": {
			"Path": "Jazz/eol.aura",
			"FrameRate": 3,
			"States": [ 1073741846 ]
		},
		"Swim": {
			"Path": "Jazz/swim_right.aura",
			"FrameRate": 6,
			"States": [ 4096 ]
		},
		"Lift": {
			"Path": "Jazz/lift.aura",
			"Flags": 1,
			"FrameRate": 16,
			"States": [ 131072 ]
		},
		"LiftStart": {
			"Path": "Jazz/lift_start.aura",
			"FrameRate": 16,
			"States": [ 1073741859 ]
		},
		"LiftEnd": {
			"Path": "Jazz/lift_end.aura",
			"States": [ 1073741860 ]
		},
		"Ledge": {
			"Path": "Jazz/ledge.aura",
			"FrameRate": 3,
			"States": [ 1073741861 ]
		},
		"Airboard": {
			"Path": "Jazz/airboard.aura",
			"FrameRate": 6,
			"States": [ 1024 ]
		},
		"LedgeClimb": {
			"Path": "Jazz/ledge_climb.aura",
			"FrameRate": 8,
			"States": [ 1073741862 ]
		},
		"Swing": {
			"Path": "Jazz/swing.aura",
			"FrameRate": 4,
			"States": [ 32768 ],
			"Flags": 1
		},
		
		"IdleBored1": {
			"Path": "Jazz/idle_flavor_1.aura",
			"FrameRate": 2,
			"States": [ 536870944 ]
		},
		"IdleBored2": {
			"Path": "Jazz/idle_flavor_2.aura",
			"FrameRate": 1,
			"States": [ 536870945 ]
		},
		"IdleBored3": {
			"Path": "Jazz/idle_flavor_3.aura",
			"FrameRate": 2,
			"States": [ 536870946 ]
		},
		"IdleBored4": {
			"Path": "Jazz/idle_flavor_4.aura",
			"FrameRate": 3,
			"States": [ 536870947 ]
		},
		"IdleBored5": {
			"Path": "Jazz/idle_flavor_5.aura",
			"FrameRate": 3,
			"States": [ 536870948 ]
		},
		
		"TransformFromFrog": {
			"Path": "Jazz/transform_frog_end.aura",
			"FrameRate": 3,
			"States": [ 1073741888 ]
		},
		
		"Corpse": {
			"Path": "Jazz/corpse.aura",
			"States": [ 536870912 ]
		},

		"SugarRush": {
			"Path": "Common/sugar_rush_stars.aura",
			"States": [ 536870913 ]
		},
		"Shield": {
			"Path": "Common/player_shield.aura",
			"States": [ 536870928 ]
		},
		"ShieldFire": {
			"Path": "Common/shield_fire.aura",
			"States": [ 536870929 ]
		},
		"ShieldWater": {
			"Path": "Common/shield_water.aura",
			"States": [ 536870930 ]
		},
		"ShieldLightning": {
			"Path": "Common/shield_lightning.aura",
			"States": [ 536870931 ]
		},
		
		"WeaponFlare": {
			"Path": "Weapon/flare_hor_2.aura",
			"States": [ 536870950 ]
		}
	},

	"Sounds": {
		"ChangeWeapon": {
			"Paths": [ "UI/weapon_change.wav" ]
		},
		"EndOfLevel": {
			"Paths": [ "Jazz/level_complete.wav" ]
		},
		"WarpIn": {
			"Paths": [ "Common/warp_in.wav" ]
		},
		"WarpOut": {
			"Paths": [ "Common/warp_out.wav" ]
		},
		"Jump": {
			"Paths": [ "Common/char_jump.wav" ]
		},
		"Land": {
			"Paths": [ "Common/char_land.wav" ]
		},
		"Hurt": {
			"Paths": [ "Jazz/hurt_1.wav", "Jazz/hurt_2.wav", "Jazz/hurt_3.wav", "Jazz/hurt_4.wav", "Jazz/hurt_5.wav", "Jazz/hurt_6.wav", "Jazz/hurt_7.wav", "Jazz/hurt_8.wav" ]
		},
		"HurtSoft": {
			"Paths": [ "Jazz/hurt_1.wav", "Jazz/hurt_5.wav", "Jazz/hurt_6.wav", "Jazz/hurt_7.wav", "Jazz/hurt_8.wav" ]
		},
		"Die": {
			"Paths": [ "Common/gunsm1.wav" ]
		},
		"Airboard": {
			"Paths": [ "Common/char_airboard.wav" ]
		},
		"AirboardTurnStart": {
			"Paths": [ "Common/char_airboard_turn_1.wav" ]
		},
		"AirboardTurnEnd": {
			"Paths": [ "Common/char_airboard_turn_2.wav" ]
		},
		"Copter": {
			"Paths": [ "Common/copter_noise.wav" ]
		},
		"PickupAmmo": {
			"Paths": [ "Pickup/ammo.wav" ]
		},
		"PickupCoin": {
			"Paths": [ "Pickup/coin.wav" ]
		},
		"PickupGem": {
			"Paths": [ "Pickup/gem.wav" ]
		},
		"PickupOneUp": {
			"Paths": [ "Pickup/1up.wav" ]
		},
		"PickupDrink": {
			"Paths": [ "Pickup/food_drink_1.wav", "Pickup/food_drink_2.wav", "Pickup/food_drink_3.wav", "Pickup/food_drink_4.wav" ]
		},
		"PickupFood": {
			"Paths": [ "Pickup/food_edible_1.wav", "Pickup/food_edible_2.wav", "Pickup/food_edible_3.wav", "Pickup/food_edible_4.wav" ]
		},
		"PickupMaxCarrot": {
			"Paths": [ "Jazz/carrot.wav" ]
		},
		"WeaponBlaster": {
			"Paths": [ "Weapon/bullet_blaster_jazz_4.wav" ]
		},
		"WeaponToaster": {
			"Paths": [ "Weapon/toaster.wav" ]
		},
		"WeaponThunderbolt": {
			"Paths": [ "Unknown/unknown_bonus1.wav" ]
		},
		"WeaponThunderboltStart": {
			"Paths": [ "Cinematics/opening_shot.wav" ]
		},
		"WeaponThunderboltEnd": {
			"Paths": [ "Pickup/shield_lightning_bullet_1.wav" ]
		},
		"HookAttach": {
			"Paths": [ "Common/swish_9.wav" ]
		},
		"Buttstomp": {
			"Paths": [ "Common/down.wav" ]
		},
		"Buttstomp2": {

		},
		"EndOfLevel1": {
			"Paths": [ "Common/char_revup.wav" ]
		},
		"EndOfLevel2": {
			"Paths": [ "Weapon/ricochet_bullet_3.wav" ]
		},
		"Spring": {

		},
		"Pole": {
			"Paths": [ "Birdy/fly_1.wav", "Birdy/fly_2.wav" ]
		},
		"Ledge": {
			"Paths": [ "Jazz/ledge.wav" ]
		},
		"IdleBored3": {
			"Paths": [ "Jazz/idle_flavor_3.wav" ]
		},
		"IdleBored4": {
			"Paths": [ "Jazz/idle_flavor_4.wav" ]
		},
		"BonusWarpNotEnoughCoins": {
			"Paths": [ "Object/bonus_not_enough_coins.wav" ]
		}
	}
}