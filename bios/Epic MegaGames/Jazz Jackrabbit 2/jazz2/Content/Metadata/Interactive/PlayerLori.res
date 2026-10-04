{
	"Version": {
		"Target": "Jazz² Resurrection"
	},

	"Animations": {
		"Idle": {
			"Path": "Lori/idle.aura",
			"FrameRate": 5,
			"States": [ 0 ]
		},
		"Walk": {
			"Path": "Lori/run.aura",
			"FrameRate": 8,
			"States": [ 1, 17 ]
		},
		"Run": {
			"Path": "Lori/dash_start.aura",
			"FrameRate": 12,
			"States": [ 2, 18 ]
		},
		"Jump": {
			"Path": "Lori/jump.aura",
			"States": [ 4 ]
		},
		"RunJump": {
			"Path": "Lori/jump_diag.aura",
			"Flags": 1,
			"States": [ 5, 6 ]
		},
		"Fall": {
			"Path": "Lori/fall.aura",
			"FrameRate": 12.97,
			"States": [ 8 ]
		},
		"FallDiag": {
			"Path": "Lori/fall_diag.aura",
			"States": [ 9, 10, 11 ]
		},
		"Freefall": {
			"Path": "Lori/freefall.aura",
			"States": [ 65536, 65537, 65538, 65539 ]
		},
		"Dash": {
			"Path": "Lori/dash.aura",
			"FrameRate": 20,
			"States": [ 3, 19 ]
		},
		"DashJump": {
			"Path": "Lori/ball.aura",
			"States": [ 7 ]
		},
		"Lookup": {
			"Path": "Lori/lookup_start.aura",
			"Flags": 1,
			"FrameRate": 28,
			"States": [ 64 ]
		},
		"Crouch": {
			"Path": "Lori/crouch_start.aura",
			"Flags": 1,
			"FrameRate": 24,
			"States": [ 32 ]
		},
		"DizzyIdle": {
			"Path": "Lori/dizzy.aura",
			"FrameRate": 6,
			"States": [ 128 ]
		},
		"DizzyWalk": {
			"Path": "Lori/dizzy_walk.aura",
			"FrameRate": 6,
			"States": [ 129, 145 ]
		},
		"Shoot": {
			"Path": "Lori/shoot.aura",
			"FrameRate": 8,
			"States": [ 16, 144 ],
			"Flags": 1
		},
		"CrouchShoot": {
			"Path": "Lori/crouch_shoot.aura",
			"FrameRate": 8,
			"States": [ 48 ],
			"Flags": 1
		},
		"LookupShoot": {
			"Path": "Lori/shoot_ver.aura",
			"FrameRate": 8,
			"States": [ 80 ],
			"Flags": 1
		},
		"Hurt": {
			"Path": "Lori/hurt.aura",
			"FrameRate": 6,
			"States": [ 2048 ]
		},
		"Sidekick": {
			"Path": "Lori/sidekick.aura",
			"FrameOffset": 2,
			"States": [ 512 ]
		},
		"Buttstomp": {
			"Path": "Lori/buttstomp.aura",
			"States": [ 256 ]
		},
		"HookIdleFlavor": {
			"Path": "Lori/vine_idle_flavor.aura",
			"FrameRate": 1.56,
			"States": [ 1073741866 ]
		},
		"Hook": {
			"Path": "Lori/vine_idle.aura",
			"States": [ 12 ]
		},
		"HookLookup": {
			"Path": "Lori/vine_shoot_up_end.aura",
			"States": [ 76 ]
		},
		"HookMove": {
			"Path": "Lori/vine_walk.aura",
			"States": [ 13, 14, 15 ]
		},
		"Copter": {
			"Path": "Lori/copter.aura",
			"FrameRate": 3,
			"States": [ 8192, 8193, 8194, 8195 ]
		},
		"CopterShoot": {
			"Path": "Lori/copter_shoot.aura",
			"FrameRate": 22,
			"States": [ 8208, 8209, 8210, 8211 ]
		},
		"AerialShoot": {
			"Path": "Lori/fall_shoot.aura",
			"FrameRate": 14,
			"States": [ 20, 21, 22, 23, 24, 25, 26, 27, 262160, 262161, 262162, 262163 ]
		},
		"HookShoot": {
			"Path": "Lori/vine_shoot.aura",
			"States": [ 28, 29, 30, 31 ],
			"Flags": 1
		},
		"HookLookupShoot": {
			"Path": "Lori/vine_shoot_up.aura",
			"States": [ 92 ],
			"Flags": 1
		},
		"RunToIdle": {
			"Path": "Lori/run_stop.aura",
			"FrameRate": 10.9,
			"States": [ 1073741824 ]
		},
		"WalkToIdle": {
			"Path": "Lori/walk_stop.aura",
			"FrameRate": 21.9,
			"States": [ 1073741865 ]
		},
		"RevUpSpark": {
			"Path": "Common/explosion_tiny.aura",
			"States": [ 1325400080 ]
		},
		"RevUp": {
			"Path": "Lori/revup.aura",
			"FrameRate": 5,
			"States": [ 524288 ]
		},
		"RevUpStart": {
			"Path": "Lori/revup_start.aura",
			"FrameRate": 80,
			"States": [ 1073741863 ]
		},
		"RevUpEnd": {
			"Path": "Lori/revup_end.aura",
			"FrameRate": 23,
			"States": [ 1073741864 ]
		},
		"RunToDash": {
			"Path": "Lori/dash_start.aura",
			"States": [ 1073741825 ]
		},
		"DashToIdle": {
			"Path": "Lori/dash_stop.aura",
			"FrameRate": 25,
			"States": [ 1073741856 ]
		},
		"FallToIdle": {
			"Path": "Lori/fall_end.aura",
			"States": [ 1073741826 ],
			"FrameRate": 15.76
		},
		"ShootToIdle": {
			"Path": "Lori/shoot_end.aura",
			"FrameRate": 20,
			"States": [ 1073741828 ]
		},
		"HookShootToHook": {
			"Path": "Lori/vine_shoot_end.aura",
			"FrameRate": 24,
			"States": [ 1073741829 ]
		},
		"CopterShootToCopter": {
			"Path": "Lori/copter_shoot_start.aura",
			"FrameRate": 27,
			"States": [ 1073741830 ]
		},
		"FallShootToFall": {
			"Path": "Lori/jump_shoot_end.aura",
			"FrameRate": 29.2,
			"States": [ 1073741872 ]
		},

		"SidekickA": {
			"Path": "Lori/sidekick.aura",
			"FrameCount": 2,
			"FrameRate": 20,
			"States": [ 1073741831 ]
		},
		"SidekickC": {
			"Path": "Lori/sidekick.aura",
			"FrameOffset": 9,
			"FrameRate": 100,
			"States": [ 1073741833 ]
		},
		"SidekickFull": {
			"Path": "Lori/sidekick.aura",
			"FrameCount": 9,
			"FrameRate": 9.5,
			"States": [ 1073741867 ]
		},
		"ButtstompStart": {
			"Path": "Lori/spring.aura",
			"States": [ 1073741834 ]
		},
		"ButtstompEnd": {
			"Path": "Lori/buttstomp_end.aura",
			"FrameRate": 10,
			"States": [ 1073741858 ]
		},
		"PoleH": {
			"Path": "Lori/pole_h.aura",
			"FrameRate": 20,
			"States": [ 1073741835 ]
		},
		"PoleHSlow": {
			"Path": "Lori/pole_h.aura",
			"States": [ 1073741837 ]
		},
		"PoleV": {
			"Path": "Lori/pole_v.aura",
			"FrameRate": 20,
			"States": [ 1073741836 ]
		},
		"PoleVSlow": {
			"Path": "Lori/pole_v.aura",
			"States": [ 1073741838 ]
		},
		"Death": {
			"Path": "Lori/die.aura",
			"FrameRate": 3,
			"States": [ 1073741839 ]
		},
		"WarpIn": {
			"Path": "Lori/warp_in.aura",
			"FrameRate": 10,
			"States": [ 1073741843 ]
		},
		"WarpOut": {
			"Path": "Lori/warp_out.aura",
			"FrameRate": 10,
			"States": [ 1073741844 ]
		},
		"WarpInFreefall": {
			"Path": "Lori/warp_in_freefall.aura",
			"States": [ 1073741847 ]
		},
		"WarpOutFreefall": {
			"Path": "Lori/warp_out_freefall.aura",
			"States": [ 1073741848 ]
		},
		"Spring": {
			"Path": "Lori/spring.aura",
			"States": [ 262144, 262145, 262146, 262147 ]
		},
		"Push": {
			"Path": "Lori/push.aura",
			"FrameRate": 6,
			"States": [ 16384, 16385 ]
		},
		"EndOfLevel": {
			"Path": "Lori/eol.aura",
			"States": [ 1073741846 ]
		},
		"Swim": {
			"Path": "Lori/swim_right.aura",
			"FrameRate": 6,
			"States": [ 4096 ]
		},
		"Lift": {
			"Path": "Lori/lift.aura",
			"Flags": 1,
			"FrameRate": 16,
			"States": [ 131072 ]
		},
		"LiftStart": {
			"Path": "Lori/lift_start.aura",
			"FrameRate": 16,
			"States": [ 1073741859 ]
		},
		"LiftEnd": {
			"Path": "Lori/lift_end.aura",
			"States": [ 1073741860 ]
		},
		"Ledge": {
			"Path": "Lori/ledge.aura",
			"FrameRate": 5,
			"FrameOffset": 1,
			"States": [ 1073741861 ]
		},
		"Airboard": {
			"Path": "Lori/airboard.aura",
			"FrameRate": 6,
			"States": [ 1024 ]
		},
		"Swing": {
			"Path": "Lori/swing.aura",
			"FrameRate": 4,
			"States": [ 32768 ],
			"Flags": 1,
			"FrameOffset": 7
		},
		
		"IdleBored1": {
			"Path": "Lori/idle_flavor_2.aura",
			"FrameRate": 1,
			"States": [ 536870944 ]
		},
		"IdleBored2": {
			"Path": "Lori/idle_flavor_3.aura",
			"FrameRate": 3,
			"States": [ 536870945 ]
		},
		"IdleBored3": {
			"Path": "Lori/idle_flavor_4.aura",
			"FrameRate": 2,
			"States": [ 536870946 ]
		},
		
		"TransformFromFrog": {
			"Path": "Lori/transform_frog_end.aura",
			"FrameRate": 3,
			"States": [ 1073741888 ]
		},
		
		"Corpse": {
			"Path": "Lori/corpse.aura",
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
			"Paths": [ "Lori/level_complete.wav" ]
		},
		"WarpIn": {
			"Paths": [ "Common/warp_in.wav" ]
		},
		"WarpOut": {
			"Paths": [ "Common/warp_out.wav" ]
		},
		"Jump": {
			"Paths": [ "Lori/jump_2.wav", "Lori/jump_3.wav", "Lori/jump_4.wav" ]
		},
		"Land": {
			"Paths": [ "Common/char_land.wav" ]
		},
		"Hurt": {
			"Paths": [ "Lori/hurt_2.wav", "Lori/hurt_3.wav", "Lori/hurt_5.wav", "Lori/hurt_6.wav", "Lori/hurt_7.wav", "Lori/hurt_8.wav" ]
		},
		"HurtSoft": {
			"Paths": [ "Lori/hurt_1.wav", "Lori/hurt_3.wav", "Lori/hurt_4.wav" ]
		},
		"Die": {
			"Paths": [ "Lori/die.wav" ]
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
			"Paths": [ "Pickup/food_edible_1.wav" ]
		},
		"WeaponBlaster": {
			"Paths": [ "Weapon/bullet_blaster_jazz_2.wav", "Weapon/bullet_blaster_jazz_3.wav" ]
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
			"Paths": [ "Lori/fall.wav" ]
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

		},
		"Sidekick": {

		},
		"BonusWarpNotEnoughCoins": {
			"Paths": [ "Object/bonus_not_enough_coins.wav" ]
		}
	}
}