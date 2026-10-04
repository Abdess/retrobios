;; Copyright 1995 Crack dot Com,  All Rights reserved
;; See licensing information for more details on usage rights

;; all messages that need translation here
;; Latest version of this file is "V-E"  (version E=1.47)

(select section
	('game_section

	 ;; XXX: Mac Abuse implements these
	 ;(setq double_pix         "Double Pixel Mode")
	 ;(setq scanlined_pix      "Scan skip Mode")
	 ;(setq single_pix         "Single Pixel Mode")
	 ;(setq smooth_pix         "Smoothed Pixel Mode")
	 ;(setq round_pix          "Rounded Pixel Mode")

	 /********** New for Version E (1.51)   **************/
	 (setq level_name         "Level name")
	 (setq FILENAME           "FILENAME")
	 (setq CHAT               "CHAT")
	 (setq resync             "Clients are re-syncing, please wait...")
	 (setq slack              "Disconnect slackers")
	 (setq hold!              "Hold on!")
	 (setq waiting            "Waiting for data...")
	 (setq Error              "Error")
	 (setq locating           "Attempting to locate server %s, please wait\n")
	 (setq unable_locate      "unable_locate")
	 (setq located            "Server located!  Please wait while data loads....\n")
	 (setq no_prot            "No network protocols installed\n")
	 (setq Installed          "Installed")
	 (setq Not_Installed      "Not Installed")
	 (setq calc_crc           "Net : calculating file CRC's")
	 (setq edit_saved         "Edit info has been saved")
	 (setq saveas_name        "Saveas name")
	 (setq l_light            "light")
	 (setq l_fg               "fg")
	 (setq l_bg               "bg")
	 (setq New?               "New?")
	 (setq l_EDIT             "EDIT")


	 /********** New for Version D (1.46)   **************/

	 (setq ant_hide           "hiden (1=true,0=false)")
	 (setq ant_total          "total")
	 (setq ant_type           "type (0..7)")
	 (setq obj_frames         "frames till arrival")
	 (setq obj_frame          "current frame")
	 (setq respawn_reg        "frames to regenerate")
	 (setq conc_flash         "flash [1=on]")
	 (setq bomb_blink         "blink time")
	 (setq lightin_speed      "flash_speed 0..9")
	 (setq gate_delay_time    "delay_time")
	 (setq gate_pulse_speed   "pulse_speed")
	 (setq pusher_speed       "push speed")
	 (setq spring_yvel        "set yvel to?")
	 (setq train_msg_num      "message num")
	 (setq obj_holder_xoff    "x offset")
	 (setq obj_holder_yoff    "y offset")
	 (setq obj_holder_del     "delete if off (1=yes)")
	 (setq spray_delay        "delay")
	 (setq spray_start        "start angle")
	 (setq spray_end          "end angle")
	 (setq spray_speed        "angle speed")
	 (setq spray_cangle       "current angle")
	 (setq d_track_speed      "tracking speed")
	 (setq track_fspeed       "fire speed")
	 (setq track_burst        "burst total")
	 (setq track_cont         "continue delay")
	 (setq track_sangle       "start angle")
	 (setq track_eangle       "end   angle")
	 (setq track_cangle       "current angle")
	 (setq jug_throw_spd      "throw speed (0..255)")
	 (setq jug_throw_xv       "throw xvel")
	 (setq jug_throw_yv       "throw yvel")
	 (setq jug_stat           "stationary? (1=yes,0=no)")
	 (setq rob_noturn         "no turn around (1=on)")
	 (setq rob_hide           "hiden start (1=hiden,0=visable)")
	 (setq who_fdelay         "fire_delay")
	 (setq who_bdelay         "burst_delay")
	 (setq who_btotal         "burst_total")
	 (setq who_mxv            "max xvel")
	 (setq who_myv            "max yvel")
	 (setq wrob_fdelay        "fire delay")
	 (setq wrob_bdelay        "burst delay")
	 (setq wrob_btotal        "burst total")
	 (setq wrob_mxv           "Max xvel")
	 (setq wrob_myv           "Max Yvel")
	 (setq dimmer_step_amount "step amount")
	 (setq dimmer_steps       "dim steps")
	 (setq dimmer_dist        "activate distance")
	 (setq dimmer_dedist      "deactivate distance")
	 (setq dimmer_silent      "slient mode (1=yes,0=no)")
	 (setq restart_station    "station number")
	 (setq next_level         "next_level")
	 (setq plat_speed         "speed")
	 (setq plat_2speed        "second speed")
	 (setq plat_pos           "current pos (0..speed)")
	 (setq plat_wait          "max wait time")
	 (setq amb_num            "sound # (0-15)")
	 (setq amb_vol            "volume (0-127)")
	 (setq amb_rep            "repeat delay (0=no repeat)")
	 (setq amb_rand           "random delay (0=none)")
	 (setq switch_reset       "reset time")
	 (setq sens_onxd          "(on) x dist")
	 (setq sens_onyd          "(on) y dist")
	 (setq sens_offxd         "(off) x dist")
	 (setq sens_offyd         "(off) y dist")
	 (setq sens_reset         "(off) reset time")
	 (setq sens_unoff         "unoffable (1=yes)")
	 (setq sens_cs            "current state")
	 (setq tp_amb             "ambient setting")



	 (setq ai_xvel            "Xvel    ")
	 (setq ai_yvel            "Yvel    ")
	 (setq ai_xacel           "Xacel   ")
	 (setq ai_yacel           "Yacel   ")
	 (setq ai_stime           "ST time ")
	 (setq ai_gravity         "gravity ")
	 (setq ai_health          "Health  ")
	 (setq ai_morph           "MorphPr ")
	 (setq ai_type            "ai type ")
	 (setq ai_state           "ai state")
	 (setq ai_fade            "fade 0-15")

	 (setq a_ambient          "Ambient      ")
	 (setq a_aspeed           "Ambient speed")
	 (setq a_view_xoff        "View xoff    ")
	 (setq a_view_yoff        "View yoff    ")
	 (setq a_view_xspd        "View x speed ")
	 (setq a_view_yspd        "View y speed ")
	 (setq saved_game         "Saved game savegame.spe")
	 (setq saved_level        "Saved level '%s'..\n")
	 (setq _scroll            "scroll")    ; as in left-right, up-down
	 (setq ap_width           "width ")
	 (setq ap_height          "height")
	 (setq ap_name            "name")
	 (setq ap_pal             "Add palette")
	 (setq mouse_at           "Mouse at location %d, %d\n")


	 (setq l_links            "Links")
	 (setq l_light            "Light")
	 (setq l_char             "Char")
	 (setq l_back             "Back")
	 (setq l_bound            "Bound")
	 (setq l_fore             "Fore")


	 (setq SHOW?              "SHOW?")
	 (setq back_loss (concatenate 'string "This scroll rate decreases the size of the background map\n"
				      "Tiles may be lost, are you sure you want to do this?\n"))
	 (setq WARNING            "WARNING")
	 (setq x_mul              "X mul")    ; X multiple
	 (setq y_mul              "Y mul")
	 (setq x_div              "X div")    ; X divisor
	 (setq y_div              "Y div")

	 /*********** New for Version 1.45 ***********************/
	 (setq file_top           "File")
	 (setq edit_top           "Edit")
	 (setq window_top         "Windows")
	 (setq menu1_load         "Load Level")
	 (setq menu1_save         "Save Level (S)")
	 (setq menu1_saveas       "Save level as")
	 (setq menu1_savegame     "Save game")
	 (setq menu1_new          "New level")
	 (setq menu1_resize       "Resize map")
	 (setq menu1_suspend      "Suspend non-players")
	 (setq menu1_toggle       "Play mode toggle (TAB)")
	 (setq menu1_savepal      "Save Palettes         ")
	 (setq menu1_startc       "Start cache profile   ")
	 (setq menu1_endc         "End cache profile     ")
	 (setq menu1_quit         "Quit      (Q)")

	 (setq menu2_light        "Toggle light")
	 (setq menu2_scroll       "Set scroll rate")
	 (setq menu2_center       "Center on player   (c)")
	 (setq menu2_addpal       "Add palette")
	 (setq menu2_delay        "Toggle Delays      (D)")
	 (setq menu2_god          "God mode")
	 (setq menu2_clear        "Clear weapons (z)")
	 (setq menu2_mscroll      "Mouse scroll")
	 (setq menu2_lock         "Lock palette windows")
	 (setq menu2_raise        "Raise all foreground")
	 (setq menu2_names        "Toggle object names")
	 (setq menu2_map          "Toggle map        (m)")
	 (setq menu2_view         "Disable view shifts")
	 (setq menu2_alight       "Disable Autolight (A)")
	 (setq menu2_fps          "Show FPS/Obj count")

	 (setq menu3_fore         "Foreground  (f)")
	 (setq menu3_back         "Background  (b)")
	 (setq menu3_layers       "Draw layers (L)")
	 (setq menu3_light        "Lighting    (l)")
	 (setq menu3_pal          "Palettes    (p)")
	 (setq menu3_objs         "Objects     (o)")
	 (setq menu3_console      "Console     (/)")
	 (setq menu3_toolbar      "Tool Bar    (a)")
	 (setq menu3_prof         "Profile     (P)")
	 (setq menu3_save         "Save positions")




	 (setq level_size "Level size")
                           ; 012345678901234567 (please keep same allignment of Name level & total)
	 (setq score_header "Name              Level Total")   ; V-E
	 (setq space_cont "Press SPACEBAR to continue")        ; V-E
	 (setq no_saved "No saved game")

	 (setq lvl_2   "Small") ; V-C added
	 (setq lvl_4   "Medium") ; V-C added
	 (setq lvl_8   "Large") ; V-C added

	 (setq status  "Status..")    ; V-A added
	 (setq Station "Station #")   ; V-A added
	 (setq secured " secured!")   ; V-A added
	 (setq loading "loading %s")  ; V-A added

         (setq gamma_msg "Select the darkest grey visible on your\nmonitor then click the check mark")
	 (setq telep_msg "Press down to teleport")

	 (defun get_train_msg (message_num)
	   (select message_num
                   ;   0123456789012345678901234567890123456789012345678901234567890123456789
		   ;  "--------------------------------------------------------------------"  ; V-A
		   ; Please keep all strings below shorter than the above line.               ; V-A
		   (0 "Aim gun with mouse, fire with left mouse button")
		   ;(0 "Aim gun with mouse, fire with left mouse button") XXX: Mac Abuse
		   (1 "Collect ammo to increase firing speed")
                   (2 "Press the down key to activate objects. This is a switch.")
		   (3 "This console saves the state of the game, press down")
		   (4 "Press down to activate platform")
		   (5 "Hold down the right mouse button to use special powers")
		   (6 "Use the CTRL & INS keys to select weapons")
		   ;(5 "You can now use the special key to use your special powers") XXX: Mac Abuse
		   ;(6 "You can now select weapons with the selection keys") XXX: Mac Abuse
		   (7 "Press the up key to climb ladders")
		   (8 "Press the down key to start!")

		   (9 "Shoot hidden walls to destroy them")
		   (10 "Shoot switch ball to activate")
		   (11 "Press down to teleport")
		   ))

	 (setq not_there       "This game has stopped running")
	 (setq max_error       "Max players should be greater than or equal to Min players") ; V-C changed


         ;(setq min_error      "Min players should be 1-8\nMin players must be less than or equal to Max players")  ; V-A changed, V-B deleted

	 (setq port_error      "Game number should be 1-9")       ; V-A changed
	 (setq kill_error      "Kills to win should be 1-99")      ; V-A changed
         (setq name_error      "Bad string for your name")         ; V-B changed
	 (setq game_error      "Bad string for game name")         ; V-B added
	 (setq input_error     "Input Error")
	 (setq ok_button       "OK")
	 (setq cancel_button   "CANCEL")
	 (setq kills_to_win    "Kills to win")
	 (setq max_play        "Maximum # of players")
	 (setq min_play        "\nMinimum # of players")          ; V-B (added \n)
	 (setq use_port        "Game number")
	 (setq your_name       "Your name")
         (setq max_players     "The server already has its maximum number players, try again later\n  Get back to work!!\n")
	 (setq net_not_reg     "Sorry you cannot play against this server with a demo version\n")
	 (setq min_wait        "Waiting for %d more player(s) to join!")
	 (setq lev_complete    "Level Completed!")
	 ;(setq lev_complete    "Level %d Completed!") XXX: Mac Abuse
	 (setq no_low_mem      "Not enough low memory")
	 (setq no_mem          "Not enough memory")

         ; this is not used right now...
         ;(setq server_not_reg  (concatenate 'string "Sorry server is running demo version of ABUSE,\n"
	 ;                                           "to avoid compatiblity issues please use the -share option\n"))

         (setq server_port     "Server Port")
         (setq server_name     "Game Name")              ; V-B
	 (setq Networking      "Networking")
         (setq server          " Start New Net Game  ")
         (setq client          " Join Existing Game  ")
         (setq single_play     "    Exit Net Game    ")  ; V-A
	 (setq cancel_net      "      Cancel         ")


         (setq ic_return       "Return to Game")        ; ----
         (setq ic_quit         "Quit Abuse")            ;  |
	 (setq ic_volume       "Volume Control")        ;  |
	 (setq ic_gamma        "Gamma Correction")      ;  |
	 (setq ic_easy         "Difficulty : Wimp")     ;  |
	 (setq ic_medium       "Difficulty : Easy")     ;  |
	 (setq ic_hard         "Difficulty : Normal")   ;  \/
	 (setq ic_extreme      "Difficulty : Extreme")  ; don't make any strings longer than this!
         (setq ic_load         "Load Saved Game")       ;  /\
         (setq ic_start        "Start New Game")        ;  |
	 (setq ic_sell         "Credits")               ;  |
	 ;; XXX: Mac Abuse
	 ;(setq ic_mackeys      "Setup Keys")
	 ;(setq ic_macconf      "Screen Options")
	 (setq ic_networking   "Networking")            ; ----


	 (setq no_file         "Could not find file '%s'")
	 (setq SFXv            "Sound")  ; this needs to be <=6 characters!!
	 (setq MUSICv          "Music")  ; this needs to be <=6 characters!!

	 (setq to_be_continued "To be continued.....")
         (setq no_edit         "This version of ABUSE does not have editing features")
         (setq no_hirez        "Hi-rez is only available for edit mode (-edit)")
	 (setq no2             "Cannot use -2 with -edit")
	 (setq no_pals         "No palettes defined")
         (setq unchop1         "usage : unchop xsize ysize\n")
         (setq size1           "usage : size width height\n")
	 (setq name_now        "level name is now '%s'\n")
	 (setq esave           "edit save : writing edit.lsp\n")
	 (setq nd_player       "Cannot delete player!\n")
	 (setq d_nosel         "No selected object or light to delete.")
	 (setq forward?        "Forward which object?")
	 (setq back?           "Back which object?")
         (setq aitype?         "Ai type for who?")
	 (setq prof_off        "Cache profiling is now off.")
	 (setq prof?           "Cache profiling isn't on!")
	 (setq sure?           "Are you sure?")
	 (setq width_          "width")
	 (setq height_         "height")
	 (setq suspend_on      "Non-players will not be executed")
	 (setq suspend_off     "Suspend mode off")
	 (setq quit_title      "Quit?")
	 (setq YES             "YES")
	 (setq NO              "NO")
	 (setq seqs_off        "Sequential screen shots off\n")
	 (setq seqs_on         "Sequential screen shots on (1 per 5 sec)\n")
	 (setq ms_on           "Mouse scrolling enabled\n")
	 (setq ms_off          "Mouse scrolling disabled\n")
	 (setq pal_lock        "Palettes are locked")
	 (setq pal_unlock      "Palettes are unlocked")
	 (setq vs_dis          "View shift disabled")
	 (setq vs_en           "View shift enabled")
	 (setq fg_r            "All foreground tile will be raised")
	 (setq fg_l            "All foreground tile will be lowered")
	 (setq no_clone        "Cannot clone player!\n")
	 (setq no_edit.lsp     "unable to open edit.lsp for writing")
	 (setq missing_sym     "Missing language symbol!")
	 (setq delay_off       "Delay off")
	 (setq delay_on        "Delay on")
	 (setq too_big         "This is too big, please use smaller numbers!")
	 (setq LOAD            "LOAD")   ; don't let this get too long
	 (setq SAVE            "SAVE")   ; don't let this get too long


	 (setq net_not_reg
	       (concatenate 'string "Sorry, this server is running REGISTERED ABUSE and you are not.\n"
			    "Ask the server operator to run with -share option or better yet,\n"
                            "buy ABUSE. Registered net games are more fun because you can fly,\n"
			    "turn invisible and have more weapons to duke it out with\n"))
	 (setq server_not_reg
	       (concatenate 'string
                            "This is server is not running the registered version of ABUSE, and\n"
                            "you are (thanks!).  So there are no conflicts between the two games,\n"
                            "please start with the -share option when connecting to this server\n"
                            "Example : abuse -net somewhere.someplace.net -share\n"))



	 (setq thank_you "Thank you for playing Abuse!\n\n")     ; V-A

         (setq load_warn nil)
         (setq end_msg thank_you)

         (setq load_warn T)

         (setq plot_start
               (concatenate 'string
                            "You are Nick Vrenna. It is the year 2009.  You have been falsely incarcerated "
                            "inside a high security underground prison where illegal genetic experiments "
                            "are taking place.\\n"
                            "Alan Blake, the head research scientist, has isolated the specific gene which "
                            "causes violence and aggression in humans.  This genetic sequence, called "
                            '(#\") "Abuse" '(#\") ", is highly infectious, causing horrific transformations and grotesque "
                            "side-effects.  You are the only person to show immunity to it. \\n"
                            "A prison riot erupts, and in the confusion all the cell doors are opened.  Soon "
                            "everyone, guards and convicts alike, become infected and transform into a "
                            "horde of mutants which take over the building.\\n"
                            "Your only chance for escape is to don battle armor and reach the Control Room "
                            "situated in the structure's deepest level.  You must first stop the prison's "
                            "Abuse-infected water supply from contaminating the outside world.   Freedom and "
                            "the fate of the world now depend on you. "))



         (setq plot_middle
               (concatenate 'string
                            "You have survived the initial outbreak, but you are still lost deep "
                            "within the prison. So far it's been suspiciously easy. \\n"
			    "If you want to break out - the real ABUSE lies ahead. "))


         (setq plot_end
               (concatenate 'string
                            "You've survived impossible odds and made it to the Control Room.  "
                            "By pulling the switch, you have diverted the water supply and stopped the spread of Abuse!\\n "
                            "CONGRATULATIONS!  YOU'RE HOWLING!!!"))
;; XXX: Mac Abuse uses this
;	 (setq thanks_text
;               (concatenate 'string
;                            "Bungie Crew\\n"
;                            "- Production Manager "
;                            "- Tuncer Deniz\\n"
;                            "- Development Manager "
;                            "- Eric Klein\\n"
;                            "- Packaging "
;                            "- Randy Nelsen\\n"
;                            "- Damage & Spin\\n"
;                            "- Alexander Seropian\\n"
;                            "- Jay Barry\\n"
;                            "- Alex Rosenberg\\n"
;                            "- Doug Zartman\\n"
;                            "- Jonas Enroth\\n"
;                            "Special Thanks to:\\n"
;                            "- Gnu Foundation\\n"
;                            "- Steven Donaldson\\n"
;                            "- Carly Staehlin for voices\\n"
;                            "Apple Game Evangelists/Engineers\\n"
;                            "- James Osborne for networking\\n"
;                            "- Mark Gavini\\n"
;                            "- Steve Bollinger\\n"
;                            "- Chris DeSalvo\\n"
;                            "- Michael Evans\\n"
;                            "- Cary Farrier\\n"
;                            "- and others...\\n"
;                            "Beta Testers\\n"
;                            "Chris Yeh, "
;                            "Matt Lee, "
;                            "Kaoru Ueda, "
;                            "Cameron Logie, "
;                            "Zachary Zeliff, "
;                            "Francis W. Sweigart, "
;                            "Dan Merchant, "
;                            "Tim Seufert, "
;                            "Donald Lawton, "
;                            "Ryan Mack, "
;                            "Kenneth R Brownfield, "
;                            "Caleb Corey, "
;                            "Michael Saji, "
;                            "Jesse Shrieve, "
;                            "Jedd Horvath, "
;                            "Mark Woodward, "
;                            "Michael Hale, "
;                            "Wesley Arnett, "
;                            "Brian Carter, "
;                            "Will Starck, "
;                            "Krzysztof Murawski, "
;                            "John Whitney, "
;                            "Ian Harford, "
;                            "Robert Steel, "
;                            "Joseph T. Hegeman, "
;                            "Dave Harkness, "
;                            "Marc Jordan, "
;                            "Kenyon Kopp, "
;                            "Peter Worley, "
;                            "Peter Johnson, "
;                            "Michael Roca Jr., "
;                            "Preston Leingang Jr., "
;                            "Jonathan Biebesheimer, "
;                            "Chad G Poland, "
;                            "James R Graham, "
;                            "Karl L Jayne, "
;                            "Patrick Hearon, "
;                            "Joe Trussell, "
;                            "Matthew Fleming, "
;                            "Dave Lovell, "
;                            "Ben Eloy, "
;                            "Anthony Yvanovich, "
;                            "Andre Snyder, "
;                            "David Tessler, "
;                            "Brian Johansen, "
;                            "Scott Mullen, "
;                            "Jason Budravage, "
;                            "and Jonah Kowall\\n"
;                            "\\nIcepops!\n"))
	)
)
