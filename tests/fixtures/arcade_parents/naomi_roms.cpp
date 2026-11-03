// Fixture in the shape of flycast core/hw/naomi/naomi_roms.cpp
const BIOS_t BIOS[] =
{
	{
		"naomi",
		{
			{ 1, "epr-21576h.ic27", 0x000000, 0x200000, 0xd4895685 },
		}
	},
	{
		"naomi-jp-d",
		{
			{ 0, "epr-21576d.ic27", 0x000000, 0x200000, 0x3b2afa7b },
		},
		"naomi"
	},
	{
		"awbios",
		{
			/* "commented", { 9, "x" } */
			{ 1, "bios0.ic23", 0x000000, 0x020000, 0x719b2b0b },
		}
	},
	{ nullptr }
};

const Game Games[] =
{
    // "not a game", nullptr,
    {
        "gram2000",
        nullptr,
        "Giant Gram 2000",
        0x0b000000,
        0x7f805c3f,
        nullptr,
        M1,
        ROT0,
        {
            { "epr-23377.ic11",  0x0000000, 0x0400000, 0x4ca3149c },
        },
		nullptr,
		&giant_gram_inputs,
    },
    {
        "kofnw",
        nullptr,
        "The King of Fighters Neowave",
        0x08000000,
        0,
        "awbios",
        AW,
        ROT0,
        {
            { "ax2201p01.ic12", 0x0000000, 0x0800000, 0xb1fff0c8 },
        },
    },
    {
        "jpgame",
        "gram2000",
        "Japan only, a brace } in a string",
        0x08000000,
        0,
        "naomi-jp-d",
        M1,
        ROT0,
        {
            { "x.ic11", 0x0000000, 0x0800000, 0x00000001 },
        },
    },
    {
        "ikaruga",
        nullptr,
        "Ikaruga",
        0x8000000,
        0,
        nullptr,
        GD,
        ROT270,
        {
            { "317-0323-jpn.pic", 0, 0x4000 },
        },
        "ikaruga",
    },
    {
        "bad",
        nullptr,
        "Unknown BIOS name",
        0x8000000,
        0,
        "nosuchbios",
        M1,
        ROT0,
        {
            { "b.ic11", 0, 0x4000 },
        },
    },
    { nullptr }
};
