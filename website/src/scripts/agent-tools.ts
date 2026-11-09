// WebMCP tools (https://developer.chrome.com/docs/ai/webmcp): what an AI
// agent browsing the site can ask it directly, instead of reading pages.
// Each tool reads the JSON the site already publishes (api/v1/) or its
// search index, changes nothing and sends nothing anywhere else. A browser
// without WebMCP skips the whole file.

type ToolResult = string;
type Tool = {
	name: string;
	description: string;
	inputSchema: Record<string, unknown>;
	annotations?: { readOnlyHint?: boolean };
	execute: (input: Record<string, unknown>) => Promise<ToolResult>;
};
type ModelContext = { registerTool: (tool: Tool) => Promise<void> | void };

const BASE = import.meta.env.BASE_URL.replace(/\/?$/, '/');
const SITE = new URL(BASE, location.origin);
const json = async <T>(path: string): Promise<T> => {
	const response = await fetch(new URL(path, SITE));
	if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
	return response.json() as Promise<T>;
};
const absolute = (url: string) => new URL(url, location.origin).href;

type LookupItem = { algorithm: string; layer: string; name?: string; value: string; url: string; owner?: string; sha1?: string };
type ProfileFile = Record<string, unknown> & { name?: string; required?: boolean };
type EmulatorDoc = { items: { id: string; profile: { emulator?: string; systems?: string[]; files?: ProfileFile[] } }[] };
type CoreIndex = { items: { name: string; profile: string; preferred?: boolean }[] };

const HASH = /^(?:[0-9a-f]{8}|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/;

const lookupHash: Tool = {
	name: 'lookup_bios_hash',
	description:
		'Find which BIOS or firmware file a hash designates in the RetroBIOS collection, and the emulators or setups that '
		+ 'declare it. Accepts a CRC32 (8 hex characters), MD5 (32), SHA-1 (40) or SHA-256 (64).',
	inputSchema: {
		type: 'object',
		properties: { hash: { type: 'string', description: 'The hash, in hexadecimal.' } },
		required: ['hash'],
	},
	annotations: { readOnlyHint: true },
	async execute({ hash }) {
		const value = String(hash ?? '').trim().toLowerCase().replace(/^0x/, '');
		if (!HASH.test(value)) return 'Not a CRC32, MD5, SHA-1 or SHA-256 value.';
		const shard = await json<{ items: LookupItem[] }>(`api/v1/lookup/${value.slice(0, 2)}.json`);
		const found = shard.items.filter((item) => item.value === value);
		if (!found.length) return `No file in the collection or its profiles has the ${value.length === 8 ? 'CRC32' : 'hash'} ${value}.`;
		return JSON.stringify(found.map((item) => ({ ...item, url: absolute(item.url) })), null, 1);
	},
};

const FILE_FIELDS = ['name', 'path', 'required', 'system', 'size', 'md5', 'sha1', 'crc32', 'sha256', 'region', 'note'];

const emulatorFiles: Tool = {
	name: 'emulator_bios_files',
	description:
		'List the BIOS and firmware files an emulator or libretro core reads, from its profile checked against its source code: '
		+ 'each file name, where it goes, whether the emulator starts without it, and its hashes.',
	inputSchema: {
		type: 'object',
		properties: {
			emulator: { type: 'string', description: 'The emulator or core name, for example "mGBA", "beetle_psx" or "DuckStation".' },
		},
		required: ['emulator'],
	},
	annotations: { readOnlyHint: true },
	async execute({ emulator }) {
		const asked = String(emulator ?? '').trim();
		const key = asked.toLowerCase().replace(/[\s_]+/g, '_');
		const cores = await json<CoreIndex>('api/v1/cores.json');
		const named = cores.items.filter((core) => [core.name.toLowerCase(), core.profile].includes(key)
			|| core.name.toLowerCase().replace(/[\s-]+/g, '_') === key);
		const id = (named.find((core) => core.preferred) ?? named[0])?.profile ?? key.replace(/_/g, '-');
		let doc: EmulatorDoc;
		try {
			doc = await json<EmulatorDoc>(`api/v1/emulators/${encodeURIComponent(id)}.json`);
		} catch {
			return `No emulator profile named "${asked}". The list is at ${absolute(`${BASE}emulators/`)}.`;
		}
		const { profile } = doc.items[0];
		const files = (profile.files ?? []).map((file) =>
			Object.fromEntries(FILE_FIELDS.filter((field) => file[field] !== undefined).map((field) => [field, file[field]])));
		return JSON.stringify({
			emulator: profile.emulator ?? id,
			page: absolute(`${BASE}emulators/${id}/`),
			systems: profile.systems ?? [],
			files,
		}, null, 1);
	},
};

type Pagefind = { search: (query: string) => Promise<{ results: { data: () => Promise<{ url: string; meta: { title?: string }; excerpt: string }> }[] }> };

const searchSite: Tool = {
	name: 'search_retrobios',
	description: 'Search the RetroBIOS site: emulators, consoles, setups (RetroArch, Batocera, EmuDeck...) and guides. Returns the best pages.',
	inputSchema: {
		type: 'object',
		properties: { query: { type: 'string', description: 'Words to search for, for example "dreamcast bios batocera".' } },
		required: ['query'],
	},
	annotations: { readOnlyHint: true },
	async execute({ query }) {
		const words = String(query ?? '').trim();
		if (!words) return 'Nothing to search for.';
		const pagefind = (await import(/* @vite-ignore */ `${BASE}pagefind/pagefind.js`)) as Pagefind;
		const { results } = await pagefind.search(words);
		const top = await Promise.all(results.slice(0, 8).map((result) => result.data()));
		if (!top.length) return `No page matches "${words}".`;
		return JSON.stringify(top.map((page) => ({
			title: page.meta.title ?? '',
			url: absolute(page.url),
			excerpt: page.excerpt.replace(/<[^>]+>/g, ''),
		})), null, 1);
	},
};

// What a setup reads, from the data the file picker reads
// (data/picker/<setup>.json, written by scripts/generate_site.py): the BIOS
// folder and, per system, each file's exact name and size. An assistant
// that answers from it names no file and no folder the data does not hold.
type PickerIndex = { platform: string; name: string; files: number }[];
type PickerSystem = { id: string; title: string; native: string[] };
type PickerData = { platform: string; name: string; folder: string; systems: PickerSystem[]; files: [string, number, number[]][] };

const words = (text: string) => text.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

const setupFiles: Tool = {
	name: 'setup_bios_files',
	description:
		'The BIOS folder of a setup (RetroArch, Batocera, EmuDeck, RetroBat, Recalbox, KNULLI, ROCKNIX, AmberELEC, MiSTer and others) '
		+ 'and the exact file names it reads for a system, from the site\'s data. Use it instead of guessing a folder or a file name: names '
		+ 'are case-sensitive and must not be renamed.',
	inputSchema: {
		type: 'object',
		properties: {
			setup: { type: 'string', description: 'The setup, for example "batocera", "RetroArch" or "EmuDeck".' },
			system: { type: 'string', description: 'A system, for example "PlayStation 2", "psx" or "gba". Without it, the systems are listed.' },
		},
		required: ['setup'],
	},
	annotations: { readOnlyHint: true },
	async execute({ setup, system }) {
		const asked = words(String(setup ?? ''));
		const index = await json<PickerIndex>('data/picker/index.json');
		const found = index.find((item) => item.platform === asked.replace(/ /g, '') || words(item.name) === asked);
		if (!found) return `No setup named "${String(setup)}". Setups: ${index.map((item) => item.name).join(', ')}.`;
		const data = await json<PickerData>(`data/picker/${found.platform}.json`);
		const page = absolute(`${BASE}platforms/${found.platform}/`);
		// RetroArch and EmuDeck keep no single folder: it depends on the device.
		const folder = data.folder || `Depends on the device and its system: ${page}#where-the-files-go`;
		const wanted = words(String(system ?? ''));
		if (!wanted) {
			return JSON.stringify({ setup: data.name, bios_folder: folder, page,
				systems: data.systems.map((item) => ({ id: item.id, title: item.title })) }, null, 1);
		}
		const matches = data.systems
			.map((item, position) => ({ item, position }))
			.filter(({ item }) => [item.id, item.title, ...item.native].some((name) => {
				const said = words(name);
				return said === wanted || said.split(' ').includes(wanted) || said.includes(wanted);
			}));
		if (!matches.length) return `${data.name} lists no system matching "${String(system)}". Call again without system to list them.`;
		const positions = new Set(matches.map(({ position }) => position));
		const files = data.files.filter(([, , systems]) => systems.some((position) => positions.has(position)));
		return JSON.stringify({
			setup: data.name,
			bios_folder: folder,
			systems: matches.map(({ item }) => item.title),
			note: 'Every file the emulators of this setup read for these systems: an emulator reads only some of them '
				+ '(its page names them, emulator_bios_files lists them). Keep each name exactly as written.',
			files: files.slice(0, 200).map(([name, bytes]) => ({ name, bytes })),
			more: Math.max(files.length - 200, 0),
			page,
			install: 'device_setup_command gives the command that installs and checks these files.',
		}, null, 1);
	},
};

// The command an agent runs to set up its user's device, from the same
// options wiki/installer.md documents: the fewest files the games on the
// card need, unless the user asks for everything.
const SH = 'curl -fsSL https://abdess.github.io/retrobios/i | sh -s --';
const PS = '& ([scriptblock]::Create((irm https://abdess.github.io/retrobios/i.ps1)))';

const setupCommand: Tool = {
	name: 'device_setup_command',
	description:
		'The one command that installs the BIOS files a device or computer needs, with RetroBIOS\'s installer. By default it '
		+ 'installs only what the games on the card need to start, which is what most players want. It finds the setup '
		+ '(RetroArch, Batocera, ArkOS, dArkOS, muOS, KNULLI, ROCKNIX...) and its BIOS folder itself.',
	inputSchema: {
		type: 'object',
		properties: {
			shell: { type: 'string', enum: ['sh', 'powershell'], description: '"sh" on Linux, macOS and handhelds (the default), "powershell" on Windows.' },
			everything: { type: 'boolean', description: 'Install every file of the setup\'s list instead of only what the games need. Gigabytes.' },
			bios_folder: { type: 'string', description: 'The BIOS folder, when run on a computer and the card is not found, for example "/media/user/EASYROMS/bios".' },
			games_folder: { type: 'string', description: 'A games folder that is not on the card, one subfolder per system.' },
			platform: { type: 'string', description: 'The setup, only when it is not detected (names from the installer\'s --list-platforms).' },
		},
	},
	annotations: { readOnlyHint: true },
	async execute({ shell, everything, bios_folder, games_folder, platform }) {
		const powershell = shell === 'powershell';
		// The command is pasted into a shell: a value that could close its
		// quotes (PowerShell also ends a string on the typographic ones) or
		// start another option is refused, never escaped.
		const unsafe = /[\u0000-\u001f\u007f'"`‘’‚‛“”„]/;
		for (const [field, value] of [['bios_folder', bios_folder], ['games_folder', games_folder]] as const) {
			if (value !== undefined && (typeof value !== 'string' || !value || unsafe.test(value) || value.startsWith('-'))) {
				return `${field} must be a folder path without quotes or control characters.`;
			}
		}
		if (platform !== undefined && (typeof platform !== 'string' || !/^[a-z0-9_-]+$/.test(platform))) {
			return 'platform must be a setup name such as retroarch or batocera.';
		}
		const run = powershell ? PS : SH;
		const quote = (value: string) => `'${value}'`;
		const place: string[] = [];
		if (platform) place.push(`--platform=${platform}`);
		if (bios_folder) place.push(`--dest=${quote(bios_folder as string)}`);
		const games = everything ? [] : [games_folder ? `--for-games=${quote(games_folder as string)}` : '--for-games', '--required-only'];
		const command = (...more: string[]) => [run, ...place, ...more].join(' ');
		return JSON.stringify({
			preview: command(...games, '--dry-run'),
			install: command(...games, '--yes'),
			check_later: command('--check'),
			notes: [
				'Run the preview first: it writes nothing and lists what would be downloaded.',
				'Run on the device itself, or on a computer with the device\'s card plugged in.',
				'A game the installer cannot identify gets every BIOS of its system, and the run names it.',
				`Guide: ${absolute(`${BASE}llms.txt`)}`,
			],
		}, null, 1);
	},
};

const context = (document as Document & { modelContext?: ModelContext }).modelContext;
if (context?.registerTool) {
	for (const tool of [setupCommand, setupFiles, lookupHash, emulatorFiles, searchSite]) {
		Promise.resolve(context.registerTool(tool)).catch((error) => console.warn(`WebMCP: ${tool.name}:`, error));
	}
}
