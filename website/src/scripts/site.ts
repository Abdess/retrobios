// Progressive enhancement of the generated pages: table captions, filters
// and keyboard scrolling, the hash lookup on files/ (a pasted hash or a file
// hashed on this device), moved cards, a hash typed in the search, glossary
// terms on a tap, the OS tab of the visitor's system, the setup picked in an
// install box, copy buttons on hashes, the current page in
// the sidebar, and the 404 page's hints.
// Which tables stack on a phone is decided when the page is built
// (src/plugins/rehype-stack-tables.mjs), so the layout is right on first paint.

const HASH_LENGTHS: Record<number, string> = { 8: 'CRC32', 32: 'MD5', 40: 'SHA1', 64: 'SHA256' };
// One line of api/v1/lookup/. `system_name` is read when a record carries it.
// `algorithm` is the hash the value was found under, `declared` the hash
// type the setup or profile wrote for that entry.
type Item = {
	algorithm: string;
	declared?: string;
	layer: string;
	name?: string;
	value: string;
	url: string;
	owner?: string;
	sha1?: string;
	system_name?: string;
	// On an archive-member record: the collection archive holding the member.
	archive?: string;
	// On a retired record: the day the file left, and the file in its place.
	left?: string;
	successor?: string;
};

const siteRoot = () => new URL(import.meta.env.BASE_URL.replace(/\/?$/, '/'), location.origin);
// A pasted hash, or the line a checksum tool prints around it: md5sum
// (`<hash>  <file>`), BSD and shasum --tag (`SHA1 (<file>) = <hash>`),
// certutil (the bytes spaced on a line of their own), Get-FileHash's table.
// The one word of an MD5, SHA1 or SHA256's length is taken: an 8-character
// word in a file name searched for is no CRC32. None or two, and the text is
// kept as typed, which isHash refuses.
const normalizeHash = (raw: string) => {
	const text = raw.trim().toLowerCase();
	const bare = text.replace(/^0x/, '').replace(/\s+/g, '');
	if (/^[0-9a-f]*$/.test(bare)) return bare;
	const words = text.split('\n').flatMap((line) =>
		/^[0-9a-f ]+$/.test(line.trim()) ? [line.replace(/\s+/g, '')] : (line.match(/\b[0-9a-f]+\b/g) ?? []));
	const found = [...new Set(words.filter((word) => word.length > 8 && word.length in HASH_LENGTHS))];
	return found.length === 1 ? found[0] : bare;
};
const isHash = (value: string) => /^[0-9a-f]+$/.test(value) && value.length in HASH_LENGTHS;

// Tables

// The heading a table sits under: the nearest one before it, looking up
// through the blocks that hold it, else the page title.
const headingText = (element: Element): string => {
	for (let block: Element | null = element; block && !block.matches('.sl-markdown-content'); block = block.parentElement) {
		for (let cursor = block.previousElementSibling; cursor; cursor = cursor.previousElementSibling) {
			const heading = /^H[1-6]$/.test(cursor.tagName)
				? cursor
				: cursor.classList.contains('sl-heading-wrapper')
					? cursor.querySelector('h1, h2, h3, h4, h5, h6')
					: null;
			if (heading?.textContent?.trim()) return heading.textContent.trim();
		}
	}
	return document.querySelector('h1')?.textContent?.trim() || document.title;
};

// Each table's name, once per page: two tables under one heading are told
// apart by their order, so no two regions share a label (axe landmark-unique).
const tableNames = new WeakMap<HTMLTableElement, string>();
const tableName = (table: HTMLTableElement): string => {
	let name = tableNames.get(table);
	if (name) return name;
	const tables = [...document.querySelectorAll<HTMLTableElement>('.sl-markdown-content table')];
	const seen = new Map<string, number>();
	for (const each of tables) {
		const heading = headingText(each);
		const count = (seen.get(heading) ?? 0) + 1;
		seen.set(heading, count);
		tableNames.set(each, count === 1 ? heading : `${heading}, table ${count}`);
	}
	name = tableNames.get(table) ?? headingText(table);
	tableNames.set(table, name);
	return name;
};

// A table that overflows is a named stop in the tab order, so a keyboard
// can scroll it (WCAG 2.1.1). Checked again when a closed block opens. All
// widths are read first and the attributes written after, so a page of
// twenty tables is laid out once, not twenty times.
const markScrollable = (tables: HTMLTableElement[]) => {
	const overflowing = tables.map((table) => table.scrollWidth > table.clientWidth + 1);
	tables.forEach((table, index) => setScrollable(table, overflowing[index]));
};

const setScrollable = (table: HTMLTableElement, overflows: boolean) => {
	if (overflows) {
		table.tabIndex = 0;
		table.setAttribute('role', 'region');
		table.setAttribute('aria-label', `${tableName(table)}, scrollable table`);
	} else if (table.getAttribute('role') === 'region') {
		table.removeAttribute('tabindex');
		table.removeAttribute('role');
		table.removeAttribute('aria-label');
	}
};

// The filter box above a long table is written when the page is built
// (src/plugins/rehype-stack-tables.mjs), so the table never moves down once
// drawn. Here it only filters.
// A table folded in a closed block can have its box above the block
// (the provenance lists): typing opens the block on the rows it keeps.
const filterControls = (table: HTMLTableElement) => {
	const controls = table.previousElementSibling;
	if (controls?.matches('.rb-table-filter')) return controls;
	const block = table.closest('details');
	return block?.previousElementSibling?.matches('.rb-table-filter') ? block.previousElementSibling : null;
};

const filterTable = (table: HTMLTableElement) => {
	const controls = filterControls(table);
	if (!controls) return;
	const block = controls.nextElementSibling instanceof HTMLDetailsElement ? controls.nextElementSibling : null;
	const input = controls.querySelector('input');
	const count = controls.querySelector('.rb-table-filter-count');
	if (!input || !count || input.dataset.rbWired) return;
	input.dataset.rbWired = 'true';
	const rows = [...table.querySelectorAll<HTMLTableRowElement>('tbody tr')];
	// Each row's text is read on the first keystroke, not on every page load.
	let searchable: { row: HTMLTableRowElement; text: string }[] | null = null;
	input.addEventListener('input', () => {
		searchable ??= rows.map((row) => ({ row, text: row.textContent!.normalize('NFKD').toLocaleLowerCase() }));
		const query = input.value.trim().normalize('NFKD').toLocaleLowerCase();
		if (block && query) block.open = true;
		let visible = 0;
		for (const entry of searchable) {
			entry.row.hidden = !!query && !entry.text.includes(query);
			if (!entry.row.hidden) visible += 1;
		}
		count.textContent = query
			? `${visible.toLocaleString('en')} of ${rows.length.toLocaleString('en')} rows`
			: `${rows.length.toLocaleString('en')} rows`;
	});
};

// A stacked table of many rows leaves its column names out of the HTML
// (rehype-stack-tables.mjs): each cell gets its own here, as the table nears
// the screen. The name sits in the left room every stacked cell keeps, so
// writing it moves nothing. A header's `title` is its short stacked name.
const stackedLabel = (cell: Element) => cell.getAttribute('title')?.trim() || (cell.textContent?.trim() ?? '');

const labelCells = (table: HTMLTableElement) => {
	if (table.dataset.rbStack !== 'true') return;
	const labels = [...table.querySelectorAll('thead th')].map(stackedLabel);
	for (const row of table.tBodies[0]?.rows ?? []) {
		[...row.cells].forEach((cell, column) => {
			if (labels[column] && !cell.dataset.label) cell.dataset.label = labels[column];
		});
	}
};

const enhanceTables = () => {
	const tables = [...document.querySelectorAll<HTMLTableElement>('.sl-markdown-content table')];
	const enhance = (table: HTMLTableElement) => {
		for (const cell of table.querySelectorAll('thead th')) if (!cell.hasAttribute('scope')) cell.setAttribute('scope', 'col');
		labelCells(table);
		const heading = tableName(table);
		if (!table.querySelector('caption') && !table.closest('.rb-meta-card')) {
			const caption = document.createElement('caption');
			caption.className = 'rb-visually-hidden';
			caption.textContent = heading;
			table.prepend(caption);
		}
		filterTable(table);
	};
	// A table is set up and measured when it nears the screen. Doing all of
	// them at load relaid out every row of a 3,800-row page after its first
	// paint. One that appears later (a block opened, a tab chosen) is handled
	// then.
	const near = new Set<HTMLTableElement>();
	const observer = new IntersectionObserver(
		(entries) => {
			const shown = entries.filter((entry) => entry.isIntersecting).map((entry) => entry.target as HTMLTableElement);
			for (const table of shown) {
				if (!near.has(table)) enhance(table);
				near.add(table);
			}
			if (shown.length) requestAnimationFrame(() => markScrollable(shown));
		},
		{ rootMargin: '400px 0px' },
	);
	// Every table is measured once the page is drawn and idle, before anything
	// is written, so the read finds the layout done instead of forcing it: a
	// keyboard reaches a scrolling table anywhere on the page, not only near
	// the screen.
	const idle = window.requestIdleCallback ?? ((callback: () => void) => setTimeout(callback, 1));
	const start = () =>
		idle(() => {
			// A table in a closed block is not laid out, and measuring it would
			// lay it out: it is measured when its block opens.
			markScrollable(tables.filter((table) => table.checkVisibility?.() ?? true));
			tables.forEach((table) => observer.observe(table));
		});
	if (document.readyState === 'complete') start();
	else addEventListener('load', start, { once: true });
	// A box above a closed block is typed in before its table is ever near
	// the screen: it is wired now.
	for (const table of tables) if (table.closest('details:not([open])') && filterControls(table)) filterTable(table);
	let timer = 0;
	addEventListener('resize', () => {
		clearTimeout(timer);
		timer = window.setTimeout(() => markScrollable([...near]), 150);
	});
};

// Paths

// A long path breaks at its separators, never inside a word. The build
// writes the `wbr` of a page's first BREAK_BUDGET separators
// (rehype-short-code.mjs), since each is an element of the page. The others
// are written here, as their code nears the screen. Same rule: inline code
// over 30 characters, a break after each `/` and `\` but the last character.
const LONG_CODE = 30;
const SEPARATORS = /([/\\])(?!$)/g;
const SEPARATOR = /[/\\](?!$)/;
const unbrokenPath = (code: Element) =>
	!code.closest('pre') &&
	!code.querySelector('wbr') &&
	[...code.childNodes].every((child) => child.nodeType === Node.TEXT_NODE) &&
	(code.textContent ?? '').length > LONG_CODE &&
	SEPARATOR.test(code.textContent ?? '');
const breakPath = (code: Element) => {
	if (!unbrokenPath(code)) return;
	const parts = (code.textContent ?? '').split(SEPARATORS).flatMap((piece, index) => [
		...(piece ? [document.createTextNode(piece)] : []),
		...(index % 2 ? [document.createElement('wbr')] : []),
	]);
	code.replaceChildren(...parts);
};
const breakPaths = () => {
	const observer = new IntersectionObserver(
		(entries) => {
			for (const entry of entries) {
				if (!entry.isIntersecting) continue;
				breakPath(entry.target);
				observer.unobserve(entry.target);
			}
		},
		{ rootMargin: '400px 0px' },
	);
	const idle = window.requestIdleCallback ?? ((callback: () => void) => setTimeout(callback, 1));
	idle(() => {
		for (const code of document.querySelectorAll('.sl-markdown-content code')) {
			if (unbrokenPath(code)) observer.observe(code);
		}
	});
};

// Hashing a file on this device: SHA1 and SHA256 by Web Crypto, MD5 and
// CRC32 here, since Web Crypto has neither. The bytes never leave the page.

const CRC_TABLE = (() => {
	const table = new Uint32Array(256);
	for (let n = 0; n < 256; n += 1) {
		let c = n;
		for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		table[n] = c >>> 0;
	}
	return table;
})();

const crc32 = (bytes: Uint8Array): string => {
	let crc = 0xffffffff;
	for (let i = 0; i < bytes.length; i += 1) crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
	return ((crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, '0');
};

const MD5_SHIFTS = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
const MD5_TABLE = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);

const hexBytes = (bytes: Uint8Array) => [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');

// RFC 1321, block by block over the file's own buffer: no padded copy of a
// 500 MB file.
const md5 = (bytes: Uint8Array): string => {
	const state = new Int32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);
	const words = new Int32Array(16);
	const block = (view: DataView, offset: number) => {
		for (let i = 0; i < 16; i += 1) words[i] = view.getInt32(offset + i * 4, true);
		let [a, b, c, d] = state;
		for (let i = 0; i < 64; i += 1) {
			const round = i >> 4;
			const f = round === 0 ? (b & c) | (~b & d) : round === 1 ? (d & b) | (~d & c) : round === 2 ? b ^ c ^ d : c ^ (b | ~d);
			const g = round === 0 ? i : round === 1 ? (5 * i + 1) % 16 : round === 2 ? (3 * i + 5) % 16 : (7 * i) % 16;
			const shift = MD5_SHIFTS[round * 4 + (i % 4)];
			const sum = (a + f + MD5_TABLE[i] + words[g]) | 0;
			a = d;
			d = c;
			c = b;
			b = (b + ((sum << shift) | (sum >>> (32 - shift)))) | 0;
		}
		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;
	};
	const whole = bytes.length - (bytes.length % 64);
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	for (let offset = 0; offset < whole; offset += 64) block(view, offset);
	const tail = new Uint8Array(bytes.length - whole < 56 ? 64 : 128);
	tail.set(bytes.subarray(whole));
	tail[bytes.length - whole] = 0x80;
	const tailView = new DataView(tail.buffer);
	const bits = bytes.length * 8;
	tailView.setUint32(tail.length - 8, bits >>> 0, true);
	tailView.setUint32(tail.length - 4, Math.floor(bits / 2 ** 32), true);
	for (let offset = 0; offset < tail.length; offset += 64) block(tailView, offset);
	return hexBytes(new Uint8Array(state.buffer));
};

type FileHashes = { sha1: string; md5: string; crc32: string; sha256: string };

const hashFile = async (file: Blob): Promise<FileHashes> => {
	const buffer = await file.arrayBuffer();
	const bytes = new Uint8Array(buffer);
	const [sha1, sha256] = await Promise.all(
		['SHA-1', 'SHA-256'].map(async (name) => hexBytes(new Uint8Array(await crypto.subtle.digest(name, buffer)))),
	);
	return { sha1, md5: md5(bytes), crc32: crc32(bytes), sha256 };
};

// files/?hash= reads one shard of the lookup, named by the first two hex
// characters of the value. ?md5=, ?crc32= and ?sha256= are read the same way.

const HASH_PARAMS = ['hash', 'md5', 'crc32', 'sha256'];

const lookupShard = (value: string): Promise<Item[]> =>
	fetch(new URL(`api/v1/lookup/${value.slice(0, 2)}.json`, siteRoot()))
		.then((response) => (response.ok ? response.json() : { items: [] }))
		.then((shard) => shard.items || []);

const lookupValues = async (values: string[]): Promise<Item[]> => {
	const prefixes = [...new Set(values.map((value) => value.slice(0, 2)))];
	const shards = await Promise.all(prefixes.map(lookupShard));
	const wanted = new Set(values);
	return shards.flat().filter((item) => wanted.has(item.value));
};

type Held = { name: string; path: string; sha1: string; size: number; md5?: string; crc32?: string; sha256?: string };

// Every hash of a collection file, lower case.
const heldHashes = (file: Held) =>
	[file.sha1, file.md5, file.crc32, file.sha256].filter((value): value is string => !!value).map((value) => value.toLowerCase());
type Declared = { name?: string; destination?: string; required?: boolean; [hash: string]: unknown };
type ProfileFile = { name?: string; region?: string | string[]; category?: string; [field: string]: unknown };
type Reader = { name: string; files: ProfileFile[] };

const json = (path: string) =>
	fetch(new URL(path, siteRoot())).then((response) => (response.ok ? response.json() : Promise.reject(response.status)));

const formatSize = (bytes: number) =>
	bytes >= 1024 ** 3 ? `${(bytes / 1024 ** 3).toFixed(1)} GB`
	: bytes >= 1024 ** 2 ? `${(bytes / 1024 ** 2).toFixed(1)} MB`
	: bytes >= 1024 ? `${(bytes / 1024).toFixed(1)} KB`
	: `${bytes} B`;

const code = (text: string) => {
	const element = document.createElement('code');
	element.textContent = text;
	return element;
};

const link = (url: string, ...content: (Node | string)[]) => {
	const element = document.createElement('a');
	element.href = new URL(url, siteRoot()).href;
	element.append(...content);
	return element;
};

const paragraph = (...content: (Node | string)[]) => {
	const element = document.createElement('p');
	element.append(...content);
	return element;
};

const strong = (text: string) => {
	const element = document.createElement('strong');
	element.textContent = text;
	return element;
};

const count = (n: number, one: string, many: string) => `${n.toLocaleString('en')} ${n === 1 ? one : many}`;

const listed = (words: string[]) =>
	words.length < 3 ? words.join(' and ') : `${words.slice(0, -1).join(', ')} and ${words.at(-1)}`;

// A region: value in words, as the system pages write it.
const REGION_WORDS: Record<string, string> = { uk: 'UK', 'asia-ntsc': 'Asia (NTSC)', 'asia-pal': 'Asia (PAL)' };
const regionWord = (region: string) =>
	REGION_WORDS[region] ?? region.replace(/-/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
const CATEGORY_WORDS: Record<string, string> = { bios: 'BIOS', game_data: 'game data', bios_zip: 'BIOS ZIP' };

// The card a collection match points at, read from its manufacturer's file
// of api/v1/systems/: the path in the collection and the size. A console's
// own page (systems/sony-playstation/) is part of its manufacturer's file
// (systems/sony.json), found by dropping words from the end of the slug.
const heldFile = async (item: Item): Promise<Held | undefined> => {
	// Lookup urls are site-absolute (/retrobios/systems/...) since the API
	// names every address from the site root.
	const slug = /(?:^|\/)systems\/([^/]+)\//.exec(item.url)?.[1];
	if (!slug || !item.sha1) return undefined;
	const words = slug.split('-');
	for (let size = words.length; size > 0; size -= 1) {
		const data = await json(`api/v1/systems/${words.slice(0, size).join('-')}.json`).catch(() => undefined);
		if (!data) continue;
		for (const files of Object.values<Held[]>(data.items?.[0]?.consoles ?? {})) {
			const found = files.find((file) => file.sha1 === item.sha1);
			if (found) return found;
		}
		return undefined;
	}
	return undefined;
};

// Whether an entry of a list declares one of *values*, under any of its
// hash fields. Recalbox writes several MD5 in one field, separated by commas.
const HASH_FIELDS = ['sha1', 'md5', 'crc32', 'sha256'];
const declares = (entry: Record<string, unknown>, values: Set<string>) =>
	HASH_FIELDS.some((field) =>
		String(entry[field] ?? '').toLowerCase().split(',').some((hash) => values.has(hash.trim())));

// A setup's own entry for the value, from its contract in api/v1/platforms/:
// where the file goes and whether the setup requires it. *values* are the
// hashes of the file the value names.
const declaredEntry = async (item: Item, values: Set<string>): Promise<Declared | undefined> => {
	const system = decodeURIComponent(new URL(item.url, siteRoot()).hash.slice(1));
	const data = await json(`api/v1/platforms/${item.owner}.json`);
	const files: Declared[] = data.items?.[0]?.contract?.systems?.[system]?.files ?? [];
	const holds = (entry: Declared) => declares(entry, values);
	return files.find((entry) => holds(entry) && entry.name === item.name) ?? files.find(holds);
};

// An emulator by the name its page carries, with the entries of its profile.
const readerProfile = async (owner: string): Promise<Reader | undefined> => {
	const data = await json(`api/v1/emulators/${owner}.json`).catch(() => undefined);
	const profile = data?.items?.[0]?.profile;
	if (!profile) return undefined;
	return { name: String(profile.emulator || profile.display_name || owner), files: profile.files ?? [] };
};

// The entry of a profile that reads the value: by name and hash, else by hash.
const readerEntry = (reader: Reader | undefined, item: Item, values: Set<string>): ProfileFile | undefined => {
	const holds = (entry: ProfileFile) => declares(entry, values);
	return reader?.files.find((entry) => holds(entry) && entry.name === item.name) ?? reader?.files.find(holds);
};

// One value every reader that says something agrees on, else nothing.
const agreed = (values: (string | undefined)[]): string | undefined => {
	const said = new Set(values.filter((value): value is string => !!value));
	return said.size === 1 ? [...said][0] : undefined;
};

// A name a setup writes in place of a file name: EmuDeck lists a hash under
// "system:md5", and any file that has it passes.
const anyName = (name: string) => !name || name.includes(':');

// The column name a stacked row shows where the full one wraps on a phone,
// as rehype-stack-tables.mjs reads a header's `title`.
const STACKED_LABELS: Record<string, string> = { 'Name as declared': 'Declared as' };

// "Hash matched" is the hash the setup's list writes, whatever was pasted:
// Batocera declares an MD5, so its row says MD5 when a CRC32 found it.
const declaredHash = (item: Item) => (item.declared || item.algorithm).toUpperCase();

const setupTable = (rows: { item: Item; entry?: Declared; setup: string }[]) => {
	const table = document.createElement('table');
	const head = table.createTHead().insertRow();
	for (const label of ['Setup', 'Name as declared', 'Destination', 'Hash matched', 'Required']) {
		const cell = document.createElement('th');
		cell.scope = 'col';
		cell.textContent = label;
		if (STACKED_LABELS[label]) cell.title = STACKED_LABELS[label];
		head.append(cell);
	}
	const body = table.createTBody();
	for (const { item, entry, setup } of rows) {
		const row = body.insertRow();
		const name = entry?.name ?? item.name ?? '';
		const destination = entry?.destination;
		const cells: (Node | string)[] = [
			link(item.url, setup),
			anyName(name) ? 'Any name' : code(name),
			destination ? code(destination) : '-',
			declaredHash(item),
			entry?.required === undefined ? '-' : entry.required ? 'Yes' : 'No',
		];
		cells.forEach((content, column) => {
			const cell = row.insertCell();
			cell.dataset.label = stackedLabel(head.cells[column]);
			cell.append(content);
		});
	}
	table.dataset.rbStack = 'true';
	return table;
};

// One declaration per setup, name and section: a value found by two of its
// hashes (a file hashed here) is still one line of the setup's list.
const distinct = (items: Item[], key: (item: Item) => string) => {
	const seen = new Map<string, Item>();
	for (const item of items) if (!seen.has(key(item))) seen.set(key(item), item);
	return [...seen.values()];
};

// The answer first: which file this is, for which system and region, and
// how many setups list it under which names. Then where the collection
// holds it, the setups that list it (where it goes, whether it is
// required), and the emulators that read it, by name.
//
// A setup or a profile declares one hash of a file, the one its list
// writes. When the value matches a file of the collection, the lists are
// read under every hash of that file, so the MD5, the SHA1, the CRC32 and
// the SHA256 of one dump give one answer. Setups and emulators are counted
// per file, by its SHA1.
const renderMatches = async (status: HTMLElement, result: HTMLElement, matched: Item[]) => {
	// A declaration that names the file holding the value: Batocera pins
	// naomi2.zip by the MD5 of a ROM inside it, which no file of the
	// collection has.
	const searched = new Set(matched.map((item) => item.value));
	// A member's record names its archive, which is not the file searched for.
	const carried = [...new Set(matched.flatMap((item) =>
		(item.sha1 && !['archive-member', 'retired'].includes(item.layer) && !searched.has(item.sha1) ? [item.sha1] : [])))];
	const found = carried.length ? [...matched, ...(await lookupValues(carried).catch(() => [] as Item[]))] : matched;
	const held = distinct(found.filter((item) => item.layer === 'collection'), (item) => item.sha1 ?? item.url);
	const files = await Promise.all(held.map((item) => heldFile(item).catch(() => undefined)));
	const looked = new Set(found.map((item) => item.value));
	const others = [...new Set(files.flatMap((file) => (file ? heldHashes(file) : [])))].filter((value) => !looked.has(value));
	const items = others.length ? [...found, ...(await lookupValues(others).catch(() => [] as Item[]))] : found;
	// The file a declaration names: the SHA1 the record carries, else the
	// collection file one of whose hashes it declares.
	const fileOf = (item: Item) =>
		item.sha1 ?? files.find((file) => file && heldHashes(file).includes(item.value))?.sha1;
	const valuesOf = (item: Item) => {
		const file = files.find((each) => each && each.sha1 === fileOf(item));
		return new Set([item.value, ...(file ? heldHashes(file) : [])]);
	};
	const byLayer = (layer: string) => items.filter((item) => item.layer === layer);
	const platforms = distinct(byLayer('platform'), (item) => `${item.owner}|${item.name}|${item.url}`);
	const emulators = distinct(byLayer('emulator'), (item) => `${item.owner}|${item.name}|${item.url}`);
	const owners = [...new Set(emulators.map((item) => item.owner ?? ''))];
	const [entries, names, readers] = await Promise.all([
		Promise.all(platforms.map((item) => declaredEntry(item, valuesOf(item)).catch(() => undefined))),
		json('data/picker/index.json').catch(() => []) as Promise<{ platform: string; name: string }[]>,
		Promise.all(owners.map((owner) => readerProfile(owner))),
	]);
	const setupName = new Map(names.map((entry) => [entry.platform, entry.name]));
	const reader = new Map(owners.map((owner, index) => [owner, readers[index]]));
	const readEntries = emulators.map((item) => readerEntry(reader.get(item.owner ?? ''), item, valuesOf(item)));
	const setups = new Set(platforms.map((item) => item.owner));

	const members = distinct(byLayer('archive-member'), (item) => `${item.sha1}|${item.name}`);
	// A dump a catalog lists and the collection lacks: the Wanted list.
	const wanted = held.length || members.length ? [] : distinct(byLayer('wanted'), (item) => `${item.owner}|${item.name}`);
	const counted = [
		held.length ? count(held.length, 'file in the collection', 'files in the collection')
			: members.length ? count(members.length, 'member of a collection archive', 'members of collection archives')
			: wanted.length ? 'a wanted dump, not in the collection yet'
			: 'not in the collection',
		...(platforms.length ? [`${count(platforms.length, 'declaration', 'declarations')} by ${count(setups.size, 'setup', 'setups')}`] : []),
		...(owners.length ? [count(owners.length, 'emulator that reads it', 'emulators that read it')] : []),
	];
	status.textContent = `Found: ${counted.join(', ')}.`;

	const blocks: Node[] = [];
	const category = agreed(readEntries.map((entry) => entry && CATEGORY_WORDS[String(entry.category ?? 'bios')]));
	const regions = agreed(readEntries.map((entry) => {
		const raw = entry?.region;
		const list = Array.isArray(raw) ? raw : raw ? [String(raw)] : [];
		return list.length ? listed(list.map(regionWord)) : undefined;
	}));
	held.forEach((item, index) => {
		const file = files[index];
		const name = file?.name ?? item.name ?? item.value;
		const system = item.system_name;
		const what: (Node | string)[] = system
			? [', ', link(item.url, system), category ? ` ${category}` : ' file']
			: category ? [`, a ${category} file`] : [];
		// The setups that list this file, whatever hash their list writes.
		const listing = platforms.filter((declared) => (fileOf(declared) ?? item.sha1) === item.sha1);
		const listers = new Set(listing.map((declared) => declared.owner));
		const others = new Map<string, Set<string>>();
		for (const declared of listing) {
			const other = declared.name ?? '';
			if (anyName(other) || other === name) continue;
			if (!others.has(other)) others.set(other, new Set());
			others.get(other)!.add(declared.owner ?? '');
		}
		const renamed = new Set([...others.values()].flatMap((set) => [...set]));
		const otherNames = [...others.keys()].sort();
		const named: (Node | string)[] = [];
		otherNames.forEach((other, position) => {
			if (position) named.push(position === otherNames.length - 1 ? ' and ' : ', ');
			named.push(code(other));
		});
		const verdict: (Node | string)[] = listers.size
			? [
				` ${count(listers.size, 'setup lists', 'setups list')} it`,
				...(renamed.size
					? [`, ${renamed.size.toLocaleString('en')} of them under ${otherNames.length === 1 ? 'another name' : 'other names'}: `, ...named]
					: []),
				'.',
			]
			: [];
		blocks.push(
			paragraph('This is ', code(name), ...what, ...(regions ? [` for ${regions}`] : []), '.', ...verdict),
			paragraph(
				...(file ? ['Held in the collection at ', code(file.path), '. SHA1 ', code(file.sha1), `, ${formatSize(file.size)}. `] : []),
				link(item.url, 'Open its card'),
				'.',
			),
		);
	});
	const retired = held.length ? [] : distinct(byLayer('retired'), (item) => item.sha1 ?? item.value);
	if (!held.length && !members.length && !retired.length && !wanted.length) blocks.push(paragraph('No file in the collection has this hash.'));
	blocks.push(...retired.map(retiredParagraph));
	if (wanted.length) {
		const list = document.createElement('ul');
		for (const item of wanted) {
			const row = document.createElement('li');
			row.append(link(item.url, item.owner ?? ''), ' lists it as ', code(item.name ?? item.value));
			list.append(row);
		}
		blocks.push(
			paragraph(strong('Wanted.'), ' The collection does not hold this dump yet. Anyone who dumped it can ', link('contributing/', 'add it'), '.'),
			list,
		);
	}
	if (members.length) {
		// A ROM the collection holds inside a set: the set's card, by its name.
		const list = document.createElement('ul');
		for (const item of members) {
			const row = document.createElement('li');
			row.append(code(item.name ?? item.value), ' in ', link(item.url, code(item.archive ?? '')));
			list.append(row);
		}
		blocks.push(paragraph(strong('Inside an archive of the collection')), list);
	}
	const shipped = byLayer('data-directory');
	if (shipped.length) {
		const list = document.createElement('ul');
		for (const item of shipped) {
			const row = document.createElement('li');
			row.append(link(item.url, code(item.name || item.value)));
			list.append(row);
		}
		blocks.push(paragraph(strong('In a data directory the packs ship')), list);
	}
	if (platforms.length) {
		blocks.push(
			paragraph(strong('Setups that list it: '), `${count(platforms.length, 'declaration', 'declarations')} by ${count(setups.size, 'setup', 'setups')}`),
			setupTable(platforms.map((item, index) => ({
				item,
				entry: entries[index],
				setup: setupName.get(item.owner ?? '') ?? item.owner ?? '',
			}))),
		);
	}
	if (owners.length) {
		const list = document.createElement('ul');
		emulators.forEach((item) => {
			const row = document.createElement('li');
			row.append(link(item.url, reader.get(item.owner ?? '')?.name ?? item.owner ?? item.name ?? ''));
			if (item.name && item.name !== (files[0]?.name ?? held[0]?.name)) row.append(' as ', code(item.name));
			list.append(row);
		});
		blocks.push(paragraph(strong(`Emulators that read it (${owners.length.toLocaleString('en')})`)), list);
	}
	result.replaceChildren(...blocks);
};

// A file the collection held: its address keeps answering, with the day
// it left and the card of the file in its place.
const retiredParagraph = (item: Item) =>
	paragraph(
		code(item.name || item.value), ` left the collection on ${item.left}. `,
		item.successor ? link(item.url, 'Open the card of the file in its place') : link(item.url, 'Open the page it was on'),
		'.',
	);

const WANTED = 'provenance/#wanted-catalogued-dumps-this-project-does-not-have';

// Nothing the site knows has the value: where a dump of one's own can go.
const renderNoMatch = (status: HTMLElement, result: HTMLElement) => {
	status.textContent = 'No file, setup or emulator the site knows has this hash.';
	result.replaceChildren(
		paragraph('Anyone who dumped it can ', link('contributing/', 'add it'), '.'),
		paragraph('The ', link(WANTED, 'wanted list'), ' names the catalogued dumps the collection still lacks.'),
	);
};

const lookUp = (status: HTMLElement, result: HTMLElement, values: string[]) => {
	status.textContent = 'Looking it up...';
	result.replaceChildren();
	return lookupValues(values)
		.then((matches) => (matches.length ? renderMatches(status, result, matches) : renderNoMatch(status, result)))
		.catch(() => {
			status.textContent = 'The file index could not be read.';
		});
};

// A file chosen on files/ is hashed here, its four hashes shown, and all
// four looked up: a setup may list only the MD5.
const MAX_HASHED = 512 * 1024 ** 2;

const fileHasher = (status: HTMLElement, result: HTMLElement) => {
	const form = document.querySelector('form.rb-file-lookup');
	if (!form) return;
	const box = document.createElement('div');
	box.className = 'rb-file-pick';
	const label = document.createElement('label');
	label.htmlFor = 'rb-file';
	label.textContent = 'Or choose the file';
	const input = document.createElement('input');
	input.type = 'file';
	input.id = 'rb-file';
	const note = paragraph('It is hashed on this device. Nothing is uploaded.');
	note.className = 'rb-file-pick-note';
	const hashes = document.createElement('p');
	hashes.className = 'rb-file-pick-hashes';
	hashes.hidden = true;
	box.append(label, input, note, hashes);
	form.after(box);
	input.addEventListener('change', async () => {
		const file = input.files?.[0];
		if (!file) return;
		hashes.hidden = true;
		if (file.size > MAX_HASHED) {
			status.textContent = `This page hashes files up to ${formatSize(MAX_HASHED)}. ${file.name} is ${formatSize(file.size)}.`;
			result.replaceChildren();
			return;
		}
		status.textContent = `Hashing ${file.name}...`;
		result.replaceChildren();
		let found: FileHashes;
		try {
			found = await hashFile(file);
		} catch {
			status.textContent = `${file.name} could not be read.`;
			return;
		}
		hashes.replaceChildren(
			strong(file.name), ` ${formatSize(file.size)}`,
			...(['sha1', 'md5', 'crc32', 'sha256'] as const).flatMap((algorithm) => [
				document.createElement('br'), `${algorithm.toUpperCase()} `, code(found[algorithm]),
			]),
		);
		hashes.hidden = false;
		const field = document.getElementById('rb-hash') as HTMLInputElement | null;
		if (field) field.value = found.sha1;
		const url = new URL(location.href);
		url.search = `?hash=${found.sha1}`;
		history.replaceState(null, '', url);
		await lookUp(status, result, [found.sha1, found.md5, found.crc32, found.sha256]);
	});
};

// files/?sha1=<sha1> is a file's content address and opens its card
// wherever it is now; files/?hash= also takes an MD5, CRC32 or SHA256 and
// lists every page that names the value.
const resolveFileAddress = () => {
	const status = document.getElementById('rb-file-lookup-status');
	if (!status) return;
	const result = document.createElement('div');
	result.id = 'rb-file-lookup-result';
	status.after(result);
	fileHasher(status, result);
	const params = new URLSearchParams(location.search);
	const permalink = params.has('sha1');
	const raw = params.get('sha1') || HASH_PARAMS.map((key) => params.get(key)).find(Boolean) || '';
	const value = normalizeHash(raw);
	if (!value) return;
	const input = document.getElementById('rb-hash') as HTMLInputElement | null;
	if (input) input.value = value;
	const prefix = permalink && /^[0-9a-f]{12}$/.test(value);
	if (!prefix && !isHash(value)) {
		status.textContent = 'A hash is 8 (CRC32), 32 (MD5), 40 (SHA1) or 64 (SHA256) hexadecimal characters.';
		return;
	}
	if (!prefix && !permalink) {
		lookUp(status, result, [value]);
		return;
	}
	status.textContent = 'Looking it up...';
	lookupShard(value)
		.then((items) => {
			const matches = items.filter((item) =>
				prefix ? item.algorithm === 'sha1' && item.value.startsWith(value) : item.value === value);
			const cards = matches.filter((item) => item.layer === 'collection' || item.layer === 'data-directory');
			const retired = matches.filter((item) => item.layer === 'retired' && item.algorithm === 'sha1');
			if (new Set(cards.map((item) => item.url)).size === 1) {
				location.replace(new URL(cards[0].url, siteRoot()));
			} else if (!cards.length && retired.length) {
				status.textContent = 'This file is no longer in the collection.';
				result.replaceChildren(...distinct(retired, (item) => item.value).map(retiredParagraph));
			} else if (matches.length) {
				return renderMatches(status, result, prefix ? cards : matches);
			} else {
				renderNoMatch(status, result);
			}
		})
		.catch(() => {
			status.textContent = 'The file index could not be read.';
		});
};

// A file card moved to another page keeps its address: an id of the form
// sha1-<12 hex> that this page does not hold is looked up by content, and
// an emulator card listed in the table of a split page opens its page. A
// part of a split emulator page (emulators/mame-files-1/) sends a card id
// it no longer holds to that table: an entry added to the profile moves
// hundreds of cards from one part to the next.
const followMovedCard = () => {
	const id = decodeURIComponent(location.hash.slice(1));
	if (!id) return;
	const target = document.getElementById(id);
	const link = target?.closest('.rb-card-index tr')?.querySelector<HTMLAnchorElement>('a[href]');
	if (link) {
		location.replace(link.href);
		return;
	}
	if (target) return;
	const match = /^sha1-([0-9a-f]{12})$/.exec(id);
	if (match) {
		location.replace(new URL(`files/?sha1=${match[1]}`, siteRoot()));
		return;
	}
	const part = /\/emulators\/(.+)-files-\d+\/?$/.exec(location.pathname);
	if (part && id.startsWith('file-')) location.replace(new URL(`emulators/${part[1]}/#${encodeURIComponent(id)}`, siteRoot()));
};

// A link to a card folded in a table row (emulators with many entries)
// opens its row. Chrome does it on its own. Where the browser left the
// target hidden, the same address is followed again once the row is open,
// so the browser brings the card into view as for any link.
const openTargetBlock = () => {
	const id = decodeURIComponent(location.hash.slice(1));
	const block = id ? document.getElementById(id)?.closest('details') : null;
	if (!block || block.open) return;
	block.open = true;
	location.replace(location.hash);
};

// The site search holds no hashes. A hash typed in it gets "Look up this
// hash" as its first result, and Enter opens the lookup. The pages Pagefind
// finds for the same characters (a file name that holds them, a word that
// starts like them) are no answer: they stay folded under a button that
// says what they are.
const hashLookupRow = (drawer: HTMLElement, value: string) => {
	let row = drawer.querySelector<HTMLElement>(':scope > .rb-search-hash');
	if (!isHash(value)) {
		row?.remove();
		delete drawer.dataset.rbHash;
		delete drawer.dataset.rbPagesShown;
		return;
	}
	drawer.dataset.rbHash = '';
	const target = new URL(`files/?hash=${value}`, siteRoot()).href;
	if (row?.querySelector('a')?.href === target) return;
	if (!row) {
		row = document.createElement('div');
		row.className = 'rb-search-hash';
		drawer.prepend(row);
	}
	delete drawer.dataset.rbPagesShown;
	const anchor = document.createElement('a');
	anchor.href = target;
	anchor.append('Look up this hash');
	const toggle = document.createElement('button');
	toggle.type = 'button';
	toggle.className = 'rb-search-pages';
	toggle.setAttribute('aria-expanded', 'false');
	toggle.textContent = 'Pages that mention these characters';
	toggle.addEventListener('click', () => {
		const open = toggle.getAttribute('aria-expanded') !== 'true';
		toggle.setAttribute('aria-expanded', String(open));
		if (open) drawer.dataset.rbPagesShown = '';
		else delete drawer.dataset.rbPagesShown;
	});
	row.replaceChildren(paragraph(anchor, ` ${HASH_LENGTHS[value.length]} `, code(value)), toggle);
};

// Pagefind lists a page's title twice: once for the page and once for the
// anchor of its h1 (#_top). The second title is hidden, its excerpt kept.
// The `files`, `aliases`, `devices`, `consoles`, `exact` and `terms` fields weigh in
// the ranking and are never shown: a result is not a list of 120 names. Pagefind reuses
// its nodes from one query to the next, so both are worked out again on
// every change.
const UNSHOWN_FIELDS = new Set(['files', 'aliases', 'devices', 'consoles', 'exact', 'terms']);

const tidyResults = (root: Element) => {
	for (const title of root.querySelectorAll<HTMLElement>('.pagefind-ui__result-nested > .pagefind-ui__result-title')) {
		title.hidden = !!title.querySelector('a')?.getAttribute('href')?.endsWith('#_top');
	}
	for (const tags of root.querySelectorAll<HTMLElement>('.pagefind-ui__result-tags')) {
		let shown = 0;
		for (const tag of tags.querySelectorAll<HTMLElement>('.pagefind-ui__result-tag')) {
			tag.hidden = UNSHOWN_FIELDS.has(tag.dataset.pagefindUiMeta ?? '');
			if (!tag.hidden) shown += 1;
		}
		tags.hidden = shown === 0;
	}
};

const hashSearch = () => {
	const root = document.getElementById('starlight__search');
	if (root) {
		const refresh = () => {
			tidyResults(root);
			const input = root.querySelector<HTMLInputElement>('input');
			const drawer = root.querySelector<HTMLElement>('.pagefind-ui__drawer');
			if (input && drawer) hashLookupRow(drawer, normalizeHash(input.value));
		};
		new MutationObserver(refresh).observe(root, {
			childList: true,
			subtree: true,
			characterData: true,
			attributes: true,
			attributeFilter: ['href', 'data-pagefind-ui-meta'],
		});
		root.addEventListener('input', refresh);
	}
	document.addEventListener(
		'keydown',
		(event) => {
			if (event.key !== 'Enter') return;
			const input = event.target as HTMLInputElement;
			if (!input.matches?.('site-search dialog input')) return;
			const value = normalizeHash(input.value);
			if (!isHash(value)) return;
			event.preventDefault();
			event.stopPropagation();
			location.assign(new URL(`files/?hash=${value}`, siteRoot()));
		},
		true,
	);
};

// The OS tabs open on the visitor's own system: the tab its label names, on
// every tab set of the page that shares the "os" sync key. A tab the
// visitor chose before (Starlight keeps it under the sync key and restores
// it as the page draws) wins over the guess, and the guess is not saved as
// a choice. No tab is for iOS or ChromeOS: those keep the first tab.
const OS_SYNC_KEY = 'os';
const OS_TAB_RULES: [RegExp, string][] = [
	[/SteamOS|Valve Steam/i, 'Steam Deck'],
	[/Android/i, 'Android (Termux)'],
	[/iPhone|iPad|iPod|CrOS|Chrome OS/i, ''],
	[/Mac/i, 'macOS'],
	[/Win/i, 'Windows'],
	[/Linux|X11/i, 'Linux'],
];

const osTabLabel = (userAgent: string, platform: string): string =>
	OS_TAB_RULES.find(([pattern]) => pattern.test(userAgent) || pattern.test(platform))?.[1] ?? '';
// End of the OS tab rule.

type SyncedTabs = HTMLElement & { tabs: HTMLElement[]; switchTab(tab: HTMLElement, index: number, sync?: boolean): void };

const savedTab = (key: string): string | null => {
	try {
		return localStorage.getItem(`starlight-synced-tabs__${key}`);
	} catch {
		// Storage refused (a private window, blocked site data): no saved tab.
		return null;
	}
};

const osTabs = () => {
	const sets = [...document.querySelectorAll<SyncedTabs>(`starlight-tabs[data-sync-key="${OS_SYNC_KEY}"]`)];
	if (!sets.length || savedTab(OS_SYNC_KEY)) return;
	const agent = navigator as Navigator & { userAgentData?: { platform?: string } };
	const label = osTabLabel(navigator.userAgent, agent.userAgentData?.platform ?? '');
	if (!label) return;
	customElements.whenDefined('starlight-tabs').then(() => {
		for (const set of sets) {
			const index = set.tabs.findIndex((tab) => tab.textContent?.trim() === label);
			if (index > 0 && set.tabs[index].getAttribute('aria-selected') !== 'true') set.switchTab(set.tabs[index], index, false);
		}
	});
};

// The sidebar lists 91 manufacturers: the current page's link sat below the
// pane, out of sight. On load, and when the phone menu opens, the pane
// scrolls so the link sits a third of the way down. Only the pane scrolls,
// never the page.
const showCurrentPage = () => {
	const pane = document.getElementById('starlight__sidebar');
	if (!pane) return;
	const reveal = () => {
		const current = pane.querySelector<HTMLElement>('[aria-current="page"]');
		if (!current) return;
		const box = pane.getBoundingClientRect();
		const link = current.getBoundingClientRect();
		if (link.top >= box.top && link.bottom <= box.bottom) return;
		pane.scrollTop += link.top - box.top - pane.clientHeight / 3;
	};
	reveal();
	pane.addEventListener('toggle', (event) => {
		if ((event as ToggleEvent).newState === 'open') requestAnimationFrame(reveal);
	});
};

// A glossary term shows its definition on hover; a tap or Enter shows it
// on a phone or to a keyboard, and Escape or a tap elsewhere closes it.
const glossaryTerms = () => {
	const terms = document.querySelectorAll<HTMLElement>('abbr.rb-term');
	if (!terms.length) return;
	const close = () => document.querySelectorAll('abbr.rb-term[data-open]').forEach((term) => term.removeAttribute('data-open'));
	for (const term of terms) {
		term.tabIndex = 0;
		term.setAttribute('role', 'button');
		term.setAttribute('aria-label', `${term.textContent}: ${term.title}`);
		term.dataset.definition = term.title;
		const toggle = (event: Event) => {
			event.stopPropagation();
			const open = term.hasAttribute('data-open');
			close();
			if (!open) term.setAttribute('data-open', '');
		};
		term.addEventListener('click', toggle);
		term.addEventListener('keydown', (event) => {
			if (event.key === 'Enter' || event.key === ' ') {
				event.preventDefault();
				toggle(event);
			} else if (event.key === 'Escape') close();
		});
	}
	document.addEventListener('click', close);
};

// Copy buttons. A system card's hash cell (dd.rb-hash) gets one: in its
// fold, each hash copies itself, and the short SHA1 shown open copies the
// whole value, the fold's first hash. An emulator card's hash and each
// command of an install box's list carry data-copy: the value to copy, or
// empty when the text shown is the value. The buttons are added where the
// reader sees the values, and when a fold opens for the ones inside it, so a
// page of 250 closed folds holds none of them.
// A platform row's button carries its own data-copy: it is not a value to
// give a button.
const COPYABLE = '[data-copy]:not(button), .rb-sys-file dd.rb-hash';

// What the button copies, in words: the label of its grid row, else the
// words before the value ("MD5: ", ", SHA1 ", "RetroArch: "), else the
// label its list item opens on.
const copyLabel = (value: HTMLElement) => {
	const term = (value.tagName === 'DD' ? value : value.closest('dd'))?.previousElementSibling;
	if (term?.tagName === 'DT') return term.textContent?.trim() ?? '';
	const before = (value.previousSibling?.textContent ?? '').replace(/[:\s]+$/, '').split(',').pop()?.trim();
	if (before) return before;
	return /^\s*([^:]+):/.exec(value.closest('li')?.textContent ?? '')?.[1]?.trim() ?? '';
};

// The value's own text, without the button a cell holds.
const shownText = (value: Element) =>
	[...value.childNodes].filter((node) => !(node instanceof HTMLButtonElement)).map((node) => node.textContent).join('').trim();

const copyText = (value: HTMLElement) => {
	const own = value.dataset.copy;
	// An MDX page writes an empty attribute as "true".
	if (own && own !== 'true') return own;
	if (value.matches('dd.rb-hash') && !value.closest('details')) {
		const whole = value.closest('.rb-sys-file')?.querySelector('details dd.rb-hash');
		if (whole) return shownText(whole);
	}
	return shownText(value);
};

const addCopyButtons = (root: ParentNode) => {
	for (const value of root.querySelectorAll<HTMLElement>(COPYABLE)) {
		if (value.hasAttribute('data-copy-ready') || value.closest('details:not([open])')) continue;
		value.setAttribute('data-copy-ready', '');
		const button = document.createElement('button');
		button.type = 'button';
		button.className = 'rb-copy';
		button.textContent = 'Copy';
		// The word that replaces "Copy" is read out.
		button.setAttribute('aria-live', 'polite');
		const label = copyLabel(value);
		button.setAttribute('aria-label', label ? `Copy ${label}` : 'Copy');
		// A grid cell holds its button, a value elsewhere is followed by it.
		if (value.tagName === 'DD') value.append(button);
		else value.after(button);
	}
};

const copyButtons = () => {
	if (!document.querySelector(`${COPYABLE}, button.rb-copy[data-copy]`)) return;
	addCopyButtons(document);
	document.addEventListener('toggle', (event) => {
		const fold = event.target as HTMLDetailsElement;
		if (fold.open) addCopyButtons(fold);
	}, true);
	document.addEventListener('click', async (event) => {
		const button = (event.target as Element).closest?.<HTMLButtonElement>('button.rb-copy');
		if (!button) return;
		// A platform row's button shows a short hash and copies the whole one
		// from data-copy: its text stays, a mark shows for two seconds.
		const own = button.dataset.copy;
		if (own && own !== 'true') {
			try {
				await navigator.clipboard.writeText(own);
				let status = document.querySelector<HTMLElement>('#rb-copy-status');
				if (!status) {
					status = document.createElement('p');
					status.id = 'rb-copy-status';
					status.className = 'rb-visually-hidden';
					status.setAttribute('role', 'status');
					document.body.append(status);
				}
				status.textContent = `Copied ${own}`;
				button.dataset.copied = '';
				window.setTimeout(() => delete button.dataset.copied, 2000);
			} catch {
				// No clipboard: the full value is in the row's details.
			}
			return;
		}
		const value = button.parentElement?.matches(COPYABLE)
			? button.parentElement
			: (button.previousElementSibling as HTMLElement | null);
		if (!value?.matches(COPYABLE)) return;
		try {
			await navigator.clipboard.writeText(copyText(value));
			button.textContent = 'Copied';
		} catch {
			// No clipboard (an insecure page, a refused permission): the value
			// is selected, for Ctrl+C.
			const range = document.createRange();
			range.selectNodeContents(value.tagName === 'DD' && value.firstChild ? value.firstChild : value);
			getSelection()?.removeAllRanges();
			getSelection()?.addRange(range);
			button.textContent = 'Selected';
		}
		window.setTimeout(() => { button.textContent = 'Copy'; }, 1500);
	});
};

// A system's install box: one command, for the setup picked in its list,
// under the site's OS tabs. The box is built with its selected setup's command;
// the choice rewrites the options of each command and its copy text, and is
// remembered for the next box and the next page. Without this script the
// picker stays hidden and the list of every command shows instead.
const SETUP_KEY = 'rb-setup';

const savedSetup = (): string | null => {
	try {
		return localStorage.getItem(SETUP_KEY);
	} catch {
		// Storage refused (a private window, blocked site data): no saved setup.
		return null;
	}
};

// The colours a flag and a value take in the highlighted sh command, read
// from the box's own first command so a rewritten one looks the same.
type ArgStyles = { flag: string; value: string; space: string };

const argStyles = (block: Element): ArgStyles | null => {
	const leaves = [...block.querySelectorAll<HTMLElement>('pre[data-language="sh"] .ec-line .code span')].filter((span) => !span.children.length);
	const at = leaves.findIndex((leaf) => leaf.textContent === '--platform');
	if (at < 0) return null;
	const value = leaves.slice(at + 1).find((leaf) => leaf.textContent?.trim());
	const space = leaves.find((leaf) => leaf.textContent === ' ');
	return { flag: leaves[at].getAttribute('style') ?? '', value: value?.getAttribute('style') ?? '', space: space?.getAttribute('style') ?? '' };
};

// Rewrites the options of a highlighted command, from " --platform": the
// installer's own part keeps its colours, the options take *styles*.
const setCommandArgs = (frame: Element, args: string, styles: ArgStyles | null) => {
	const line = frame.querySelector<HTMLElement>('.ec-line .code');
	if (!line) return;
	const text = line.textContent ?? '';
	const start = text.indexOf(' --platform ');
	if (start < 0) return;
	const walker = document.createTreeWalker(line, NodeFilter.SHOW_TEXT);
	let seen = 0;
	const range = document.createRange();
	for (let node = walker.nextNode(); node; node = walker.nextNode()) {
		const length = node.textContent?.length ?? 0;
		if (seen + length > start) {
			range.setStart(node, start - seen);
			break;
		}
		seen += length;
	}
	range.setEndAfter(line.lastChild!);
	range.deleteContents();
	for (const part of ` ${args}`.split(/(\s+)/)) {
		if (!part) continue;
		const span = document.createElement('span');
		const space = /^\s+$/.test(part);
		const style = space ? styles?.space : part.startsWith('-') ? styles?.flag : styles?.value;
		if (style) span.setAttribute('style', style);
		span.textContent = part;
		// The theme colours a span that has no class: a word kept whole is
		// wrapped, as the build wraps it (ec-unbroken-tokens.mjs).
		if (space) {
			line.append(span);
		} else {
			const whole = document.createElement('span');
			whole.className = 'rb-nb';
			whole.append(span);
			line.append(whole);
		}
	}
	frame.querySelector('.copy button')?.setAttribute('data-code', text.slice(0, start) + ` ${args}`);
};

const installPickers = () => {
	const blocks = [...document.querySelectorAll<HTMLElement>('[data-rb-install]')];
	if (!blocks.length) return;
	const pick = (setup: string | null) => {
		for (const block of blocks) {
			const select = block.querySelector('select');
			if (!select) continue;
			if (setup && [...select.options].some((option) => option.value === setup)) select.value = setup;
			const option = select.selectedOptions[0];
			if (!option) continue;
			const styles = (block as HTMLElement & { rbStyles?: ArgStyles | null }).rbStyles;
			for (const frame of block.querySelectorAll('.expressive-code')) {
				const shell = frame.querySelector('pre')?.dataset.language === 'powershell' ? 'ps' : 'sh';
				setCommandArgs(frame, option.dataset[shell] ?? '', styles ?? null);
			}
		}
	};
	for (const block of blocks) {
		(block as HTMLElement & { rbStyles?: ArgStyles | null }).rbStyles = argStyles(block);
		block.hidden = false;
		const list = block.nextElementSibling;
		if (list instanceof HTMLDetailsElement && list.classList.contains('rb-install-all')) list.open = false;
		block.querySelector('select')?.addEventListener('change', (event) => {
			const setup = (event.target as HTMLSelectElement).value;
			try {
				localStorage.setItem(SETUP_KEY, setup);
			} catch {
				// Storage refused: the choice holds for this page only.
			}
			pick(setup);
		});
	}
	pick(savedSetup());
};

// A platform's file list (div.rb-files) is rows of a details and its copy
// button. The filter box written above a long one hides both of a row.
const filterFiles = () => {
	for (const list of document.querySelectorAll<HTMLElement>('.rb-table-filter + .rb-files')) {
		const controls = list.previousElementSibling!;
		const input = controls.querySelector('input');
		const count = controls.querySelector('.rb-table-filter-count');
		if (!input || !count) continue;
		const rows = [...list.querySelectorAll<HTMLElement>(':scope > details.rb-file')];
		let searchable: { row: HTMLElement; text: string }[] | null = null;
		input.addEventListener('input', () => {
			searchable ??= rows.map((row) => ({
				row,
				text: `${row.querySelector('summary')?.textContent ?? ''} ${row.nextElementSibling?.matches('button.rb-copy') ? row.nextElementSibling.textContent : ''}`
					.normalize('NFKD')
					.toLocaleLowerCase(),
			}));
			const query = input.value.trim().normalize('NFKD').toLocaleLowerCase();
			let visible = 0;
			for (const { row, text } of searchable) {
				row.hidden = !!query && !text.includes(query);
				const button = row.nextElementSibling;
				if (button?.matches('button.rb-copy')) (button as HTMLElement).hidden = row.hidden;
				if (!row.hidden) visible += 1;
			}
			count.textContent = query
				? `${visible.toLocaleString('en')} of ${rows.length.toLocaleString('en')} rows`
				: `${rows.length.toLocaleString('en')} rows`;
		});
	}
};

// "Start with" names the file to get first and links its card, where the
// download is. A console's first file is the most downloaded of the site
// (the PS2's: 436 in three days): its download sits beside its name too,
// the card's own link reused, never a second address.
const startDownloads = () => {
	for (const strong of document.querySelectorAll<HTMLElement>('.sl-markdown-content strong')) {
		if (strong.textContent?.trim() !== 'Start with') continue;
		const block = strong.closest('p')?.nextElementSibling?.matches('ul') && !strong.closest('p')?.querySelector('a[href^="#sha1-"]')
			? strong.closest('p')!.nextElementSibling!
			: strong.closest('p');
		for (const named of block?.querySelectorAll<HTMLAnchorElement>('a[href^="#sha1-"]') ?? []) {
			const card = document.getElementById(named.hash.slice(1))?.closest('.rb-sys-file');
			const source = card?.querySelector<HTMLAnchorElement>('a.rb-download');
			if (!source || named.nextElementSibling?.classList.contains('rb-start-download')) continue;
			const download = document.createElement('a');
			download.className = 'rb-start-download';
			download.href = source.href;
			download.textContent = 'Download';
			download.setAttribute('aria-label', source.getAttribute('aria-label') ?? 'Download');
			named.after(' ', download);
		}
	}
};

// The GitHub page of a repository path typed under this site, or null.
// The address is split before it is decoded, so an encoded slash stays in
// its segment, and a segment that decodes to nothing, '.', '..' or a slash
// gives no link: /blob/..%2F..%2Fother/x led to another account's page.
function githubPathHref(raw: string): string | null {
	const match = raw.replace(/\/$/, '').match(/^(blob|tree|raw)\/(.+)$/);
	if (!match) return null;
	const kind = match[1] === 'raw' ? 'blob' : match[1];
	const segments: string[] = [];
	for (const piece of match[2].split('/')) {
		let segment: string;
		try {
			segment = decodeURIComponent(piece);
		} catch {
			return null;
		}
		if (!segment || segment === '.' || segment === '..' || /[\\/]/.test(segment)) return null;
		segments.push(encodeURIComponent(segment));
	}
	const prefix = `/Abdess/retrobios/${kind}/`;
	const url = new URL(`https://github.com${prefix}${segments.join('/')}`);
	return url.origin === 'https://github.com' && url.pathname.startsWith(prefix) ? url.href : null;
}
// End of the GitHub path rule.

// The 404 page: a search button, and what the address it was asked for
// looks like. The addresses readers reached (counted, wiki/privacy.md): a
// command pasted as a link (/i.ps1%20%7C%20iex), a file name under files/,
// a GitHub path (/blob/main/bios), a section below a page
// (/platforms/emudeck/install). The address is only ever set as text.
const INSTALL_COMMANDS: [string, string][] = [
	['Windows (PowerShell)', 'irm https://abdess.github.io/retrobios/i.ps1 | iex'],
	['Linux, macOS, Steam Deck, handhelds', 'curl -fsSL https://abdess.github.io/retrobios/i | sh'],
];

const openSearch = (query = '') => {
	document.querySelector<HTMLButtonElement>('site-search button[data-open-modal]')?.click();
	if (!query) return;
	// The search box exists once the search has loaded: fill it then.
	const fill = (tries: number) => {
		const input = document.querySelector<HTMLInputElement>('.pagefind-ui__search-input');
		if (input) {
			input.value = query;
			input.dispatchEvent(new Event('input', { bubbles: true }));
		} else if (tries > 0) {
			setTimeout(() => fill(tries - 1), 100);
		}
	};
	fill(30);
};

const hintLine = (...parts: (string | Node)[]) => {
	const line = document.createElement('p');
	line.append(...parts);
	return line;
};

const notFound = () => {
	document.querySelector('[data-rb-open-search]')?.addEventListener('click', () => openSearch());
	const hint = document.getElementById('rb-notfound-hint');
	if (!hint) return;
	const base = siteRoot().pathname;
	const raw = location.pathname.startsWith(base) ? location.pathname.slice(base.length) : location.pathname;
	let rest = raw;
	try {
		rest = decodeURIComponent(rest);
	} catch {
		// A malformed escape stays as typed.
	}
	const show = (...lines: HTMLElement[]) => {
		hint.replaceChildren(...lines);
		hint.hidden = false;
	};

	// A command that a chat or a forum turned into a link.
	if (/^i(\.ps1)?[\s|)(;'"&-]/.test(rest)) {
		const list = document.createElement('ul');
		for (const [where, command] of INSTALL_COMMANDS) {
			const item = document.createElement('li');
			const code = document.createElement('code');
			code.textContent = command;
			item.append(`${where}: `, code);
			list.append(item);
		}
		show(hintLine('This address is an install command, not a page. Paste the command into a terminal, not into the browser:'), list);
		return;
	}
	// A GitHub path: the files are browsed on the repository.
	const href = githubPathHref(raw);
	if (href) {
		const link = document.createElement('a');
		link.href = href;
		link.textContent = 'the same path on GitHub';
		show(hintLine('This is a path of the GitHub repository. Open ', link, '.'));
		return;
	}
	// A file name: the search finds the pages that list it.
	const file = rest.match(/(?:^|\/)([^/]+\.[a-z0-9]{1,5})\/?$/i);
	const word = file ? file[1] : rest.replace(/\/$/, '').split('/').pop() ?? '';
	const lines: HTMLElement[] = [];
	const known = rest.match(/^(emulators|systems|platforms)\/([^/]+)\/?$/);
	if (known) {
		const link = document.createElement('a');
		link.href = new URL(`${known[1]}/`, siteRoot()).href;
		link.textContent = `the list of ${known[1]}`;
		lines.push(hintLine(`No page is named ${known[2]} here. It may be listed under another name in `, link, '.'));
	}
	if (word && word.length <= 60) {
		const button = document.createElement('button');
		button.type = 'button';
		button.className = 'rb-notfound-search';
		button.textContent = `Search for ${word}`;
		button.addEventListener('click', () => openSearch(word));
		lines.push(hintLine(button));
	}
	if (lines.length) show(...lines);
	// A section below a page: the nearest page above it that exists.
	// Empty segments dropped: "//host/x" would read as another site's address.
	const parts = rest.split('/').filter((part) => part && part !== '.' && part !== '..');
	const parents = parts.slice(0, -1).map((_, index) => parts.slice(0, parts.length - 1 - index).join('/'));
	(async () => {
		for (const parent of parents) {
			const url = new URL(`${parent}/`, siteRoot());
			// Only a page of this site, under its base, is fetched or linked.
			if (url.origin !== siteRoot().origin || !url.pathname.startsWith(siteRoot().pathname)) return;
			try {
				if ((await fetch(url, { method: 'HEAD' })).ok) {
					const link = document.createElement('a');
					link.href = url.href;
					link.textContent = url.pathname;
					show(...lines, hintLine('The page above it: ', link, '.'));
					return;
				}
			} catch {
				return;
			}
		}
	})();
};

resolveFileAddress();
followMovedCard();
openTargetBlock();
addEventListener('hashchange', openTargetBlock);
enhanceTables();
breakPaths();
hashSearch();
glossaryTerms();
copyButtons();
filterFiles();
osTabs();
installPickers();
showCurrentPage();
startDownloads();
notFound();
