// The wanted page's reading of public/data/wanted.json (scripts/sitewanted.py):
// which entries a hashed file is, and where its upload goes. An entry
// with no h is known by its name only: a dropped file meets it by name,
// and the review of the upload decides.

import type { FileHashes } from './hashes.ts';

export type Entry = {
	n: string;
	h?: { sha1?: string[]; sha256?: string[]; md5?: string[]; crc32?: string[] };
	w: number[];
	s?: number[];
	r?: number;
	z?: number[];
	d?: string;
	u?: string;
	l?: [string, string][];
	f?: number;
	t?: string;
	v?: number;
};

export type Wanted = {
	upload: string;
	issue: string;
	limit: number;
	readers: [string, string, string][];
	systems: string[];
	folders: string[];
	entries: Entry[];
};

// A declaration is met when every hash it writes is the file's, as
// resolve_local_file reads it. An md5 cut short (Batocera writes 29
// characters) is compared as a prefix: the list keeps a cut only when no
// other wanted md5 starts with it. A crc32 is declared only where no
// stronger hash is, and a declared size bounds it.
export const satisfies = (entry: Entry, file: FileHashes, size: number): boolean => {
	if (!entry.h) return false;
	const { sha1, sha256, md5, crc32 } = entry.h;
	if (sha1 && !sha1.includes(file.sha1)) return false;
	if (sha256 && !sha256.includes(file.sha256)) return false;
	if (md5 && !md5.some((value) => (value.length === 32 ? value === file.md5 : file.md5.startsWith(value)))) return false;
	if (crc32 && (!crc32.includes(file.crc32) || (entry.z && !entry.z.includes(size)))) return false;
	return true;
};

// The strongest hash an entry declares, the lowest first: a sha1 match
// settles the folder before an md5 or a crc32 one.
const strength = (entry: Entry) =>
	entry.h?.sha1 ? 0 : entry.h?.sha256 ? 1 : entry.h?.md5?.some((value) => value.length === 32) ? 2 : entry.h?.md5 ? 3 : 4;

export const matches = (data: Wanted, file: FileHashes, size: number): Entry[] =>
	data.entries.filter((entry) => satisfies(entry, file, size)).sort((a, b) => strength(a) - strength(b));

// The entries known by their name only that a file of this name may be.
export const byName = (data: Wanted, name: string): Entry[] =>
	data.entries.filter((entry) => !entry.h && entry.n.toLowerCase() === name.toLowerCase());

// The folder and the name an upload carries, as validate_pr.Placement
// gives them: the declared name, beside the held file of that name in
// .variants/ with the first 8 characters of the sha1, or the file's own
// name when the declarations settle none. bios/ when no folder is known.
export const target = (data: Wanted, entry: Entry, file: FileHashes, ownName: string) => {
	const folder = entry.f === undefined ? 'bios/' : data.folders[entry.f];
	if (!entry.t) return { folder, name: ownName };
	if (entry.v) return { folder: `${folder}.variants/`, name: `${entry.t}.${file.sha1.slice(0, 8)}` };
	return { folder, name: entry.t };
};

// Where the list sends a file before it is read: the drop target, under
// the name the declarations give. A variant's name ends with the first 8
// characters of its sha1: with no single sha1 declared, the name is known
// once the file is dropped, and name is empty.
export const rowTarget = (data: Wanted, entry: Entry) => {
	const folder = entry.f === undefined ? 'bios/' : data.folders[entry.f];
	if (!entry.t) return { folder, name: entry.n };
	if (!entry.v) return { folder, name: entry.t };
	const sha1 = entry.h?.sha1?.length === 1 ? entry.h.sha1[0] : '';
	return { folder: `${folder}.variants/`, name: sha1 ? `${entry.t}.${sha1.slice(0, 8)}` : '' };
};

// Too large for GitHub's upload page: every size the declarations allow
// is over the limit.
export const tooLarge = (data: Wanted, entry: Entry) => !!entry.z?.length && entry.z.every((size) => size > data.limit);

let loaded: Promise<Wanted> | null = null;
// The list, fetched once for the drop box and the list below it. The
// version (wanted-version.ts) keeps a cached older list out.
export const loadWanted = (base: string, version = ''): Promise<Wanted> =>
	(loaded ??= fetch(`${base}data/wanted.json${version ? `?v=${version}` : ''}`).then((response) => {
		if (!response.ok) throw new Error(`wanted.json: ${response.status}`);
		return response.json();
	}));

export const uploadUrl = (data: Wanted, folder: string) =>
	data.upload + folder.replace(/\/$/, '').split('/').map(encodeURIComponent).join('/');

// The issue form for a file too large for the browser, filled as
// validate_pr.large_file_issue_url fills it.
export const issueUrl = (data: Wanted, name: string, file: FileHashes, size: number) =>
	`${data.issue}&${new URLSearchParams({
		title: `[BIOS] Missing: ${name}`,
		filename: name,
		sha1: file.sha1,
		md5: file.md5,
		size: String(size),
	})}`;

// The issue form for a listed file too large for the browser, with the
// hashes and the size its declarations write.
export const rowIssueUrl = (data: Wanted, entry: Entry) =>
	`${data.issue}&${new URLSearchParams({
		title: `[BIOS] Missing: ${entry.n}`,
		filename: entry.n,
		sha1: entry.h?.sha1?.[0] ?? '',
		md5: entry.h?.md5?.find((value) => value.length === 32) ?? '',
		size: entry.z?.length === 1 ? String(entry.z[0]) : '',
	})}`;
