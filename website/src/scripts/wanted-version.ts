// Read at build time by WantedFiles.astro and WantedList.astro: the first
// characters of the sha1 of public/data/wanted.json, added to its address.
// A browser that kept an older list in its cache asks for the new one: the
// two components read the list's current shape, and an older list broke
// them.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

// npm runs the build from website/, the project root.
const LIST = join(process.cwd(), 'public', 'data', 'wanted.json');

export const wantedVersion = (): string =>
	existsSync(LIST) ? createHash('sha1').update(readFileSync(LIST)).digest('hex').slice(0, 12) : '';
