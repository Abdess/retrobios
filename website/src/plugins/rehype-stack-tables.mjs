// Tables, settled when the page is built so the layout is right on first
// paint (the CSS is retrobios.css, table[data-rb-stack] and .rb-table-filter).
// The rule reads the table, never the page that wrote it.
//
// Which tables a phone reads one row at a time:
// - two columns: a list of label and value, data-rb-stack="kv";
// - four columns or more: too wide for a phone column, one block per row,
//   each cell under its column name;
// - a row that ends in an action (a release download, a button, the link to
//   a setup's install command) or a header that names a ZIP column: one
//   block per row, so the action is never behind a horizontal scroll;
// - on a level 0 or 1 page (`level: start` or `setup`), a three-column table
//   short enough to read as records (under RECORD_ROWS rows): one block per
//   row. A longer one is a list scanned by column and keeps its scroll.
// - three columns or more where a column holds hashes: a hash cannot break,
//   so the row is wider than a phone at any length (NetherSX2's File,
//   Required, Hash summary measured 604 px in a 358 px column).
//
// A stacked cell is labelled with its column name, or with the header's
// `title` when the table's writer gives one: "Name as declared" wrapped to two
// lines in the label column, its title "Declared as" does not.
//
// A table of RECORD_ROWS rows or more gets its filter box here, above it.
// Written by site.ts once the page had painted, the box pushed the table
// down (CLS 0.066 on gaps-files-to-source). site.ts only wires it.
//
// Satteri runs hast plugins (the rehype stage of its pipeline): this one is
// registered in astro.config.mjs through satteri({ hastPlugins }).

const ACTION_HREF = /\/releases\/(download\/|latest\/?$)|#install$/;
const ACTION_CLASS = /\bclass=["'][^"']*\brb-button\b/;
const DOWNLOAD_HEADER = /^(zip|download)$/i;
const READER_LEVELS = new Set(['start', 'setup']);
const HEADING = /^h[1-6]$/;
export const RECORD_ROWS = 20;
export const WIDE_COLUMNS = 4;
// The column names a filter's placeholder offers, at most.
const PLACEHOLDER_COLUMNS = 4;

const elements = (node, tag, found = []) => {
	for (const child of node.children ?? []) {
		if (child.type !== 'element') continue;
		if (child.tagName === tag) found.push(child);
		// A table inside a cell is its own table.
		if (child.tagName !== 'table') elements(child, tag, found);
	}
	return found;
};

const classes = (node) => String(node.properties?.className ?? '').split(/[\s,]+/);

const holdsAction = (node) =>
	(node.children ?? []).some(
		(child) =>
			(child.type === 'element' &&
				((child.tagName === 'a' && ACTION_HREF.test(String(child.properties?.href ?? ''))) ||
					classes(child).includes('rb-button') ||
					holdsAction(child))) ||
			(child.type === 'raw' && ACTION_CLASS.test(child.value ?? '')),
	);

const HASH_HEADER = /^(hash|sha-?1|sha-?256|md5|crc-?32)$/i;

export const stackKind = ({ labels, rows, action, level }) => {
	if (labels.length === 2) return 'kv';
	if (labels.length >= WIDE_COLUMNS) return 'true';
	if (action || DOWNLOAD_HEADER.test(labels.at(-1) ?? '')) return 'true';
	if (labels.length > 2 && labels.some((label) => HASH_HEADER.test(label))) return 'true';
	if (READER_LEVELS.has(level) && labels.length > 2 && rows < RECORD_ROWS) return 'true';
	return null;
};

// "File, region, required, hash...": what the rows can be filtered by, in
// the table's own words. A word that is not capitalised prose (MD5, ZIP)
// keeps its case.
export const filterPlaceholder = (labels) => {
	const words = labels.filter(Boolean).slice(0, PLACEHOLDER_COLUMNS);
	if (!words.length) return 'Type to filter...';
	const lowered = words.map((word, index) =>
		index > 0 && /^[A-Z][a-z]/.test(word) ? word[0].toLowerCase() + word.slice(1) : word,
	);
	return `${lowered.join(', ')}...`;
};

// The heading a table sits under: the nearest one before it, looking up
// through the blocks that hold it, else the page title. site.ts names the
// table's scroll region the same way.
const headingBefore = (ctx, table, title) => {
	for (let block = table; block; block = ctx.parent(block)) {
		const parent = ctx.parent(block);
		if (!parent) break;
		const siblings = parent.children ?? [];
		for (let index = (ctx.indexOf(block) ?? 0) - 1; index >= 0; index -= 1) {
			const node = siblings[index];
			if (node.type !== 'element') continue;
			const heading = HEADING.test(node.tagName)
				? node
				: classes(node).includes('sl-heading-wrapper')
					? (node.children ?? []).find((child) => child.type === 'element' && HEADING.test(child.tagName))
					: undefined;
			const text = heading && ctx.textContent(heading).trim();
			if (text) return text;
		}
	}
	return title || 'this table';
};

// The label a stacked cell shows: the header's title, else its text.
export const stackedLabel = (title, text) => String(title ?? '').trim() || text;

// The same box as siteentries.filter_box: `hidden` until site.ts wires it,
// so a reader without the script, a text dump and the search skip a field
// that would filter nothing. The count describes the input, and the spaces
// keep label, field and count apart in any text read from the HTML.
const space = () => ({ type: 'text', value: ' ' });

export const filterBox = ({ id, heading, labels, rows }) => ({
	type: 'element',
	tagName: 'div',
	properties: { className: ['rb-table-filter'], hidden: true, dataPagefindIgnore: true },
	children: [
		{
			type: 'element',
			tagName: 'label',
			properties: { htmlFor: id },
			children: [{ type: 'text', value: `Filter ${heading}` }],
		},
		space(),
		{
			type: 'element',
			tagName: 'input',
			properties: {
				id,
				type: 'search',
				autoComplete: 'off',
				placeholder: filterPlaceholder(labels),
				ariaDescribedBy: `${id}-count`,
			},
			children: [],
		},
		space(),
		{
			type: 'element',
			tagName: 'span',
			properties: { id: `${id}-count`, className: ['rb-table-filter-count'], ariaLive: 'polite' },
			children: [{ type: 'text', value: `${rows.toLocaleString('en')} rows` }],
		},
	],
});

export default function stackTables() {
	return {
		name: 'rb-stack-tables',
		element: {
			filter: ['table'],
			visit(table, ctx) {
				const head = elements(table, 'thead')[0];
				const body = elements(table, 'tbody')[0];
				if (!head || !body) return;
				const headers = elements(head, 'th');
				const labels = headers.map((cell) => ctx.textContent(cell).trim());
				const stacked = headers.map((cell, column) => stackedLabel(cell.properties?.title, labels[column]));
				const rows = elements(body, 'tr');
				const frontmatter = ctx.data.astro?.frontmatter ?? {};
				if (rows.length >= RECORD_ROWS) {
					ctx.data.rbFilters = (ctx.data.rbFilters ?? 0) + 1;
					const heading = headingBefore(ctx, table, frontmatter.title);
					ctx.insertBefore(table, filterBox({ id: `rb-table-filter-${ctx.data.rbFilters}`, heading, labels, rows: rows.length }));
				}
				const kind = stackKind({ labels, rows: rows.length, action: holdsAction(body), level: frontmatter.level });
				if (!kind) return;
				ctx.setProperty(table, 'dataRbStack', kind);
				// A long table's labels are written by site.ts when it nears the
				// screen: on mame they were 122 KB of the page. The label is drawn
				// in the room the cell already keeps for it, so nothing moves.
				if (kind === 'kv' || rows.length >= RECORD_ROWS) return;
				for (const row of rows) {
					elements(row, 'td').forEach((cell, column) => {
						if (stacked[column] && cell.properties?.dataLabel === undefined) ctx.setProperty(cell, 'dataLabel', stacked[column]);
					});
				}
			},
		},
	};
}
