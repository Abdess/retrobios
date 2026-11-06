// What the site counts, as wiki/privacy.md states it. No cookie, no storage
// on the device, no identifier: one request per page or action to
// GoatCounter, which keeps totals. Nothing is sent when the browser asks
// not to be tracked (Do Not Track, Global Privacy Control), from a local
// build, or from a page not served at the site's address.
//
// Sent: the page path (never its query or #anchor), the domain of the site
// the reader came from, and the name of an action. An action is a click on
// a copy button, a pack or file download, a link that leaves the site, a
// site search that found nothing (its words only when they are a file
// name or a hash), and the answer to "Did this page help?".

const ENDPOINT = 'https://retrobios.goatcounter.com/count';
const HOST = 'abdess.github.io';
const BASE = import.meta.env.BASE_URL.replace(/\/?$/, '/');

const declined = (): boolean => {
	const nav = navigator as Navigator & { globalPrivacyControl?: boolean };
	return nav.doNotTrack === '1' || nav.globalPrivacyControl === true;
};
const enabled = location.hostname === HOST && !declined();

// The path under the site, "/emulators/mgba/": the base names every page.
const pagePath = (): string => {
	const path = location.pathname;
	return path.startsWith(BASE) ? `/${path.slice(BASE.length)}` : path;
};

const send = (params: Record<string, string>): void => {
	if (!enabled) return;
	const url = `${ENDPOINT}?${new URLSearchParams({ ...params, rnd: Math.random().toString(36).slice(2) })}`;
	if (!navigator.sendBeacon?.(url)) new Image().src = url;
};

// An action, filed under its name with the page it happened on as title.
export const countEvent = (name: string): void => {
	send({ p: name.slice(0, 120), t: pagePath(), e: 'true' });
};

// The site the reader came from, by domain alone: a path can carry a
// search or a private thread.
const referrer = (): string => {
	try {
		const from = new URL(document.referrer);
		return from.hostname && from.hostname !== location.hostname ? from.origin : '';
	} catch {
		return '';
	}
};

const countPage = (): void => {
	const params: Record<string, string> = { p: pagePath() };
	const from = referrer();
	if (from) params.r = from;
	// GitHub Pages serves 404.html at the address asked for: the path says
	// which link is broken, the title that it was one.
	if (document.title.startsWith('Page not found')) params.t = '404';
	send(params);
};

// Clicks

const slug = (text: string): string => text.trim().toLowerCase().replace(/[^a-z0-9.+-]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);

const linkAction = (link: HTMLAnchorElement): string | undefined => {
	let url: URL;
	try {
		url = new URL(link.href, location.href);
	} catch {
		return undefined;
	}
	const release = /\/releases\/download\/[^/]+\/([^/?#]+)$/.exec(url.pathname);
	if (url.hostname === 'github.com' && release) return `download/${decodeURIComponent(release[1])}`;
	if (url.hostname === 'raw.githubusercontent.com') {
		return `file/${decodeURIComponent(url.pathname.split('/').pop() ?? '')}`;
	}
	if (url.hostname === location.hostname) {
		const get = new RegExp(`^${BASE}get/([^/]+)/`).exec(url.pathname);
		return get ? `get/${get[1]}` : undefined;
	}
	return url.protocol.startsWith('http') ? `out/${url.hostname}` : undefined;
};

const onClick = (event: MouseEvent): void => {
	const target = event.target instanceof Element ? event.target : null;
	if (!target) return;
	const copy = target.closest('.expressive-code .copy button, [data-copy]');
	if (copy) {
		const frame = copy.closest('.frame');
		const title = frame?.querySelector('.title')?.textContent ?? '';
		countEvent(`copy/${slug(title) || (copy.matches('[data-copy]') ? 'picker' : 'code')}`);
		return;
	}
	const help = target.closest<HTMLButtonElement>('[data-rb-helpful]');
	if (help) {
		countEvent(`helpful/${help.dataset.rbHelpful}`);
		return;
	}
	const link = target.closest<HTMLAnchorElement>('a[href]');
	const action = link && linkAction(link);
	if (action) countEvent(action);
};

// Search

// A search that found nothing names a missing page. Its words are sent
// only in a shape no person's details take: a hash, a file name
// ("scph5501.bin"), or one word of letters and at most four digits
// ("scph5501", "ps3updat"). Any other search is counted with no words,
// as "other": a name, a phone number or an address is never sent.
const isHash = (query: string): boolean => /^(?:[0-9a-f]{8}|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/.test(query);
// The extensions of the files the collection holds: "john.smith" is no file.
const isFileName = (query: string): boolean =>
	/^[\w.+-]{1,60}\.(?:bin|rom|zip|7z|pup|keys|img|dat|bios|ic\d+|u\d+|sys|nvm|mec|rom1|j64|pce|col|sms|gb|gbc|gba|nds|cfg|chd|iso|txt|fw|xml|yaml|pak|pk3|grp)$/.test(query);
const isFileStem = (query: string): boolean =>
	/^[a-z][a-z0-9_-]{1,30}$/.test(query) && /\d/.test(query) && (query.match(/\d/g) ?? []).length <= 4;
const searchWords = (query: string): string =>
	isHash(query) || isFileName(query) || isFileStem(query) ? query : 'other';

const watchSearch = (): void => {
	const root = document.getElementById('starlight__search');
	if (!root) return;
	const sent = new Set<string>();
	let timer: number | undefined;
	const settle = (): void => {
		const input = root.querySelector<HTMLInputElement>('.pagefind-ui__search-input');
		const query = (input?.value ?? '').trim().toLowerCase().replace(/\s+/g, ' ');
		// Pagefind's English message once a search has ended with nothing;
		// while it runs the message reads "Searching for ...".
		const message = root.querySelector('.pagefind-ui__message')?.textContent ?? '';
		if (!query || !message.startsWith('No results for') || sent.has(query)) return;
		sent.add(query);
		countEvent(`search-none/${searchWords(query)}`);
	};
	new MutationObserver(() => {
		window.clearTimeout(timer);
		timer = window.setTimeout(settle, 1500);
	}).observe(root, { childList: true, subtree: true, characterData: true });
};

// "Did this page help?": the buttons answer once, then say thanks.
const wireHelpful = (): void => {
	// Shown only where an answer is sent: a box that counts nothing would ask for nothing.
	if (!enabled) return;
	for (const box of document.querySelectorAll<HTMLElement>('[data-rb-helpful-box]')) {
		box.hidden = false;
		box.addEventListener('click', (event) => {
			if (!(event.target instanceof Element) || !event.target.closest('[data-rb-helpful]')) return;
			for (const button of box.querySelectorAll('button')) button.remove();
			const thanks = box.querySelector<HTMLElement>('[data-rb-helpful-thanks]');
			if (thanks) thanks.hidden = false;
		});
	}
};

countPage();
document.addEventListener('click', onClick, { capture: true });
watchSearch();
wireHelpful();
