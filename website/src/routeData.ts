// What each page knows of its place in the site, computed once per page
// from what scripts/sitestarlight.py writes beside the sidebar:
// - breadcrumbs: the tab and the groups above the page, each linked to the
//   page or the section that introduces it, never to a sibling page. A
//   group of names by their first letter (A, B) is no crumb;
// - previous and next: the reading order of `reading`. Start here runs on
//   into Setups, every other tab is read on its own, and a system,
//   emulator or platform page has none;
// - a pruned sidebar: in the tabs listing every system and emulator, a
//   group that does not hold the page becomes one link to its overview, so
//   an emulator page does not carry the links of every other emulator. The
//   groups of the other tabs stay groups;
// - a part page (one console of a setup's list) names the page it belongs
//   to in its `parent:` front matter: that page is its last crumb, and its
//   sidebar entry is marked when the part page has none of its own;
// - a page's "Next steps" link is its next only when it reads forward: one
//   pointing back to an earlier page of the run made Start here loop.
import { defineRouteMiddleware, type StarlightRouteData } from '@astrojs/starlight/route-data';
import sidebar from './generated/sidebar.json' with { type: 'json' };

type Entry = StarlightRouteData['sidebar'][number];
type Link = Extract<Entry, { type: 'link' }>;
type Group = { href: string | null; prune: boolean; crumb?: boolean };
export type Crumb = { label: string; href?: string };

const BASE = import.meta.env.BASE_URL.replace(/\/?$/, '/');
const withBase = (link: string) => (link.startsWith(BASE) ? link : BASE + link.replace(/^\//, ''));

const GROUPS = sidebar.groups as Record<string, Group>;
const RUNS = sidebar.reading as { label: string; link: string }[][];

const groupOf = (trail: string[]): Group | undefined => GROUPS[trail.join('/')];

const holdsCurrent = (entry: Entry): boolean =>
	entry.type === 'link' ? entry.isCurrent : entry.entries.some(holdsCurrent);

const prune = (entries: Entry[], trail: string[]): Entry[] =>
	entries.map((entry) => {
		if (entry.type === 'link') return entry;
		const here = [...trail, entry.label];
		if (holdsCurrent(entry)) return { ...entry, collapsed: false, entries: prune(entry.entries, here) };
		const group = groupOf(here);
		if (group?.prune && group.href) {
			return { type: 'link', label: entry.label, href: withBase(group.href), isCurrent: false, badge: entry.badge, attrs: {} };
		}
		return { ...entry, entries: prune(entry.entries, here) };
	});

// The groups above the current page, outermost first.
const trail = (entries: Entry[], labels: string[]): Crumb[] | undefined => {
	for (const entry of entries) {
		if (entry.type === 'link') {
			if (entry.isCurrent) return [];
			continue;
		}
		const here = [...labels, entry.label];
		const below = trail(entry.entries, here);
		if (below) {
			const group = groupOf(here);
			// A group of names by their first letter is a way through the
			// list, not a place: the crumb stops at the list.
			if (group?.crumb === false) return below;
			const href = group?.href;
			return [{ label: entry.label, href: href ? withBase(href) : undefined }, ...below];
		}
	}
	return undefined;
};

// A page the navigation does not list (part of a split page) sits under the
// group holding the pages of its folder.
const folderTrail = (entries: Entry[], labels: string[], folder: string): Crumb[] => {
	const links = (entry: Entry): string[] => (entry.type === 'link' ? [entry.href] : entry.entries.flatMap(links));
	for (const entry of entries) {
		if (entry.type !== 'group' || !links(entry).some((href) => href.startsWith(folder))) continue;
		const href = groupOf([...labels, entry.label])?.href;
		return [{ label: entry.label, href: href ? withBase(href) : undefined }];
	}
	return [];
};

// The parent's entry marked current, for a page the sidebar does not list.
const markCurrent = (entries: Entry[], href: string): Entry[] =>
	entries.map((entry) =>
		entry.type === 'link'
			? entry.href === href
				? { ...entry, isCurrent: true }
				: entry
			: { ...entry, entries: markCurrent(entry.entries, href) },
	);

const bare = (link: string) => withBase(link).replace(/[?#].*$/, '');

const asLink = (entry: { label: string; link: string }): Link => ({
	type: 'link',
	label: entry.label,
	href: withBase(entry.link),
	isCurrent: false,
	badge: undefined,
	attrs: {},
});

export const onRequest = defineRouteMiddleware(async (context, next) => {
	await next();
	const route = context.locals.starlightRoute;
	const path = context.url.pathname;

	const topic = context.locals.starlightSidebarTopics?.topics.find((t) => t.isCurrent);
	const parent = route.entry.data.parent;
	if (parent && !route.sidebar.some(holdsCurrent)) route.sidebar = markCurrent(route.sidebar, bare(parent.link));
	const crumbs: Crumb[] = [];
	if (topic && withBase(topic.link) !== path && route.id !== '404') {
		crumbs.push({ label: topic.label, href: withBase(topic.link) });
		const segments = path.slice(BASE.length).split('/').filter(Boolean);
		const groups =
			trail(route.sidebar, [topic.label]) ??
			(segments.length > 1 ? folderTrail(route.sidebar, [topic.label], `${BASE}${segments[0]}/`) : []);
		for (const crumb of groups) {
			// A group introduced by the page itself is the page, and one with
			// no section of its own adds nothing to the crumb before it.
			if (crumb.href === path) continue;
			if (crumb.href && crumb.href === crumbs.at(-1)?.href) continue;
			crumbs.push(crumb);
		}
		const parentHref = parent ? withBase(parent.link) : undefined;
		if (parent && parentHref !== path && parentHref !== crumbs.at(-1)?.href) {
			// A board page sits under the Arcade group of the index and has
			// the Arcade page as parent: one crumb, the page, not two "Arcade".
			if (crumbs.length > 1 && crumbs.at(-1)?.label === parent.label) crumbs.pop();
			crumbs.push({ label: parent.label, href: parentHref });
		}
	}
	context.locals.rbBreadcrumbs = crumbs;

	const { prev, next: following } = route.entry.data;
	const run = RUNS.find((pages) => pages.some((entry) => withBase(entry.link) === path));
	const position = run ? run.findIndex((entry) => withBase(entry.link) === path) : -1;
	if (prev === undefined) route.pagination.prev = run && position > 0 ? asLink(run[position - 1]) : undefined;
	const inOrder = run && position < run.length - 1 ? asLink(run[position + 1]) : undefined;
	if (following === undefined) route.pagination.next = inOrder;
	else if (run && typeof following === 'object' && following.link) {
		const target = run.findIndex((entry) => bare(entry.link) === bare(following.link));
		if (target !== -1 && target <= position) route.pagination.next = inOrder;
	}

	route.sidebar = prune(route.sidebar, [topic?.label ?? '']);
});
