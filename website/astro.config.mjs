// The RetroBIOS site. Pages, navigation and data files are written by
// scripts/generate_site.py; this folder holds the engine's configuration,
// the components and the styles.
import { readFileSync } from 'node:fs';
import { copyFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import sitemap from '@astrojs/sitemap';
import { satteri } from '@astrojs/markdown-satteri';
import starlightSidebarTopics from 'starlight-sidebar-topics';
import starlightLinksValidator from 'starlight-links-validator';
import sidebar from './src/generated/sidebar.json' with { type: 'json' };
import lastmod from './src/generated/lastmod.json' with { type: 'json' };
import stackTables from './src/plugins/rehype-stack-tables.mjs';
import shortCode from './src/plugins/rehype-short-code.mjs';
import unbrokenTokens from './src/plugins/ec-unbroken-tokens.mjs';

const SITE = 'https://abdess.github.io';
const BASE = '/retrobios/';

// Old addresses that lead on to a page: {"/from/": "/to/"}, site paths
// written by the generator. A checkout that has not run it builds with none.
// Astro puts the base before the old address but not before the new one.
const readRedirects = () => {
	let redirects;
	try {
		redirects = JSON.parse(readFileSync(new URL('./src/generated/redirects.json', import.meta.url), 'utf-8'));
	} catch (error) {
		if (error.code === 'ENOENT') return {};
		throw error;
	}
	const withBase = (to) => (/^https?:/.test(to) || to.startsWith(BASE) ? to : BASE + to.replace(/^\//, ''));
	const withoutBase = (from) => (from.startsWith(BASE) ? `/${from.slice(BASE.length)}` : from);
	return Object.fromEntries(Object.entries(redirects).map(([from, to]) => [withoutBase(from), withBase(to)]));
};

// The sitemap keeps the address MkDocs gave it: sitemap.xml, beside the index.
// Each page as Markdown beside its HTML, and llms-full.txt, written from the
// built pages by scripts/site_markdown.py: what an assistant reads to help a
// reader. Every page's head names its copy (rel="alternate" below), so a
// build that cannot write them fails rather than link to nothing.
const markdownCopies = {
	name: 'retrobios-markdown',
	hooks: {
		'astro:build:done': ({ dir }) => {
			const script = fileURLToPath(new URL('../scripts/site_markdown.py', import.meta.url));
			const run = spawnSync(process.env.PYTHON || 'python3', [script, fileURLToPath(dir)], { stdio: 'inherit' });
			if (run.status !== 0) throw new Error(`site_markdown.py exited with ${run.status ?? run.error}`);
		},
	},
};

const sitemapAlias = {
	name: 'retrobios-sitemap-alias',
	hooks: {
		'astro:build:done': async ({ dir }) => {
			const root = fileURLToPath(dir);
			await copyFile(`${root}sitemap-index.xml`, `${root}sitemap.xml`);
		},
	},
};

export default defineConfig({
	site: SITE,
	base: BASE,
	trailingSlash: 'always',
	redirects: readRedirects(),
	markdown: {
		processor: satteri({
			hastPlugins: [stackTables(), shortCode()],
			features: {
				headingAttributes: true,
				definitionList: true,
				// Straight quotes: curly ones would change a copied command.
				smartPunctuation: false,
			},
		}),
	},
	integrations: [
		starlight({
			title: 'RetroBIOS',
			titleDelimiter: '-',
			description:
				'Source-verified BIOS and firmware packs for RetroArch, Batocera, Recalbox, Lakka, RetroPie, EmuDeck, RetroBat, RetroDECK, RomM, BizHawk, ROCKNIX, KNULLI, AmberELEC, EmuELEC and MiSTer FPGA.',
			// The brand mark is white on the indigo of the old header: indigo on a light page.
			logo: { light: './src/assets/logo-light.svg', dark: './src/assets/logo-dark.svg', replacesTitle: false },
			favicon: '/assets/brand/favicon-32.png',
			head: [
				{ tag: 'link', attrs: { rel: 'icon', type: 'image/svg+xml', href: `${BASE}assets/brand/favicon.svg` } },
				{ tag: 'link', attrs: { rel: 'apple-touch-icon', sizes: '180x180', href: `${BASE}assets/brand/apple-touch-icon.png` } },
				// Ownership of the URL-prefix property https://abdess.github.io/retrobios/
				// in Google Search Console. Removing it unverifies the property.
				{ tag: 'meta', attrs: { name: 'google-site-verification', content: '8SueST3hNHl8_vM-OJJP0rz-ZMlI2DALLpChrwZoGMs' } },
				// What an AI agent reads first (scripts/siteagents.py): the ARD manifest lists
				// llms.txt and the JSON API.
				{ tag: 'link', attrs: { rel: 'ard', type: 'application/json', href: `${BASE}ard.json` } },
				// The page as Markdown (scripts/site_markdown.py), beside its index.html.
				{ tag: 'link', attrs: { rel: 'alternate', type: 'text/markdown', href: 'index.md' } },
			],
			social: [{ icon: 'github', label: 'RetroBIOS on GitHub', href: 'https://github.com/Abdess/retrobios' }],
			customCss: ['./src/styles/retrobios.css'],
			components: {
				PageTitle: './src/components/PageTitle.astro',
				MarkdownContent: './src/components/MarkdownContent.astro',
				Footer: './src/components/Footer.astro',
				Pagination: './src/components/Pagination.astro',
				Header: './src/components/Header.astro',
				Search: './src/components/Search.astro',
			},
			routeMiddleware: ['./src/routeData.ts'],
			tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
			// Commands wrap instead of scrolling, so the end of a one-liner stays
			// visible, and never inside a word that holds a hyphen (`--platform`,
			// `nintendo-64dd`: src/plugins/ec-unbroken-tokens.mjs). A command block
			// is titled (Terminal, PowerShell) and drawn without the three window
			// dots. Starlight writes the dots into each theme after the global
			// style overrides, so they are set here.
			expressiveCode: {
				defaultProps: { wrap: true },
				plugins: [unbrokenTokens()],
				customizeTheme(theme) {
					theme.styleOverrides.frames = { ...theme.styleOverrides.frames, terminalTitlebarDotsOpacity: '0' };
					return theme;
				},
			},
			lastUpdated: false,
			pagination: true,
			// Measured on the queries of tools/search_gate.py, at the centre of a
			// range where all of them answer. How often a word appears counts more
			// than in Starlight's defaults (0.1, 0.1, 2, 9), a page's title weighs
			// ten times its text, so "dolphin" finds Dolphin, and the file names of
			// a system page (its `files` field, written by sitestarlight.py) count
			// half, so "scph5501" finds the Sony page without a file name winning
			// every other query. `devices`, the handhelds and boxes a setup's own
			// site names (R36S, Miyoo Mini), weighs half a title. `aliases`, the ids
			// setups file a system under (psx, dreamcast, gba), weighs a title: with
			// file names written as their parts, half a title put GBA.emu and two
			// more emulators above the Nintendo page for "gba bios". `terms`, the
			// words of a task or a message on screen (bios not found, which mame
			// version, check my dump), weighs three titles: a field match scores
			// below a title match, and the cards of a part page keep their own
			// weight, so below 30 the MAME parts, whose card titles name MAME files,
			// came before the version table for "which mame version".
			//
			// A field adds the same score to every page whose field holds the
			// word, whatever else the field holds, and a query word also matches
			// the start of a longer one. `consoles`, the consoles a system page
			// answers for, weighs ten titles: below that an emulator named after
			// its console (Saturn.emu, BK, PIECE) came before the console. The
			// PlayStation 2 page holds every word of "playstation bios", so
			// `exact` repeats, on its own page, a console whose every word another
			// page's consoles hold (PlayStation, Nintendo DS, Nintendo Super
			// System). It weighs two titles: enough over the other page, and less
			// than the "3" of "playstation 3 bios" adds to the Sony page. Measured
			// on the "<console> bios" query of every system page and on
			// tools/search_gate.py. All of them are attributes on an empty
			// element, so no text of theirs reaches an excerpt.
			pagefind: {
				ranking: {
					pageLength: 0.1,
					termFrequency: 0.5,
					termSaturation: 1.4,
					termSimilarity: 9,
					metaWeights: { title: 10, files: 0.5, aliases: 10, devices: 5, consoles: 100, exact: 20, terms: 30 },
				},
			},
			plugins: [
				starlightSidebarTopics(sidebar.topics, sidebar.options),
				starlightLinksValidator(),
			],
		}),
		// A page that states its own date (an emulator page: the day its
		// profile was last read against the source) gives it to the sitemap.
		// The others get no lastmod rather than the build date.
		sitemap({
			serialize(item) {
				const date = lastmod[new URL(item.url).pathname];
				return date ? { ...item, lastmod: date } : item;
			},
		}),
		sitemapAlias,
		markdownCopies,
	],
});
