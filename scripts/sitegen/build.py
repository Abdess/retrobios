"""One run of the generator: every page, data file and asset, in order."""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from core.artifacts import build_timestamp
from romrecipes import ledger
from model import releaserecord
from model import siteinputs
from model.collection import group_by_manufacturer, manufacturer_slug
from model.composition import compute_composition
from model.database import load_database
from model.dumpcatalog import load_provenance_snapshots
from sitegen.guidedata import handheld_guide
from model.profiles import is_emulator, lists_files, load_emulator_profiles
from model.registry import list_registered_platforms, load_platform_registry
from model.systemnames import program_names, set_console_sections, system_name
from packs.consumers import FileConsumers
from packs.crossref import whole_tree_gaps
from packs.supplemental import SupplementalIndex
from acquire.provenance import build_report, profile_needs
from resolve.cores import resolve_platform_cores
from resolve.review import load_platform_hashes, load_profile_hashes
from installer_build.handhelds import GROUP_PAGE
from sitegen import (
    agents as siteagents,
    bootstrap as sitebootstrap,
    diagrams,
    handheld as sitehandheld,
    measurements as sitemeasurements,
    runlinks,
    starlight as sitestarlight,
    steps as sitesteps,
    wanted as sitewanted,
)
from sitegen.cards import wanted_link, system_install_choices, tables_out_of_search
from sitegen.config import GENERATED_DIRS, PUBLIC_DIRS, REPO_URL, yaml
from core.paths import REPO_ROOT
from sitegen.archivecounts import ARCHIVE_RECIPES_PAGE, with_archive_counts
from sitegen.crossref import generate_cross_reference
from sitegen.dataexports import (
    source_commit,
    generate_data_exports,
    generate_stats,
    system_export_item,
    write_single_item,
)
from sitegen.datapage import generate_data_page
from sitegen.pageregistry import PageRegistry
from sitegen.decorate import front_matter, decorate_markdown_pages
from sitegen.descriptions import title_noun
from sitegen.emulatorcards import (
    ROMSET_FAQ_PAGE,
    emulator_setups,
    with_romset_table,
)
from sitegen.emulatorpage import (
    availability_check,
    emulator_pages,
    emulator_parts,
    plan_emulator_pages,
)
from sitegen.emulatorsindex import generate_emulators_index
from sitegen.exports import generate_exports_page, load_export_reports
from sitegen.gaps import PlatformRegistries, SourceListing, generate_gap_analysis
from sitegen.getpages import generate_get_index, generate_get_page, get_page_data
from sitegen.guidepage import DEMO_ASSETS, generate_handheld_guide
from sitegen.home import generate_explore_index, generate_home
from sitegen.lookup import (
    data_directory_members,
    data_directory_revisions,
    data_tree_pages,
    generate_files_page,
    page_data_directories,
)
from sitegen.nav import overview_anchors, generate_nav
from sitegen.parts import PUBLISHED_PARTS_FILE, load_published_parts, record_parts
from sitegen.arcadeboards import elect_arcade_boards
from sitegen.places import system_pages_from_data
from sitegen.platformfiles import EXPORTED
from sitegen.platformindex import SETUP_TABLE_PAGE, generate_platform_index, with_setup_table
from sitegen.platformpage import own_list_only, generate_platform_page
from sitegen.provenance import WantedDumps, generate_provenance_page, load_derivable, wanted_dumps
from sitegen.publish import write_release_advertised
from sitegen.coverage import platform_coverages
from sitegen.reference import (
    generate_contributing,
    generate_not_found,
    generate_wiki_data_model,
    reference_next,
)
from sitegen.render import WIKI_SRC_DIR, console_icon_name, percent_text
from sitegen.runlinks import (
    ICON_DIR,
    prime_system_icons,
    reset_console_pages,
    set_system_page_map,
    split_system_stems,
    use_arcade_boards,
)
from sitegen.structured import (
    dataset_structured_data,
    emulator_structured_data,
    platform_structured_data,
    record_emulator_page,
    system_structured_data,
)
from sitegen.systempages import arcade_board_sections, system_pages
from sitegen.systemsindex import generate_systems_index
from sitegen.versions import compute_stats
from sitegen.whichpack import build_emulator_file_index, build_file_consumers, generate_which_pack
from sitegen.write import record_written, sweep_generated, sweep_top_pages, write_if_changed


def _write_public_assets(docs: Path, public: Path) -> None:
    """The folders every generator writes into, and the files the site
    serves as they are: bootstraps, launchers, logos, diagrams, demo."""
    for d in GENERATED_DIRS:
        (public / d if d in PUBLIC_DIRS else docs / d).mkdir(parents=True, exist_ok=True)

    # No robots.txt: a crawler reads it only at the host root (RFC 9309), and
    # this project site lives under /retrobios/. Every page's head points at
    # the sitemap instead (Starlight's head links it).
    (public / "robots.txt").unlink(missing_ok=True)
    # The one-line commands' bootstraps, at the site's root.
    sitebootstrap.write_bootstraps(public, REPO_ROOT)
    # The handheld launchers, built from the same commit (sitehandheld).
    sitehandheld.write_launchers(public, REPO_ROOT)

    images_dest = public / "assets" / "images"
    images_dest.mkdir(parents=True, exist_ok=True)
    # Logos, system icons and sharing cards are served from the site itself
    # (docs_assets/*/sources.json records where each came from).
    # brand: the mark, favicons and touch icon (scripts/make_site_icons.py).
    folders = [("logos", "logos"), ("system-icons", "system-icons"), ("og", "og"),
               ("brand", "brand")]
    for folder, dest in folders:
        source = Path("docs_assets") / folder
        if source.is_dir():
            shutil.copytree(source, public / "assets" / dest, dirs_exist_ok=True)
    # The diagrams and the drawn install steps, one SVG per layout and theme.
    diagrams.write_diagram_files(public / diagrams.DIAGRAM_DIR,
                                     {**diagrams.figure_files(), **sitesteps.steps_files()})
    demo_dest = public / "assets" / "demo"
    demo_dest.mkdir(parents=True, exist_ok=True)
    for name in DEMO_ASSETS:
        shutil.copy2(Path("docs_assets") / "demo" / name, demo_dest / name)
    assets_src = Path(".github") / "assets"
    for name, dest_name in [("logo.png", "logo.png"), ("favicon.png", "favicon.png")]:
        src = assets_src / name
        if src.exists():
            shutil.copy2(src, images_dest / dest_name)


def _load_registry(platforms_dir: str) -> dict:
    """The platforms of _registry.yml, by name."""
    return load_platform_registry(platforms_dir)


@dataclass
class _SiteRun:
    """What one run of the generator reads and where it writes."""

    args: argparse.Namespace
    db: dict
    docs: Path
    public: Path
    registry: dict
    platform_names: list[str]
    data_registry: dict
    suppl_names: SupplementalIndex
    coverages: dict
    profiles: dict
    consumers: FileConsumers
    gap_report: dict = dataclasses.field(default_factory=dict)
    file_held: Callable[[dict], bool] = bool
    manufacturers: dict = dataclasses.field(default_factory=dict)
    # What the pages record for the pages written after them and the decorator.
    pages: PageRegistry = dataclasses.field(default_factory=PageRegistry)


def _load_site_run(args: argparse.Namespace, db: dict, docs: Path, public: Path) -> _SiteRun:
    """The registry, the coverage of every platform and the profiles."""
    from model.registry import load_data_dir_registry
    from packs.supplemental import build_supplemental_index

    registry = _load_registry(args.platforms_dir)

    platform_names = list_registered_platforms(
        args.platforms_dir
    )

    data_registry = load_data_dir_registry(args.platforms_dir)
    suppl_names = build_supplemental_index()

    print("Computing platform coverage...")
    coverages = platform_coverages(
        sorted(platform_names), args.platforms_dir, db, data_registry,
        emulators_dir=args.emulators_dir, db_path=args.db,
        report=lambda _name, cov: print(
            f"  {cov['platform']}: {cov['present']}/{cov['total']} ({percent_text(cov['present'], cov['total'])})"
        ),
    )

    print("Loading emulator profiles...")
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    unique_count = sum(1 for p in profiles.values() if p.get("type") != "alias")
    print(
        f"  {len(profiles)} profiles ({unique_count} unique, {len(profiles) - unique_count} aliases)"
    )

    consumers = build_file_consumers(db, coverages, profiles)
    return _SiteRun(args, db, docs, public, registry, platform_names, data_registry,
                    suppl_names, coverages, profiles, consumers)


def _write_home_pages(run: _SiteRun) -> dict:
    """The home and explore pages, stats.json and the agents' files.
    Returns the stats."""
    docs, public, db = run.docs, run.public, run.db
    coverages, profiles = run.coverages, run.profiles
    print("Generating home page...")
    write_if_changed(
        str(docs / "index.md"), generate_home(
            db, coverages, profiles, run.registry, run.args.platforms_dir
        )
    )

    write_if_changed(str(docs / "explore.md"), generate_explore_index(db, coverages, profiles))

    stats = compute_stats(db, coverages, profiles)
    stats["composition"] = compute_composition(db)
    write_if_changed(str(public / "stats.json"), generate_stats(stats))
    # llms.txt and the ARD manifest an agent reads first, from the registry.
    siteagents.write(public, sorted(((name, cov["platform"]) for name, cov in coverages.items()),
                                    key=lambda row: row[1].casefold()), write_if_changed)
    return stats


def _write_system_pages(run: _SiteRun) -> None:
    """The system pages, each manufacturer's, and their API items."""
    from sitegen.render import system_ids
    from sitegen.runlinks import link_coverage

    docs, public, db = run.docs, run.public, run.db
    manufacturers = run.manufacturers
    print("Generating system pages...")

    missing = prime_system_icons({
        console_icon_name(mfr, console)
        for mfr, consoles in manufacturers.items()
        for console in consoles
    })
    if missing:
        print(f"  {missing} systems have no icon in {ICON_DIR.relative_to(ICON_DIR.parents[1])}")

    # The arcade boards are recorded before any page links one, the
    # system pages and their install commands first among them.
    reset_console_pages()
    sections = arcade_board_sections(manufacturers)
    console_installs = system_install_choices(run.coverages)
    linked, total = link_coverage(
        system_ids(run.profiles, [cov["config"] for cov in run.coverages.values()]))
    print(f"  {linked} of {total} system ids linked")

    write_if_changed(
        str(docs / "systems" / "index.md"), generate_systems_index(sections)
    )
    (docs / "files").mkdir(parents=True, exist_ok=True)
    write_if_changed(str(docs / "files" / "index.md"), generate_files_page())
    for mfr, consoles in sections.items():
        slug = mfr.lower().replace(" ", "-")
        pages = system_pages(mfr, consoles, run.consumers, console_installs.get(slug))
        for stem, (page, held) in pages.items():
            run.pages.page_data[f"systems/{stem}.md"] = system_structured_data(stem, held)
            run.pages.title_nouns[f"systems/{stem}.md"] = title_noun(
                str(entry.get("name", "")) for entries in held.values() for entry in entries)
            if stem != slug:
                run.pages.part_pages.add(f"systems/{stem}.md")
            write_if_changed(str(docs / "systems" / f"{stem}.md"), page)
        write_single_item(
            public / "api" / "v1" / "systems" / f"{slug}.json", "systems",
            # The published data keeps the collection's folders.
            system_export_item(slug, mfr, manufacturers[mfr]),
            build_timestamp(db), source_commit(),
        )
    clash = split_system_stems() & {manufacturer_slug(m) for m in manufacturers}
    if clash:
        raise RuntimeError(f"a console page takes a manufacturer's address: {sorted(clash)}")


def _write_measurements(run: _SiteRun) -> sitemeasurements.Built:
    """The measurements' data files and explorer page."""
    print("Compiling the measurements...")
    measured = sitemeasurements.build(
        run.public, emulators_dir=Path(run.args.emulators_dir), repo=REPO_URL,
        system_names={sys_id: system_name(sys_id) for sys_id in sorted(set(runlinks.current().system_pages))},
    )
    for path in measured.paths:
        record_written(path)
    run.pages.measurement_items = sitemeasurements.by_emulator(measured.index)
    print(f"  {measured.index['records']} records, {measured.index['count']} tests")
    write_if_changed(str(run.docs / sitemeasurements.EXPLORER_PAGE),
                     sitemeasurements.generate_explorer_page(measured.index) + reference_next())
    return measured


def _write_data_exports(run: _SiteRun, stats: dict, dumps: WantedDumps) -> None:
    """The static API, the bulk exports and the data page."""
    print("Generating static API and bulk data exports...")
    exports = generate_data_exports(
        run.public, run.db, run.coverages, run.profiles, stats, run.gap_report, run.consumers,
        dumps,
    )
    write_release_advertised(Path(run.args.site_dir) / "src" / "generated")
    write_if_changed(str(run.docs / "data.md"),
                     generate_data_page(exports, run.public / sitemeasurements.SQLITE_PATH)
                     + reference_next())
    run.pages.page_data["data.md"] = dataset_structured_data(exports, run.db)


def _write_platform_pages(run: _SiteRun) -> dict[str, str]:
    """The platform pages and the pages their long lists went to. Returns
    the published parts, each part's page with the anchor it came from."""
    docs, coverages = run.docs, run.coverages
    emulator_files = build_emulator_file_index(run.profiles)
    print("Generating platform pages...")
    write_if_changed(
        str(docs / "platforms" / "index.md"),
        generate_platform_index(coverages, run.registry),
    )
    handhelds = handheld_guide()
    if handhelds:
        write_if_changed(str(docs / handhelds.path), generate_handheld_guide(handhelds))
    published_parts = load_published_parts()
    for name, cov in coverages.items():
        # The emulators this platform runs, not every one of the system.
        runs = resolve_platform_cores(cov["config"], run.profiles)
        moved: dict[str, str] = {}
        write_if_changed(
            str(docs / "platforms" / f"{name}.md"),
            generate_platform_page(name, cov, run.registry, {
                emu: data for emu, data in emulator_files.items() if emu in runs
            }, moved),
        )
        for stem, page in moved.items():
            if stem in coverages:
                raise RuntimeError(f"a system page takes the platform {stem}'s address")
            run.pages.part_pages.add(f"platforms/{stem}.md")
            anchor = re.search(rf"\]\({re.escape(name)}\.md#([^)\s]+)\)", page)
            if anchor:
                published_parts[f"platforms/{stem}.md"] = f"platforms/{name}.md#{anchor[1]}"
            # One console of one setup's list, a reference: "playstation
            # bios" found five setups' lists before the console's page.
            # Weighed down, they still won on their title, which the page
            # weight does not reach, and their file list is already kept out
            # of the index: the title alone, found again on the setup's page
            # and the console's, is all the search held of them.
            run.pages.search_demoted.add(f"platforms/{stem}.md")
            front = front_matter(page)
            if front:
                page = page[page.find("\n---\n", 4) + 5:].lstrip("\n")
            front.update(level="reference", search="exclude",
                         parent={"label": cov["platform"], "link": f"{name}.md"})
            page = "---\n" + yaml.safe_dump(front, sort_keys=False, allow_unicode=True) \
                + "---\n\n" + page
            write_if_changed(str(docs / "platforms" / f"{stem}.md"), page)
        run.pages.page_data[f"platforms/{name}.md"] = platform_structured_data(name, cov)
    return published_parts


def _record_data_trees(profiles: dict, pages: PageRegistry) -> None:
    """Record in ``pages`` the data directories: their members, revisions
    and readers, and the pages their member lists go to."""
    pages.data_members.update(data_directory_members())
    pages.data_revisions.update(data_directory_revisions())
    for key in sorted(profiles):
        if not is_emulator(profiles[key]):
            continue
        display = str(profiles[key].get("emulator", key))
        for tree in page_data_directories(key, profiles):
            readers = pages.data_readers.setdefault(str(tree.get("ref", "")), [])
            if (key, display) not in readers:
                readers.append((key, display))
    for ref, members in pages.data_members.items():
        for stem, _names in data_tree_pages(ref, members):
            pages.part_pages.add(f"emulators/{stem}.md")


def _write_emulator_pages(run: _SiteRun) -> None:
    """The emulator index, and each emulator's page and API item."""
    profiles = run.profiles
    print("Generating emulator pages...")
    run.pages.emulator_setups.update(emulator_setups(run.coverages, profiles))
    _record_data_trees(profiles, run.pages)
    write_if_changed(
        str(run.docs / "emulators" / "index.md"), generate_emulators_index(profiles)
    )
    public_profiles = {
        name: profile
        for name, profile in profiles.items()
        if is_emulator(profile)
    }
    (run.public / "api" / "v1" / "emulators").mkdir(parents=True, exist_ok=True)
    for name, profile in public_profiles.items():
        _write_emulator_page(run, name, profile)


def _write_emulator_page(run: _SiteRun, name: str, profile: dict) -> None:
    """One emulator's API item, page and the pages its cards went to."""
    docs, db = run.docs, run.db
    # The profile itself, one small document per core: reusing one
    # meant downloading emulators.json (5.9 MB) and filtering it.
    # The envelope and item of emulators.json, one item long: the
    # profile validates against the published schema, which an "id"
    # beside its fields broke on all 530, and schema_version is there.
    # The commit too, as every other envelope: 625 files lacked it.
    write_single_item(
        run.public / "api" / "v1" / "emulators" / f"{name}.json", "emulators",
        {"id": name, "profile": profile},
        build_timestamp(db), source_commit(),
    )
    pages = emulator_pages(
        name, profile, db, run.consumers, run.suppl_names, run.data_registry,
        data_dirs=page_data_directories(name, run.profiles), registry=run.pages,
    )
    record_emulator_page(name, profile, run.pages)
    # A frozen copy answers after the emulator: a frozen_snapshot, and a
    # profile pinned to the revision one platform builds (pin_frozen).
    # Reicast and Flycast 2021 LE answered "dc bios missing" before Flycast.
    if (not lists_files(profile)
            or profile.get("core_classification") in ("launcher", "alias", "frozen_snapshot")
            or profile.get("pin_frozen")):
        run.pages.search_demoted.add(f"emulators/{name}.md")
    files = profile.get("files") or []
    for stem, entries in emulator_parts(name, files, profile, run.file_held):
        run.pages.page_data[f"emulators/{stem}.md"] = emulator_structured_data(
            {**profile, "files": [files[i] for i in entries]})
        run.pages.part_pages.add(f"emulators/{stem}.md")
    for stem, page in pages.items():
        write_if_changed(str(docs / "emulators" / f"{stem}.md"), page)


def _write_cross_reference(run: _SiteRun) -> None:
    """The cross-reference page and its parts."""
    docs = run.docs
    print("Generating cross-reference page...")
    xref_pages: dict[str, str] = {}
    write_if_changed(
        str(docs / "cross-reference.md"),
        tables_out_of_search(generate_cross_reference(run.coverages, run.profiles, xref_pages))
        + reference_next(),
    )
    for stem, page in xref_pages.items():
        write_if_changed(str(docs / f"{stem}.md"), tables_out_of_search(page))
    for pname, cov in run.coverages.items():
        if own_list_only(cov["config"]):
            # The empty table it had is gone: its address leads to the
            # platform's page, which says its own list decides alone.
            sitestarlight.MOVED_PAGES.setdefault(
                f"cross-reference-{pname}.md", f"platforms/{pname}.md")


def _write_gap_pages(run: _SiteRun, provenance_report: dict) -> None:
    """The gap analysis page, its parts and the wanted page."""
    docs, public, db = run.docs, run.public, run.db
    profiles, coverages = run.profiles, run.coverages
    # Where an upload goes, by validate_pr's own rule: the gaps page and the
    # wanted page send a file to the folder the review asks for.
    placer = sitewanted.Placer(
        db, load_platform_hashes(run.args.platforms_dir, db),
        load_profile_hashes(run.args.emulators_dir, db),
    )
    print("Generating gap analysis page...")
    gap_pages: dict[str, str] = {}
    write_if_changed(
        str(docs / "gaps.md"),
        tables_out_of_search(generate_gap_analysis(
            profiles, coverages, db, run.suppl_names,
            PlatformRegistries(run.registry, run.data_registry), run.gap_report,
            SourceListing(gap_pages, placer), catalogued=provenance_report,
        )) + reference_next(),
    )
    for stem, page in gap_pages.items():
        write_if_changed(str(docs / f"{stem}.md"), tables_out_of_search(page))

    print("Generating the wanted page...")
    wanted = sitewanted.build_wanted(
        profiles, coverages, run.gap_report, db, placer, system_name,
        sitewanted.load_ledger(ledger.ARCHIVES_FILE),
        wanted_link(profiles),
    )
    (public / "data").mkdir(parents=True, exist_ok=True)
    write_if_changed(str(public / sitewanted.DATA_FILE),
                     json.dumps(wanted, ensure_ascii=False, separators=(",", ":")) + "\n")
    write_if_changed(str(docs / "wanted.md"), sitewanted.page(
        len(wanted["entries"]), sum(1 for entry in wanted["entries"] if "h" in entry)))


def _write_reference_pages(
    run: _SiteRun, export_reports: list[dict], dumps: WantedDumps,
) -> None:
    """The cross-reference, gaps, wanted, updated files and provenance pages."""
    docs = run.docs
    _write_cross_reference(run)

    _write_gap_pages(run, dumps.catalogs)

    print("Generating updated platform files page...")
    write_if_changed(
        str(docs / "exports.md"),
        generate_exports_page(
            export_reports,
            {name: cov["platform"] for name, cov in run.coverages.items()},
        ) + reference_next(),
    )

    print("Generating dump provenance page...")
    provenance_pages: dict[str, str] = {}
    write_if_changed(
        str(docs / "provenance.md"),
        tables_out_of_search(
            generate_provenance_page(run.db, dumps, provenance_pages)
        ) + reference_next(),
    )
    for stem, page in provenance_pages.items():
        write_if_changed(str(docs / f"{stem}.md"), tables_out_of_search(page))


def _write_wiki_pages(run: _SiteRun, measured: sitemeasurements.Built) -> None:
    """Wiki pages: copy manually maintained sources + generate dynamic ones."""
    docs, profiles = run.docs, run.profiles
    print("Generating wiki pages...")
    wiki_dest = docs / "wiki"
    wiki_dest.mkdir(parents=True, exist_ok=True)
    wiki_src = Path(WIKI_SRC_DIR)
    # The romset table is the profiles' versions, never typed: the source
    # page is rewritten before it is copied, as the README is.
    faq = REPO_ROOT / ROMSET_FAQ_PAGE
    if faq.is_file():
        write_if_changed(str(faq), with_romset_table(faq.read_text(encoding="utf-8"), profiles))
    recipes_page = REPO_ROOT / ARCHIVE_RECIPES_PAGE
    if recipes_page.is_file():
        write_if_changed(str(recipes_page), with_archive_counts(
            recipes_page.read_text(encoding="utf-8"), ledger.rebuild_counts()))
    if wiki_src.is_dir():
        for src_file in wiki_src.glob("*.md"):
            shutil.copy2(src_file, wiki_dest / src_file.name)
            record_written(wiki_dest / src_file.name)
    method_page = docs / sitemeasurements.METHOD_PAGE
    if method_page.is_file():
        write_if_changed(str(method_page), sitemeasurements.with_hosts(
            method_page.read_text(encoding="utf-8"), measured.index))
    table_page = docs / SETUP_TABLE_PAGE
    if table_page.is_file():
        write_if_changed(str(table_page), with_setup_table(
            table_page.read_text(encoding="utf-8"), run.coverages))
    # data-model.md is generated (contains live DB stats)
    write_if_changed(
        str(wiki_dest / "data-model.md"), generate_wiki_data_model(run.db, profiles)
    )


def _write_guide_pages(run: _SiteRun) -> None:
    """The which-pack page, the download pages and the contributing page."""
    docs = run.docs
    print("Generating which-pack page...")
    write_if_changed(str(docs / "which-pack.md"), generate_which_pack())

    # One permanent download address per registered platform: the README's
    # table links each of them.
    print("Generating download pages...")
    get_dir = docs / releaserecord.GET_DIR
    get_dir.mkdir(parents=True, exist_ok=True)
    for name in run.platform_names:
        write_if_changed(str(get_dir / f"{name}.md"), generate_get_page(name))
        dated = get_page_data(name)
        if dated:
            run.pages.page_data[f"{releaserecord.GET_DIR}/{name}.md"] = dated
    write_if_changed(str(get_dir / f"{GROUP_PAGE}.md"),
                     sitehandheld.group_page(REPO_ROOT))
    write_if_changed(str(get_dir / "index.md"), generate_get_index())

    print("Generating contributing page...")
    write_if_changed(str(docs / "contributing.md"), generate_contributing())


def _write_navigation(run: _SiteRun, published_parts: dict[str, str]) -> None:
    """Sweep what nothing produced, decorate every page, then write the
    navigation, the redirects and the picker's data."""
    docs, public, coverages = run.docs, run.public, run.coverages
    # Swept before the decoration, which rewrites every page it finds: a
    # page no generator produced any more (a console moved back onto its
    # manufacturer's page) was decorated, recorded, and kept for ever.
    write_if_changed(str(docs / "404.md"), generate_not_found())
    stale = sweep_generated(docs, [d for d in GENERATED_DIRS if d not in PUBLIC_DIRS])
    stale += sweep_generated(public, list(PUBLIC_DIRS))
    stale += sweep_top_pages(docs)

    print("Adding page metadata and structured data...")
    lastmod = decorate_markdown_pages(docs, run.pages)

    nav = generate_nav(coverages, run.manufacturers, run.profiles, run.registry,
                       Path(WIKI_SRC_DIR))
    print("Writing the navigation and the picker's data...")
    site = Path(run.args.site_dir)
    present = {
        path.relative_to(docs).with_suffix(".md").as_posix()
        for path in docs.rglob("*.md*") if path.suffix in (".md", ".mdx")
    } - {"404.md"}
    published_parts = record_parts(docs, present, published_parts)
    write_if_changed(str(PUBLISHED_PARTS_FILE), json.dumps(published_parts, indent=1) + "\n")
    generated = site / "src" / "generated"
    generated.mkdir(parents=True, exist_ok=True)
    write_if_changed(str(generated / "sidebar.json"),
                     json.dumps(sitestarlight.sidebar(nav, present, overview_anchors(nav, docs)),
                                indent=1) + "\n")
    write_if_changed(str(generated / "redirects.json"),
                     json.dumps(sitestarlight.redirects(run.profiles, present, published_parts), indent=1,
                                sort_keys=True) + "\n")
    write_if_changed(str(generated / "lastmod.json"),
                     json.dumps(dict(sorted(lastmod.items())), indent=1) + "\n")
    system_ids = set(runlinks.current().system_pages) | {
        sys_id for cov in coverages.values() for sys_id in cov["config"].get("systems", {})
    }
    titles = {sys_id: system_name(sys_id) for sys_id in sorted(system_ids)}
    sitestarlight.picker_data(siteinputs.manifests_dir(), public / "data" / "picker", titles)
    total_pages = len(present)
    print(f"\nGenerated {total_pages} pages in {run.args.docs_dir}/")
    if stale:
        print(f"Removed {stale} page(s) nothing produced this run")


def generate_site(args: argparse.Namespace) -> None:

    # Every page reads these, never the repository's own files.
    siteinputs.use(siteinputs.SiteInputs(
        db=Path(args.db).resolve(),
        emulators=Path(args.emulators_dir).resolve(),
        platforms=Path(args.platforms_dir).resolve(),
    ))
    # Where this run puts systems, consoles and cards, nothing of a run before.
    runlinks.use(runlinks.LinkTables())
    db = load_database(args.db)
    docs = Path(args.docs_dir)
    # Files the site serves as they are (data, downloads, images), in the
    # project's public folder.
    public = Path(args.site_dir) / "public"
    _write_public_assets(docs, public)

    run = _load_site_run(args, db, docs, public)
    profiles, coverages = run.profiles, run.coverages
    stats = _write_home_pages(run)

    # Computed once: the gap analysis page and the published gaps export must
    # report the same files.
    run.gap_report = whole_tree_gaps(
        [cov["config"] for cov in coverages.values()], db, profiles, run.suppl_names)
    # Built once, the derivable dumps taken out once: the provenance page and
    # the CSV it links to must list the same dumps.
    dumps = wanted_dumps(
        build_report(db, load_provenance_snapshots(), needs=profile_needs(profiles, db)),
        load_derivable(),
    )

    # The test each emulator page builds for itself: the parts a page is
    # cut into weigh the status its rows show.
    run.file_held = availability_check(db, run.suppl_names)
    # The plan names systems: the sections must be this run's data first.
    run.manufacturers = group_by_manufacturer(db)
    set_console_sections(run.manufacturers, program_names(profiles))
    # Which archive is which board's depends on the sections: elected once
    # they are this run's.
    use_arcade_boards(elect_arcade_boards(profiles, db))
    plan_emulator_pages(profiles, run.file_held)
    # Build system_id -> manufacturer page map (needed by all generators)
    print("Building system cross-reference map...")
    set_system_page_map(
        system_pages_from_data(run.manufacturers, coverages, db, profiles)
    )
    print(f"  {len(runlinks.current().system_pages)} system IDs mapped to pages")
    _write_system_pages(run)

    measured = _write_measurements(run)
    _write_data_exports(run, stats, dumps)

    export_reports = load_export_reports()
    EXPORTED.update(report["platform"] for report in export_reports)

    published_parts = _write_platform_pages(run)
    _write_emulator_pages(run)
    _write_reference_pages(run, export_reports, dumps)
    _write_wiki_pages(run, measured)
    _write_guide_pages(run)
    _write_navigation(run, published_parts)
