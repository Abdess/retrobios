/* Progressive enhancement for generated RetroBIOS reference tables. */
(() => {
  "use strict";

  const textFromHeading = (element) => {
    let cursor = element;
    while (cursor) {
      cursor = cursor.previousElementSibling;
      if (!cursor) break;
      if (/^H[1-6]$/.test(cursor.tagName)) {
        return cursor.textContent.trim();
      }
    }
    return document.querySelector("h1")?.textContent.trim() || "Data table";
  };

  const enhanceTables = () => {
    document.querySelectorAll(".md-typeset table").forEach((table, index) => {
      if (table.dataset.rbEnhanced === "true") return;
      table.dataset.rbEnhanced = "true";

      table.querySelectorAll("thead th").forEach((cell) => {
        if (!cell.hasAttribute("scope")) cell.setAttribute("scope", "col");
      });
      table.querySelectorAll("tbody tr").forEach((row) => {
        const first = row.querySelector(":scope > th");
        if (first && !first.hasAttribute("scope")) first.setAttribute("scope", "row");
      });

      const container = table.parentElement;
      const heading = textFromHeading(container);
      if (!table.querySelector("caption")) {
        const caption = document.createElement("caption");
        caption.className = "rb-visually-hidden";
        caption.textContent = heading;
        table.prepend(caption);
      }
      if (container && container.scrollWidth > container.clientWidth) {
        container.tabIndex = 0;
        container.setAttribute("role", "region");
        container.setAttribute("aria-label", `${heading}, scrollable table`);
      }

      const rows = Array.from(table.querySelectorAll("tbody tr"));
      if (rows.length < 20 || !container || container.dataset.rbFilter === "true") {
        return;
      }
      container.dataset.rbFilter = "true";

      const controls = document.createElement("div");
      controls.className = "rb-table-filter";
      const id = `rb-table-filter-${index}-${Math.random().toString(36).slice(2, 8)}`;
      const label = document.createElement("label");
      label.htmlFor = id;
      label.textContent = `Filter ${heading}`;
      const input = document.createElement("input");
      input.id = id;
      input.type = "search";
      input.autocomplete = "off";
      input.placeholder = "Name, platform, system, hash...";
      const count = document.createElement("span");
      count.className = "rb-table-filter-count";
      count.setAttribute("aria-live", "polite");
      count.textContent = `${rows.length} rows`;
      controls.append(label, input, count);
      container.before(controls);

      const searchable = rows.map((row) => ({
        row,
        text: row.textContent.normalize("NFKD").toLocaleLowerCase(),
      }));
      input.addEventListener("input", () => {
        const query = input.value.trim().normalize("NFKD").toLocaleLowerCase();
        let visible = 0;
        searchable.forEach((entry) => {
          const matches = !query || entry.text.includes(query);
          entry.row.hidden = !matches;
          if (matches) visible += 1;
        });
        count.textContent = `${visible} of ${rows.length} rows`;
      });
    });
  };

  const nameMaterialWidgets = () => {
    document.querySelectorAll('[role="dialog"]').forEach((dialog) => {
      if (dialog.hasAttribute("aria-label") || dialog.hasAttribute("aria-labelledby")) return;
      const heading = dialog.querySelector("h1, h2, h3");
      dialog.setAttribute("aria-label", heading?.textContent.trim() || "Site search");
    });
    document.querySelectorAll('[role="progressbar"]').forEach((progress) => {
      if (!progress.hasAttribute("aria-label") && !progress.hasAttribute("aria-labelledby")) {
        progress.setAttribute("aria-label", "Loading page");
      }
    });
  };

  const enhance = () => {
    enhanceTables();
    nameMaterialWidgets();
  };

  if (window.document$?.subscribe) {
    window.document$.subscribe(enhance);
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", enhance, { once: true });
  } else {
    enhance();
  }
})();
