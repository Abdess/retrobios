---
level: start
order: 65
terms: privacy, cookies, analytics, tracking
---

# What we count

No cookies. No account. Nothing is stored on your device, and nothing
links a visit to a person.

## On this site

When a page opens, your browser sends one request to
[GoatCounter](https://www.goatcounter.com), an open-source counter. It
carries:

- the page address, without the part after `?` or `#`;
- the site you came from, by its domain only (`google.com`, `reddit.com`).

GoatCounter reads the browser name and the country from that request. It does
not keep your IP address. To tell a reload from a second visitor it keeps a
code made from the request for 8 hours, then drops it.

These actions are counted the same way, with the page they happened on:

- a click on a copy button, a pack download or a file link;
- a site search that found nothing, so a missing page shows up. Its words are
  sent only when they read as a file name (`scph5501.bin`, `scph5501`) or a
  hash. Any other search is counted as "other", without its words;
- the answer to "Did this page help?".

Not sent: your screen size, your language, a search that found results.

The totals are kept two years and are public:
[retrobios.goatcounter.com](https://retrobios.goatcounter.com).

If your browser sends Do Not Track or Global Privacy Control, nothing is sent,
and the "Did this page help?" question is not shown. A content blocker that
stops GoatCounter changes nothing on the site.

## The installer

The installer sends nothing back. It downloads files from GitHub, which sees
those requests as it sees any download.

## Search engines

Google and Bing tell us which searches showed the site and how often it was
clicked. They report totals, from their own records, never from your
browser.
