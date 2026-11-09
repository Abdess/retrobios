---
level: start
order: 65
terms: privacy, cookies, analytics, tracking
---

# What is counted

No cookies. No account. Nothing is stored on the device, and nothing
links a visit to a person.

## On this site

When a page opens, the browser sends one request to
[GoatCounter](https://www.goatcounter.com), an open-source counter. It
carries:

- the page address, without the part after `?` or `#`;
- the site the visit came from, by its address without a path
  (`https://www.google.com`).

GoatCounter reads the browser name and the country from that request. It does
not keep the IP address. To tell a reload from a second visitor it keeps a
code made from the request for 8 hours, then drops it.

These actions are counted the same way, with the page they happened on:

- a click on a copy button, a pack download or a file link;
- a click on a link to another site, by that site's domain (`reddit.com`);
- a site search that found nothing, so a missing page shows up. Its words are
  sent only when they read as a file name (`scph5501.bin`, `scph5501`) or a
  hash with at least one letter. A word of letters with a few digits is sent
  as typed, so a nickname written that way (`dupont1985`) would be too. A
  number alone, such as a phone number, never is. Any other search is counted
  as "other", without its words;
- the answer to "Did this page help?".

Not sent: the screen size, the language, a search that found results.

The totals are kept two years and are public:
[retrobios.goatcounter.com](https://retrobios.goatcounter.com).

If the browser sends Do Not Track or Global Privacy Control, nothing is sent,
and the "Did this page help?" question is not shown. A content blocker that
stops GoatCounter changes nothing on the site.

## The installer

The installer sends nothing back. It downloads files from GitHub, which sees
those requests as it sees any download.

## Search engines

Google and Bing report which searches showed the site and how often it was
clicked. They give totals, from their own records, never from a reader's
browser.
