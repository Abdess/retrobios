---
level: start
order: 55
terms: license
---

# Is it legal?

It depends on your country. Nothing here is legal advice.

- Making an emulator is legal in the US. EU law allows it under conditions.
- Sharing BIOS files is not settled law. The strongest case is old consoles no
  longer sold. The weakest is encryption keys (Switch, 3DS, Wii U).
- The files are here for personal backup and preservation.
- A rights holder can ask for a file to be removed:
  [open an issue](https://github.com/Abdess/retrobios/issues/new) with its path
  or hash.

## The reasoning in detail

Redistributing firmware is not settled law. Below is the reasoning the project acts on, with the strength of each argument, so anyone can weigh it. None of it has been tested in court.

### Emulation and BIOS redistribution

- **Writing an emulator is lawful.** *Sony v. Connectix* (2000) and *Sega v. Accolade* (1992) held that copying a work during reverse engineering, to reach the functional elements needed for interoperability, is fair use. Both concern the act of copying while developing, and *Connectix* specifically involved copying Sony's BIOS in the course of that work. Neither decision addresses distributing firmware to third parties, so they support the legality of emulation itself rather than of this collection.
- **Fair use (US, 17 USC 107) is a defence, argued case by case.** The project's position is that non-commercial redistribution for personal backup and archival weighs favourably on purpose and on market effect, since these files are not sold separately. It weighs poorly on the amount used: each file is copied whole. Manufacturers do still monetise some of this firmware indirectly, through re-releases, subscription services and mini consoles, so the market factor is contestable rather than clear.
- **Interoperability in the EU.** The Software Directive (2009/24/EC, Art. 5-6) permits decompilation and use to achieve interoperability, subject to conditions, and Art. 6 restricts passing the resulting information to others. It supports the emulation use case, but it is not a general redistribution permission.
- **Discontinued hardware.** Most firmware here is for hardware no longer sold or supported. This bears on the fair-use market factor and on the practical likelihood of complaint. "Abandonware" is not a legal doctrine in any jurisdiction, and nothing here rests on it.

### Encryption keys (Switch prod.keys, 3DS AES keys, Wii U keys)

This is the most contested area, and the weakest part of the project's position. The project accepts that risk deliberately, in the belief that these files are worth preserving while they can still be obtained.

- **Keys are unlikely to be copyrightable.** A bare numeric value has no author's creative expression, so copyright is a poor fit. This says nothing about the DMCA, which is the provision that actually applies.
- **DMCA 1201(f) is narrow.** Section 1201(f) allows a person who has lawfully obtained the right to use a copy to circumvent for the sole purpose of achieving interoperability with an independently created program, and 1201(f)(3) allows the means to be made available to others only for that same purpose. Publishing keys openly is not obviously within that allowance, and the trafficking prohibitions in 1201(a)(2) and 1201(b) remain in play. This is the clearest legal risk the project carries.
- **Library of Congress exemptions do not cover this repository.** The triennial exemptions at 37 CFR 201.40 let an eligible library, archive or museum circumvent access controls to preserve a lawfully acquired video game whose server support has ended, with access limited to the institution's premises. The Ninth Triennial Proceeding (2024 cycle) renewed them and declined to extend them to off-premises remote access. A public repository is neither an eligible institution nor an on-premises reading room, so these exemptions show which way preservation policy is moving without authorising what is done here.
- **Keys come from consumer hardware.** They are extracted from retail devices their owners bought. *Chamberlain v. Skylink* (2004) held that a 1201 claim requires some nexus to copyright infringement, in a dispute over a garage-door opener. Later cases have narrowed its reach, and it is a weak foundation for a general post-sale right.
- **Trade secret is not a live issue.** Keys embedded in millions of shipped devices and widely republished are not kept secret by reasonable measures.

### Recent firmware (Switch firmware, PS3UPDAT, PSVUPDAT)

- **Free download is not a licence.** Manufacturers publish these updates on open CDNs without authentication, which makes them easy to obtain but does not grant a right to redistribute them, and PlayStation firmware ships under an end-user licence agreement. The practical argument is that mirroring a file the manufacturer already gives away for free causes no identifiable loss, not that doing so is expressly permitted.
- **Functional necessity.** Emulators cannot run the software these systems were built for without this firmware. That is why the files are collected. It is a statement of purpose, not a legal defence in itself.
- **Yuzu context.** The Yuzu settlement (2024) concerned the emulator and its alleged facilitation of piracy. Yuzu settled without admitting liability, so it set no precedent either way on firmware or key redistribution. It does show that rights holders in this space litigate.

## Asking for a file to be removed

A rights holder, or anyone acting for one, can [open an issue](https://github.com/Abdess/retrobios/issues) identifying the file by path or hash. A file whose removal is requested by its rights holder is removed from the repository and from the next release. No formal notice is required and none will be demanded. State the file and the basis of the claim. The same channel is open to anyone else with a concern about a specific file.

## Contact

The project answers in public, on its
[issue tracker](https://github.com/Abdess/retrobios/issues). A removal request
goes there, as described above.

## Next steps

- [Common questions](faq.md)
- [What is a BIOS?](what-are-bios-files.md)

