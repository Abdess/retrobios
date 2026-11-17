// Hashing a file on this device: SHA1 and SHA256 by Web Crypto, MD5 and
// CRC32 here, since Web Crypto has neither. The bytes never leave the page.
// MD5 and CRC32 take the file piece by piece, so a large file is read in
// slices and the page keeps answering between them.

const CRC_TABLE = (() => {
	const table = new Uint32Array(256);
	for (let n = 0; n < 256; n += 1) {
		let c = n;
		for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		table[n] = c >>> 0;
	}
	return table;
})();

export const hexBytes = (bytes: Uint8Array) => [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');

export class Crc32 {
	crc = 0xffffffff;

	update(bytes: Uint8Array): this {
		let crc = this.crc;
		for (let i = 0; i < bytes.length; i += 1) crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
		this.crc = crc;
		return this;
	}

	digest(): string {
		return ((this.crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, '0');
	}
}

const MD5_SHIFTS = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
const MD5_TABLE = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);

// RFC 1321. Whole 64-byte blocks are read in place from each slice; only a
// block split between two slices is copied.
export class Md5 {
	state = new Int32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);
	words = new Int32Array(16);
	pending = new Uint8Array(64);
	pendingLength = 0;
	length = 0;

	block(view: DataView, offset: number) {
		const words = this.words;
		const state = this.state;
		for (let i = 0; i < 16; i += 1) words[i] = view.getInt32(offset + i * 4, true);
		let [a, b, c, d] = state;
		for (let i = 0; i < 64; i += 1) {
			const round = i >> 4;
			const f = round === 0 ? (b & c) | (~b & d) : round === 1 ? (d & b) | (~d & c) : round === 2 ? b ^ c ^ d : c ^ (b | ~d);
			const g = round === 0 ? i : round === 1 ? (5 * i + 1) % 16 : round === 2 ? (3 * i + 5) % 16 : (7 * i) % 16;
			const shift = MD5_SHIFTS[round * 4 + (i % 4)];
			const sum = (a + f + MD5_TABLE[i] + words[g]) | 0;
			a = d;
			d = c;
			c = b;
			b = (b + ((sum << shift) | (sum >>> (32 - shift)))) | 0;
		}
		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;
	}

	update(bytes: Uint8Array): this {
		this.length += bytes.length;
		let start = 0;
		if (this.pendingLength) {
			start = Math.min(64 - this.pendingLength, bytes.length);
			this.pending.set(bytes.subarray(0, start), this.pendingLength);
			this.pendingLength += start;
			if (this.pendingLength < 64) return this;
			this.block(new DataView(this.pending.buffer), 0);
			this.pendingLength = 0;
		}
		const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
		const whole = start + ((bytes.length - start) - ((bytes.length - start) % 64));
		for (let offset = start; offset < whole; offset += 64) this.block(view, offset);
		this.pending.set(bytes.subarray(whole));
		this.pendingLength = bytes.length - whole;
		return this;
	}

	digest(): string {
		const tail = new Uint8Array(this.pendingLength < 56 ? 64 : 128);
		tail.set(this.pending.subarray(0, this.pendingLength));
		tail[this.pendingLength] = 0x80;
		const view = new DataView(tail.buffer);
		const bits = this.length * 8;
		view.setUint32(tail.length - 8, bits >>> 0, true);
		view.setUint32(tail.length - 4, Math.floor(bits / 2 ** 32), true);
		for (let offset = 0; offset < tail.length; offset += 64) this.block(view, offset);
		return hexBytes(new Uint8Array(this.state.buffer));
	}
}

export const md5 = (bytes: Uint8Array) => new Md5().update(bytes).digest();
export const crc32 = (bytes: Uint8Array) => new Crc32().update(bytes).digest();

export type FileHashes = { sha1: string; md5: string; crc32: string; sha256: string };

const SLICE = 4 * 1024 * 1024;

// The four hashes of a file. MD5 and CRC32 read it slice by slice, each
// slice awaited so the page stays responsive; *progress* gets the share
// read so far, from 0 to 1. SHA1 and SHA256 then hash it whole in Web
// Crypto, which works off the page's own thread.
export const hashFile = async (file: Blob, progress?: (share: number) => void): Promise<FileHashes> => {
	const md5State = new Md5();
	const crcState = new Crc32();
	for (let offset = 0; offset < file.size; offset += SLICE) {
		const bytes = new Uint8Array(await file.slice(offset, offset + SLICE).arrayBuffer());
		md5State.update(bytes);
		crcState.update(bytes);
		progress?.(Math.min(1, (offset + bytes.length) / file.size));
	}
	const buffer = await file.arrayBuffer();
	const [sha1, sha256] = await Promise.all(
		['SHA-1', 'SHA-256'].map(async (name) => hexBytes(new Uint8Array(await crypto.subtle.digest(name, buffer)))),
	);
	progress?.(1);
	return { sha1, md5: md5State.digest(), crc32: crcState.digest(), sha256 };
};
