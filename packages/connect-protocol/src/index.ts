import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
export { kinds, ops, errors } from "./codes.js";

export class ProtocolError extends Error {
  constructor(readonly code: number) {
    super(`protocol error ${code}`);
  }
}
function fail(code = 1): never {
  throw new ProtocolError(code);
}
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();
function textBytes(s: string): Uint8Array {
  const b = encoder.encode(s);
  if (utf8.decode(b) !== s) fail(); // Reject JS lone surrogates, never replace.
  return b;
}
function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}
function cat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let n = 0;
  for (const p of parts) {
    result.set(p, n);
    n += p.length;
  }
  return result;
}
function domain(name: string, bytes: Uint8Array): Uint8Array {
  return cat(encoder.encode(`linked-realms/connect/${name}/v1\0`), bytes);
}
export function hash(bytes: Uint8Array): Uint8Array {
  return sha256(bytes);
}
export function verifySignature(
  key: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): void {
  if (key.length !== 32 || signature.length !== 64) fail(3);
  try {
    for (const raw of [key, signature.subarray(0, 32)]) {
      const point = ed25519.ExtendedPoint.fromHex(raw, false);
      if (
        !equal(point.toRawBytes(), raw) ||
        point.isSmallOrder() ||
        !point.isTorsionFree()
      )
        fail(3);
    }
    if (!ed25519.verify(signature, message, key, { zip215: false })) fail(3);
  } catch {
    fail(3);
  }
}
class Reader {
  pos = 0;
  constructor(readonly bytes: Uint8Array) {}
  take(n: number): Uint8Array {
    if (!Number.isSafeInteger(n) || n < 0 || n > this.bytes.length - this.pos)
      fail();
    const b = new Uint8Array(this.bytes.subarray(this.pos, this.pos + n));
    this.pos += n;
    return b;
  }
  u8(): number {
    return this.take(1)[0];
  }
  u16(): number {
    const b = this.take(2);
    return b[0] * 256 + b[1];
  }
  u32(): number {
    const b = this.take(4);
    return new DataView(b.buffer).getUint32(0);
  }
  u64(): bigint {
    const b = this.take(8);
    return new DataView(b.buffer).getBigUint64(0);
  }
  blob(max: number): Uint8Array {
    const n = this.u32();
    if (n > max) fail();
    return this.take(n);
  }
  text(max: number): string {
    try {
      return utf8.decode(this.blob(max));
    } catch {
      return fail();
    }
  }
  done(): void {
    if (this.pos !== this.bytes.length) fail();
  }
}
class Writer {
  private parts: Uint8Array[] = [];
  bytes(b: Uint8Array, length?: number): this {
    if (length !== undefined && b.length !== length) fail();
    this.parts.push(b);
    return this;
  }
  num(n: number, size: number): this {
    if (!Number.isInteger(n) || n < 0 || n >= 2 ** (size * 8)) fail();
    const b = new Uint8Array(size);
    let x = n;
    for (let i = size - 1; i >= 0; i--) {
      b[i] = x % 256;
      x = Math.floor(x / 256);
    }
    return this.bytes(b);
  }
  u64(n: bigint): this {
    if (typeof n !== "bigint" || n < 0n || n > (1n << 64n) - 1n) fail();
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, n);
    return this.bytes(b);
  }
  blob(b: Uint8Array, max: number): this {
    if (b.length > max) fail();
    return this.num(b.length, 4).bytes(b);
  }
  text(s: string, max: number): this {
    return this.blob(textBytes(s), max);
  }
  finish(): Uint8Array {
    return cat(...this.parts);
  }
}

export interface Endpoint {
  origin: string;
  hubKey: Uint8Array;
}
export function validateOrigin(s: string): void {
  if (
    textBytes(s).length > 192 ||
    !/^https:\/\/[\x21-\x7e]+$/.test(s) ||
    s !== s.toLowerCase() ||
    /[?#%]/.test(s)
  )
    fail();
  const match = /^https:\/\/(\[[^\]]+\]|[^:/]+)(?::([0-9]+))?$/.exec(s);
  if (!match) fail();
  const [, host, port] = match;
  if (port !== undefined) {
    const n = Number(port);
    if (n < 1 || n > 65535 || n === 443 || String(n) !== port) fail();
  }
  if (host.startsWith("[")) {
    // WHATWG is suitable for canonical IPv6, but rewrites some valid DNS labels.
    if (host.includes(".")) fail();
    try {
      if (new URL("https://" + host).hostname !== host) fail();
    } catch {
      return fail();
    }
  } else if (/^[0-9.]+$/.test(host)) {
    const octets = host.split(".");
    if (
      octets.length !== 4 ||
      octets.some((o) => o === "" || Number(o) > 255 || String(Number(o)) !== o)
    )
      fail();
  } else if (
    host.length > 253 ||
    !host
      .split(".")
      .every((l) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l))
  )
    fail();
}
function endpoints(r: Reader): Endpoint[] {
  const count = r.u16();
  if (count < 1 || count > 8) fail();
  const result: Endpoint[] = [];
  for (let i = 0; i < count; i++)
    result.push({ origin: r.text(192), hubKey: r.take(32) });
  validateEndpoints(result);
  return result;
}
function validateEndpoints(es: Endpoint[]): void {
  if (es.length < 1 || es.length > 8) fail();
  es.forEach((e, i) => {
    validateOrigin(e.origin);
    if (
      e.hubKey.length !== 32 ||
      (i > 0 && es[i - 1].origin >= e.origin) ||
      es.slice(0, i).some((p) => equal(p.hubKey, e.hubKey))
    )
      fail();
  });
}
function writeEndpoints(w: Writer, es: Endpoint[]): void {
  validateEndpoints(es);
  w.num(es.length, 2);
  for (const e of es) w.text(e.origin, 192).bytes(e.hubKey, 32);
}

export interface Profile {
  playerKey: Uint8Array;
  revision: bigint;
  displayName: string;
  avatarKind: number;
  avatar: Uint8Array;
  signature: Uint8Array;
}
function profileUnsigned(p: Profile): Uint8Array {
  return new Writer()
    .bytes(p.playerKey, 32)
    .u64(p.revision)
    .text(p.displayName, 32)
    .num(p.avatarKind, 1)
    .blob(p.avatar, 8193)
    .finish();
}
function pngCRC(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++)
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function checkAvatar(p: Profile): void {
  if (p.avatarKind === 0) {
    if (!equal(p.avatar, encoder.encode("default"))) fail();
    return;
  }
  if (p.avatarKind !== 1 || p.avatar.length < 2 || p.avatar.length > 8193)
    fail();
  const mime = p.avatar[0],
    b = p.avatar.subarray(1);
  let width = 0,
    height = 0;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (mime === 0) {
    if (
      b.length < 45 ||
      !equal(
        b.subarray(0, 8),
        Uint8Array.of(137, 80, 78, 71, 13, 10, 26, 10),
      ) ||
      dv.getUint32(8) !== 13 ||
      String.fromCharCode(...b.subarray(12, 16)) !== "IHDR"
    )
      fail();
    width = dv.getUint32(16);
    height = dv.getUint32(20);
    let offset = 8,
      idat = false,
      ended = false;
    while (offset < b.length) {
      if (b.length - offset < 12) fail();
      const n = dv.getUint32(offset);
      if (n > b.length - offset - 12) fail();
      const type = String.fromCharCode(...b.subarray(offset + 4, offset + 8));
      if (
        pngCRC(b.subarray(offset + 4, offset + 8 + n)) !==
        dv.getUint32(offset + 8 + n)
      )
        fail();
      if (type === "IDAT") idat = true;
      offset += n + 12;
      if (type === "IEND") {
        if (n !== 0) fail();
        ended = true;
        break;
      }
    }
    if (!idat || !ended) fail();
  } else if (mime === 1) {
    if (b.length < 4 || b[0] !== 255 || b[1] !== 216) fail();
    let i = 2,
      scan = false,
      ended = false;
    while (i < b.length) {
      if (b[i++] !== 255) {
        if (!scan) fail();
        continue;
      }
      while (b[i] === 255) i++;
      if (i >= b.length) fail();
      const marker = b[i++];
      if (scan && (marker === 0 || (marker >= 208 && marker <= 215))) continue;
      if (marker === 217) {
        ended = true;
        break;
      }
      if (marker === 0 || marker === 216 || i + 2 > b.length) fail();
      const n = dv.getUint16(i);
      if (n < 2 || n > b.length - i) fail();
      if ([192, 193, 194].includes(marker)) {
        if (n < 8) fail();
        height = dv.getUint16(i + 3);
        width = dv.getUint16(i + 5);
      }
      scan = marker === 218;
      i += n;
    }
    if (!ended) fail();
  } else if (mime === 2) {
    if (
      b.length < 30 ||
      String.fromCharCode(...b.subarray(0, 4)) !== "RIFF" ||
      dv.getUint32(4, true) + 8 > b.length ||
      String.fromCharCode(...b.subarray(8, 12)) !== "WEBP"
    )
      fail();
    const kind = String.fromCharCode(...b.subarray(12, 16));
    if (kind === "VP8X") {
      width = 1 + b[24] + 256 * b[25] + 65536 * b[26];
      height = 1 + b[27] + 256 * b[28] + 65536 * b[29];
    } else if (
      kind === "VP8 " &&
      b[23] === 157 &&
      b[24] === 1 &&
      b[25] === 42
    ) {
      width = dv.getUint16(26, true) & 16383;
      height = dv.getUint16(28, true) & 16383;
    } else if (kind === "VP8L" && b[20] === 47) {
      const bits = dv.getUint32(21, true);
      width = 1 + (bits & 16383);
      height = 1 + ((bits >>> 14) & 16383);
    } else fail();
  } else fail();
  if (width < 1 || height < 1 || width > 128 || height > 128) fail();
}
// Public profile codecs await native pixel decoding before accepting image avatars.
// A missing native decoder fails closed. Display data must never be inserted as HTML.
export async function validateAvatarImage(p: Profile): Promise<void> {
  checkAvatar(p);
  if (p.avatarKind === 0) return;
  const bytes = new Uint8Array(p.avatar.subarray(1));
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(
      new Blob([bytes], {
        type: ["image/png", "image/jpeg", "image/webp"][p.avatar[0]],
      }),
    );
  } catch {
    return fail();
  }
  try {
    if (
      bitmap.width < 1 ||
      bitmap.height < 1 ||
      bitmap.width > 128 ||
      bitmap.height > 128
    )
      fail();
  } finally {
    bitmap.close();
  }
}
export async function decodeProfile(b: Uint8Array): Promise<Profile> {
  if (b.length > 9216) fail();
  const r = new Reader(b);
  const p: Profile = {
    playerKey: r.take(32),
    revision: r.u64(),
    displayName: r.text(32),
    avatarKind: r.u8(),
    avatar: r.blob(8193),
    signature: r.take(64),
  };
  r.done();
  verifySignature(
    p.playerKey,
    domain("profile", b.subarray(0, -64)),
    p.signature,
  );
  await validateAvatarImage(p);
  return p;
}
export async function encodeProfile(p: Profile): Promise<Uint8Array> {
  const b = cat(
    profileUnsigned(p),
    new Writer().bytes(p.signature, 64).finish(),
  );
  await decodeProfile(b);
  return b;
}

export interface Invite {
  landKey: Uint8Array;
  hubs: Endpoint[];
  code: Uint8Array;
  expiresAt: bigint;
  signature: Uint8Array;
}
export function decodeInvite(b: Uint8Array, now?: bigint): Invite {
  if (b.length > 2048) fail();
  const r = new Reader(b);
  if (r.u8() !== 1) fail(2);
  const v = {
    landKey: r.take(32),
    hubs: endpoints(r),
    code: r.take(32),
    expiresAt: r.u64(),
    signature: r.take(64),
  };
  r.done();
  verifySignature(v.landKey, domain("invite", b.subarray(0, -64)), v.signature);
  if (now !== undefined && now >= v.expiresAt) fail(4);
  return v;
}
export function encodeInvite(v: Invite): Uint8Array {
  const w = new Writer().num(1, 1).bytes(v.landKey, 32);
  writeEndpoints(w, v.hubs);
  const b = w
    .bytes(v.code, 32)
    .u64(v.expiresAt)
    .bytes(v.signature, 64)
    .finish();
  decodeInvite(b);
  return b;
}
function base64url(b: Uint8Array): string {
  return btoa(String.fromCharCode(...b))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
export function decodeInviteURL(s: string, now: bigint): Invite {
  const prefix = "linkedrealms://invite/";
  if (s.length > 3072 || !s.startsWith(prefix)) fail();
  const raw = s.slice(prefix.length);
  if (!/^[A-Za-z0-9_-]+$/.test(raw)) fail();
  let b: Uint8Array;
  try {
    b = Uint8Array.from(atob(raw.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
      c.charCodeAt(0),
    );
  } catch {
    return fail();
  }
  if (base64url(b) !== raw) fail();
  return decodeInvite(b, now);
}
export function encodeInviteURL(v: Invite): string {
  return "linkedrealms://invite/" + base64url(encodeInvite(v));
}

export interface Card {
  sender: Uint8Array;
  nonce: Uint8Array;
  issuedAt: bigint;
  expiresAt: bigint;
  landKey: Uint8Array;
  name: string;
  description: string;
  noiseKey: Uint8Array;
  doorMode: number;
  hubs: Endpoint[];
  currentPlayers: number;
  maxPlayers: number;
  revision: bigint;
  policyRevision: bigint;
  signature: Uint8Array;
}
export function decodeCard(b: Uint8Array, now?: bigint): Card {
  if (b.length < 204 || b.length > 4096) fail();
  const r = new Reader(b);
  if (!equal(r.take(4), encoder.encode("LRC1"))) fail();
  if (r.u16() !== 1) fail(2);
  if (r.u16() !== 7) fail();
  const sender = r.take(32),
    recipient = r.take(32),
    context = r.take(16),
    nonce = r.take(32),
    issuedAt = r.u64(),
    expiresAt = r.u64(),
    n = r.u32();
  if (n + 204 !== b.length) fail();
  verifySignature(
    sender,
    domain("control", b.subarray(0, -64)),
    b.subarray(-64),
  );
  const landKey = r.take(32),
    name = r.text(64),
    description = r.text(512),
    noiseKey = r.take(32),
    doorMode = r.u8(),
    hubs = endpoints(r),
    currentPlayers = r.u16(),
    maxPlayers = r.u16();
  if (r.u16() !== 1) fail(2);
  const revision = r.u64(),
    policyRevision = r.u64();
  if (r.u8() !== 0) fail();
  const signature = r.take(64);
  r.done();
  if (expiresAt < issuedAt || expiresAt - issuedAt > 600n) fail(4);
  if (
    recipient.some((x) => x !== 0) ||
    context.some((x) => x !== 0) ||
    !equal(sender, landKey) ||
    doorMode > 1 ||
    currentPlayers > maxPlayers ||
    maxPlayers > 64 ||
    expiresAt - issuedAt !== 600n
  )
    fail();
  if (now !== undefined && (now >= expiresAt || issuedAt > now + 120n)) fail(4);
  return {
    sender,
    nonce,
    issuedAt,
    expiresAt,
    landKey,
    name,
    description,
    noiseKey,
    doorMode,
    hubs,
    currentPlayers,
    maxPlayers,
    revision,
    policyRevision,
    signature,
  };
}
export function encodeCard(v: Card): Uint8Array {
  const body = new Writer()
    .bytes(v.landKey, 32)
    .text(v.name, 64)
    .text(v.description, 512)
    .bytes(v.noiseKey, 32)
    .num(v.doorMode, 1);
  writeEndpoints(body, v.hubs);
  body
    .num(v.currentPlayers, 2)
    .num(v.maxPlayers, 2)
    .num(1, 2)
    .u64(v.revision)
    .u64(v.policyRevision)
    .num(0, 1);
  const b = new Writer()
    .bytes(encoder.encode("LRC1"))
    .num(1, 2)
    .num(7, 2)
    .bytes(v.sender, 32)
    .bytes(new Uint8Array(48))
    .bytes(v.nonce, 32)
    .u64(v.issuedAt)
    .u64(v.expiresAt)
    .blob(body.finish(), 4096)
    .bytes(v.signature, 64)
    .finish();
  decodeCard(b);
  return b;
}
export interface Revision {
  revision: bigint;
  hash: Uint8Array;
}
export function checkRevision(
  previous: Revision | undefined,
  revision: bigint,
  b: Uint8Array,
): Revision {
  const next = { revision, hash: hash(b) };
  if (
    previous &&
    (revision < previous.revision ||
      (revision === previous.revision && !equal(next.hash, previous.hash)))
  )
    fail(8);
  return next;
}
