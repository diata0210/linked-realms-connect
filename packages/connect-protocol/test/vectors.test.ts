import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  kinds,
  ops,
  errors,
  decodeCard,
  encodeCard,
  decodeInvite,
  encodeInvite,
  decodeInviteURL,
  encodeInviteURL,
  decodeProfile,
  encodeProfile,
  hash,
  checkRevision,
  ProtocolError,
  verifySignature,
  validateOrigin,
} from "../src/index.js";

const root = resolve(import.meta.dirname, "../../..");
const vectors = JSON.parse(
  readFileSync(resolve(root, "protocol/vectors/v1.json"), "utf8"),
);
const bytes = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, "hex"));
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
function errorCode(fn: () => unknown, code: number): void {
  try {
    fn();
    expect.fail("accepted invalid object");
  } catch (e) {
    expect(e).toBeInstanceOf(ProtocolError);
    expect((e as ProtocolError).code).toBe(code);
  }
}

describe("frozen public object parity", () => {
  const card = vectors.envelopes.find((v: any) => v.kind.code === 7);
  const profile = vectors.objects.find(
    (v: any) => v.name === "signed_profile_preset",
  );
  const invite = vectors.objects.find((v: any) => v.name === "invite_link");
  for (const [name, vector, decode, encode] of [
    ["card", card, decodeCard, encodeCard],
    ["invite", invite, decodeInvite, encodeInvite],
  ] as const) {
    it(`${name} bytes/signature/hash/round-trip`, () => {
      const raw = bytes(vector.envelope_hex ?? vector.bytes_hex);
      const object = (decode as (b: Uint8Array) => any)(raw);
      expect(hex((encode as (v: any) => Uint8Array)(object))).toBe(hex(raw));
      if (vector.sha256_hex) expect(hex(hash(raw))).toBe(vector.sha256_hex);
      for (let i = 0; i < raw.length; i++) {
        const mutated = raw.slice();
        mutated[i] ^= 1;
        expect(() => decode(mutated)).toThrow();
      }
      expect(() => decode(raw.slice(0, -1))).toThrow();
      expect(() => decode(Uint8Array.from([...raw, 0]))).toThrow();
    });
  }
  it("profile bytes/signature/hash and async round-trip", async () => {
    const raw = bytes(profile.bytes_hex);
    expect(hex(await encodeProfile(await decodeProfile(raw)))).toBe(hex(raw));
    for (let i = 0; i < raw.length; i++) {
      const mutated = raw.slice();
      mutated[i] ^= 1;
      await expect(decodeProfile(mutated)).rejects.toBeInstanceOf(
        ProtocolError,
      );
    }
    await expect(decodeProfile(raw.slice(0, -1))).rejects.toBeInstanceOf(
      ProtocolError,
    );
    await expect(
      decodeProfile(Uint8Array.from([...raw, 0])),
    ).rejects.toBeInstanceOf(ProtocolError);
  });
  it("accepts Buffer and views with nonzero offsets", async () => {
    for (const [vector, decode, encode] of [
      [card, decodeCard, encodeCard],
      [invite, decodeInvite, encodeInvite],
      [profile, decodeProfile, encodeProfile],
    ] as const) {
      const raw = bytes(vector.envelope_hex ?? vector.bytes_hex);
      const padded = new Uint8Array(raw.length + 13);
      padded.set(raw, 7);
      for (const input of [
        Buffer.from(raw),
        padded.subarray(7, 7 + raw.length),
        Buffer.from(padded.buffer, 7, raw.length),
      ]) {
        const object = await (decode as (b: Uint8Array) => any)(input);
        expect(hex(await (encode as (v: any) => any)(object))).toBe(hex(raw));
      }
    }
  });
  it("invite URL canonical encoding and exact expiry", () => {
    const v = decodeInviteURL(invite.url, 1700000000n);
    expect(encodeInviteURL(v)).toBe(invite.url);
    errorCode(() => decodeInviteURL(invite.url, v.expiresAt), 4);
    for (const suffix of ["=", "?", "#", "/", " "])
      expect(() => decodeInviteURL(invite.url + suffix, 0n)).toThrow();
    expect(() =>
      decodeInviteURL("linkedrealms://invite/" + "A".repeat(4096), 0n),
    ).toThrow();
  });
  it("revision high-water and byte conflicts", () => {
    const raw = bytes(card.envelope_hex),
      c = decodeCard(raw),
      r = checkRevision(undefined, c.revision, raw);
    expect(checkRevision(r, c.revision, raw)).toEqual(r);
    errorCode(() => checkRevision(r, c.revision - 1n, raw), 8);
    errorCode(() => checkRevision(r, c.revision, Uint8Array.of(1)), 8);
    decodeCard(raw, c.expiresAt - 1n);
    errorCode(() => decodeCard(raw, c.expiresAt), 4);
  });
  it("strict Ed25519 negatives from envelope fixtures without TS session codecs", () => {
    // Signature-only parity is additional to the object contract. No seeds or
    // session state are consumed and no TS handshake is implemented.
    for (const v of vectors.negative.filter((v: any) => v.error?.code === 3)) {
      const b = bytes(v.envelope_hex);
      const prefix = new TextEncoder().encode(
        "linked-realms/connect/control/v1\0",
      );
      const message = new Uint8Array(prefix.length + b.length - 64);
      message.set(prefix);
      message.set(b.subarray(0, -64), prefix.length);
      errorCode(
        () => verifySignature(b.subarray(8, 40), message, b.subarray(-64)),
        3,
      );
    }
  });
  it("signed inline profile is the same public object", async () => {
    const greeting = vectors.objects.find(
      (v: any) => v.name === "greeting_inline_profile_and_wallet",
    );
    const raw = bytes(greeting.envelope_hex); // fixed fixture: no source, inline profile starts at body+52
    const inline = raw.subarray(
      140 + 52,
      140 + 52 + bytes(profile.bytes_hex).length,
    );
    expect(hex(await encodeProfile(await decodeProfile(inline)))).toBe(
      profile.bytes_hex,
    );
  });
  it("bounded malformed input property seeds", async () => {
    let x = 0x12345678;
    for (let n = 0; n < 256; n++) {
      const raw = new Uint8Array(n);
      for (let i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >>> 17;
        x ^= x << 5;
        raw[i] = x & 255;
      }
      for (const decode of [decodeCard, decodeInvite])
        expect(() => decode(raw)).toThrow();
      await expect(decodeProfile(raw)).rejects.toBeInstanceOf(ProtocolError);
    }
  });
});
it("Go/TS/spec code-table parity", () => {
  const spec = readFileSync(resolve(root, "protocol/v1.md"), "utf8");
  const table = JSON.parse(
    spec.match(/<!-- code-table -->\s*```json\s*([\s\S]*?)\s*```/)![1],
  );
  for (const [name, rows] of Object.entries({ kinds, ops, errors })) {
    expect(rows).toEqual(table[name]);
    const start = name === "errors" ? 0 : 1;
    expect(new Set(rows.map((row) => row[1])).size).toBe(rows.length);
    rows.forEach((row, i) => expect(row[0]).toBe(start + i));
  }
});
it("canonical origins", () => {
  for (const s of [
    "https://hub.example",
    "https://[2001:db8::1]:8443",
    "https://host.123",
    "https://a.0x1",
    "https://0x7f.0.0.1",
    "https://127.0.0.1:65535",
  ])
    expect(() => validateOrigin(s)).not.toThrow();
  for (const s of [
    "https://HUB.example",
    "https://hub.example/",
    "https://hub.example:443",
    "https://hub.example:0",
    "https://hub.example:01",
    "https://hub.example:65536",
    "https://123",
    "https://[::ffff:127.0.0.1]",
    "https://01.2.3.4",
    "https://host?",
    "https://[2001:0db8::1]",
  ])
    expect(() => validateOrigin(s)).toThrow();
});

it("image-profile decoding fails closed without a native decoder", async () => {
  const cases = JSON.parse(
    readFileSync(resolve(import.meta.dirname, "browser-vectors.json"), "utf8"),
  );
  const valid = cases.find((row: any) => row.name === "profile-png-valid");
  if (!valid) throw new Error("missing valid PNG fixture");
  vi.stubGlobal("createImageBitmap", undefined);
  try {
    await expect(decodeProfile(bytes(valid.hex))).rejects.toBeInstanceOf(
      ProtocolError,
    );
  } finally {
    vi.unstubAllGlobals();
  }
});
