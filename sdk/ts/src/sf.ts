// HTTP Structured Field Values (RFC 8941): Signature-Input, Signature,
// Signature-Agent, component identifiers, and fields covered with sf or key.

/** A bare item. A decimal is held in thousandths, so serializing it never depends on floating point. */
export type Bare =
  | { t: "int"; v: number }
  | { t: "dec"; v: number }
  | { t: "str"; v: string }
  | { t: "tok"; v: string }
  | { t: "bin"; v: Uint8Array }
  | { t: "bool"; v: boolean };

/** Parameters in order; keys are unique. */
export type Params = [string, Bare][];
export interface Item { bare: Bare; params: Params }
/** A list or dictionary member: an item, or an inner list. */
export type Member = { inner: false; bare: Bare; params: Params } | { inner: true; items: Item[]; params: Params };
/** Dictionary members in order; keys are unique (a repeated key keeps its first position and its last value). */
export type Dictionary = [string, Member][];

export const str = (v: string): Bare => ({ t: "str", v });
export const int = (v: number): Bare => ({ t: "int", v });
export const bin = (v: Uint8Array): Bare => ({ t: "bin", v });
export const TRUE: Bare = { t: "bool", v: true };

export function param(ps: Params, key: string): Bare | undefined {
  return ps.find(([k]) => k === key)?.[1];
}

export function member(d: Dictionary, key: string): Member | undefined {
  return d.find(([k]) => k === key)?.[1];
}

function setParam(ps: Params, key: string, v: Bare): void {
  const e = ps.find(([k]) => k === key);
  if (e) e[1] = v;
  else ps.push([key, v]);
}

// --- parsing (RFC 8941 §4.2) ---

const fail = (msg: string) => new Error(`structured field: ${msg}`);
const isLCAlpha = (c: string) => c >= "a" && c <= "z";
const isAlpha = (c: string) => isLCAlpha(c) || (c >= "A" && c <= "Z");
const isDigit = (c: string) => c >= "0" && c <= "9";
const isTChar = (c: string) => isAlpha(c) || isDigit(c) || "!#$%&'*+-.^_`|~".includes(c);

class Parser {
  i = 0;
  constructor(readonly s: string) {
    if (/[^\x00-\x7f]/.test(s)) throw fail("not ASCII");
    this.skip(" ");
  }
  eof() { return this.i >= this.s.length; }
  peek() { return this.s[this.i]; }
  skip(chars: string) {
    while (!this.eof() && chars.includes(this.peek())) this.i++;
  }
  end() {
    this.skip(" ");
    if (!this.eof()) throw fail(`unexpected ${JSON.stringify(this.peek())} at ${this.i}`);
  }
  /** Moves past the comma between members; true at the end. */
  next(): boolean {
    this.skip(" \t");
    if (this.eof()) return true;
    if (this.peek() !== ",") throw fail(`expected a comma at ${this.i}`);
    this.i++;
    this.skip(" \t");
    if (this.eof()) throw fail("trailing comma");
    return false;
  }
  member(): Member {
    if (!this.eof() && this.peek() === "(") return this.innerList();
    const it = this.item();
    return { inner: false, bare: it.bare, params: it.params };
  }
  innerList(): Member {
    this.i++;
    const items: Item[] = [];
    while (!this.eof()) {
      this.skip(" ");
      if (this.eof()) break;
      if (this.peek() === ")") {
        this.i++;
        return { inner: true, items, params: this.params() };
      }
      items.push(this.item());
      if (!this.eof() && this.peek() !== " " && this.peek() !== ")") throw fail(`expected a space or ) at ${this.i}`);
    }
    throw fail("unterminated inner list");
  }
  item(): Item {
    const bare = this.bare();
    return { bare, params: this.params() };
  }
  params(): Params {
    const ps: Params = [];
    while (!this.eof() && this.peek() === ";") {
      this.i++;
      this.skip(" ");
      const key = this.key();
      let v: Bare = TRUE;
      if (!this.eof() && this.peek() === "=") {
        this.i++;
        v = this.bare();
      }
      setParam(ps, key, v);
    }
    return ps;
  }
  key(): string {
    if (this.eof() || !(isLCAlpha(this.peek()) || this.peek() === "*")) throw fail(`expected a key at ${this.i}`);
    const start = this.i;
    while (!this.eof() && (isLCAlpha(this.peek()) || isDigit(this.peek()) || "_-.*".includes(this.peek()))) this.i++;
    return this.s.slice(start, this.i);
  }
  bare(): Bare {
    if (this.eof()) throw fail("expected an item");
    const c = this.peek();
    if (c === "-" || isDigit(c)) return this.number();
    if (c === '"') return this.string();
    if (c === "*" || isAlpha(c)) return this.token();
    if (c === ":") return this.bytes();
    if (c === "?") {
      const b = this.s[this.i + 1];
      if (b === "0" || b === "1") {
        this.i += 2;
        return { t: "bool", v: b === "1" };
      }
      throw fail(`bad boolean at ${this.i}`);
    }
    throw fail(`unexpected ${JSON.stringify(c)} at ${this.i}`);
  }
  number(): Bare {
    let neg = false;
    if (this.peek() === "-") {
      neg = true;
      this.i++;
    }
    if (this.eof() || !isDigit(this.peek())) throw fail(`expected a digit at ${this.i}`);
    const start = this.i;
    let dot = -1;
    while (!this.eof()) {
      const c = this.peek();
      if (isDigit(c)) this.i++;
      else if (c === "." && dot < 0) {
        if (this.i - start > 12) throw fail("decimal has too many integer digits");
        dot = this.i++;
      } else break;
      if (dot < 0 && this.i - start > 15) throw fail("integer has too many digits");
      if (dot >= 0 && this.i - start > 16) throw fail("decimal has too many digits");
    }
    const num = this.s.slice(start, this.i);
    const sign = neg ? -1 : 1;
    if (dot < 0) return { t: "int", v: sign * Number(num) };
    const whole = num.slice(0, dot - start), frac = num.slice(dot - start + 1);
    if (frac === "" || frac.length > 3) throw fail("decimal needs 1 to 3 fractional digits");
    return { t: "dec", v: sign * (Number(whole) * 1000 + Number((frac + "00").slice(0, 3))) };
  }
  string(): Bare {
    this.i++;
    let out = "";
    while (!this.eof()) {
      const c = this.s[this.i++];
      if (c === "\\") {
        if (this.eof() || (this.peek() !== '"' && this.peek() !== "\\")) throw fail("bad escape in string");
        out += this.s[this.i++];
      } else if (c === '"') {
        return { t: "str", v: out };
      } else if (c < " " || c === "\x7f") {
        throw fail("control character in string");
      } else out += c;
    }
    throw fail("unterminated string");
  }
  token(): Bare {
    const start = this.i++;
    while (!this.eof() && (isTChar(this.peek()) || this.peek() === ":" || this.peek() === "/")) this.i++;
    return { t: "tok", v: this.s.slice(start, this.i) };
  }
  bytes(): Bare {
    this.i++;
    const end = this.s.indexOf(":", this.i);
    if (end < 0) throw fail("unterminated byte sequence");
    const content = this.s.slice(this.i, end);
    this.i = end + 1;
    if (!/^[A-Za-z0-9+/=]*$/.test(content)) throw fail("bad base64 in byte sequence");
    const data = content.replace(/=+$/, "");
    if (data.length % 4 === 1) throw fail("bad base64 in byte sequence");
    return { t: "bin", v: new Uint8Array(Buffer.from(data, "base64")) };
  }
}

export function parseItem(s: string): Item {
  const p = new Parser(s);
  const it = p.item();
  p.end();
  return it;
}

export function parseList(s: string): Member[] {
  const p = new Parser(s);
  const out: Member[] = [];
  while (!p.eof()) {
    out.push(p.member());
    if (p.next()) break;
  }
  return out;
}

/** Parse a dictionary; duplicates lists keys that occurred more than once. */
export function parseDictionary(s: string): { dict: Dictionary; duplicates: string[] } {
  const p = new Parser(s);
  const dict: Dictionary = [];
  const duplicates: string[] = [];
  while (!p.eof()) {
    const key = p.key();
    let m: Member;
    if (!p.eof() && p.peek() === "=") {
      p.i++;
      m = p.member();
    } else {
      m = { inner: false, bare: TRUE, params: p.params() };
    }
    const e = dict.find(([k]) => k === key);
    if (e) {
      e[1] = m;
      duplicates.push(key);
    } else dict.push([key, m]);
    if (p.next()) break;
  }
  return { dict, duplicates };
}

// --- serializing (RFC 8941 §4.1) ---

export function validKey(s: string): boolean {
  return /^[a-z*][a-z0-9_\-.*]*$/.test(s);
}

export function validString(s: string): boolean {
  return /^[\x20-\x7e]*$/.test(s);
}

export function serializeBare(b: Bare): string {
  switch (b.t) {
    case "int":
      return String(b.v);
    case "dec": {
      const n = Math.abs(b.v);
      const frac = String(n % 1000).padStart(3, "0").replace(/0+$/, "") || "0";
      return `${b.v < 0 ? "-" : ""}${Math.floor(n / 1000)}.${frac}`;
    }
    case "str":
      return `"${b.v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
    case "tok":
      return b.v;
    case "bin":
      return `:${Buffer.from(b.v).toString("base64")}:`;
    case "bool":
      return b.v ? "?1" : "?0";
  }
}

export function serializeParams(ps: Params): string {
  return ps.map(([k, v]) => (v.t === "bool" && v.v ? `;${k}` : `;${k}=${serializeBare(v)}`)).join("");
}

export const serializeItem = (it: Item) => serializeBare(it.bare) + serializeParams(it.params);

export function serializeMember(m: Member): string {
  if (!m.inner) return serializeBare(m.bare) + serializeParams(m.params);
  return `(${m.items.map(serializeItem).join(" ")})${serializeParams(m.params)}`;
}

export const serializeList = (l: Member[]) => l.map(serializeMember).join(", ");

export function serializeDictionary(d: Dictionary): string {
  return d
    .map(([k, m]) => (!m.inner && m.bare.t === "bool" && m.bare.v ? k + serializeParams(m.params) : `${k}=${serializeMember(m)}`))
    .join(", ");
}
