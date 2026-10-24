import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { z } from "zod";

test("bounded schema collections reject excess input before element validation", () => {
  let visits = 0;
  const schema = z.array(z.string().superRefine(() => { visits += 1; })).max(3);
  const rejected = schema.safeParse(["a", "b", "c", "d", "e"]);
  assert.equal(rejected.success, false);
  assert.equal(visits, 0);
  assert.deepEqual(rejected.error.issues.map(issue => issue.code), ["too_big"]);
  assert.deepEqual(schema.parse(["a", "b"]), ["a", "b"]);
  assert.equal(visits, 2);
});

test("URI normalization preserves encoded scheme text instead of activating it", () => {
  const uri = createRequire(import.meta.url)("fast-uri");
  const encoded = "%68ttp://example.com/a";
  assert.equal(uri.normalize(encoded), encoded);
  assert.equal(uri.normalize("https://example.com/a/../b"), "https://example.com/b");
});
