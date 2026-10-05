import { execFileSync } from 'node:child_process';
import { test, expect } from 'vitest';

test('validate reports no schema yet while pricing.v1.json is absent', () => {
  const output = execFileSync('node', ['tools/validate.mjs'], {
    encoding: 'utf-8',
    cwd: process.cwd(),
  });
  expect(output).toContain('no schema yet');
});
