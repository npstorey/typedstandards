// Purity guard for @typedstandards/produce-core (verify-core's discipline).
//
// The package's load-bearing promise is that it is format-neutral, I/O-free,
// and browser-safe: no Node built-ins, no environment reads, no network, no
// clock, no RNG. This `no-restricted-imports` rule surfaces violations at
// edit/lint time; the dependency-free `browser-safety.test.ts` enforces the
// same contract mechanically under `node --test` in CI. Test files are exempt
// from the import ban: they legitimately use `node:test` / `node:crypto` to
// build fixtures and cross-check against Node's crypto.

import parser from '@typescript-eslint/parser';

// Bare specifiers that resolve to Node built-ins; the `node:*` pattern below
// covers every prefixed form.
const FORBIDDEN_BARE_IMPORTS = [
  'crypto',
  'fs',
  'fs/promises',
  'path',
  'process',
];

export default [
  {
    files: ['src/**/*.ts'],
    ignores: ['src/**/*.test.ts'],
    languageOptions: { parser },
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: FORBIDDEN_BARE_IMPORTS.map((name) => ({
            name,
            message: `produce-core is I/O-free and browser-safe — do not import "${name}". Use @typedstandards/verify-core primitives, or take the value as a caller-supplied argument.`,
          })),
          patterns: [
            {
              group: ['node:*'],
              message:
                'produce-core is I/O-free and browser-safe — no node:* imports in shipped source.',
            },
          ],
        },
      ],
      'no-restricted-globals': [
        'error',
        {
          name: 'process',
          message:
            'No environment reads — configuration (signing key, kid, trust-registry URL) is caller-supplied.',
        },
        {
          name: 'Buffer',
          message:
            'Buffer is Node-only — use Uint8Array / atob / btoa / verify-core primitives.',
        },
      ],
    },
  },
];
