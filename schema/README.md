# schema

The JSON Schema every data file must pass: `pricing.v1.json`.

Schema changes follow semver (CLAUDE.md rule 7): additive is minor, a rename or
removal is major and needs a new `/v2`. The schema does not exist yet; until it
lands, `npm run validate` reports "no schema yet" and exits 0.
