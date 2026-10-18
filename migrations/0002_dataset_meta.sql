-- Tokker dataset metadata (migration 0002): the small key/value table the
-- /v1/offers envelope reads (issue #19), filled by the repo-mirror work
-- (plan.md §5.2 G1) every time it loads data/pricing.json into D1.
--
-- Table privacy: published dataset metadata only — nothing personal
-- (plan.md §5.1 table_privacy: holds nothing).
--
-- Like 0001, these tables are applied by wrangler (`migrations_dir` in
-- wrangler.toml); the module's Rust-side `Migrations` stay EMPTY.
--
-- Keys the API reads today (additive keys are fine; a rename or removal
-- needs a new migration):
--   source_commit  the data/pricing.json commit the mirror loaded
--   license        the dataset license line (data/LICENSE)

CREATE TABLE dataset_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
