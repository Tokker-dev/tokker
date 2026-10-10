//! The portable-SQL lint (ADR 0004): flags tokens that SQLite and Postgres
//! disagree about, or that betray non-portable DDL. One canonical definition
//! shared by `fz doctor` and the Postgres migration runner's set selection
//! (issue #18) so the two can never drift.
//!
//! The lint reads **DDL**, not the whole file. Comments and string
//! literals are stripped first, because neither is executed: a migration
//! that explains itself in prose, or stores the word `blob` as data, is
//! portable. Scanning them produced false positives that failed a module
//! for a backtick inside a `--` comment.

/// Returns `(token, explanation)` pairs found in `sql`.
///
/// This is the predicate behind both `fz doctor`'s migration lint and the
/// `cratefield-adapter-postgres` runner's rule that a module's `sqlite`
/// migration set may be applied to Postgres only when it passes.
///
/// SQL comments (`-- ...`, `/* ... */`) and single-quoted string literals
/// are ignored: they are not DDL. Double-quoted identifiers are not
/// ignored, because they are DDL and portable in both dialects.
#[must_use]
pub fn lint_portable_sql(sql: &str) -> Vec<(&'static str, &'static str)> {
    const BANNED: &[(&str, &str)] = &[
        (
            "AUTOINCREMENT",
            "SQLite-only; use plain INTEGER PRIMARY KEY (ULID ids instead of autoincrement)",
        ),
        (
            "datetime(",
            "dialect function; store ISO-8601 TEXT and compute in code",
        ),
        ("SERIAL", "Postgres-only; use TEXT ULID ids"),
        (
            "NOW()",
            "dialect function; bind an ISO-8601 timestamp instead",
        ),
        (
            "json_extract",
            "SQLite-only JSON function; parse JSON in code",
        ),
        (
            "`",
            "backtick quoting is MySQL/SQLite; use double quotes or none",
        ),
        (
            "BLOB",
            "SQLite-only type; Postgres has BYTEA — ship a migrations/postgres override",
        ),
    ];

    let haystack = strip_non_ddl(sql).to_ascii_lowercase();
    BANNED
        .iter()
        .filter(|(token, _)| {
            if *token == "`" {
                haystack.contains('`')
            } else {
                haystack.contains(&token.to_ascii_lowercase())
            }
        })
        .copied()
        .collect()
}

/// Card-data fragments the harness never stores. With a normal Stripe
/// integration the card details go straight to Stripe (Checkout, Elements, the
/// SDKs) and never reach a backend, so a column or secret shaped like a card
/// number, verification code or full expiry is a mistake. Deliberately the
/// *specific* forms and not bare `pan`, `track` or `expiry`, which collide with
/// legitimate columns — an audio `pan`, a music `track`, a `session_expiry`
/// (issue #44).
pub const CARD_DATA: &[&str] = &[
    "card_number",
    "cardnumber",
    "card_no",
    "cardno",
    "primary_account_number",
    "full_pan",
    "cvv",
    "cvc",
    "cvv2",
    "cvc2",
    "card_cvv",
    "card_cvc",
    "exp_month",
    "exp_year",
    "card_expiry",
    "expiry_date",
    "expiration_date",
    "track_data",
    "track2",
    "magstripe",
    "magnetic_stripe",
    // `tools/migration-guard.sh` carried these four and this list did
    // not, so the same non-goal was two different rules: a `.sql`
    // migration naming `expiry_month` failed the shell guard, and a
    // declared table naming it passed everything, because a declared
    // table's DDL is not a `.sql` file and only ever meets this list.
    // `the_migration_guard_knows_the_same_card_data` keeps them one.
    "cardholder",
    "expiry_month",
    "expiry_year",
];

/// The first card-data fragment `text` contains (case-insensitive), or `None`.
/// Keeps card numbers, verification codes and full expiry out of migrations and
/// secret names — with a normal Stripe integration none of them should exist
/// (issue #44).
#[must_use]
pub fn card_data_hit(text: &str) -> Option<&'static str> {
    let hay = text.to_ascii_lowercase();
    CARD_DATA.iter().copied().find(|frag| hay.contains(frag))
}

/// Card-data column or table names found in `sql`, as `(fragment, why)` pairs.
/// Comments and string literals are ignored, so documenting the rule does not
/// trip it.
#[must_use]
pub fn lint_card_data(sql: &str) -> Vec<(&'static str, &'static str)> {
    match card_data_hit(&strip_non_ddl(sql)) {
        Some(frag) => vec![(
            frag,
            "looks like card data; with a normal Stripe integration the card never \
             reaches a backend — store only Stripe's identifiers",
        )],
        None => Vec::new(),
    }
}

/// Words a `CREATE` may carry before `TABLE`. Anything else after `CREATE`
/// — `INDEX`, `UNIQUE`, `VIEW`, `TRIGGER` — ends the match, which is how
/// `CREATE UNIQUE INDEX deletion_jobs_confirmation_code` stays out of the
/// result.
///
/// `VIRTUAL` is here because a virtual table is a table: it holds rows, an
/// export would read it, and leaving it out would be a hole shaped exactly
/// like the one this scan exists to close.
const CREATE_MODIFIERS: &[&str] = &[
    "temp",
    "temporary",
    "unlogged",
    "global",
    "local",
    "virtual",
];

/// Every table `sql` leaves behind, in the order it creates them.
///
/// This is the other half of the personal-data rule (issue #272).
/// [`undeclared_tables`](crate::undeclared_tables) compares
/// [`Module::tables`](crate::Module::tables) against
/// [`Module::personal_data`](crate::Module::personal_data), so it can only see
/// a table that is already in one of those two lists; a table the module never
/// lists is invisible to it, to `fz data export` and to erasure at once. The
/// migrations are where a table actually comes into being, so they are what
/// [`unlisted_tables`](crate::unlisted_tables) compares against — and this is
/// the scan it reads them with.
///
/// **Not a SQL parser, on purpose.** A parser is a dependency and a decision
/// this workspace has not taken; what a `CREATE TABLE` names is recoverable
/// from a token walk, and a narrow scan that is wrong loudly is worth more
/// here than a general one nobody can audit. It reads the same stripped DDL
/// [`lint_portable_sql`] does, so the four ways it could be wrong are handled
/// the same way in both:
///
/// 1. **A `CREATE TABLE` in a comment or a string is not DDL.** Both are
///    replaced with spaces before the walk, so a migration that explains its
///    own schema in prose — as `deletion_jobs` and `cms_item` both do — does
///    not report the tables it mentions.
/// 2. **A temporary table is not the module's table.** `CREATE TEMP TABLE`
///    and `CREATE TEMPORARY TABLE` are skipped: the table is gone with the
///    connection, so no export could read it and no erasure could miss it.
/// 3. **The rebuild pattern leaves one table, not two.** SQLite cannot relax
///    a `NOT NULL`, so `auth-core 0003` and `waitlist 0005` both create
///    `<table>_rebuild`, copy into it, drop the original and rename. Rather
///    than special-casing the name, the walk tracks what each statement does:
///    `CREATE` adds, `DROP TABLE` removes, `ALTER TABLE … RENAME TO` moves.
///    The answer is therefore what exists when the last migration has run,
///    which is the thing `tables()` is supposed to describe. `ALTER TABLE …
///    RENAME COLUMN … TO …` is left alone — it renames a column, not a table.
/// 4. **Case.** Names come back exactly as the SQL wrote them; duplicates are
///    collapsed ASCII-case-insensitively, because an unquoted identifier is
///    case-folded by both dialects.
///
/// A name that is not a plain identifier — schema-qualified, or quoted with
/// something exotic inside — is returned verbatim rather than dropped. It will
/// not match anything in `tables()` and the module will fail the check, which
/// is the safe direction for a scan to be uncertain in: nothing in this
/// workspace needs such a name, and silently ignoring one is how a table
/// escapes.
///
/// Postgres dollar-quoted bodies (`$$ … $$`) are **not** stripped, because
/// nothing in this workspace uses one; a `CREATE TABLE` inside a function body
/// would be reported. That, too, fails loudly rather than quietly.
///
/// ```
/// use cratefield_core::created_tables;
///
/// let sql = "\
/// -- CREATE TABLE mentioned_in_prose (…)
/// CREATE TABLE IF NOT EXISTS notes (id TEXT PRIMARY KEY);
/// CREATE INDEX notes_by_id ON notes (id);
/// CREATE TEMP TABLE scratch (id TEXT);
/// CREATE TABLE notes_rebuild (id TEXT PRIMARY KEY, body TEXT);
/// DROP TABLE notes;
/// ALTER TABLE notes_rebuild RENAME TO notes;";
/// assert_eq!(created_tables(sql), ["notes"]);
/// ```
#[must_use]
pub fn created_tables(sql: &str) -> Vec<String> {
    let ddl = strip_non_ddl(sql);
    let words: Vec<&str> = ddl
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '"' || c == '.'))
        .filter(|word| !word.is_empty())
        .collect();

    let mut live: Vec<String> = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let word = words[i];
        i += 1;
        if word.eq_ignore_ascii_case("create") {
            create_table(&words, &mut i, &mut live);
        } else if word.eq_ignore_ascii_case("drop") {
            drop_table(&words, &mut i, &mut live);
        } else if word.eq_ignore_ascii_case("alter") {
            rename_table(&words, &mut i, &mut live);
        }
    }
    live
}

/// Whether the word at `at` is `keyword`, ignoring case. `false` past the end,
/// so a statement cut off mid-way simply does not match.
fn word_is(words: &[&str], at: usize, keyword: &str) -> bool {
    words
        .get(at)
        .is_some_and(|word| word.eq_ignore_ascii_case(keyword))
}

/// `CREATE [TEMP|…] TABLE [IF NOT EXISTS] <name>`, from just after `CREATE`.
fn create_table(words: &[&str], i: &mut usize, live: &mut Vec<String>) {
    let mut temporary = false;
    while CREATE_MODIFIERS
        .iter()
        .any(|modifier| word_is(words, *i, modifier))
    {
        temporary |= word_is(words, *i, "temp") || word_is(words, *i, "temporary");
        *i += 1;
    }
    if !word_is(words, *i, "table") {
        return;
    }
    *i += 1;
    skip_keywords(words, i, &["if", "not", "exists"]);
    let Some(name) = words.get(*i).copied() else {
        return;
    };
    *i += 1;
    if !temporary {
        add(live, name);
    }
}

/// `DROP TABLE [IF EXISTS] <name>`, from just after `DROP`.
fn drop_table(words: &[&str], i: &mut usize, live: &mut Vec<String>) {
    if !word_is(words, *i, "table") {
        return;
    }
    *i += 1;
    skip_keywords(words, i, &["if", "exists"]);
    if let Some(name) = words.get(*i).copied() {
        *i += 1;
        remove(live, name);
    }
}

/// `ALTER TABLE [IF EXISTS] <from> RENAME TO <to>`, from just after `ALTER`.
/// Every other `ALTER TABLE` — including `RENAME COLUMN … TO …` — leaves the
/// set alone.
fn rename_table(words: &[&str], i: &mut usize, live: &mut Vec<String>) {
    if !word_is(words, *i, "table") {
        return;
    }
    *i += 1;
    skip_keywords(words, i, &["if", "exists"]);
    let Some(from) = words.get(*i).copied() else {
        return;
    };
    *i += 1;
    if !(word_is(words, *i, "rename") && word_is(words, *i + 1, "to")) {
        return;
    }
    let Some(to) = words.get(*i + 2).copied() else {
        return;
    };
    *i += 3;
    remove(live, from);
    add(live, to);
}

/// Steps over `keywords` when they all appear next, in order; leaves `i`
/// alone otherwise, so a table actually called `if` is still read as a name.
fn skip_keywords(words: &[&str], i: &mut usize, keywords: &[&str]) {
    let matched = keywords
        .iter()
        .enumerate()
        .all(|(offset, keyword)| word_is(words, *i + offset, keyword));
    if matched {
        *i += keywords.len();
    }
}

/// Adds a table name, unquoted, unless an equal-ignoring-case one is there.
fn add(live: &mut Vec<String>, name: &str) {
    let name = unquote(name);
    if !live.iter().any(|table| table.eq_ignore_ascii_case(&name)) {
        live.push(name);
    }
}

/// Removes a table name, ignoring case; a name that is not there is a drop of
/// a table another module or an earlier deployment owns, and is not our
/// business.
fn remove(live: &mut Vec<String>, name: &str) {
    let name = unquote(name);
    live.retain(|table| !table.eq_ignore_ascii_case(&name));
}

/// `"users"` → `users`. Anything else is returned unchanged, including a
/// half-quoted name, which will fail the comparison rather than be guessed at.
fn unquote(name: &str) -> String {
    name.strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(name)
        .to_owned()
}

/// Replaces every SQL comment and single-quoted string literal with spaces,
/// leaving the executable DDL and its byte positions alone.
///
/// Block comments nest in Postgres and do not in SQLite; this counts depth,
/// which is right for Postgres and harmless for SQLite (a migration relying
/// on the difference is not portable anyway). An unterminated comment or
/// literal swallows the rest of the input rather than panicking — the
/// database will reject it long before the lint matters.
fn strip_non_ddl(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    while i < bytes.len() {
        // `--` to end of line.
        if bytes[i] == b'-' && bytes.get(i + 1) == Some(&b'-') {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        // `/* ... */`, nesting.
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            let mut depth = 1_usize;
            out.push_str("  ");
            i += 2;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    out.push_str("  ");
                    i += 2;
                } else {
                    out.push(if bytes[i] == b'\n' { '\n' } else { ' ' });
                    i += 1;
                }
            }
            continue;
        }
        // `'...'`, with `''` as the escape.
        if bytes[i] == b'\'' {
            out.push(' ');
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\'' {
                    if bytes.get(i + 1) == Some(&b'\'') {
                        out.push_str("  ");
                        i += 2;
                        continue;
                    }
                    out.push(' ');
                    i += 1;
                    break;
                }
                out.push(if bytes[i] == b'\n' { '\n' } else { ' ' });
                i += 1;
            }
            continue;
        }
        // Not a byte we rewrite: copy the whole UTF-8 character.
        let start = i;
        i += 1;
        while i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
            i += 1;
        }
        out.push_str(&sql[start..i]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::lint_portable_sql;

    #[test]
    fn clean_portable_sql_passes() {
        let sql = "CREATE TABLE t (id TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0, \
                   created_at TEXT NOT NULL, UNIQUE(id));";
        assert!(lint_portable_sql(sql).is_empty());
    }

    #[test]
    fn every_banned_token_is_flagged() {
        let sql = "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, \
                   at datetime('now'), s SERIAL, n NOW(), j json_extract(x,'$'), c `col`);";
        let found = lint_portable_sql(sql);
        let tokens: Vec<&str> = found.iter().map(|(token, _)| *token).collect();
        assert_eq!(
            tokens,
            [
                "AUTOINCREMENT",
                "datetime(",
                "SERIAL",
                "NOW()",
                "json_extract",
                "`"
            ]
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(
            lint_portable_sql("SELECT autoincrement FROM t;")
                .iter()
                .any(|(token, _)| *token == "AUTOINCREMENT")
        );
    }

    #[test]
    fn prose_in_a_comment_is_not_ddl() {
        // The regression: `module-cms` explains its tables in a `--`
        // comment, and markdown-style backticks around a table name failed
        // the whole module for MySQL quoting it does not use.
        let sql = "-- A small content store. `cms_item` is the working copy;\n\
                   -- `cms_revision` is append-only history (stored as BLOB\n\
                   -- in some other database, but not here).\n\
                   CREATE TABLE cms_item (id TEXT PRIMARY KEY);";
        assert_eq!(lint_portable_sql(sql), vec![]);
    }

    #[test]
    fn a_block_comment_is_not_ddl_and_may_nest() {
        let sql = "/* uses `backticks` and /* nests, mentioning SERIAL */ still inside */ \
                   CREATE TABLE t (id TEXT PRIMARY KEY);";
        assert_eq!(lint_portable_sql(sql), vec![]);
    }

    #[test]
    fn a_string_literal_is_data_not_ddl() {
        // Storing the word as a value says nothing about the column type.
        let sql = "INSERT INTO kinds (name) VALUES ('blob'), ('serial'), \
                   ('it''s NOW() in prose');";
        assert_eq!(lint_portable_sql(sql), vec![]);
    }

    #[test]
    fn stripping_comments_does_not_hide_real_ddl() {
        // The other half: the same tokens outside a comment still fail, and
        // a comment must not swallow the statement that follows it.
        let sql = "-- a note about ids\n\
                   CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, c `col` TEXT);";
        let tokens: Vec<&str> = lint_portable_sql(sql)
            .iter()
            .map(|(token, _)| *token)
            .collect();
        assert_eq!(tokens, ["AUTOINCREMENT", "`"]);
    }

    #[test]
    fn a_double_quoted_identifier_is_still_ddl() {
        // Double quotes are portable, so they are not stripped: a banned
        // token inside them is a real column type, not prose.
        let tokens: Vec<&str> = lint_portable_sql(r#"CREATE TABLE t ("data" BLOB);"#)
            .iter()
            .map(|(token, _)| *token)
            .collect();
        assert_eq!(tokens, ["BLOB"]);
    }

    #[test]
    fn an_unterminated_comment_or_literal_does_not_panic() {
        // Malformed SQL is the database's problem, not the lint's.
        assert_eq!(lint_portable_sql("/* never closed"), vec![]);
        assert_eq!(lint_portable_sql("SELECT 'never closed"), vec![]);
        assert_eq!(lint_portable_sql("-- never newline"), vec![]);
        // Multi-byte characters inside and outside the stripped spans.
        assert_eq!(
            lint_portable_sql("-- naïve ünicode ✓\nCREATE TABLE t (id TEXT);"),
            vec![]
        );
    }

    #[test]
    fn now_without_parens_is_not_flagged() {
        // `NOW()` is the dialect function; the word "now" in prose or a
        // column name is not.
        assert!(lint_portable_sql("SELECT now FROM t;").is_empty());
    }
}

#[cfg(test)]
mod created_tables_tests {
    use super::created_tables;

    #[test]
    fn a_plain_create_is_found() {
        assert_eq!(
            created_tables("CREATE TABLE deletion_jobs (id TEXT PRIMARY KEY);"),
            ["deletion_jobs"]
        );
        assert_eq!(
            created_tables("create table if not exists users(id TEXT);"),
            ["users"]
        );
        // No space before the column list, and a quoted name.
        assert_eq!(
            created_tables(r#"CREATE TABLE "users"(id TEXT);"#),
            ["users"]
        );
    }

    #[test]
    fn every_create_in_one_set_is_found_in_order() {
        // The anti-vacuity case at the scan's own level: a scan that stopped
        // matching would return an empty vec and every absence assertion
        // built on it would keep passing.
        let sql = "CREATE TABLE a (id TEXT);\n\
                   CREATE TABLE IF NOT EXISTS b (id TEXT);\n\
                   CREATE UNLOGGED TABLE c (id TEXT);";
        assert_eq!(created_tables(sql), ["a", "b", "c"]);
    }

    #[test]
    fn an_index_view_or_trigger_is_not_a_table() {
        // `CREATE UNIQUE INDEX deletion_jobs_confirmation_code ON deletion_jobs`
        // is the real line this protects: a scan that read the word after
        // `CREATE` would report the index name as a table.
        let sql = "CREATE UNIQUE INDEX deletion_jobs_confirmation_code ON deletion_jobs (code);\n\
                   CREATE INDEX by_status ON deletion_jobs (status);\n\
                   CREATE VIEW live_jobs AS SELECT * FROM deletion_jobs;\n\
                   CREATE TRIGGER t AFTER INSERT ON deletion_jobs BEGIN SELECT 1; END;";
        assert_eq!(created_tables(sql), Vec::<String>::new());
    }

    #[test]
    fn a_create_table_in_a_comment_or_a_string_is_not_ddl() {
        // The regression `lint_portable_sql` already learned once: a migration
        // that explains its own schema in prose must not report the tables the
        // prose names. `deletion_jobs` opens with twelve lines of exactly that.
        let sql = "-- CREATE TABLE ghost (id TEXT) is what this replaces.\n\
                   /* CREATE TABLE also_a_ghost (id TEXT); */\n\
                   INSERT INTO note (body) VALUES ('CREATE TABLE quoted_ghost (id TEXT)');\n\
                   CREATE TABLE real_one (id TEXT);";
        assert_eq!(created_tables(sql), ["real_one"]);
    }

    #[test]
    fn a_temporary_table_is_not_the_modules_table() {
        // It is gone with the connection, so no export could read it and no
        // erasure could miss it. Requiring it in `tables()` would put a name
        // in the export list that names nothing.
        let sql = "CREATE TEMP TABLE scratch (id TEXT);\n\
                   CREATE TEMPORARY TABLE also_scratch (id TEXT);\n\
                   CREATE GLOBAL TEMPORARY TABLE still_scratch (id TEXT);\n\
                   CREATE TABLE kept (id TEXT);";
        assert_eq!(created_tables(sql), ["kept"]);
    }

    #[test]
    fn the_rebuild_pattern_leaves_one_table() {
        // `auth-core 0003` and `waitlist 0005`, both on main and both
        // unchangeable: SQLite cannot relax a NOT NULL, so the table is
        // rebuilt under another name and renamed over the original.
        let sql = "CREATE TABLE IF NOT EXISTS single_use_tokens_rebuild (id TEXT);\n\
                   INSERT INTO single_use_tokens_rebuild SELECT * FROM single_use_tokens;\n\
                   DROP TABLE single_use_tokens;\n\
                   ALTER TABLE single_use_tokens_rebuild RENAME TO single_use_tokens;";
        assert_eq!(created_tables(sql), ["single_use_tokens"]);
    }

    #[test]
    fn a_renamed_column_does_not_rename_the_table() {
        let sql = "CREATE TABLE notes (id TEXT, body TEXT);\n\
                   ALTER TABLE notes RENAME COLUMN body TO text;\n\
                   ALTER TABLE notes ADD COLUMN amr TEXT;";
        assert_eq!(created_tables(sql), ["notes"]);
    }

    #[test]
    fn a_table_created_and_dropped_is_not_left_behind() {
        let sql = "CREATE TABLE gone (id TEXT);\n\
                   CREATE TABLE kept (id TEXT);\n\
                   DROP TABLE IF EXISTS gone;\n\
                   DROP INDEX kept_by_id;";
        assert_eq!(created_tables(sql), ["kept"]);
    }

    #[test]
    fn the_same_table_twice_is_reported_once() {
        // Two migrations may both guard with IF NOT EXISTS.
        let sql = "CREATE TABLE IF NOT EXISTS notes (id TEXT);\n\
                   CREATE TABLE IF NOT EXISTS NOTES (id TEXT);";
        assert_eq!(created_tables(sql), ["notes"]);
    }

    #[test]
    fn a_name_the_scan_cannot_read_is_returned_rather_than_dropped() {
        // The safe direction to be uncertain in: it fails the comparison
        // loudly instead of escaping it silently.
        assert_eq!(
            created_tables("CREATE TABLE public.users (id TEXT);"),
            ["public.users"]
        );
    }

    #[test]
    fn truncated_or_malformed_sql_does_not_panic() {
        for sql in [
            "CREATE",
            "CREATE TABLE",
            "CREATE TABLE IF NOT EXISTS",
            "DROP TABLE",
            "ALTER TABLE notes RENAME",
            "ALTER TABLE notes RENAME TO",
            "-- CREATE TABLE never_closed",
            "CREATE TABLE t (id TEXT); -- naïve ünicode ✓",
        ] {
            let _ = created_tables(sql);
        }
    }
}

#[cfg(test)]
mod card_data_tests {
    use super::{card_data_hit, lint_card_data};

    #[test]
    fn a_card_number_column_is_flagged() {
        let sql = "CREATE TABLE payment (id TEXT PRIMARY KEY, card_number TEXT)";
        assert_eq!(lint_card_data(sql).len(), 1);
        assert_eq!(lint_card_data(sql)[0].0, "card_number");
        assert!(card_data_hit("cvv").is_some());
        assert!(card_data_hit("exp_month").is_some());
    }

    #[test]
    fn card_data_only_in_a_comment_or_string_is_not_flagged() {
        // Documenting the rule must not trip it.
        let sql = "CREATE TABLE t (id TEXT) -- never store card_number here\n";
        assert!(lint_card_data(sql).is_empty());
        let sql2 = "INSERT INTO note (body) VALUES ('do not store card_number')";
        assert!(lint_card_data(sql2).is_empty());
    }

    #[test]
    fn ambiguous_words_do_not_false_positive() {
        // A music track, an audio pan, a session expiry are all legitimate.
        for sql in [
            "CREATE TABLE song (id TEXT, track INTEGER)",
            "CREATE TABLE mix (id TEXT, pan REAL)",
            "CREATE TABLE session (id TEXT, session_expiry TEXT)",
            "CREATE TABLE t (id TEXT, token_expiry TEXT)",
        ] {
            assert!(lint_card_data(sql).is_empty(), "false positive on: {sql}");
        }
    }
}
