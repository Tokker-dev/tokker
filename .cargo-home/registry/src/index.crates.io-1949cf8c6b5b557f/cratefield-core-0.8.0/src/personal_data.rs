//! What a module holds about a person, declared next to the table that holds it.
//!
//! Export and erasure are cross-cutting: the rows belong to whichever modules a
//! venture composed, and a privacy module that named them would be a copy of
//! somebody else's schema that a migration can leave behind. So the module that
//! owns a table declares what is personal about it, and
//! `cratefield-module-privacy` reads those declarations rather than knowing any
//! venture's shape.
//!
//! One declaration serves three readers, which is the point of putting it here
//! rather than in three places:
//!
//! 1. **Export** — every row for a subject, per [`PersonalDataSet::subject`].
//! 2. **Erasure** — what happens to each row, per [`Disposition`].
//! 3. **The published table** — the sentence a privacy page shows, per
//!    [`PersonalDataSet::description`]. A page generated from the schema cannot
//!    drift from the schema; a page written beside it always eventually does.
//!
//! ```
//! use cratefield_core::{DataKind, Disposition, PersonalDataSet};
//!
//! const SETS: &[PersonalDataSet] = &[PersonalDataSet {
//!     table: "practice_sessions",
//!     subject: "account_id",
//!     kind: DataKind::Fitness,
//!     disposition: Disposition::Erase,
//!     description: "Joint angles and scores for one practice, with its date.",
//!     redacted: &[],
//!     subject_via: None,
//! }];
//! ```

use std::fmt;

/// The category a row falls into, in the vocabulary a privacy page and an App
/// Store questionnaire both use.
///
/// Deliberately coarse. A finer taxonomy invites a judgement call per column,
/// and the reader this exists for — someone deciding whether to trust the
/// product — is not served by precision nobody can check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DataKind {
    /// Name, email, phone: how to reach the person.
    Contact,
    /// Account ids, device ids, tokens: how the system recognises them.
    Identifier,
    /// Health and fitness measurements.
    Fitness,
    /// What they did and when: sessions, streaks, usage.
    Usage,
    /// Things they wrote or uploaded.
    Content,
    /// Money: invoices, payouts, ledger entries.
    Financial,
}

/// Declares [`DataKind::ALL`] and, from the same list, a match that has to
/// be exhaustive.
///
/// The manifest carries its own copy of this vocabulary
/// (`cratefield_manifest::KINDS`) because that crate does not depend on
/// the harness, and `fz build` turns an author's `kind` straight into
/// `DataKind::<Kind>` in generated source. A variant here that the
/// manifest does not know is a kind no author can declare; a string
/// there that is not a variant here is a generated venture that does not
/// compile. `the_manifest_knows_every_data_kind` compares them, and this
/// is what gives it something to compare against.
macro_rules! kinds {
    ($($variant:ident),+ $(,)?) => {
        impl DataKind {
            /// Every kind.
            pub const ALL: &'static [DataKind] = &[$(DataKind::$variant),+];
        }

        /// Never called. It exists so that a variant absent from the list
        /// above is a compile error here.
        #[expect(dead_code, reason = "its only job is to be exhaustive")]
        fn every_kind_is_in_all(kind: DataKind) {
            match kind {
                $(DataKind::$variant => {}),+
            }
        }
    };
}

kinds!(Contact, Identifier, Fitness, Usage, Content, Financial);

impl DataKind {
    /// The stable wire name, used by the manifest endpoint and by anything that
    /// renders the table. Kebab-case, matching the harness's route convention.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Contact => "contact",
            Self::Identifier => "identifier",
            Self::Fitness => "fitness",
            Self::Usage => "usage",
            Self::Content => "content",
            Self::Financial => "financial",
        }
    }
}

impl fmt::Display for DataKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What erasure does to these rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Disposition {
    /// The rows go. The ordinary case.
    Erase,
    /// The rows stay and the person leaves them: the named columns are
    /// overwritten, everything else is untouched.
    ///
    /// This exists because [`Erase`] breaks aggregates. A commission ledger
    /// cannot lose rows without the totals becoming wrong, and "your deletion
    /// made the accounts disagree" is not a story anybody wants. The columns
    /// named here must be nullable or have a default, which
    /// `cratefield-module-privacy` checks against the applied schema rather
    /// than trusting.
    ///
    /// [`Erase`]: Disposition::Erase
    Anonymise(&'static [&'static str]),
    /// The rows stay, whole, and this says why in a sentence a regulator could
    /// read.
    ///
    /// Retention is sometimes required — tax law outlives an account. Making it
    /// a variant that carries a reason means the argument is written next to
    /// the table it applies to, in a reviewed diff, rather than being the
    /// silence left by a table nobody declared.
    Retain(&'static str),
    /// The rows hold personal data and erasure **cannot reach them**, and this
    /// says why in a sentence a regulator could read.
    ///
    /// This is a third thing, and the reason it exists is that the other two
    /// are both wrong for it: [`Erase`] and [`Anonymise`] name a subject column
    /// the query builder binds a request value to, and [`Retain`] says "the
    /// rows stay on purpose", which reads as *your data, kept deliberately* —
    /// not as *your data, kept because we have no way to find it*. The case
    /// that demanded the variant is a table whose personal data is inside a
    /// value no equality predicate can match — a rendered message filed under
    /// the send, a composite `<email>:<product>` key — where declaring
    /// `PersonalDataSet::none` would make a subject-facing manifest report a
    /// table holding the person's message as **not personal data** (issue
    /// #274).
    ///
    /// [`Erase`]: Disposition::Erase
    /// [`Anonymise`]: Disposition::Anonymise
    /// [`Retain`]: Disposition::Retain
    Unreachable(&'static str),
}

impl Disposition {
    /// Whether erasure leaves the row in place.
    ///
    /// `Unreachable` is included: the row is not deleted, and anything reading
    /// this answer as "the data is gone" is being lied to exactly as hard as
    /// a `Retain` would lie. The difference is that a `Retain` row is counted,
    /// exported and described, while an `Unreachable` row can be none of
    /// those — which is the whole problem.
    #[must_use]
    pub const fn keeps_row(self) -> bool {
        matches!(
            self,
            Self::Anonymise(_) | Self::Retain(_) | Self::Unreachable(_)
        )
    }
}

/// One table's worth of personal data, declared by the module that owns it.
///
/// Deliberately **not** `#[non_exhaustive]`, unlike the enums above: every
/// declaration is a `const` literal written in a module's own crate, and
/// `#[non_exhaustive]` forbids exactly that from outside this one. The type
/// would be undeclarable by the only people who declare it. Adding a field is
/// therefore a breaking change here, which is the honest trade — a new required
/// field ought to make every module state its answer rather than inherit a
/// default nobody chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersonalDataSet {
    /// The table. Must be one this module claims in
    /// [`Module::tables`](crate::Module::tables); a name that is not is a build
    /// error, so a rename that misses this declaration cannot ship.
    pub table: &'static str,
    /// The column holding the subject's id — the value export and erasure match
    /// on.
    pub subject: &'static str,
    /// What kind of data this is.
    pub kind: DataKind,
    /// What erasure does to it.
    pub disposition: Disposition,
    /// One sentence, for a person deciding whether to trust this. It is
    /// published verbatim, so write it for them rather than for a colleague.
    pub description: &'static str,
    /// Columns an export names but never copies: the row is the subject's,
    /// and one of its columns is credential material.
    ///
    /// A push token and a Web Push endpoint are the case this exists for. They
    /// are the subject's — the table has to be declared, or erasure never
    /// reaches them — but an endpoint is a **bearer capability**: whoever holds
    /// it can notify that device, so a copy in an export file is a copy of the
    /// credential, and ADR 0015 keeps that material out of a response body.
    /// Dropping the column silently would be worse than either: an export is
    /// read by somebody checking whether anything is missing, so the column is
    /// listed with its value replaced by `[redacted]`, which says "held, not
    /// handed over" rather than "not held".
    ///
    /// It changes nothing about erasure. A row that is deleted takes its
    /// columns with it, and a column named here is still counted, still
    /// erased, and still described.
    pub redacted: &'static [&'static str],
    /// How this table reaches its subject through another table, when the
    /// column that identifies a person here is not the column the requests
    /// are made with.
    ///
    /// The privacy query builders run **one** subject value across every
    /// declaration, and by default match it against [`subject`](Self::subject)
    /// directly. A table whose rows are written before an account is known —
    /// a provider callback naming a person by their app-scoped id — has an
    /// honest `subject` that no request value will ever match. Naming a route
    /// through the table that does hold the account id makes the export find
    /// the row and the erasure preview count it:
    ///
    /// ```text
    /// WHERE <subject> IN (SELECT <via.key> FROM <via.table> WHERE <via.subject> = ?)
    /// ```
    ///
    /// `Some` **replaces** direct matching rather than adding to it: the row
    /// is found only through the join, so there is exactly one answer to
    /// "which rows are this person's", the same one for export, preview,
    /// delete and verify. The subject value is still bound, never
    /// interpolated, and the three names are checked to be plain identifiers
    /// exactly like the rest.
    ///
    /// The case that demanded this is `deletion_jobs` (issue #281): keyed on
    /// `provider_subject`, reached through `identities(user_id →
    /// provider_subject)`.
    pub subject_via: Option<SubjectVia>,
}

/// One hop to the subject, through a table that holds the id requests are
/// made with.
///
/// Read as a sentence: *rows of `table` belong to the person whose
/// `subject` value the caller supplies, when that value appears in the join
/// table's `subject` column; the join table's `key` column is the one the
/// declaring table's own subject column matches against.* `None` means the
/// declaring table is matched directly, which is the ordinary case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubjectVia {
    /// The table one hop away that holds the account id.
    pub table: &'static str,
    /// The column on that table the request's subject value is matched
    /// against — usually the account id.
    pub subject: &'static str,
    /// The column on that table whose values the declaring table's subject
    /// column matches — for `deletion_jobs`, `identities.provider_subject`.
    pub key: &'static str,
}

impl PersonalDataSet {
    /// A table this module owns that holds nothing personal, and the reason.
    ///
    /// The reason is the point. A module may legitimately own reference data
    /// keyed to nobody — pose definitions, plan tiers, a cue library — and
    /// those tables should not appear in an export. But "no declaration" and
    /// "nothing personal here" look identical in source, and only one of them
    /// is a decision. This makes the second one say so.
    #[must_use]
    pub const fn none(table: &'static str, reason: &'static str) -> Self {
        Self {
            table,
            subject: "",
            kind: DataKind::Identifier,
            disposition: Disposition::Retain(reason),
            description: "",
            redacted: &[],
            subject_via: None,
        }
    }

    /// A table this module owns that holds personal data erasure cannot reach,
    /// and the reason.
    ///
    /// The table *does* hold data about somebody — the sentence says what —
    /// but no declaration can make it queryable, because the identifying
    /// value is inside a rendered message or a composite key rather than in a
    /// column an `… = ?` predicate can match. Declaring it
    /// [`none`](Self::none) would be a lie in the other direction: a
    /// subject-facing manifest would report a table holding the person's
    /// message as **not personal data** (issue #274).
    ///
    /// Like [`none`](Self::none), this sets a blank subject, so export,
    /// erasure and [`PersonalDataCatalog::subject_sets`] skip the table —
    /// they cannot reach it, and pretending otherwise would mean building a
    /// predicate that matches nothing. Unlike `none`, the declaration counts
    /// towards [`PersonalDataCatalog::is_empty`]: a deployment holding data
    /// it cannot erase does hold data.
    #[must_use]
    pub const fn unreachable(
        table: &'static str,
        kind: DataKind,
        description: &'static str,
        reason: &'static str,
    ) -> Self {
        Self {
            table,
            subject: "",
            kind,
            disposition: Disposition::Unreachable(reason),
            description,
            redacted: &[],
            subject_via: None,
        }
    }

    /// Whether this declaration says the table holds no personal data.
    ///
    /// Read as "no subject column a request value can be bound to", not
    /// literally "nothing personal": [`unreachable`](Self::unreachable)
    /// declarations also have a blank subject, and a manifest must bucket
    /// those with [`is_unreachable`](Self::is_unreachable) before treating
    /// a blank subject as an answer about the table's contents.
    #[must_use]
    pub const fn is_none(&self) -> bool {
        self.subject.is_empty()
    }

    /// Whether this declaration describes personal data erasure cannot reach.
    ///
    /// A table answering `true` holds somebody's data and says so; the reason
    /// is the [`Unreachable`] payload, published verbatim. It is not
    /// queryable — there is no subject column a request value can be bound
    /// to — so it never appears in an export, an erasure plan or
    /// [`PersonalDataCatalog::subject_sets`], but it *is* counted by
    /// [`PersonalDataCatalog::is_empty`] and bucketed on its own by a
    /// subject-facing manifest.
    ///
    /// [`Unreachable`]: Disposition::Unreachable
    /// [`PersonalDataCatalog::subject_sets`]: PersonalDataCatalog::subject_sets
    /// [`PersonalDataCatalog::is_empty`]: PersonalDataCatalog::is_empty
    #[must_use]
    pub const fn is_unreachable(&self) -> bool {
        matches!(self.disposition, Disposition::Unreachable(_))
    }

    /// Rejects a declaration that cannot mean anything, reporting against the
    /// module that made it. Called by `HarnessBuilder::build`.
    ///
    /// The rules are the ones a typo breaks: a table the module does not own, a
    /// subject column that is blank on a set that claims to hold data, an
    /// `Anonymise` naming no columns (which would erase nothing and report
    /// success), and a description missing from something that gets published.
    #[must_use]
    pub fn validate(&self, module: &str, owns: &[&'static str]) -> Vec<String> {
        let mut errors: Vec<String> = Vec::new();

        // The privacy module builds SQL from these names. They are `&'static
        // str` written by a module author, not user input, so this is not an
        // injection defence so much as a refusal to make one necessary: a name
        // that is not a plain identifier never reaches a query builder,
        // because it never gets past `build`.
        for (label, name) in [("table", self.table), ("subject column", self.subject)] {
            if name.is_empty() {
                continue;
            }
            if !is_plain_identifier(name) {
                errors.push(format!(
                    "module `{module}` declares {label} `{name}`, which is not a plain identifier"
                ));
            }
        }
        if let Disposition::Anonymise(columns) = self.disposition {
            for column in columns {
                if !is_plain_identifier(column) {
                    errors.push(format!(
                        "module `{module}` anonymises column `{column}` of `{}`, which is not a plain identifier",
                        self.table
                    ));
                }
            }
        }
        // A join names three more things the privacy module interpolates into
        // SQL, so it gets the same refusal a bad table or column name gets.
        if let Some(via) = self.subject_via {
            for (label, name) in [
                ("via table", via.table),
                ("via subject column", via.subject),
                ("via key column", via.key),
            ] {
                check_identifier(
                    &mut errors,
                    module,
                    label,
                    name,
                    &format!("for `{}`", self.table),
                );
            }
        }
        for column in self.redacted {
            if !is_plain_identifier(column) {
                errors.push(format!(
                    "module `{module}` redacts column `{column}` of `{}`, which is not a plain identifier",
                    self.table
                ));
            }
            // Redacting the key the export matched on protects nothing: the
            // caller supplied that value. A list that reads as a protection
            // and is not one is worse than no list.
            if *column == self.subject && !self.subject.is_empty() {
                errors.push(format!(
                    "module `{module}` redacts the subject column `{}` of `{}`, which the caller already has",
                    self.subject, self.table
                ));
            }
        }
        if !owns.contains(&self.table) {
            errors.push(format!(
                "module `{module}` declares personal data in table `{}`, which it does not own",
                self.table
            ));
        }
        if self.is_none() {
            if self.is_unreachable() {
                errors.extend(self.unreachable_errors(module));
            } else {
                errors.extend(self.none_errors(module));
            }
            return errors;
        }
        if self.description.trim().is_empty() {
            errors.push(format!(
                "module `{module}` declares personal data in `{}` with no description; it is published verbatim",
                self.table
            ));
        }
        match self.disposition {
            Disposition::Anonymise([]) => errors.push(format!(
                "module `{module}` anonymises `{}` without naming a column, which would erase nothing",
                self.table
            )),
            Disposition::Anonymise(columns) if columns.contains(&self.subject) => {
                errors.push(format!(
                    "module `{module}` anonymises the subject column `{}` of `{}`; erasure could then never find the row again",
                    self.subject, self.table
                ));
            }
            Disposition::Retain(reason) if reason.trim().is_empty() => errors.push(format!(
                "module `{module}` retains personal data in `{}` without saying why",
                self.table
            )),
            _ => {}
        }
        errors
    }

    /// The contradictions only an `Unreachable` declaration can contain.
    ///
    /// Mirror of [`none_errors`](Self::none_errors): the blank subject is not
    /// carelessness here but the point, so the checks are about refusing the
    /// escape hatches that would make the blank subject lie.
    fn unreachable_errors(&self, module: &str) -> Vec<String> {
        let mut errors: Vec<String> = Vec::new();
        if let Disposition::Unreachable(reason) = self.disposition
            && reason.trim().is_empty()
        {
            errors.push(format!(
                "module `{module}` declares personal data in `{}` as unreachable without saying why",
                self.table
            ));
        }
        // The description is published beside the reason in the manifest's
        // unreachable bucket, so an empty one publishes a bucket entry that
        // names a table and says nothing about it.
        if self.description.trim().is_empty() {
            errors.push(format!(
                "module `{module}` declares personal data in `{}` as unreachable with no description; it is published verbatim",
                self.table
            ));
        }
        if self.subject_via.is_some() {
            errors.push(format!(
                "module `{module}` declares table `{}` as unreachable and names a way to reach a subject; one or the other",
                self.table
            ));
        }
        if !self.redacted.is_empty() {
            errors.push(format!(
                "module `{module}` redacts a column of `{}`, which is declared unreachable; nothing is exported from it to redact",
                self.table
            ));
        }
        errors
    }

    /// The contradictions only a `none` declaration can contain.
    fn none_errors(&self, module: &str) -> Vec<String> {
        let mut errors: Vec<String> = Vec::new();
        if self.subject_via.is_some() {
            errors.push(format!(
        "module `{module}` declares table `{}` as holding no personal data and names a way to reach a subject; one or the other",
        self.table
    ));
        }
        if let Disposition::Retain(reason) = self.disposition
            && reason.trim().is_empty()
        {
            errors.push(format!(
        "module `{module}` declares table `{}` as holding no personal data without saying why",
        self.table
    ));
        }
        if !self.redacted.is_empty() {
            errors.push(format!(
        "module `{module}` redacts a column of `{}`, which it declares holds no personal data; nothing is exported from it to redact",
        self.table
    ));
        }
        errors
    }
}

/// One refusal for a name the privacy module would interpolate into SQL.
///
/// The same rule as [`is_plain_identifier`], said once because `validate`
/// applies it to five kinds of name and counting them in one function made
/// that function outgrow any reader's patience.
fn check_identifier(errors: &mut Vec<String>, module: &str, label: &str, name: &str, where_: &str) {
    if !is_plain_identifier(name) {
        errors.push(format!(
            "module `{module}` declares {label} `{name}` {where_}, which is not a plain identifier"
        ));
    }
}

/// Every personal-data declaration in a composition, with the module that made
/// it.
///
/// Composed once at `HarnessBuilder::build` and handed to every module through
/// [`ModuleContext`](crate::ModuleContext), the same way the UI surface is.
/// `cratefield-module-privacy` reads it to export, to erase, and to publish the
/// table; nothing else needs it, but nothing else is harmed by having it, and a
/// port just for this would be a capability the runtime has to provide for a
/// list the harness already holds.
#[derive(Debug, Clone, Default)]
pub struct PersonalDataCatalog {
    entries: Vec<CatalogEntry>,
}

/// One declaration, and the module that owns the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogEntry {
    /// The declaring module's [`Module::name`](crate::Module::name).
    pub module: &'static str,
    /// What it declared.
    pub set: PersonalDataSet,
}

impl PersonalDataCatalog {
    /// Collects declarations in composition order.
    ///
    /// Tables declared as holding nothing personal are kept rather than
    /// filtered: the published table is more honest for saying `pose_library`:
    /// reference poses, identical for every member than for omitting it, and a
    /// reader cannot tell an omission from an oversight.
    #[must_use]
    pub fn compose<'a>(
        modules: impl IntoIterator<Item = (&'static str, &'a [PersonalDataSet])>,
    ) -> Self {
        let mut entries = Vec::new();
        for (module, sets) in modules {
            for set in sets {
                entries.push(CatalogEntry { module, set: *set });
            }
        }
        Self { entries }
    }

    /// Every declaration, composition order.
    #[must_use]
    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries
    }

    /// The declarations that actually hold data about somebody: what export
    /// reads and erasure acts on.
    ///
    /// Unreachable declarations are skipped too. They hold personal data, but
    /// there is no subject column to bind a request value to, so there is no
    /// predicate to build — which is the point of the variant. They are not
    /// forgotten: [`is_empty`](Self::is_empty) counts them, and the manifest
    /// publishes them in their own bucket, because "cannot reach" and "holds
    /// nobody" must never look the same to a subject.
    pub fn subject_sets(&self) -> impl Iterator<Item = &CatalogEntry> {
        self.entries.iter().filter(|e| !e.set.is_none())
    }

    /// Whether anything in this composition holds personal data at all.
    ///
    /// A venture where this is false has an honest empty export, and its
    /// privacy page can say so. It is also the signal that a venture composed
    /// the privacy module and forgot that its own modules declare nothing —
    /// an export that succeeds and returns nothing is the failure this
    /// distinguishes.
    ///
    /// Unreachable declarations count as holding. An export over a table
    /// erasure cannot reach is empty, yes — but "we hold nothing about you"
    /// over a table that holds the person's message is precisely the
    /// mis-answer issue #274 is about, and `subject_sets` alone would
    /// produce it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self
            .entries
            .iter()
            .any(|e| !e.set.is_none() || e.set.is_unreachable())
    }
}

/// The tables a module owns and has said nothing about: the gap this type
/// exists to close, named so a test can fail on it.
///
/// `HarnessBuilder::build` already rejects a declaration for a table the
/// module does **not** own, so a rename that misses a declaration cannot ship.
/// This is the converse — a table with no declaration at all — and it is the
/// one that actually happens: a module grows a migration, the new table joins
/// [`Module::tables`](crate::Module::tables) because `fz data export` reads
/// that list, and nothing anywhere notices that erasure plans from a different
/// list. `cratefield-module-notifications` gained six migrations in two days
/// and declared none of them (issue #244).
///
/// It is a **kit** check rather than a build error on purpose. Silence is
/// legitimate for a module with no tables, and a venture composing a module
/// whose author has not got to this yet should not be unable to boot; the
/// place a module is *supposed* to be complete is its own test suite, so
/// `cratefield_testing::conformance` fails on a non-empty result here and a
/// deployment keeps running.
///
/// ```
/// # use cratefield_core::{
/// #     Config, ConfigError, Migrations, Module, ModuleContext, PersonalDataSet, Port,
/// #     undeclared_tables,
/// # };
/// struct Notes;
/// impl Module for Notes {
///     fn name(&self) -> &'static str { "notes" }
///     fn version(&self) -> &'static str { "0.1.0" }
///     fn requires(&self) -> &'static [Port] { &[] }
///     fn tables(&self) -> &'static [&'static str] { &["notes", "note_tags"] }
///     fn personal_data(&self) -> &'static [PersonalDataSet] {
///         const SETS: &[PersonalDataSet] = &[PersonalDataSet::none(
///             "notes",
///             "Notes belong to a board, not to a person.",
///         )];
///         SETS
///     }
/// #   fn migrations(&self) -> Migrations { Migrations::EMPTY }
/// #   fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> { Ok(()) }
/// #   fn router(&self, _ctx: ModuleContext) -> axum::Router { axum::Router::new() }
/// }
/// // `notes` is declared — as holding nobody, which is a declaration. The
/// // table nobody wrote a line for is the one that comes back.
/// assert_eq!(undeclared_tables(&Notes), vec!["note_tags"]);
/// ```
#[must_use]
pub fn undeclared_tables(module: &dyn crate::Module) -> Vec<&'static str> {
    let declared: Vec<&'static str> = module.personal_data().iter().map(|set| set.table).collect();
    module
        .tables()
        .iter()
        .copied()
        .filter(|table| !declared.contains(table))
        .collect()
}

/// Every table a module's migrations leave behind, on either dialect.
///
/// The union of the two sets rather than one of them: the `postgres` set is an
/// override list (ADR 0004) that reuses most of the sqlite files unchanged, so
/// a table is the module's if either dialect creates it. Each set is read in
/// its own apply order, because that is what makes a drop or a rename mean
/// anything — see [`created_tables`](crate::created_tables) for how a
/// statement is read and which shapes are deliberately not counted.
///
/// The list is the input to [`unlisted_tables`], and it is public because the
/// check that consumes it has to be able to say *what it found* and not only
/// what was missing: an absence assertion over a scan that has silently
/// stopped matching passes for the wrong reason, forever.
#[must_use]
pub fn migration_tables(module: &dyn crate::Module) -> Vec<String> {
    let migrations = module.migrations();
    let mut found: Vec<String> = Vec::new();
    for set in [migrations.sqlite, migrations.postgres] {
        // Joined with a newline, never bare: a migration whose last line is a
        // `--` comment would otherwise swallow the first line of the next.
        let sql = set
            .iter()
            .map(|migration| migration.sql)
            .collect::<Vec<_>>()
            .join("\n");
        for table in crate::lint::created_tables(&sql) {
            if !found.iter().any(|seen| seen.eq_ignore_ascii_case(&table)) {
                found.push(table);
            }
        }
    }
    found
}

/// The tables a module's own migrations create and its
/// [`Module::tables`](crate::Module::tables) never mentions: the hole the
/// declaration rule cannot see (issue #272).
///
/// [`undeclared_tables`] asks whether every table in `tables()` has a
/// declaration, which is the right question about a table that is in the
/// list. It has nothing to say about a table that is in neither list, and
/// that table is outside **three** things at once rather than one: `fz data
/// export` walks `tables()`, subject access and erasure walk
/// `personal_data()`, and the rule compares the two. `auth-core` grew
/// `deletion_jobs` — a row holding `provider_subject`, a person's identifier
/// at their identity provider — and the table was in none of them.
///
/// So the comparison is against the migrations, because a `CREATE TABLE` is
/// where a table actually comes into being and is the one statement an author
/// cannot forget to write. A non-empty result means the module owns a table
/// nothing in the harness knows it owns.
///
/// Like [`undeclared_tables`] this is a **kit** check rather than a build
/// error, for the same reason: a venture should not fail to boot because some
/// other module's author has not got to this yet, and the place a module is
/// supposed to be complete is its own test suite. `cratefield_testing::conformance`
/// fails on a non-empty result.
///
/// ```
/// # use cratefield_core::{
/// #     Config, ConfigError, Migrations, Module, ModuleContext, PersonalDataSet, Port,
/// #     SqlMigration, unlisted_tables,
/// # };
/// struct Notes;
/// impl Module for Notes {
///     fn name(&self) -> &'static str { "notes" }
///     fn version(&self) -> &'static str { "0.1.0" }
///     fn requires(&self) -> &'static [Port] { &[] }
///     fn tables(&self) -> &'static [&'static str] { &["notes"] }
///     fn migrations(&self) -> Migrations {
///         const MIGRATIONS: [SqlMigration; 1] = [SqlMigration::new(
///             "0001",
///             "init",
///             "CREATE TABLE notes (id TEXT PRIMARY KEY);
///                   CREATE TABLE note_tags (note_id TEXT NOT NULL);",
///         )];
///         Migrations::sqlite(&MIGRATIONS)
///     }
/// #   fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> { Ok(()) }
/// #   fn router(&self, _ctx: ModuleContext) -> axum::Router { axum::Router::new() }
/// }
/// // The migration creates two tables; `tables()` names one. The other is
/// // outside export, outside erasure, and outside the rule that checks them.
/// assert_eq!(unlisted_tables(&Notes), ["note_tags"]);
/// ```
#[must_use]
pub fn unlisted_tables(module: &dyn crate::Module) -> Vec<String> {
    let listed = module.tables();
    let mut found = migration_tables(module);
    found.retain(|table| !listed.iter().any(|name| name.eq_ignore_ascii_case(table)));
    found
}

/// An unquoted SQL identifier: ASCII letters, digits and underscore, starting
/// with a letter or underscore, at most 63 bytes — the shortest limit among the
/// dialects the harness targets (Postgres truncates there; SQLite does not
/// care).
///
/// Deliberately stricter than any dialect allows. A quoted identifier can
/// contain a space, a dot, or a closing quote, and every one of those is a way
/// to make a generated statement mean something else. Nothing in a schema
/// anybody would want needs them.
#[must_use]
pub fn is_plain_identifier(name: &str) -> bool {
    if name.is_empty() || name.len() > 63 {
        return false;
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap_or('\0');
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
