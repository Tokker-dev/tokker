//! The all-or-nothing `Database::batch_atomic` contract (issue #126),
//! asserted against a live adapter rather than trusted from its docs. A
//! batch that fails part-way must leave nothing behind; a batch that
//! succeeds must commit every statement.

use cratefield_core::{Database, Statement};

/// Proves `db`'s `batch_atomic` is all-or-nothing: a committed batch is
/// fully visible, a failing batch is invisible. Runs its own probe table,
/// so it can be called against any adapter with a writable connection.
///
/// An adapter that cannot honour the contract fails loudly here — the
/// port's answer to "atomic where supported" (issue #126).
///
/// # Panics
///
/// Panics when the batch contract is violated: a valid batch fails, a
/// failed batch leaves rows behind, or the probe table cannot be created
/// on the given connection.
pub async fn assert_batch_is_atomic(db: &dyn Database) {
    db.execute(&Statement::new(
        "CREATE TABLE IF NOT EXISTS batch_atomicity_probe \
         (id TEXT PRIMARY KEY, marker TEXT NOT NULL)",
    ))
    .await
    .expect("probe table");

    db.execute(&Statement::new("DELETE FROM batch_atomicity_probe"))
        .await
        .expect("clear probe");

    let commits = vec![
        Statement::with_values(
            "INSERT INTO batch_atomicity_probe (id, marker) VALUES (?, ?)",
            vec!["committed-1".into(), "batch".into()],
        ),
        Statement::with_values(
            "INSERT INTO batch_atomicity_probe (id, marker) VALUES (?, ?)",
            vec!["committed-2".into(), "batch".into()],
        ),
    ];
    db.batch_atomic(&commits)
        .await
        .expect("a valid batch commits");
    let rows = db
        .query(&Statement::new(
            "SELECT id FROM batch_atomicity_probe ORDER BY id",
        ))
        .await
        .expect("read back");
    assert_eq!(
        rows.len(),
        2,
        "a committed batch leaves every statement visible"
    );

    let mid_batch = vec![
        Statement::with_values(
            "INSERT INTO batch_atomicity_probe (id, marker) VALUES (?, ?)",
            vec!["doomed".into(), "must not survive".into()],
        ),
        Statement::new("THIS IS NOT SQL"),
    ];
    assert!(
        db.batch_atomic(&mid_batch).await.is_err(),
        "a batch with a failing statement must fail"
    );
    let survivors = db
        .query(&Statement::with_values(
            "SELECT id FROM batch_atomicity_probe WHERE id = ?",
            vec!["doomed".into()],
        ))
        .await
        .expect("read back");
    assert!(
        survivors.is_empty(),
        "nothing from a failed batch is visible afterwards"
    );

    db.execute(&Statement::new("DELETE FROM batch_atomicity_probe"))
        .await
        .expect("clean probe");
}
