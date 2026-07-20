PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS person (
    id INTEGER PRIMARY KEY,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'ghost')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS event (
    id INTEGER PRIMARY KEY,
    event_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    starts_at TEXT NOT NULL,
    ends_at TEXT,
    event_type TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS source_file (
    id INTEGER PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES event(id) ON DELETE RESTRICT,
    source_type TEXT NOT NULL,
    file_sha256 TEXT NOT NULL,
    mapping_version TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    ingested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (event_id, source_type, file_sha256)
);

CREATE TABLE IF NOT EXISTS source_record (
    id INTEGER PRIMARY KEY,
    source_file_id INTEGER NOT NULL REFERENCES source_file(id) ON DELETE RESTRICT,
    external_record_id TEXT NOT NULL,
    mapping_version TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    raw_payload_json TEXT,
    quarantined INTEGER NOT NULL DEFAULT 0 CHECK (quarantined IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (source_file_id, external_record_id)
);

CREATE TABLE IF NOT EXISTS person_identity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    person_id INTEGER NOT NULL REFERENCES person(id) ON DELETE RESTRICT,
    source_record_id INTEGER NOT NULL REFERENCES source_record(id) ON DELETE RESTRICT,
    identity_type TEXT NOT NULL CHECK (identity_type IN ('email', 'github', 'linkedin')),
    display_value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0 CHECK (verified IN (0, 1)),
    applicant_provided INTEGER NOT NULL DEFAULT 0 CHECK (applicant_provided IN (0, 1)),
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (person_id, identity_type, normalized_value)
);

CREATE INDEX IF NOT EXISTS person_identity_lookup
    ON person_identity(identity_type, normalized_value);

CREATE TABLE IF NOT EXISTS hashed_identity (
    id INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL REFERENCES person(id) ON DELETE RESTRICT,
    evidence_identity_id INTEGER NOT NULL,
    evidence_source_record_id INTEGER NOT NULL
        REFERENCES source_record(id) ON DELETE RESTRICT,
    identity_hmac TEXT NOT NULL,
    key_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (evidence_identity_id, key_version),
    UNIQUE (identity_hmac, key_version)
);

CREATE TRIGGER IF NOT EXISTS hashed_identity_verified_email_insert
BEFORE INSERT ON hashed_identity
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM person_identity
    WHERE id = NEW.evidence_identity_id
      AND person_id = NEW.person_id
      AND source_record_id = NEW.evidence_source_record_id
      AND identity_type = 'email'
      AND verified = 1
)
BEGIN
    SELECT RAISE(ABORT, 'hashed identities require a verified email owned by the person');
END;

CREATE TABLE IF NOT EXISTS identity_evidence (
    id INTEGER PRIMARY KEY,
    source_record_id INTEGER NOT NULL REFERENCES source_record(id) ON DELETE RESTRICT,
    person_id INTEGER REFERENCES person(id) ON DELETE RESTRICT,
    person_identity_id INTEGER REFERENCES person_identity(id) ON DELETE SET NULL,
    evidence_type TEXT NOT NULL,
    normalized_value TEXT,
    applicant_provided INTEGER NOT NULL DEFAULT 0 CHECK (applicant_provided IN (0, 1)),
    mapping_version TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS identity_decision (
    id INTEGER PRIMARY KEY,
    source_record_id INTEGER NOT NULL REFERENCES source_record(id) ON DELETE RESTRICT,
    person_id INTEGER REFERENCES person(id) ON DELETE RESTRICT,
    decision TEXT NOT NULL CHECK (
        decision IN ('linked', 'kept_separate', 'quarantined', 'merged_with_email_mismatch')
    ),
    reviewer TEXT NOT NULL,
    reason TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    supersedes_decision_id INTEGER UNIQUE
        REFERENCES identity_decision(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (supersedes_decision_id IS NULL OR supersedes_decision_id != id)
);

CREATE TABLE IF NOT EXISTS consent_assertion (
    id INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL REFERENCES person(id) ON DELETE RESTRICT,
    event_id INTEGER NOT NULL REFERENCES event(id) ON DELETE RESTRICT,
    source_record_id INTEGER NOT NULL REFERENCES source_record(id) ON DELETE RESTRICT,
    purpose TEXT NOT NULL,
    recipient_scope TEXT NOT NULL,
    granted INTEGER NOT NULL CHECK (granted IN (0, 1)),
    source_text TEXT NOT NULL,
    source_version TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    withdrawal_time TEXT,
    evidence_source TEXT NOT NULL,
    supersedes_assertion_id INTEGER UNIQUE
        REFERENCES consent_assertion(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (supersedes_assertion_id IS NULL OR supersedes_assertion_id != id)
);

CREATE INDEX IF NOT EXISTS consent_assertion_state_lookup
    ON consent_assertion(person_id, event_id, purpose, recipient_scope, observed_at);

CREATE TABLE IF NOT EXISTS fact_assertion (
    id INTEGER PRIMARY KEY,
    subject_table TEXT NOT NULL CHECK (
        subject_table IN (
            'person', 'event', 'application', 'participation', 'team', 'submission',
            'enrichment_snapshot', 'classification', 'intro'
        )
    ),
    subject_id INTEGER NOT NULL,
    field_name TEXT NOT NULL,
    source_record_id INTEGER NOT NULL REFERENCES source_record(id) ON DELETE RESTRICT,
    mapping_version TEXT NOT NULL,
    authority TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    supersedes_assertion_id INTEGER UNIQUE
        REFERENCES fact_assertion(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (supersedes_assertion_id IS NULL OR supersedes_assertion_id != id)
);

CREATE TABLE IF NOT EXISTS fact_assertion_payload (
    assertion_id INTEGER PRIMARY KEY
        REFERENCES fact_assertion(id) ON DELETE RESTRICT,
    canonical_value_json TEXT NOT NULL CHECK (json_valid(canonical_value_json)),
    pii_class TEXT NOT NULL CHECK (
        pii_class IN ('non_pii', 'direct', 'free_text', 'sensitive')
    )
);

CREATE INDEX IF NOT EXISTS fact_assertion_subject_lookup
    ON fact_assertion(subject_table, subject_id, field_name, observed_at);

CREATE TABLE IF NOT EXISTS team (
    id INTEGER PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES event(id) ON DELETE RESTRICT,
    source_record_id INTEGER NOT NULL REFERENCES source_record(id) ON DELETE RESTRICT,
    canonical_name TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (event_id, source_record_id)
);

CREATE TABLE IF NOT EXISTS application (
    id INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL REFERENCES person(id) ON DELETE RESTRICT,
    event_id INTEGER NOT NULL REFERENCES event(id) ON DELETE RESTRICT,
    source_record_id INTEGER NOT NULL REFERENCES source_record(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('applied', 'accepted', 'declined', 'waitlist')),
    raw_answers_json TEXT,
    applied_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (event_id, source_record_id)
);

CREATE TABLE IF NOT EXISTS submission (
    id INTEGER PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES event(id) ON DELETE RESTRICT,
    team_id INTEGER REFERENCES team(id) ON DELETE RESTRICT,
    source_record_id INTEGER NOT NULL UNIQUE REFERENCES source_record(id) ON DELETE RESTRICT,
    title TEXT,
    built_with_json TEXT,
    links_json TEXT,
    judging_scores_json TEXT,
    submitted_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS participation (
    id INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL REFERENCES person(id) ON DELETE RESTRICT,
    event_id INTEGER NOT NULL REFERENCES event(id) ON DELETE RESTRICT,
    source_record_id INTEGER NOT NULL REFERENCES source_record(id) ON DELETE RESTRICT,
    checked_in INTEGER NOT NULL DEFAULT 0 CHECK (checked_in IN (0, 1)),
    checked_in_at TEXT,
    team_id INTEGER REFERENCES team(id) ON DELETE RESTRICT,
    submission_id INTEGER REFERENCES submission(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (event_id, person_id, source_record_id)
);

CREATE TABLE IF NOT EXISTS enrichment_snapshot (
    id INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL REFERENCES person(id) ON DELETE RESTRICT,
    source_record_id INTEGER NOT NULL REFERENCES source_record(id) ON DELETE RESTRICT,
    source_type TEXT NOT NULL CHECK (source_type IN ('github', 'coresignal', 'manual')),
    payload_json TEXT,
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS classification (
    id INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL REFERENCES person(id) ON DELETE RESTRICT,
    event_id INTEGER NOT NULL REFERENCES event(id) ON DELETE RESTRICT,
    source_record_id INTEGER NOT NULL REFERENCES source_record(id) ON DELETE RESTRICT,
    taxonomy_version TEXT NOT NULL,
    occupation TEXT,
    signal_tier TEXT,
    facts_json TEXT,
    confidence REAL CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    provider TEXT,
    model TEXT,
    prompt_version TEXT,
    reviewed_by TEXT,
    observed_at TEXT NOT NULL,
    supersedes_classification_id INTEGER UNIQUE
        REFERENCES classification(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (
        supersedes_classification_id IS NULL OR supersedes_classification_id != id
    )
);

CREATE TABLE IF NOT EXISTS intro (
    id INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL REFERENCES person(id) ON DELETE RESTRICT,
    event_id INTEGER NOT NULL REFERENCES event(id) ON DELETE RESTRICT,
    source_record_id INTEGER NOT NULL REFERENCES source_record(id) ON DELETE RESTRICT,
    partner TEXT NOT NULL,
    context TEXT,
    introduced_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS intro_outcome (
    id INTEGER PRIMARY KEY,
    intro_id INTEGER NOT NULL REFERENCES intro(id) ON DELETE RESTRICT,
    source_record_id INTEGER NOT NULL REFERENCES source_record(id) ON DELETE RESTRICT,
    outcome TEXT NOT NULL CHECK (
        outcome IN ('none', 'interview', 'hire', 'investment')
    ),
    observed_at TEXT NOT NULL,
    confirmed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS identity_review (
    id INTEGER PRIMARY KEY,
    source_record_id INTEGER NOT NULL REFERENCES source_record(id) ON DELETE RESTRICT,
    provisional_person_id INTEGER NOT NULL REFERENCES person(id) ON DELETE RESTRICT,
    suggested_person_id INTEGER REFERENCES person(id) ON DELETE RESTRICT,
    reason_code TEXT NOT NULL,
    evidence_json TEXT,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS aggregate_snapshot (
    id INTEGER PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES event(id) ON DELETE RESTRICT,
    config_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (event_id, config_hash)
);

CREATE TABLE IF NOT EXISTS publication (
    id INTEGER PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES event(id) ON DELETE RESTRICT,
    aggregate_snapshot_id INTEGER NOT NULL
        REFERENCES aggregate_snapshot(id) ON DELETE RESTRICT,
    partner_key TEXT NOT NULL,
    report_hash TEXT NOT NULL UNIQUE,
    published_at TEXT NOT NULL,
    ledger_complete_asserted INTEGER NOT NULL DEFAULT 0
        CHECK (ledger_complete_asserted IN (0, 1))
);

CREATE TABLE IF NOT EXISTS publication_cell (
    id INTEGER PRIMARY KEY,
    publication_id INTEGER NOT NULL REFERENCES publication(id) ON DELETE RESTRICT,
    metric_key TEXT NOT NULL,
    cell_key TEXT NOT NULL,
    published_value REAL,
    suppression_status TEXT NOT NULL CHECK (
        suppression_status IN ('published', 'primary', 'complementary', 'withheld')
    ),
    member_hmacs_json TEXT NOT NULL,
    UNIQUE (publication_id, metric_key, cell_key)
);

CREATE TABLE IF NOT EXISTS deletion_log (
    id INTEGER PRIMARY KEY,
    person_id INTEGER REFERENCES person(id) ON DELETE SET NULL,
    source_record_id INTEGER REFERENCES source_record(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL,
    rows_affected INTEGER NOT NULL DEFAULT 0 CHECK (rows_affected >= 0),
    occurred_at TEXT NOT NULL,
    details_json TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE VIEW IF NOT EXISTS person_source_record_link AS
SELECT person_id, source_record_id FROM person_identity
UNION
SELECT person_id, evidence_source_record_id FROM hashed_identity
UNION
SELECT person_id, source_record_id FROM identity_evidence WHERE person_id IS NOT NULL
UNION
SELECT person_id, source_record_id FROM identity_decision WHERE person_id IS NOT NULL
UNION
SELECT person_id, source_record_id FROM consent_assertion
UNION
SELECT person_id, source_record_id FROM application
UNION
SELECT person_id, source_record_id FROM participation
UNION
SELECT person_id, source_record_id FROM enrichment_snapshot
UNION
SELECT person_id, source_record_id FROM classification
UNION
SELECT person_id, source_record_id FROM intro
UNION
SELECT provisional_person_id, source_record_id FROM identity_review
UNION
SELECT suggested_person_id, source_record_id
FROM identity_review
WHERE suggested_person_id IS NOT NULL
UNION
SELECT subject_id, source_record_id
FROM fact_assertion
WHERE subject_table = 'person'
UNION
SELECT application.person_id, fact_assertion.source_record_id
FROM fact_assertion
JOIN application ON application.id = fact_assertion.subject_id
WHERE fact_assertion.subject_table = 'application'
UNION
SELECT participation.person_id, fact_assertion.source_record_id
FROM fact_assertion
JOIN participation ON participation.id = fact_assertion.subject_id
WHERE fact_assertion.subject_table = 'participation'
UNION
SELECT enrichment_snapshot.person_id, fact_assertion.source_record_id
FROM fact_assertion
JOIN enrichment_snapshot ON enrichment_snapshot.id = fact_assertion.subject_id
WHERE fact_assertion.subject_table = 'enrichment_snapshot'
UNION
SELECT classification.person_id, fact_assertion.source_record_id
FROM fact_assertion
JOIN classification ON classification.id = fact_assertion.subject_id
WHERE fact_assertion.subject_table = 'classification'
UNION
SELECT intro.person_id, fact_assertion.source_record_id
FROM fact_assertion
JOIN intro ON intro.id = fact_assertion.subject_id
WHERE fact_assertion.subject_table = 'intro';

CREATE TRIGGER IF NOT EXISTS fact_assertion_subject_exists
BEFORE INSERT ON fact_assertion
FOR EACH ROW
WHEN
    (NEW.subject_table = 'person' AND
        NOT EXISTS (SELECT 1 FROM person WHERE id = NEW.subject_id)) OR
    (NEW.subject_table = 'event' AND
        NOT EXISTS (SELECT 1 FROM event WHERE id = NEW.subject_id)) OR
    (NEW.subject_table = 'application' AND
        NOT EXISTS (SELECT 1 FROM application WHERE id = NEW.subject_id)) OR
    (NEW.subject_table = 'participation' AND
        NOT EXISTS (SELECT 1 FROM participation WHERE id = NEW.subject_id)) OR
    (NEW.subject_table = 'team' AND
        NOT EXISTS (SELECT 1 FROM team WHERE id = NEW.subject_id)) OR
    (NEW.subject_table = 'submission' AND
        NOT EXISTS (SELECT 1 FROM submission WHERE id = NEW.subject_id)) OR
    (NEW.subject_table = 'enrichment_snapshot' AND
        NOT EXISTS (SELECT 1 FROM enrichment_snapshot WHERE id = NEW.subject_id)) OR
    (NEW.subject_table = 'classification' AND
        NOT EXISTS (SELECT 1 FROM classification WHERE id = NEW.subject_id)) OR
    (NEW.subject_table = 'intro' AND
        NOT EXISTS (SELECT 1 FROM intro WHERE id = NEW.subject_id))
BEGIN
    SELECT RAISE(ABORT, 'fact assertion subject does not exist');
END;

CREATE TRIGGER IF NOT EXISTS fact_assertion_valid_supersession
BEFORE INSERT ON fact_assertion
FOR EACH ROW
WHEN NEW.supersedes_assertion_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1
    FROM fact_assertion AS previous
    WHERE previous.id = NEW.supersedes_assertion_id
      AND previous.subject_table = NEW.subject_table
      AND previous.subject_id = NEW.subject_id
      AND previous.field_name = NEW.field_name
 )
BEGIN
    SELECT RAISE(ABORT, 'fact assertion supersession must retain its subject and field');
END;

CREATE TRIGGER IF NOT EXISTS consent_assertion_valid_supersession
BEFORE INSERT ON consent_assertion
FOR EACH ROW
WHEN NEW.supersedes_assertion_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1
    FROM consent_assertion AS previous
    WHERE previous.id = NEW.supersedes_assertion_id
      AND previous.person_id = NEW.person_id
      AND previous.event_id = NEW.event_id
      AND previous.purpose = NEW.purpose
      AND previous.recipient_scope = NEW.recipient_scope
 )
BEGIN
    SELECT RAISE(
        ABORT,
        'consent supersession must retain person, event, purpose, and recipient scope'
    );
END;

CREATE TRIGGER IF NOT EXISTS person_ghost_requires_erased_fact_payloads
BEFORE UPDATE OF state ON person
FOR EACH ROW
WHEN NEW.state = 'ghost'
 AND OLD.state != 'ghost'
 AND EXISTS (
    SELECT 1
    FROM fact_assertion AS assertion
    JOIN fact_assertion_payload AS payload
      ON payload.assertion_id = assertion.id
    WHERE payload.pii_class IN ('direct', 'free_text')
      AND (
        (assertion.subject_table = 'person' AND assertion.subject_id = NEW.id)
        OR (
            assertion.subject_table = 'application'
            AND EXISTS (
                SELECT 1 FROM application
                WHERE id = assertion.subject_id AND person_id = NEW.id
            )
        )
        OR (
            assertion.subject_table = 'participation'
            AND EXISTS (
                SELECT 1 FROM participation
                WHERE id = assertion.subject_id AND person_id = NEW.id
            )
        )
        OR (
            assertion.subject_table = 'enrichment_snapshot'
            AND EXISTS (
                SELECT 1 FROM enrichment_snapshot
                WHERE id = assertion.subject_id AND person_id = NEW.id
            )
        )
        OR (
            assertion.subject_table = 'classification'
            AND EXISTS (
                SELECT 1 FROM classification
                WHERE id = assertion.subject_id AND person_id = NEW.id
            )
        )
        OR (
            assertion.subject_table = 'intro'
            AND EXISTS (
                SELECT 1 FROM intro
                WHERE id = assertion.subject_id AND person_id = NEW.id
            )
        )
      )
 )
BEGIN
    SELECT RAISE(ABORT, 'erase direct and free-text fact payloads before ghosting');
END;

CREATE TRIGGER IF NOT EXISTS person_ghost_requires_erased_person_stores
BEFORE UPDATE OF state ON person
FOR EACH ROW
WHEN NEW.state = 'ghost'
 AND OLD.state != 'ghost'
 AND (
    EXISTS (SELECT 1 FROM person_identity WHERE person_id = NEW.id)
    OR EXISTS (
        SELECT 1 FROM application
        WHERE person_id = NEW.id AND raw_answers_json IS NOT NULL
    )
    OR EXISTS (
        SELECT 1 FROM enrichment_snapshot
        WHERE person_id = NEW.id AND payload_json IS NOT NULL
    )
    OR EXISTS (
        SELECT 1 FROM classification
        WHERE person_id = NEW.id AND facts_json IS NOT NULL
    )
    OR EXISTS (
        SELECT 1 FROM intro
        WHERE person_id = NEW.id AND context IS NOT NULL
    )
    OR EXISTS (
        SELECT 1 FROM identity_evidence
        WHERE person_id = NEW.id AND normalized_value IS NOT NULL
    )
    OR EXISTS (
        SELECT 1 FROM identity_review
        WHERE (provisional_person_id = NEW.id OR suggested_person_id = NEW.id)
          AND evidence_json IS NOT NULL
    )
    OR EXISTS (
        SELECT 1
        FROM person_source_record_link AS link
        JOIN source_record AS record ON record.id = link.source_record_id
        WHERE link.person_id = NEW.id AND record.raw_payload_json IS NOT NULL
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'erase all person-linked PII before ghosting');
END;

CREATE TRIGGER IF NOT EXISTS person_identity_no_ghost_insert
BEFORE INSERT ON person_identity
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM person WHERE id = NEW.person_id AND state = 'ghost')
BEGIN
    SELECT RAISE(ABORT, 'ghost people cannot regain plaintext identities');
END;
CREATE TRIGGER IF NOT EXISTS person_identity_no_ghost_update
BEFORE UPDATE OF person_id ON person_identity
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM person WHERE id = NEW.person_id AND state = 'ghost')
BEGIN
    SELECT RAISE(ABORT, 'ghost people cannot regain plaintext identities');
END;

CREATE TRIGGER IF NOT EXISTS fact_assertion_payload_no_update
BEFORE UPDATE ON fact_assertion_payload
BEGIN
    SELECT RAISE(ABORT, 'fact assertion payloads are immutable; supersede metadata');
END;

CREATE TRIGGER IF NOT EXISTS fact_assertion_payload_no_ghost_pii
BEFORE INSERT ON fact_assertion_payload
FOR EACH ROW
WHEN NEW.pii_class IN ('direct', 'free_text')
 AND EXISTS (
    SELECT 1
    FROM fact_assertion AS assertion
    JOIN person ON person.state = 'ghost'
    WHERE assertion.id = NEW.assertion_id
      AND (
        (assertion.subject_table = 'person' AND assertion.subject_id = person.id)
        OR (
            assertion.subject_table = 'application'
            AND EXISTS (
                SELECT 1 FROM application
                WHERE id = assertion.subject_id AND person_id = person.id
            )
        )
        OR (
            assertion.subject_table = 'participation'
            AND EXISTS (
                SELECT 1 FROM participation
                WHERE id = assertion.subject_id AND person_id = person.id
            )
        )
        OR (
            assertion.subject_table = 'enrichment_snapshot'
            AND EXISTS (
                SELECT 1 FROM enrichment_snapshot
                WHERE id = assertion.subject_id AND person_id = person.id
            )
        )
        OR (
            assertion.subject_table = 'classification'
            AND EXISTS (
                SELECT 1 FROM classification
                WHERE id = assertion.subject_id AND person_id = person.id
            )
        )
        OR (
            assertion.subject_table = 'intro'
            AND EXISTS (
                SELECT 1 FROM intro
                WHERE id = assertion.subject_id AND person_id = person.id
            )
        )
      )
 )
BEGIN
    SELECT RAISE(ABORT, 'ghost people cannot regain direct fact payloads');
END;

CREATE TRIGGER IF NOT EXISTS source_record_no_ghost_raw_resurrection
BEFORE UPDATE OF raw_payload_json ON source_record
FOR EACH ROW
WHEN NEW.raw_payload_json IS NOT NULL
 AND EXISTS (
    SELECT 1
    FROM person_source_record_link AS link
    JOIN person ON person.id = link.person_id
    WHERE link.source_record_id = NEW.id AND person.state = 'ghost'
 )
BEGIN
    SELECT RAISE(ABORT, 'raw source payload cannot be restored for a ghost');
END;

CREATE TRIGGER IF NOT EXISTS consent_assertion_event_coherence
BEFORE INSERT ON consent_assertion
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM source_record AS record
    JOIN source_file AS file ON file.id = record.source_file_id
    WHERE record.id = NEW.source_record_id AND file.event_id = NEW.event_id
)
BEGIN
    SELECT RAISE(ABORT, 'consent source record must belong to its event');
END;
CREATE TRIGGER IF NOT EXISTS consent_assertion_no_ghost_raw_source
BEFORE INSERT ON consent_assertion
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM person WHERE id = NEW.person_id AND state = 'ghost')
 AND EXISTS (
    SELECT 1 FROM source_record
    WHERE id = NEW.source_record_id AND raw_payload_json IS NOT NULL
 )
BEGIN
    SELECT RAISE(ABORT, 'ghost consent requires an erased source payload');
END;

CREATE TRIGGER IF NOT EXISTS identity_evidence_owner_matches_identity
BEFORE INSERT ON identity_evidence
FOR EACH ROW
WHEN NEW.person_identity_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM person_identity
    WHERE id = NEW.person_identity_id AND person_id = NEW.person_id
 )
BEGIN
    SELECT RAISE(ABORT, 'identity evidence owner must match identity owner');
END;
CREATE TRIGGER IF NOT EXISTS identity_evidence_no_ghost_pii
BEFORE INSERT ON identity_evidence
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM person WHERE id = NEW.person_id AND state = 'ghost')
 AND (
    NEW.normalized_value IS NOT NULL
    OR EXISTS (
        SELECT 1 FROM source_record
        WHERE id = NEW.source_record_id AND raw_payload_json IS NOT NULL
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'ghost identity evidence requires erased values');
END;

CREATE TRIGGER IF NOT EXISTS identity_evidence_immutable_metadata
BEFORE UPDATE ON identity_evidence
FOR EACH ROW
WHEN NEW.source_record_id IS NOT OLD.source_record_id
 OR NEW.person_id IS NOT OLD.person_id
 OR (
    NEW.person_identity_id IS NOT OLD.person_identity_id
    AND NOT (OLD.person_identity_id IS NOT NULL AND NEW.person_identity_id IS NULL)
 )
 OR NEW.evidence_type IS NOT OLD.evidence_type
 OR NEW.applicant_provided IS NOT OLD.applicant_provided
 OR NEW.mapping_version IS NOT OLD.mapping_version
 OR NEW.observed_at IS NOT OLD.observed_at
 OR NEW.created_at IS NOT OLD.created_at
 OR (
    NEW.normalized_value IS NOT OLD.normalized_value
    AND NOT (OLD.normalized_value IS NOT NULL AND NEW.normalized_value IS NULL)
 )
BEGIN
    SELECT RAISE(ABORT, 'identity evidence metadata is immutable except PII erasure');
END;

CREATE TRIGGER IF NOT EXISTS publication_event_matches_aggregate
BEFORE INSERT ON publication
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM aggregate_snapshot
    WHERE id = NEW.aggregate_snapshot_id AND event_id = NEW.event_id
)
BEGIN
    SELECT RAISE(ABORT, 'publication event must match aggregate event');
END;

CREATE TRIGGER IF NOT EXISTS aggregate_snapshot_event_immutable
BEFORE UPDATE OF event_id ON aggregate_snapshot
FOR EACH ROW
WHEN NEW.event_id IS NOT OLD.event_id
BEGIN
    SELECT RAISE(ABORT, 'aggregate snapshot event is immutable');
END;

CREATE TRIGGER IF NOT EXISTS publication_ownership_immutable
BEFORE UPDATE OF event_id, aggregate_snapshot_id ON publication
FOR EACH ROW
WHEN NEW.event_id IS NOT OLD.event_id
  OR NEW.aggregate_snapshot_id IS NOT OLD.aggregate_snapshot_id
BEGIN
    SELECT RAISE(ABORT, 'publication ownership is immutable');
END;

CREATE TRIGGER IF NOT EXISTS identity_decision_no_ghost_raw_source
BEFORE INSERT ON identity_decision
FOR EACH ROW
WHEN NEW.person_id IS NOT NULL
 AND EXISTS (SELECT 1 FROM person WHERE id = NEW.person_id AND state = 'ghost')
 AND EXISTS (
    SELECT 1 FROM source_record
    WHERE id = NEW.source_record_id AND raw_payload_json IS NOT NULL
 )
BEGIN
    SELECT RAISE(ABORT, 'ghost identity decisions require erased source payloads');
END;

CREATE TRIGGER IF NOT EXISTS identity_review_no_ghost_pii_insert
BEFORE INSERT ON identity_review
FOR EACH ROW
WHEN EXISTS (
    SELECT 1 FROM person
    WHERE state = 'ghost'
      AND (id = NEW.provisional_person_id OR id = NEW.suggested_person_id)
)
 AND (
    NEW.evidence_json IS NOT NULL
    OR EXISTS (
        SELECT 1 FROM source_record
        WHERE id = NEW.source_record_id AND raw_payload_json IS NOT NULL
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'ghost identity reviews require erased evidence');
END;
CREATE TRIGGER IF NOT EXISTS identity_review_no_ghost_pii_update
BEFORE UPDATE OF evidence_json ON identity_review
FOR EACH ROW
WHEN NEW.evidence_json IS NOT NULL
 AND EXISTS (
    SELECT 1 FROM person
    WHERE state = 'ghost'
      AND (id = NEW.provisional_person_id OR id = NEW.suggested_person_id)
 )
BEGIN
    SELECT RAISE(ABORT, 'ghost identity reviews cannot regain evidence');
END;
CREATE TRIGGER IF NOT EXISTS identity_review_ownership_immutable
BEFORE UPDATE OF source_record_id, provisional_person_id, suggested_person_id
ON identity_review
FOR EACH ROW
WHEN NEW.source_record_id IS NOT OLD.source_record_id
  OR NEW.provisional_person_id IS NOT OLD.provisional_person_id
  OR NEW.suggested_person_id IS NOT OLD.suggested_person_id
BEGIN
    SELECT RAISE(ABORT, 'identity review ownership is immutable');
END;

CREATE TRIGGER IF NOT EXISTS source_file_event_no_reassignment
BEFORE UPDATE OF event_id ON source_file
FOR EACH ROW
WHEN NEW.event_id IS NOT OLD.event_id
BEGIN
    SELECT RAISE(ABORT, 'source file event provenance is immutable');
END;

CREATE TRIGGER IF NOT EXISTS source_record_file_no_reassignment
BEFORE UPDATE OF source_file_id ON source_record
FOR EACH ROW
WHEN NEW.source_file_id != OLD.source_file_id
BEGIN
    SELECT RAISE(ABORT, 'source record file provenance is immutable');
END;

CREATE TRIGGER IF NOT EXISTS fact_assertion_event_coherence
BEFORE INSERT ON fact_assertion
FOR EACH ROW
WHEN NEW.subject_table IN (
    'event', 'application', 'participation', 'team', 'submission',
    'classification', 'intro'
)
 AND NOT EXISTS (
    SELECT 1
    FROM source_record AS record
    JOIN source_file AS file ON file.id = record.source_file_id
    WHERE record.id = NEW.source_record_id
      AND file.event_id = CASE NEW.subject_table
          WHEN 'event' THEN NEW.subject_id
          WHEN 'application' THEN (
              SELECT event_id FROM application WHERE id = NEW.subject_id
          )
          WHEN 'participation' THEN (
              SELECT event_id FROM participation WHERE id = NEW.subject_id
          )
          WHEN 'team' THEN (
              SELECT event_id FROM team WHERE id = NEW.subject_id
          )
          WHEN 'submission' THEN (
              SELECT event_id FROM submission WHERE id = NEW.subject_id
          )
          WHEN 'classification' THEN (
              SELECT event_id FROM classification WHERE id = NEW.subject_id
          )
          WHEN 'intro' THEN (
              SELECT event_id FROM intro WHERE id = NEW.subject_id
          )
      END
 )
BEGIN
    SELECT RAISE(ABORT, 'fact assertion source must match its subject event');
END;

CREATE TRIGGER IF NOT EXISTS fact_assertion_no_ghost_raw_source
BEFORE INSERT ON fact_assertion
FOR EACH ROW
WHEN EXISTS (
    SELECT 1
    FROM person
    WHERE person.state = 'ghost'
      AND (
        (NEW.subject_table = 'person' AND NEW.subject_id = person.id)
        OR (
            NEW.subject_table = 'application'
            AND EXISTS (
                SELECT 1 FROM application
                WHERE id = NEW.subject_id AND person_id = person.id
            )
        )
        OR (
            NEW.subject_table = 'participation'
            AND EXISTS (
                SELECT 1 FROM participation
                WHERE id = NEW.subject_id AND person_id = person.id
            )
        )
        OR (
            NEW.subject_table = 'enrichment_snapshot'
            AND EXISTS (
                SELECT 1 FROM enrichment_snapshot
                WHERE id = NEW.subject_id AND person_id = person.id
            )
        )
        OR (
            NEW.subject_table = 'classification'
            AND EXISTS (
                SELECT 1 FROM classification
                WHERE id = NEW.subject_id AND person_id = person.id
            )
        )
        OR (
            NEW.subject_table = 'intro'
            AND EXISTS (
                SELECT 1 FROM intro
                WHERE id = NEW.subject_id AND person_id = person.id
            )
        )
      )
 )
 AND EXISTS (
    SELECT 1 FROM source_record
    WHERE id = NEW.source_record_id AND raw_payload_json IS NOT NULL
 )
BEGIN
    SELECT RAISE(ABORT, 'ghost fact assertions require erased source payloads');
END;

CREATE TRIGGER IF NOT EXISTS application_event_coherence_insert
BEFORE INSERT ON application
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM source_record AS record
    JOIN source_file AS file ON file.id = record.source_file_id
    WHERE record.id = NEW.source_record_id AND file.event_id = NEW.event_id
)
BEGIN
    SELECT RAISE(ABORT, 'application source record must belong to its event');
END;
CREATE TRIGGER IF NOT EXISTS application_no_ghost_pii_insert
BEFORE INSERT ON application
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM person WHERE id = NEW.person_id AND state = 'ghost')
 AND (
    NEW.raw_answers_json IS NOT NULL
    OR EXISTS (
        SELECT 1 FROM source_record
        WHERE id = NEW.source_record_id AND raw_payload_json IS NOT NULL
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'ghost applications require erased payloads');
END;
CREATE TRIGGER IF NOT EXISTS application_no_ghost_pii_update
BEFORE UPDATE OF raw_answers_json ON application
FOR EACH ROW
WHEN NEW.raw_answers_json IS NOT NULL
 AND EXISTS (SELECT 1 FROM person WHERE id = NEW.person_id AND state = 'ghost')
BEGIN
    SELECT RAISE(ABORT, 'ghost applications cannot regain raw answers');
END;
CREATE TRIGGER IF NOT EXISTS application_event_coherence_update
BEFORE UPDATE OF event_id, source_record_id ON application
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM source_record AS record
    JOIN source_file AS file ON file.id = record.source_file_id
    WHERE record.id = NEW.source_record_id AND file.event_id = NEW.event_id
)
BEGIN
    SELECT RAISE(ABORT, 'application source record must belong to its event');
END;
CREATE TRIGGER IF NOT EXISTS application_ownership_immutable
BEFORE UPDATE OF person_id, event_id, source_record_id ON application
FOR EACH ROW
WHEN NEW.person_id IS NOT OLD.person_id
  OR NEW.event_id IS NOT OLD.event_id
  OR NEW.source_record_id IS NOT OLD.source_record_id
BEGIN
    SELECT RAISE(ABORT, 'application ownership is immutable');
END;

CREATE TRIGGER IF NOT EXISTS team_event_coherence_insert
BEFORE INSERT ON team
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM source_record AS record
    JOIN source_file AS file ON file.id = record.source_file_id
    WHERE record.id = NEW.source_record_id AND file.event_id = NEW.event_id
)
BEGIN
    SELECT RAISE(ABORT, 'team source record must belong to its event');
END;
CREATE TRIGGER IF NOT EXISTS team_event_coherence_update
BEFORE UPDATE OF event_id, source_record_id ON team
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM source_record AS record
    JOIN source_file AS file ON file.id = record.source_file_id
    WHERE record.id = NEW.source_record_id AND file.event_id = NEW.event_id
)
BEGIN
    SELECT RAISE(ABORT, 'team source record must belong to its event');
END;
CREATE TRIGGER IF NOT EXISTS team_ownership_immutable
BEFORE UPDATE OF event_id, source_record_id ON team
FOR EACH ROW
WHEN NEW.event_id IS NOT OLD.event_id
  OR NEW.source_record_id IS NOT OLD.source_record_id
BEGIN
    SELECT RAISE(ABORT, 'team ownership is immutable');
END;

CREATE TRIGGER IF NOT EXISTS submission_event_coherence_insert
BEFORE INSERT ON submission
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM source_record AS record
    JOIN source_file AS file ON file.id = record.source_file_id
    WHERE record.id = NEW.source_record_id AND file.event_id = NEW.event_id
)
 OR (
    NEW.team_id IS NOT NULL
    AND NOT EXISTS (
        SELECT 1 FROM team
        WHERE id = NEW.team_id AND event_id = NEW.event_id
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'submission source and team must belong to its event');
END;
CREATE TRIGGER IF NOT EXISTS submission_event_coherence_update
BEFORE UPDATE OF event_id, source_record_id, team_id ON submission
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM source_record AS record
    JOIN source_file AS file ON file.id = record.source_file_id
    WHERE record.id = NEW.source_record_id AND file.event_id = NEW.event_id
)
 OR (
    NEW.team_id IS NOT NULL
    AND NOT EXISTS (
        SELECT 1 FROM team
        WHERE id = NEW.team_id AND event_id = NEW.event_id
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'submission source and team must belong to its event');
END;
CREATE TRIGGER IF NOT EXISTS submission_ownership_immutable
BEFORE UPDATE OF event_id, team_id, source_record_id ON submission
FOR EACH ROW
WHEN NEW.event_id IS NOT OLD.event_id
  OR NEW.team_id IS NOT OLD.team_id
  OR NEW.source_record_id IS NOT OLD.source_record_id
BEGIN
    SELECT RAISE(ABORT, 'submission ownership is immutable');
END;

CREATE TRIGGER IF NOT EXISTS participation_event_coherence_insert
BEFORE INSERT ON participation
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM source_record AS record
    JOIN source_file AS file ON file.id = record.source_file_id
    WHERE record.id = NEW.source_record_id AND file.event_id = NEW.event_id
)
 OR (
    NEW.team_id IS NOT NULL
    AND NOT EXISTS (
        SELECT 1 FROM team
        WHERE id = NEW.team_id AND event_id = NEW.event_id
    )
 )
 OR (
    NEW.submission_id IS NOT NULL
    AND NOT EXISTS (
        SELECT 1 FROM submission
        WHERE id = NEW.submission_id AND event_id = NEW.event_id
    )
 )
BEGIN
    SELECT RAISE(
        ABORT,
        'participation source, team, and submission must belong to its event'
    );
END;
CREATE TRIGGER IF NOT EXISTS participation_no_ghost_raw_source
BEFORE INSERT ON participation
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM person WHERE id = NEW.person_id AND state = 'ghost')
 AND EXISTS (
    SELECT 1 FROM source_record
    WHERE id = NEW.source_record_id AND raw_payload_json IS NOT NULL
 )
BEGIN
    SELECT RAISE(ABORT, 'ghost participation requires an erased source payload');
END;
CREATE TRIGGER IF NOT EXISTS participation_event_coherence_update
BEFORE UPDATE OF event_id, source_record_id, team_id, submission_id ON participation
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM source_record AS record
    JOIN source_file AS file ON file.id = record.source_file_id
    WHERE record.id = NEW.source_record_id AND file.event_id = NEW.event_id
)
 OR (
    NEW.team_id IS NOT NULL
    AND NOT EXISTS (
        SELECT 1 FROM team
        WHERE id = NEW.team_id AND event_id = NEW.event_id
    )
 )
 OR (
    NEW.submission_id IS NOT NULL
    AND NOT EXISTS (
        SELECT 1 FROM submission
        WHERE id = NEW.submission_id AND event_id = NEW.event_id
    )
 )
BEGIN
    SELECT RAISE(
        ABORT,
        'participation source, team, and submission must belong to its event'
    );
END;
CREATE TRIGGER IF NOT EXISTS participation_ownership_immutable
BEFORE UPDATE OF person_id, event_id, source_record_id, team_id, submission_id
ON participation
FOR EACH ROW
WHEN NEW.person_id IS NOT OLD.person_id
  OR NEW.event_id IS NOT OLD.event_id
  OR NEW.source_record_id IS NOT OLD.source_record_id
  OR NEW.team_id IS NOT OLD.team_id
  OR NEW.submission_id IS NOT OLD.submission_id
BEGIN
    SELECT RAISE(ABORT, 'participation ownership is immutable');
END;

CREATE TRIGGER IF NOT EXISTS enrichment_snapshot_no_ghost_pii_insert
BEFORE INSERT ON enrichment_snapshot
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM person WHERE id = NEW.person_id AND state = 'ghost')
 AND (
    NEW.payload_json IS NOT NULL
    OR EXISTS (
        SELECT 1 FROM source_record
        WHERE id = NEW.source_record_id AND raw_payload_json IS NOT NULL
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'ghost enrichment snapshots require erased payloads');
END;
CREATE TRIGGER IF NOT EXISTS enrichment_snapshot_no_ghost_pii_update
BEFORE UPDATE OF payload_json ON enrichment_snapshot
FOR EACH ROW
WHEN NEW.payload_json IS NOT NULL
 AND EXISTS (SELECT 1 FROM person WHERE id = NEW.person_id AND state = 'ghost')
BEGIN
    SELECT RAISE(ABORT, 'ghost enrichment snapshots cannot regain payloads');
END;

CREATE TRIGGER IF NOT EXISTS classification_event_coherence
BEFORE INSERT ON classification
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM source_record AS record
    JOIN source_file AS file ON file.id = record.source_file_id
    WHERE record.id = NEW.source_record_id AND file.event_id = NEW.event_id
)
BEGIN
    SELECT RAISE(ABORT, 'classification source record must belong to its event');
END;
CREATE TRIGGER IF NOT EXISTS classification_no_ghost_pii_insert
BEFORE INSERT ON classification
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM person WHERE id = NEW.person_id AND state = 'ghost')
 AND (
    NEW.facts_json IS NOT NULL
    OR EXISTS (
        SELECT 1 FROM source_record
        WHERE id = NEW.source_record_id AND raw_payload_json IS NOT NULL
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'ghost classifications require erased payloads');
END;

CREATE TRIGGER IF NOT EXISTS intro_event_coherence_insert
BEFORE INSERT ON intro
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM source_record AS record
    JOIN source_file AS file ON file.id = record.source_file_id
    WHERE record.id = NEW.source_record_id AND file.event_id = NEW.event_id
)
BEGIN
    SELECT RAISE(ABORT, 'intro source record must belong to its event');
END;
CREATE TRIGGER IF NOT EXISTS intro_no_ghost_pii_insert
BEFORE INSERT ON intro
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM person WHERE id = NEW.person_id AND state = 'ghost')
 AND (
    NEW.context IS NOT NULL
    OR EXISTS (
        SELECT 1 FROM source_record
        WHERE id = NEW.source_record_id AND raw_payload_json IS NOT NULL
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'ghost intros require erased context and source payload');
END;
CREATE TRIGGER IF NOT EXISTS intro_no_ghost_context_update
BEFORE UPDATE OF context ON intro
FOR EACH ROW
WHEN NEW.context IS NOT NULL
 AND EXISTS (SELECT 1 FROM person WHERE id = NEW.person_id AND state = 'ghost')
BEGIN
    SELECT RAISE(ABORT, 'ghost intros cannot regain context');
END;
CREATE TRIGGER IF NOT EXISTS intro_event_coherence_update
BEFORE UPDATE OF event_id, source_record_id ON intro
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM source_record AS record
    JOIN source_file AS file ON file.id = record.source_file_id
    WHERE record.id = NEW.source_record_id AND file.event_id = NEW.event_id
)
BEGIN
    SELECT RAISE(ABORT, 'intro source record must belong to its event');
END;
CREATE TRIGGER IF NOT EXISTS intro_ownership_immutable
BEFORE UPDATE OF person_id, event_id, source_record_id ON intro
FOR EACH ROW
WHEN NEW.person_id IS NOT OLD.person_id
  OR NEW.event_id IS NOT OLD.event_id
  OR NEW.source_record_id IS NOT OLD.source_record_id
BEGIN
    SELECT RAISE(ABORT, 'intro ownership is immutable');
END;

CREATE TRIGGER IF NOT EXISTS intro_outcome_event_coherence
BEFORE INSERT ON intro_outcome
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM intro
    JOIN source_record AS record ON record.id = NEW.source_record_id
    JOIN source_file AS file ON file.id = record.source_file_id
    WHERE intro.id = NEW.intro_id AND file.event_id = intro.event_id
)
BEGIN
    SELECT RAISE(ABORT, 'intro outcome source must belong to the intro event');
END;

CREATE TRIGGER IF NOT EXISTS fact_assertion_no_update
BEFORE UPDATE ON fact_assertion BEGIN
    SELECT RAISE(ABORT, 'fact_assertion is append-only');
END;
CREATE TRIGGER IF NOT EXISTS fact_assertion_no_delete
BEFORE DELETE ON fact_assertion BEGIN
    SELECT RAISE(ABORT, 'fact_assertion is append-only');
END;

CREATE TRIGGER IF NOT EXISTS consent_assertion_no_update
BEFORE UPDATE ON consent_assertion BEGIN
    SELECT RAISE(ABORT, 'consent_assertion is append-only');
END;
CREATE TRIGGER IF NOT EXISTS consent_assertion_no_delete
BEFORE DELETE ON consent_assertion BEGIN
    SELECT RAISE(ABORT, 'consent_assertion is append-only');
END;

CREATE TRIGGER IF NOT EXISTS identity_decision_no_update
BEFORE UPDATE ON identity_decision BEGIN
    SELECT RAISE(ABORT, 'identity_decision is append-only');
END;
CREATE TRIGGER IF NOT EXISTS identity_decision_no_delete
BEFORE DELETE ON identity_decision BEGIN
    SELECT RAISE(ABORT, 'identity_decision is append-only');
END;

CREATE TRIGGER IF NOT EXISTS classification_no_update
BEFORE UPDATE ON classification
FOR EACH ROW
WHEN NOT (
    OLD.facts_json IS NOT NULL
    AND NEW.facts_json IS NULL
    AND NEW.id IS OLD.id
    AND NEW.person_id IS OLD.person_id
    AND NEW.event_id IS OLD.event_id
    AND NEW.source_record_id IS OLD.source_record_id
    AND NEW.taxonomy_version IS OLD.taxonomy_version
    AND NEW.occupation IS OLD.occupation
    AND NEW.signal_tier IS OLD.signal_tier
    AND NEW.confidence IS OLD.confidence
    AND NEW.provider IS OLD.provider
    AND NEW.model IS OLD.model
    AND NEW.prompt_version IS OLD.prompt_version
    AND NEW.reviewed_by IS OLD.reviewed_by
    AND NEW.observed_at IS OLD.observed_at
    AND NEW.supersedes_classification_id IS OLD.supersedes_classification_id
    AND NEW.created_at IS OLD.created_at
)
BEGIN
    SELECT RAISE(ABORT, 'classification metadata is append-only; facts may only erase');
END;
CREATE TRIGGER IF NOT EXISTS classification_no_delete
BEFORE DELETE ON classification BEGIN
    SELECT RAISE(ABORT, 'classification is append-only');
END;

CREATE TRIGGER IF NOT EXISTS intro_outcome_no_update
BEFORE UPDATE ON intro_outcome BEGIN
    SELECT RAISE(ABORT, 'intro_outcome is append-only');
END;
CREATE TRIGGER IF NOT EXISTS intro_outcome_no_delete
BEFORE DELETE ON intro_outcome BEGIN
    SELECT RAISE(ABORT, 'intro_outcome is append-only');
END;

CREATE TRIGGER IF NOT EXISTS deletion_log_no_update
BEFORE UPDATE ON deletion_log BEGIN
    SELECT RAISE(ABORT, 'deletion_log is append-only');
END;
CREATE TRIGGER IF NOT EXISTS deletion_log_no_delete
BEFORE DELETE ON deletion_log BEGIN
    SELECT RAISE(ABORT, 'deletion_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS hashed_identity_no_update
BEFORE UPDATE ON hashed_identity BEGIN
    SELECT RAISE(ABORT, 'hashed_identity is immutable');
END;
CREATE TRIGGER IF NOT EXISTS hashed_identity_no_delete
BEFORE DELETE ON hashed_identity BEGIN
    SELECT RAISE(ABORT, 'hashed_identity is immutable');
END;

PRAGMA user_version = 2;
