-- Seed data for the full legacy v1 operator schema assembled by
-- tests.test_database_migration. IDs and timestamps are explicit so migration
-- tests can prove that the table rebuild preserves exact provenance.
INSERT INTO event(id,event_key,name,starts_at,ends_at,event_type,created_at) VALUES
    (11,'legacy-event-one','Legacy Event One','2026-07-11T08:00:00Z',NULL,'hackathon','2026-07-01T00:00:00Z'),
    (12,'legacy-event-two','Legacy Event Two','2026-08-01T08:00:00Z',NULL,'hackathon','2026-07-02T00:00:00Z');

INSERT INTO person(id,state,created_at,updated_at) VALUES
    (301,'active','2026-07-01T00:00:00Z','2026-07-01T00:00:00Z'),
    (302,'active','2026-07-02T00:00:00Z','2026-07-02T00:00:00Z');

INSERT INTO source_file(
    id,event_id,source_type,file_sha256,mapping_version,observed_at,ingested_at
) VALUES
    (101,11,'luma_final','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
     'luma_final-v1','2026-07-11T10:00:00Z','2026-07-11T10:01:00Z'),
    (102,12,'devpost_final','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
     'devpost_final-v1','2026-08-01T10:00:00Z','2026-08-01T10:01:00Z');

INSERT INTO source_record(
    id,source_file_id,external_record_id,mapping_version,observed_at,
    raw_payload_json,quarantined,created_at
) VALUES
    (201,101,'legacy-record-one','luma_final-v1','2026-07-11T10:00:00Z',
     '{"status":"accepted"}',0,'2026-07-11T10:01:00Z'),
    (202,102,'legacy-record-two','devpost_final-v1','2026-08-01T10:00:00Z',
     '{"status":"applied"}',0,'2026-08-01T10:01:00Z');

INSERT INTO person_identity(
    id,person_id,source_record_id,identity_type,display_value,normalized_value,
    verified,applicant_provided,observed_at,created_at
) VALUES
    (401,301,201,'email','legacy-one@example.org','legacy-one@example.org',1,1,
     '2026-07-11T10:00:00Z','2026-07-11T10:01:00Z'),
    (402,302,202,'email','legacy-two@example.org','legacy-two@example.org',1,1,
     '2026-08-01T10:00:00Z','2026-08-01T10:01:00Z');

INSERT INTO identity_evidence(
    id,source_record_id,person_id,person_identity_id,evidence_type,
    normalized_value,applicant_provided,mapping_version,observed_at,created_at
) VALUES
    (451,201,301,401,'email','legacy-one@example.org',1,'luma_final-v1',
     '2026-07-11T10:00:00Z','2026-07-11T10:01:00Z'),
    (452,202,302,402,'email','legacy-two@example.org',1,'devpost_final-v1',
     '2026-08-01T10:00:00Z','2026-08-01T10:01:00Z');

INSERT INTO identity_decision(
    id,source_record_id,person_id,decision,reviewer,reason,decided_at,created_at
) VALUES
    (471,201,301,'kept_separate','fixture','new_identity','2026-07-11T10:01:00Z','2026-07-11T10:01:00Z'),
    (472,202,302,'kept_separate','fixture','new_identity','2026-08-01T10:01:00Z','2026-08-01T10:01:00Z');

INSERT INTO application(
    id,person_id,event_id,source_record_id,status,raw_answers_json,applied_at,created_at
) VALUES
    (501,301,11,201,'accepted','{}','2026-07-11T10:00:00Z','2026-07-11T10:01:00Z'),
    (502,302,12,202,'applied','{}','2026-08-01T10:00:00Z','2026-08-01T10:01:00Z');

INSERT INTO participation(
    id,person_id,event_id,source_record_id,checked_in,checked_in_at,created_at
) VALUES
    (601,301,11,201,1,'2026-07-11T11:00:00Z','2026-07-11T11:00:00Z'),
    (602,302,12,202,0,NULL,'2026-08-01T11:00:00Z');

INSERT INTO fact_assertion(
    id,subject_table,subject_id,field_name,source_record_id,mapping_version,
    authority,observed_at,created_at
) VALUES
    (801,'application',501,'status',201,'luma_final-v1','platform',
     '2026-07-11T10:00:00Z','2026-07-11T10:01:00Z'),
    (802,'application',502,'status',202,'devpost_final-v1','platform',
     '2026-08-01T10:00:00Z','2026-08-01T10:01:00Z');

INSERT INTO fact_assertion_payload(assertion_id,canonical_value_json,pii_class) VALUES
    (801,'"accepted"','non_pii'),
    (802,'"applied"','non_pii');

PRAGMA user_version = 0;
