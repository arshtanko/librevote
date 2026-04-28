package storage

import "context"

const schemaDDL = `
CREATE TABLE IF NOT EXISTS objects (
	object_id TEXT NOT NULL PRIMARY KEY,
	object_type TEXT NOT NULL,
	protocol_version INTEGER NOT NULL,
	network_id TEXT NOT NULL,
	scope TEXT NOT NULL,
	scope_id TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	first_seen_at INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	object_pow BLOB NOT NULL,
	payload_hash BLOB NOT NULL,
	payload_size INTEGER NOT NULL,
	payload_retained INTEGER NOT NULL CHECK(payload_retained IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_objects_scope_type_created ON objects(scope, scope_id, object_type, created_at);
CREATE INDEX IF NOT EXISTS idx_objects_type_created ON objects(object_type, created_at);
CREATE INDEX IF NOT EXISTS idx_objects_network_created ON objects(network_id, created_at);

CREATE TABLE IF NOT EXISTS object_payloads (
	object_id TEXT NOT NULL PRIMARY KEY,
	payload_bytes BLOB NOT NULL,
	FOREIGN KEY(object_id) REFERENCES objects(object_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS validation_records (
	object_id TEXT NOT NULL PRIMARY KEY,
	validation_status TEXT NOT NULL,
	validation_error_code TEXT,
	validation_error_message TEXT,
	validator_version TEXT NOT NULL,
	last_checked_at INTEGER NOT NULL,
	FOREIGN KEY(object_id) REFERENCES objects(object_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_validation_status_checked ON validation_records(validation_status, last_checked_at);
CREATE INDEX IF NOT EXISTS idx_validation_version ON validation_records(validator_version);

CREATE TABLE IF NOT EXISTS object_dependencies (
	object_id TEXT NOT NULL,
	dependency_type TEXT NOT NULL,
	dependency_id TEXT NOT NULL,
	FOREIGN KEY(object_id) REFERENCES objects(object_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_dependencies_type_id ON object_dependencies(dependency_type, dependency_id);
CREATE INDEX IF NOT EXISTS idx_dependencies_object ON object_dependencies(object_id);

CREATE TABLE IF NOT EXISTS invalid_object_records (
	object_id TEXT NOT NULL PRIMARY KEY,
	object_type TEXT NOT NULL,
	network_id TEXT NOT NULL,
	scope TEXT NOT NULL,
	scope_id TEXT NOT NULL,
	first_seen_at INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	seen_count INTEGER NOT NULL,
	validation_error_code TEXT
);

CREATE TABLE IF NOT EXISTS election_state (
	election_id TEXT NOT NULL PRIMARY KEY,
	phase TEXT NOT NULL,
	valid_object_count INTEGER NOT NULL,
	invalid_object_count INTEGER NOT NULL,
	pending_object_count INTEGER NOT NULL,
	computed_state_hash BLOB NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS trustee_selection_state (
	trustee_selection_id TEXT NOT NULL PRIMARY KEY,
	candidate_ranking_hash BLOB NOT NULL,
	initial_selected_trustees_hash BLOB NOT NULL,
	valid_vote_count INTEGER NOT NULL,
	conflicted_vote_count INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tally_state (
	election_id TEXT NOT NULL PRIMARY KEY,
	encrypted_tally_hash BLOB NOT NULL,
	valid_ballot_count INTEGER NOT NULL,
	conflicted_ballot_count INTEGER NOT NULL,
	invalid_ballot_count_diagnostic INTEGER NOT NULL,
	result_status TEXT NOT NULL,
	result_hash BLOB NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
	key_id TEXT NOT NULL PRIMARY KEY,
	key_type TEXT NOT NULL,
	public_key BLOB NOT NULL,
	encrypted_private_key BLOB NOT NULL,
	encryption_metadata BLOB,
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS local_issuance_state (
	election_id TEXT NOT NULL,
	voter_key_id TEXT NOT NULL,
	token_key_id TEXT NOT NULL,
	encrypted_blinding_factor BLOB NOT NULL,
	encrypted_unblinded_token_signatures BLOB NOT NULL,
	completed_at INTEGER,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS peers (
	peer_id TEXT NOT NULL PRIMARY KEY,
	score REAL NOT NULL,
	admission_status TEXT NOT NULL,
	first_seen_at INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS peer_addresses (
	peer_id TEXT NOT NULL,
	address TEXT NOT NULL,
	first_seen_at INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	PRIMARY KEY(peer_id, address),
	FOREIGN KEY(peer_id) REFERENCES peers(peer_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sync_state (
	peer_id TEXT NOT NULL,
	scope TEXT NOT NULL,
	scope_id TEXT NOT NULL,
	cursor BLOB,
	last_sync_at INTEGER NOT NULL,
	failed_attempts INTEGER NOT NULL,
	PRIMARY KEY(peer_id, scope, scope_id)
);

CREATE TABLE IF NOT EXISTS message_cache (
	object_id TEXT NOT NULL PRIMARY KEY,
	first_seen_at INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	seen_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS object_sources (
	object_id TEXT NOT NULL,
	peer_id TEXT NOT NULL,
	first_seen_at INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	PRIMARY KEY(object_id, peer_id),
	FOREIGN KEY(object_id) REFERENCES objects(object_id) ON DELETE CASCADE
);
`

func (s *Store) bootstrapSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schemaDDL); err != nil {
		return err
	}
	return nil
}
