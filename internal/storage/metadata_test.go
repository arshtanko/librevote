package storage

import (
	"bytes"
	"context"
	"testing"

	"librevote/internal/domain"
)

func TestPeerUpsertReadDeleteAndAddressCascade(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	peer := PeerRecord{PeerID: "peer-1", Score: 1.5, AdmissionStatus: "admitted", FirstSeenAt: 10, LastSeenAt: 20}
	if err := store.UpsertPeer(ctx, peer); err != nil {
		t.Fatalf("UpsertPeer() error = %v", err)
	}
	updated := PeerRecord{PeerID: "peer-1", Score: 2.5, AdmissionStatus: "limited", FirstSeenAt: 99, LastSeenAt: 30}
	if err := store.UpsertPeer(ctx, updated); err != nil {
		t.Fatalf("second UpsertPeer() error = %v", err)
	}

	got, err := store.Peer(ctx, "peer-1")
	if err != nil {
		t.Fatalf("Peer() error = %v", err)
	}
	if got.FirstSeenAt != 10 || got.LastSeenAt != 30 || got.Score != 2.5 || got.AdmissionStatus != "limited" {
		t.Fatalf("peer after upsert = %+v", got)
	}

	addr := PeerAddress{PeerID: "peer-1", Address: "/ip4/127.0.0.1/udp/1000/quic-v1", FirstSeenAt: 40, LastSeenAt: 50}
	if err := store.UpsertPeerAddress(ctx, addr); err != nil {
		t.Fatalf("UpsertPeerAddress() error = %v", err)
	}
	addr.FirstSeenAt = 99
	addr.LastSeenAt = 60
	if err := store.UpsertPeerAddress(ctx, addr); err != nil {
		t.Fatalf("second UpsertPeerAddress() error = %v", err)
	}

	addresses, err := store.PeerAddresses(ctx, "peer-1")
	if err != nil {
		t.Fatalf("PeerAddresses() error = %v", err)
	}
	if len(addresses) != 1 || addresses[0].FirstSeenAt != 40 || addresses[0].LastSeenAt != 60 {
		t.Fatalf("addresses after upsert = %+v", addresses)
	}

	if err := store.DeletePeer(ctx, "peer-1"); err != nil {
		t.Fatalf("DeletePeer() error = %v", err)
	}
	addresses, err = store.PeerAddresses(ctx, "peer-1")
	if err != nil {
		t.Fatalf("PeerAddresses() after delete error = %v", err)
	}
	if len(addresses) != 0 {
		t.Fatalf("addresses after peer delete = %+v, want empty", addresses)
	}
}

func TestSyncStateOpaqueCursorDefensiveCopies(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	cursor := []byte{0x01, 0x02, 0x03}
	state := SyncState{PeerID: "peer-1", Scope: "election", ScopeID: "election-1", Cursor: cursor, LastSyncAt: 100, FailedAttempts: 2}
	if err := store.PutSyncState(ctx, state); err != nil {
		t.Fatalf("PutSyncState() error = %v", err)
	}
	cursor[0] = 0xff

	got, err := store.SyncState(ctx, "peer-1", "election", "election-1")
	if err != nil {
		t.Fatalf("SyncState() error = %v", err)
	}
	if !bytes.Equal(got.Cursor, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("cursor = %x", got.Cursor)
	}
	got.Cursor[0] = 0xee

	again, err := store.SyncState(ctx, "peer-1", "election", "election-1")
	if err != nil {
		t.Fatalf("second SyncState() error = %v", err)
	}
	if !bytes.Equal(again.Cursor, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("cursor was mutated through returned slice: %x", again.Cursor)
	}

	if err := store.DeleteSyncState(ctx, "peer-1", "election", "election-1"); err != nil {
		t.Fatalf("DeleteSyncState() error = %v", err)
	}
	if _, err := store.SyncState(ctx, "peer-1", "election", "election-1"); err == nil {
		t.Fatal("SyncState() succeeded after delete, want error")
	}
}

func TestMessageCacheIncrementsSeenCountAndPreservesFirstSeenAt(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	if err := store.RecordMessageSeen(ctx, "object-1", 10); err != nil {
		t.Fatalf("RecordMessageSeen() error = %v", err)
	}
	if err := store.RecordMessageSeen(ctx, "object-1", 20); err != nil {
		t.Fatalf("second RecordMessageSeen() error = %v", err)
	}

	got, err := store.MessageCache(ctx, "object-1")
	if err != nil {
		t.Fatalf("MessageCache() error = %v", err)
	}
	if got.FirstSeenAt != 10 || got.LastSeenAt != 20 || got.SeenCount != 2 {
		t.Fatalf("message cache = %+v", got)
	}
}

func TestObjectSourceRequiresExistingObjectAndDoesNotMutateObject(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	if err := store.RecordObjectSource(ctx, "missing-object", "peer-1", 10); err == nil {
		t.Fatal("RecordObjectSource() succeeded for missing object, want FK error")
	}

	input := defaultIngestInput("object-source-1", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}
	beforeMeta, err := store.ObjectMetadata(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() before error = %v", err)
	}
	beforeValidation, err := store.ValidationRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() before error = %v", err)
	}
	beforePayload, err := store.Payload(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Payload() before error = %v", err)
	}

	if err := store.RecordObjectSource(ctx, input.ObjectID, "peer-1", 100); err != nil {
		t.Fatalf("RecordObjectSource() error = %v", err)
	}
	if err := store.RecordObjectSource(ctx, input.ObjectID, "peer-1", 200); err != nil {
		t.Fatalf("second RecordObjectSource() error = %v", err)
	}

	sources, err := store.ObjectSources(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectSources() error = %v", err)
	}
	if len(sources) != 1 || sources[0].FirstSeenAt != 100 || sources[0].LastSeenAt != 200 {
		t.Fatalf("sources = %+v", sources)
	}
	afterMeta, err := store.ObjectMetadata(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ObjectMetadata() after error = %v", err)
	}
	afterValidation, err := store.ValidationRecord(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("ValidationRecord() after error = %v", err)
	}
	afterPayload, err := store.Payload(ctx, input.ObjectID)
	if err != nil {
		t.Fatalf("Payload() after error = %v", err)
	}
	if beforeMeta.LastSeenAt != afterMeta.LastSeenAt || beforeMeta.PayloadRetained != afterMeta.PayloadRetained || !bytes.Equal(beforeMeta.PayloadHash, afterMeta.PayloadHash) {
		t.Fatalf("object metadata mutated: before=%+v after=%+v", beforeMeta, afterMeta)
	}
	if beforeValidation != afterValidation {
		t.Fatalf("validation mutated: before=%+v after=%+v", beforeValidation, afterValidation)
	}
	if !bytes.Equal(beforePayload, afterPayload) {
		t.Fatalf("payload mutated")
	}
}

func TestDerivedStatePutGetClearAndDefensiveCopies(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{DataDir: t.TempDir(), NetworkID: "testnet"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	electionHash := []byte{0x01, 0x02}
	if err := store.PutElectionState(ctx, ElectionState{
		ElectionID: "election-1", Phase: "active", ValidObjectCount: 3,
		InvalidObjectCount: 1, PendingObjectCount: 2,
		ComputedStateHash: electionHash, UpdatedAt: 10,
	}); err != nil {
		t.Fatalf("PutElectionState() error = %v", err)
	}
	electionHash[0] = 0xff

	selectionHash := []byte{0x03}
	initialHash := []byte{0x04}
	if err := store.PutTrusteeSelectionState(ctx, TrusteeSelectionState{
		TrusteeSelectionID: "selection-1", CandidateRankingHash: selectionHash,
		InitialSelectedTrusteesHash: initialHash, ValidVoteCount: 4,
		ConflictedVoteCount: 5, UpdatedAt: 20,
	}); err != nil {
		t.Fatalf("PutTrusteeSelectionState() error = %v", err)
	}
	selectionHash[0] = 0xff
	initialHash[0] = 0xff

	tallyHash := []byte{0x05}
	resultHash := []byte{0x06}
	if err := store.PutTallyState(ctx, TallyState{
		ElectionID: "election-1", EncryptedTallyHash: tallyHash,
		ValidBallotCount: 6, ConflictedBallotCount: 7,
		InvalidBallotCountDiagnostic: 8, ResultStatus: "ready",
		ResultHash: resultHash, UpdatedAt: 30,
	}); err != nil {
		t.Fatalf("PutTallyState() error = %v", err)
	}
	tallyHash[0] = 0xff
	resultHash[0] = 0xff

	election, err := store.ElectionState(ctx, "election-1")
	if err != nil {
		t.Fatalf("ElectionState() error = %v", err)
	}
	if !bytes.Equal(election.ComputedStateHash, []byte{0x01, 0x02}) {
		t.Fatalf("election hash = %x", election.ComputedStateHash)
	}
	election.ComputedStateHash[0] = 0xee
	electionAgain, err := store.ElectionState(ctx, "election-1")
	if err != nil {
		t.Fatalf("second ElectionState() error = %v", err)
	}
	if !bytes.Equal(electionAgain.ComputedStateHash, []byte{0x01, 0x02}) {
		t.Fatalf("election hash mutated through returned slice: %x", electionAgain.ComputedStateHash)
	}

	selection, err := store.TrusteeSelectionState(ctx, "selection-1")
	if err != nil {
		t.Fatalf("TrusteeSelectionState() error = %v", err)
	}
	if !bytes.Equal(selection.CandidateRankingHash, []byte{0x03}) || !bytes.Equal(selection.InitialSelectedTrusteesHash, []byte{0x04}) {
		t.Fatalf("selection hashes = %x %x", selection.CandidateRankingHash, selection.InitialSelectedTrusteesHash)
	}

	tally, err := store.TallyState(ctx, "election-1")
	if err != nil {
		t.Fatalf("TallyState() error = %v", err)
	}
	if !bytes.Equal(tally.EncryptedTallyHash, []byte{0x05}) || !bytes.Equal(tally.ResultHash, []byte{0x06}) {
		t.Fatalf("tally hashes = %x %x", tally.EncryptedTallyHash, tally.ResultHash)
	}

	if err := store.ClearElectionState(ctx, "election-1"); err != nil {
		t.Fatalf("ClearElectionState() error = %v", err)
	}
	if _, err := store.ElectionState(ctx, "election-1"); err == nil {
		t.Fatal("ElectionState() succeeded after row clear, want error")
	}
	if err := store.PutElectionState(ctx, electionAgain); err != nil {
		t.Fatalf("PutElectionState() restore error = %v", err)
	}
	if err := store.ClearTrusteeSelectionState(ctx, "selection-1"); err != nil {
		t.Fatalf("ClearTrusteeSelectionState() error = %v", err)
	}
	if _, err := store.TrusteeSelectionState(ctx, "selection-1"); err == nil {
		t.Fatal("TrusteeSelectionState() succeeded after row clear, want error")
	}
	if err := store.PutTrusteeSelectionState(ctx, selection); err != nil {
		t.Fatalf("PutTrusteeSelectionState() restore error = %v", err)
	}
	if err := store.ClearTallyState(ctx, "election-1"); err != nil {
		t.Fatalf("ClearTallyState() error = %v", err)
	}
	if _, err := store.TallyState(ctx, "election-1"); err == nil {
		t.Fatal("TallyState() succeeded after row clear, want error")
	}
	if err := store.PutTallyState(ctx, tally); err != nil {
		t.Fatalf("PutTallyState() restore error = %v", err)
	}

	input := defaultIngestInput("derived-clear-object", domain.ValidationStatusValid)
	if _, err := store.IngestObject(ctx, input); err != nil {
		t.Fatalf("IngestObject() error = %v", err)
	}
	if err := store.UpsertPeer(ctx, PeerRecord{PeerID: "peer-1", Score: 1, AdmissionStatus: "admitted", FirstSeenAt: 1, LastSeenAt: 2}); err != nil {
		t.Fatalf("UpsertPeer() error = %v", err)
	}
	if err := store.PutSyncState(ctx, SyncState{PeerID: "peer-1", Scope: "network", ScopeID: "", Cursor: []byte{0x09}, LastSyncAt: 3}); err != nil {
		t.Fatalf("PutSyncState() error = %v", err)
	}
	if err := store.RecordMessageSeen(ctx, "derived-clear-object", 4); err != nil {
		t.Fatalf("RecordMessageSeen() error = %v", err)
	}

	if err := store.ClearDerivedState(ctx); err != nil {
		t.Fatalf("ClearDerivedState() error = %v", err)
	}
	if _, err := store.ElectionState(ctx, "election-1"); err == nil {
		t.Fatal("ElectionState() succeeded after ClearDerivedState, want error")
	}
	if _, err := store.TrusteeSelectionState(ctx, "selection-1"); err == nil {
		t.Fatal("TrusteeSelectionState() succeeded after ClearDerivedState, want error")
	}
	if _, err := store.TallyState(ctx, "election-1"); err == nil {
		t.Fatal("TallyState() succeeded after ClearDerivedState, want error")
	}
	if _, err := store.ObjectMetadata(ctx, input.ObjectID); err != nil {
		t.Fatalf("ObjectMetadata() after ClearDerivedState error = %v", err)
	}
	if _, err := store.Peer(ctx, "peer-1"); err != nil {
		t.Fatalf("Peer() after ClearDerivedState error = %v", err)
	}
	if _, err := store.SyncState(ctx, "peer-1", "network", ""); err != nil {
		t.Fatalf("SyncState() after ClearDerivedState error = %v", err)
	}
	if _, err := store.MessageCache(ctx, "derived-clear-object"); err != nil {
		t.Fatalf("MessageCache() after ClearDerivedState error = %v", err)
	}
}
