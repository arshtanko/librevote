package crypto

import (
	"errors"
	"testing"
)

func TestObjectIDUsesDocumentedConcatenation(t *testing.T) {
	canonicalObjectBytes := []byte("canonical-object-bytes")
	want := "1e7b6c21fe5f38b54e29b2fdb6f8eb8e98469123e6237c2de6ab7d10a467f99b"

	got, err := ObjectID(canonicalObjectBytes)
	if err != nil {
		t.Fatalf("ObjectID() error = %v", err)
	}

	if got.String() != want {
		t.Fatalf("ObjectID() = %s; want %s", got, want)
	}
}

func TestObjectIDDeterministic(t *testing.T) {
	canonicalObjectBytes := []byte("canonical-object-bytes")

	got, err := ObjectID(canonicalObjectBytes)
	if err != nil {
		t.Fatalf("ObjectID() error = %v", err)
	}
	want, err := ObjectID(canonicalObjectBytes)
	if err != nil {
		t.Fatalf("ObjectID() error = %v", err)
	}

	if got != want {
		t.Fatalf("ObjectID() = %s; want %s", got, want)
	}
}

func TestObjectIDDifferentCanonicalBytesDiffer(t *testing.T) {
	one, err := ObjectID([]byte("canonical-object-bytes-1"))
	if err != nil {
		t.Fatalf("ObjectID() error = %v", err)
	}
	two, err := ObjectID([]byte("canonical-object-bytes-2"))
	if err != nil {
		t.Fatalf("ObjectID() error = %v", err)
	}

	if one == two {
		t.Fatalf("ObjectID() returned same digest for different canonical bytes: %s", one)
	}
}

func TestObjectIDRejectsEmptyCanonicalBytes(t *testing.T) {
	_, err := ObjectID(nil)
	if !errors.Is(err, ErrEmptyCanonicalObject) {
		t.Fatalf("ObjectID() error = %v; want %v", err, ErrEmptyCanonicalObject)
	}
}

func TestObjectIDUnaffectedByCallerMutation(t *testing.T) {
	canonicalObjectBytes := []byte("canonical-object-bytes")
	got, err := ObjectID(canonicalObjectBytes)
	if err != nil {
		t.Fatalf("ObjectID() error = %v", err)
	}

	canonicalObjectBytes[0] ^= 0xff
	want, err := ObjectID([]byte("canonical-object-bytes"))
	if err != nil {
		t.Fatalf("ObjectID() error = %v", err)
	}

	if got != want {
		t.Fatalf("ObjectID() changed after caller mutation: got %s, want %s", got, want)
	}
}
