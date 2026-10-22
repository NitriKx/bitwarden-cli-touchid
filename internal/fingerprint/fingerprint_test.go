package fingerprint

import "testing"

// TestPhrasePinnedVector pins the exact output of the original tool's test
// (src/fingerprint.test.ts) to detect algorithm regressions.
func TestPhrasePinnedVector(t *testing.T) {
	got := Formatted("test-app-id", []byte("test-public-key"))
	want := "carve-bulldozer-retake-bath-crust"
	if got != want {
		t.Fatalf("getFingerprint(\"test-app-id\", \"test-public-key\") = %q, want %q", got, want)
	}
}

func TestPhraseDifferentMaterial(t *testing.T) {
	pub := []byte("test-public-key")
	a := Formatted("app-a", pub)
	b := Formatted("app-b", pub)
	if a == b {
		t.Fatalf("expected different phrases for different material: %q", a)
	}
}

func TestWordListSize(t *testing.T) {
	if len(wordList) != 7776 {
		t.Fatalf("word list size = %d, want 7776", len(wordList))
	}
}
