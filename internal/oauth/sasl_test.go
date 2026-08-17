package oauth

import "testing"

func TestBuildSASLStringOAuthBearer(t *testing.T) {
	got, err := BuildSASLString("OAUTHBEARER", "me@example.com", "imap.gmail.com", 993, "tok123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "n,a=me@example.com,\x01host=imap.gmail.com\x01port=993\x01auth=Bearer tok123\x01\x01"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildSASLStringXOAuth2(t *testing.T) {
	got, err := BuildSASLString("XOAUTH2", "me@example.com", "outlook.office365.com", 993, "tok123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "user=me@example.com\x01auth=Bearer tok123\x01\x01"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildSASLStringUnknownMethod(t *testing.T) {
	if _, err := BuildSASLString("BOGUS", "u", "h", 1, "t"); err == nil {
		t.Fatal("expected error for unknown SASL method")
	}
}
