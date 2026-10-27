package x_forwarded_for_hop_counter

import (
	"reflect"
	"testing"
)

func TestParse_EmptyHeader(t *testing.T) {
	res := Parse("", 1)
	if res.ClientIP != "" {
		t.Fatalf("expected empty ClientIP, got %q", res.ClientIP)
	}
	if len(res.IPChain) != 0 {
		t.Fatalf("expected empty IPChain, got %v", res.IPChain)
	}
	if res.StrippedHops != 0 {
		t.Fatalf("expected 0 StrippedHops, got %d", res.StrippedHops)
	}
}

func TestParse_WhitespaceOnlyHeader(t *testing.T) {
	res := Parse("   \t  ", 2)
	if res.ClientIP != "" {
		t.Fatalf("expected empty ClientIP for whitespace-only header, got %q", res.ClientIP)
	}
	if len(res.IPChain) != 0 {
		t.Fatalf("expected empty IPChain, got %v", res.IPChain)
	}
}

func TestParse_SingleIPZeroTrustedHops(t *testing.T) {
	res := Parse("203.0.113.7", 0)
	if res.ClientIP != "203.0.113.7" {
		t.Fatalf("ClientIP = %q, want 203.0.113.7", res.ClientIP)
	}
	if res.StrippedHops != 0 {
		t.Fatalf("StrippedHops = %d, want 0", res.StrippedHops)
	}
	want := []string{"203.0.113.7"}
	if !reflect.DeepEqual(res.IPChain, want) {
		t.Fatalf("IPChain = %v, want %v", res.IPChain, want)
	}
}

func TestParse_TypicalChain(t *testing.T) {
	// client -> untrusted-proxy -> trusted-proxy-1 -> trusted-proxy-2 -> service
	header := "203.0.113.7, 198.51.100.4, 10.0.0.1, 10.0.0.2"
	res := Parse(header, 2)
	if res.ClientIP != "198.51.100.4" {
		t.Fatalf("ClientIP = %q, want 198.51.100.4", res.ClientIP)
	}
	if res.StrippedHops != 2 {
		t.Fatalf("StrippedHops = %d, want 2", res.StrippedHops)
	}
	want := []string{"203.0.113.7", "198.51.100.4", "10.0.0.1", "10.0.0.2"}
	if !reflect.DeepEqual(res.IPChain, want) {
		t.Fatalf("IPChain = %v, want %v", res.IPChain, want)
	}
}

func TestParse_TrustExceedsChainLength(t *testing.T) {
	header := "203.0.113.7, 198.51.100.4"
	res := Parse(header, 5)
	if res.ClientIP != "203.0.113.7" {
		t.Fatalf("ClientIP = %q, want 203.0.113.7 (leftmost returned when trust exceeds chain)", res.ClientIP)
	}
	if res.StrippedHops != 1 {
		t.Fatalf("StrippedHops = %d, want 1", res.StrippedHops)
	}
}

func TestParse_NegativeTrustedHops(t *testing.T) {
	res := Parse("203.0.113.7, 198.51.100.4", -3)
	if res.ClientIP != "198.51.100.4" {
		t.Fatalf("ClientIP = %q, want 198.51.100.4", res.ClientIP)
	}
	if res.StrippedHops != 0 {
		t.Fatalf("StrippedHops = %d, want 0", res.StrippedHops)
	}
}

func TestParse_LeadingAndTrailingWhitespace(t *testing.T) {
	header := "  203.0.113.7  ,  198.51.100.4  "
	res := Parse(header, 1)
	if res.ClientIP != "203.0.113.7" {
		t.Fatalf("ClientIP = %q, want 203.0.113.7", res.ClientIP)
	}
	want := []string{"203.0.113.7", "198.51.100.4"}
	if !reflect.DeepEqual(res.IPChain, want) {
		t.Fatalf("IPChain = %v, want %v", res.IPChain, want)
	}
}

func TestParse_IPv6WithBrackets(t *testing.T) {
	header := "[2001:db8::1], [2001:db8::2], [2001:db8::3]"
	res := Parse(header, 1)
	if res.ClientIP != "2001:db8::2" {
		t.Fatalf("ClientIP = %q, want 2001:db8::2", res.ClientIP)
	}
	want := []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"}
	if !reflect.DeepEqual(res.IPChain, want) {
		t.Fatalf("IPChain = %v, want %v", res.IPChain, want)
	}
}

func TestParse_IPv6WithoutBrackets(t *testing.T) {
	header := "2001:db8::1, 2001:db8::2, 2001:db8::3"
	res := Parse(header, 2)
	if res.ClientIP != "2001:db8::1" {
		t.Fatalf("ClientIP = %q, want 2001:db8::1", res.ClientIP)
	}
	if res.StrippedHops != 2 {
		t.Fatalf("StrippedHops = %d, want 2", res.StrippedHops)
	}
}

func TestParse_EmptyFieldsDropped(t *testing.T) {
	// Stray empty fields must not shift the apparent positions of real entries.
	header := "203.0.113.7, , 198.51.100.4, , 10.0.0.1"
	res := Parse(header, 1)
	if res.ClientIP != "198.51.100.4" {
		t.Fatalf("ClientIP = %q, want 198.51.100.4", res.ClientIP)
	}
	want := []string{"203.0.113.7", "198.51.100.4", "10.0.0.1"}
	if !reflect.DeepEqual(res.IPChain, want) {
		t.Fatalf("IPChain = %v, want %v", res.IPChain, want)
	}
}

func TestParse_AllEntriesEmpty(t *testing.T) {
	res := Parse(", , ,", 2)
	if res.ClientIP != "" {
		t.Fatalf("ClientIP = %q, want empty", res.ClientIP)
	}
	if len(res.IPChain) != 0 {
		t.Fatalf("IPChain = %v, want empty", res.IPChain)
	}
}

func TestParse_SingleIPWithTrustedHops(t *testing.T) {
	// One entry, but caller claims two trusted hops. We must not strip the only
	// address, so the leftmost is returned and StrippedHops reports 0.
	res := Parse("203.0.113.7", 2)
	if res.ClientIP != "203.0.113.7" {
		t.Fatalf("ClientIP = %q, want 203.0.113.7", res.ClientIP)
	}
	if res.StrippedHops != 0 {
		t.Fatalf("StrippedHops = %d, want 0", res.StrippedHops)
	}
}

func TestParse_IPChainPreservesOrder(t *testing.T) {
	header := "203.0.113.7, 198.51.100.4, 10.0.0.1"
	res := Parse(header, 0)
	want := []string{"203.0.113.7", "198.51.100.4", "10.0.0.1"}
	if !reflect.DeepEqual(res.IPChain, want) {
		t.Fatalf("IPChain = %v, want %v", res.IPChain, want)
	}
	if res.ClientIP != "10.0.0.1" {
		t.Fatalf("with 0 trusted hops, ClientIP should be rightmost = %q, want 10.0.0.1", res.ClientIP)
	}
}
