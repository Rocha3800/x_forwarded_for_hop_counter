package x_forwarded_for_hop_counter

import (
	"strings"
)

// ParseResult holds the outcome of parsing an X-Forwarded-For header against
// a known trusted-proxy hop count.
type ParseResult struct {
	// ClientIP is the originating client IP once trusted proxy hops are peeled
	// off the right-hand end of the header. It is never surrounded by brackets.
	ClientIP string

	// IPChain is the full, left-to-right list of IPs present in the header,
	// with whitespace and surrounding brackets removed but otherwise unmodified.
	// Use this for logging or for auditing how many hops were recorded.
	IPChain []string

	// StrippedHops is the number of trusted-proxy hops that were removed from
	// the right-hand end of the chain to arrive at ClientIP. It is the smaller of
	// TrustedHops and len(IPChain)-1, so a header that did not contain enough hops
	// for the trust configuration is reported honestly rather than silently
	// returning a proxy address as the client.
	StrippedHops int
}

// Parse takes a raw X-Forwarded-For header value and a TrustedHops count and
// returns the originating client IP.
//
// The header is treated as a comma-separated list read left to right, where the
// leftmost entry is the original client and each subsequent entry is a proxy that
// appended the previous hop. TrustedHops is the number of proxy hops on the
// right-hand end that are operated by the service owner and therefore trusted to
// have set the header correctly. Those hops are stripped off; what remains on the
// left is the first untrusted address, which we treat as the client.
//
// If the header carries fewer entries than TrustedHops+1, the leftmost address is
// returned as the client and StrippedHops records how many were actually removed.
// This avoids a misconfigured trust depth silently promoting a trusted proxy to
// the role of "client".
func Parse(header string, trustedHops int) ParseResult {
	chain := splitHeader(header)

	res := ParseResult{IPChain: chain}

	if len(chain) == 0 {
		return res
	}

	if trustedHops < 0 {
		trustedHops = 0
	}

	// We need at least one address left after stripping, so never strip more than
	// len(chain)-1 entries regardless of what the caller asked for.
	maxStrippable := len(chain) - 1
	strip := trustedHops
	if strip > maxStrippable {
		strip = maxStrippable
	}

	res.StrippedHops = strip
	res.ClientIP = chain[len(chain)-1-strip]
	return res
}

// splitHeader breaks an X-Forwarded-For value into individual IP strings.
//
// Each entry is trimmed of surrounding whitespace and of IPv6 brackets, because
// real-world headers vary wildly: "::1", "[::1]", and " ::1 " all appear in the
// wild. Empty fields produced by stray commas (e.g. "1.2.3.4,,5.6.7.8") are
// dropped rather than preserved, because an empty field carries no address
// information and keeping it would shift the apparent hop positions of every
// subsequent entry.
func splitHeader(header string) []string {
	if header == "" {
		return nil
	}

	parts := strings.Split(header, ",")
	out := make([]string, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.TrimPrefix(p, "[")
		p = strings.TrimSuffix(p, "]")
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}

	return out
}
