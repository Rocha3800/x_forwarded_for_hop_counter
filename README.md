# x_forwarded_for_hop_counter

Parses an `X-Forwarded-For` header, trims it to a trusted proxy hop count, and returns the originating client IP.

```go
package main

import (
	"fmt"

	xforwardedforhopcounter "example.com/x_forwarded_for_hop_counter"
)

func main() {
	res := xforwardedforhopcounter.Parse("203.0.113.7, 198.51.100.4, 10.0.0.1, 10.0.0.2", 2)
	fmt.Println(res.ClientIP)     // 198.51.100.4
	fmt.Println(res.StrippedHops) // 2
	fmt.Println(res.IPChain)      // [203.0.113.7 198.51.100.4 10.0.0.1 10.0.0.2]
}
```

## Why this exists

When a request crosses proxies, each one appends the previous hop's address to `X-Forwarded-For`. To find the real client you need to know how many of those proxies are yours and peel them off the right-hand end. Getting that count wrong is the classic way to either trust a spoofed header or to log a trusted internal address as if it were the user.

The library makes one deliberate decision: if the header contains fewer addresses than your configured trust depth implies, it returns the leftmost address it has rather than silently treating one of your own proxies as the client. `StrippedHops` in the result tells you how many were actually removed, so a mismatch between configuration and reality is visible rather than hidden.

## Edge you will hit

Empty fields from stray commas (`"1.2.3.4,,5.6.7.8"`) are dropped, not preserved. This keeps the hop positions of the real addresses stable. If you need the raw field count for some reason, split the header yourself before calling `Parse`.
