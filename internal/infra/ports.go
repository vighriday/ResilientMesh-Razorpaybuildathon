package infra

import (
	"fmt"
	"net"
	"strconv"
	"sync"
)

// freePortAttempts bounds the probe loop. Sixteen is far more than a healthy
// host ever needs; the loop exists only so a transient collision on the IPv6
// loopback cannot turn into an infinite spin.
const freePortAttempts = 16

// loopbackHost is the only address this package ever binds. Managed mode exists
// for laptops and CI runners, where a database reachable from the network would
// be a liability rather than a feature; keeping every listener on the loopback
// also avoids tripping the Windows firewall prompt that a wildcard bind raises.
const loopbackHost = "127.0.0.1"

// FreePort asks the kernel for an unused loopback TCP port and releases it
// again before returning.
//
// The port is a hint, not a reservation: between the probe closing and the real
// server binding, any other process may take it. That race is unavoidable with
// child processes that accept a port number rather than an inherited socket,
// which is exactly why StartManaged retries on a bind failure instead of
// trusting a single pick.
func FreePort() (int, error) {
	var lastErr error

	for i := 0; i < freePortAttempts; i++ {
		l, err := net.Listen("tcp", net.JoinHostPort(loopbackHost, "0"))
		if err != nil {
			lastErr = err
			continue
		}

		addr, ok := l.Addr().(*net.TCPAddr)
		if !ok {
			if closeErr := l.Close(); closeErr != nil {
				return 0, fmt.Errorf("infra: releasing port probe listener: %w", closeErr)
			}
			lastErr = fmt.Errorf("listener returned %T, want *net.TCPAddr", l.Addr())
			continue
		}

		port := addr.Port
		if err := l.Close(); err != nil {
			return 0, fmt.Errorf("infra: releasing port probe listener on %d: %w", port, err)
		}

		// PostgreSQL's default listen_addresses is "localhost", which on a
		// dual-stack host means it binds ::1 as well as 127.0.0.1. A port free
		// on v4 but held on v6 would fail deep inside pg_ctl with an error that
		// says nothing about ports, so it is rejected here where the cause is
		// still obvious.
		if ipv6LoopbackUsable() && !portBindable("tcp6", "::1", port) {
			lastErr = fmt.Errorf("port %d is free on %s but held on ::1", port, loopbackHost)
			continue
		}

		return port, nil
	}

	return 0, fmt.Errorf("infra: no free loopback TCP port after %d attempts: %w", freePortAttempts, lastErr)
}

// portBindable reports whether a listener can be opened on the given address.
// Binding rather than dialling is deliberate: a bind answers immediately and
// cannot be fooled by a firewall silently dropping connect attempts, whereas a
// dial has to wait out a timeout to conclude "nothing there".
func portBindable(network, host string, port int) bool {
	l, err := net.Listen(network, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	return l.Close() == nil
}

var ipv6Loopback struct {
	sync.Once
	usable bool
}

// ipv6LoopbackUsable caches whether this host has a working IPv6 loopback.
// Without the probe, the ::1 collision check above could not distinguish "port
// taken" from "no IPv6 stack" and would reject every candidate port on a v4-only
// machine.
func ipv6LoopbackUsable() bool {
	ipv6Loopback.Do(func() {
		ipv6Loopback.usable = portBindable("tcp6", "::1", 0)
	})
	return ipv6Loopback.usable
}
