---
title: ResilientMesh
emoji: 🛡️
colorFrom: indigo
colorTo: gray
sdk: static
app_file: index.html
pinned: false
license: apache-2.0
short_description: Deterministic control plane for AI-driven payment recovery
tags:
  - fintech
  - payments
  - razorpay
  - agents
  - ai-safety
  - go
---

# ResilientMesh: the evidence page

A record of one real execution of [ResilientMesh](https://github.com/vighriday/ResilientMesh-Razorpaybuildathon),
submitted to the Razorpay AI Buildathon, Track 03 (AI Revenue Recovery).

**This Space is deliberately static.** Every number on the page was read out of a
running system's PostgreSQL database during the run described, then exported.
Nothing is computed on a server here, which is why there is nothing here to be
down, to sleep, or to be attacked.

One thing *is* computed live, in your browser: the audit ledger's hash chain.
The page ships the exact bytes the ledger hashed and re-derives all of them with
`crypto.subtle`, so you can confirm the chain yourself, and plant a forgery in
it, without trusting anything this page claims.

To run the real system instead:

```bash
git clone https://github.com/vighriday/ResilientMesh-Razorpaybuildathon
cd ResilientMesh-Razorpaybuildathon
go run ./cmd/meshdemo
```

No Docker, no cloud account, no payment credentials, no API key required.
