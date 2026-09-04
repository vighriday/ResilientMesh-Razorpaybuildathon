package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/gatewire"
)

// Conformance vectors: inputs, and the answers this machine's Go build gave.
//
// The page runs a WebAssembly copy of the gatekeeper so a reader can attack it.
// That is only worth anything if the copy behaves like the real thing, and
// "trust me, it is the same code" is precisely the kind of claim this project
// refuses to make anywhere else. So the exporter runs a spread of inputs through
// internal/gatewire on the server and records what came back; the page runs the
// identical inputs through the module in the browser and compares. A mismatch is
// visible to the reader rather than to nobody.
//
// The cases are chosen to be hostile. A conformance suite of well-formed
// proposals would agree on both sides and prove very little; the interesting
// question is whether two builds of the same rules reject the same malformed
// ones for the same stated reason.
type gateVector struct {
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	Hostile  bool            `json:"hostile"`
	Story    string          `json:"story"`
	Request  json.RawMessage `json:"request"`
	Expected json.RawMessage `json:"expected"`
}

// vectorClock is a fixed instant so a vector means the same thing tomorrow.
// The mandate timestamps below are expressed relative to it.
const vectorNow = "2026-03-01T09:00:00Z"

func vectorTime(offset time.Duration) string {
	t, _ := time.Parse(time.RFC3339, vectorNow)
	return t.Add(offset).UTC().Format(time.RFC3339)
}

// buildVectors runs every case through the real gatekeeper and records the
// answer. It returns them in a stable order so the exported document does not
// churn between runs.
func buildVectors() ([]gateVector, error) {
	cases := []struct {
		id, title, story string
		hostile          bool
		req              map[string]any
	}{
		{
			id:      "amount",
			title:   "The model tries to change the amount",
			hostile: true,
			story: "A payment of Rs 4,999.00 failed. The proposal asks to retry, and " +
				"smuggles an amount field of Rs 49,999.00 into its JSON. The proposal " +
				"type has no amount field to decode it into, and the command's amount is " +
				"copied from the signed payload, so watch what the gate emits.",
			req: baseRequest(map[string]any{
				"proposal": map[string]any{
					"failure_class":      "ISSUER_OUTAGE",
					"recommended_action": "ASYNC_EXPONENTIAL_RETRY",
					"confidence_score":   0.91,
					"root_cause":         "issuer is degraded",
					"amount_paisa":       4999900,
				},
			}),
		},
		{
			id:      "unicode",
			title:   "The model smuggles an action past the parser",
			hostile: true,
			story: "A prompt-injected reply returns AſYNC_EXPONENTIAL_RETRY, where the " +
				"second character is U+017F, the long s. Go's strings.ToUpper applies " +
				"Unicode case mapping and folds it to a plain ASCII S, which once made " +
				"this a valid action. That was defect 3. The parsers now fold ASCII only.",
			req: baseRequest(map[string]any{
				"proposal": map[string]any{
					"failure_class":      "ISSUER_OUTAGE",
					"recommended_action": "AſYNC_EXPONENTIAL_RETRY",
					"confidence_score":   0.95,
					"root_cause":         "issuer is degraded",
				},
			}),
		},
		{
			id:      "nan",
			title:   "The model claims impossible confidence",
			hostile: true,
			story: "Confidence arrives as 1e9, far above the closed interval the contract " +
				"defines. The related defect was NaN: every ordered comparison against NaN " +
				"is false, so a naive floor check read it as maximum confidence and waved " +
				"it through. The check is now written as a positive assertion.",
			req: baseRequest(map[string]any{
				"proposal": map[string]any{
					"failure_class":      "ISSUER_OUTAGE",
					"recommended_action": "ASYNC_EXPONENTIAL_RETRY",
					"confidence_score":   1e9,
					"root_cause":         "trust me",
				},
			}),
		},
		{
			id:      "lowconf",
			title:   "The model is honestly unsure",
			hostile: false,
			story: "Confidence of 0.20, below the floor to act on. Not an attack: this is " +
				"the ordinary case where spending a gateway fee is not justified by the " +
				"evidence, and the ledger records the abstention with the rule that caused it.",
			req: baseRequest(map[string]any{
				"proposal": map[string]any{
					"failure_class":      "ISSUER_OUTAGE",
					"recommended_action": "ASYNC_EXPONENTIAL_RETRY",
					"confidence_score":   0.20,
					"root_cause":         "possibly the issuer",
				},
			}),
		},
		{
			id:      "terminal",
			title:   "The model retries a decline no retry can fix",
			hostile: true,
			story: "The issuer said the card is stolen. The model proposes a retry anyway, " +
				"with high confidence. Every retry here spends a gateway fee on an outcome " +
				"that cannot change.",
			req: baseRequest(map[string]any{
				"payment": map[string]any{
					"id": "pay_terminal", "amount_paisa": 499900, "method": "card",
					"bank": "HDFC", "error_code": "card_lost_or_stolen",
				},
				"proposal": map[string]any{
					"failure_class":      "ISSUER_OUTAGE",
					"recommended_action": "ASYNC_EXPONENTIAL_RETRY",
					"confidence_score":   0.99,
					"root_cause":         "worth another try",
				},
			}),
		},
		{
			id:      "rbi",
			title:   "The model debits a mandate inside the cooling window",
			hostile: true,
			story: "A recurring mandate was debited two hours ago. RBI requires 24 hours " +
				"between attempts. The model proposes retrying now, and the gate answers " +
				"with arithmetic rather than judgment.",
			req: baseRequest(map[string]any{
				"payment": map[string]any{
					"id": "pay_mandate", "amount_paisa": 129900, "method": "card",
					"bank": "ICIC", "subscription_id": "sub_demo", "error_code": "payment_failed",
				},
				"proposal": map[string]any{
					"failure_class":      "MANDATE_LIMIT",
					"recommended_action": "MANDATE_COMPLIANT_CASCADE",
					"confidence_score":   0.93,
					"root_cause":         "retry the debit",
				},
				"mandate": map[string]any{
					"subscription_id":   "sub_demo",
					"amount_paisa":      129900,
					"last_attempt_at":   vectorTime(-2 * time.Hour),
					"attempts_in_cycle": 1,
					"cycle_key":         "2026-03",
					"category":          "GENERAL",
				},
			}),
		},
		{
			id:      "afa",
			title:   "The model debits above the additional-factor ceiling",
			hostile: true,
			story: "A general-category mandate for Rs 40,000.00. RBI allows a registered " +
				"mandate to debit without a fresh authentication factor only up to " +
				"Rs 15,000.00. Above it a retry is not a suboptimal choice, it is a breach.",
			req: baseRequest(map[string]any{
				"payment": map[string]any{
					"id": "pay_afa", "amount_paisa": 4000000, "method": "card",
					"bank": "ICIC", "subscription_id": "sub_big", "error_code": "payment_failed",
				},
				"proposal": map[string]any{
					"failure_class":      "MANDATE_LIMIT",
					"recommended_action": "MANDATE_COMPLIANT_CASCADE",
					"confidence_score":   0.96,
					"root_cause":         "large recurring debit",
				},
				"mandate": map[string]any{
					"subscription_id":       "sub_big",
					"amount_paisa":          4000000,
					"last_attempt_at":       vectorTime(-72 * time.Hour),
					"pre_debit_notified_at": vectorTime(-30 * time.Hour),
					"attempts_in_cycle":     0,
					"cycle_key":             "2026-03",
					"category":              "GENERAL",
				},
			}),
		},
		{
			id:      "halted",
			title:   "The model debits a mandate an operator halted",
			hostile: true,
			story: "An operator halted this mandate through meshctl, which wrote its intent " +
				"to the ledger before acting. The model has no way to know that and proposes " +
				"a debit; the gate reads the record.",
			req: baseRequest(map[string]any{
				"payment": map[string]any{
					"id": "pay_halted", "amount_paisa": 99900, "method": "card",
					"bank": "SBIN", "subscription_id": "sub_halted", "error_code": "payment_failed",
				},
				"proposal": map[string]any{
					"failure_class":      "MANDATE_LIMIT",
					"recommended_action": "MANDATE_COMPLIANT_CASCADE",
					"confidence_score":   0.88,
					"root_cause":         "retry",
				},
				"mandate": map[string]any{
					"subscription_id":       "sub_halted",
					"amount_paisa":          99900,
					"last_attempt_at":       vectorTime(-72 * time.Hour),
					"pre_debit_notified_at": vectorTime(-30 * time.Hour),
					"cycle_key":             "2026-03",
					"category":              "GENERAL",
					"halted":                true,
					"halt_reason":           "customer disputed the mandate",
				},
			}),
		},
		{
			id:      "morph",
			title:   "The model morphs a rail with no live session",
			hostile: true,
			story: "In-session rail morphing moves a customer who is still on the checkout " +
				"page onto a healthy rail. There is no session here, so there is nothing to " +
				"move, and the proposal is downgraded rather than executed.",
			req: baseRequest(map[string]any{
				"session_active": false,
				"proposal": map[string]any{
					"failure_class":      "ISSUER_OUTAGE",
					"recommended_action": "IN_SESSION_RAIL_MORPH",
					"target_rail":        "upi",
					"confidence_score":   0.94,
					"root_cause":         "netbanking is down, move them to UPI",
				},
			}),
		},
		{
			id:      "rail",
			title:   "The model picks a rail the merchant never enabled",
			hostile: true,
			story: "The proposal moves the payment to a wallet. This merchant has card, " +
				"netbanking and UPI configured, and the allowlist is the merchant's, not " +
				"the model's.",
			req: baseRequest(map[string]any{
				"session_active":  true,
				"available_rails": []string{"card", "netbanking", "upi"},
				"proposal": map[string]any{
					"failure_class":      "ISSUER_OUTAGE",
					"recommended_action": "IN_SESSION_RAIL_MORPH",
					"target_rail":        "wallet",
					"confidence_score":   0.9,
					"root_cause":         "try a wallet",
				},
			}),
		},
		{
			id:      "ok",
			title:   "A legitimate proposal, permitted",
			hostile: false,
			story: "For contrast. A well-formed diagnosis of a genuine issuer outage, with " +
				"evidence behind it. The gate permits it, and names every rule it applied " +
				"on the way, which is what makes the permission auditable rather than silent.",
			req: baseRequest(map[string]any{
				"proposal": map[string]any{
					"failure_class":      "ISSUER_OUTAGE",
					"recommended_action": "ASYNC_EXPONENTIAL_RETRY",
					"confidence_score":   0.88,
					"root_cause":         "issuer success rate collapsed and a downtime notice is open",
					"delay_seconds":      900,
				},
			}),
		},
	}

	out := make([]gateVector, 0, len(cases))
	for _, c := range cases {
		reqBytes, err := json.Marshal(c.req)
		if err != nil {
			return nil, fmt.Errorf("encoding vector %s: %w", c.id, err)
		}
		// The server's own answer, from the same function the browser will call.
		got := gatewire.DecideJSON(string(reqBytes))
		out = append(out, gateVector{
			ID: c.id, Title: c.title, Hostile: c.hostile, Story: c.story,
			Request: reqBytes, Expected: json.RawMessage(got),
		})
	}
	return out, nil
}

// baseRequest supplies a realistic incident so each case only has to state the
// part it is actually about.
func baseRequest(over map[string]any) map[string]any {
	req := map[string]any{
		"now":            vectorNow,
		"incident_id":    "inc_vector",
		"attempt_number": 1,
		"max_attempts":   3,
		"seed":           42,
		"session_active": false,
		"payment": map[string]any{
			"id": "pay_vector", "order_id": "order_vector",
			"amount_paisa": 499900, "currency": "INR",
			"method": "netbanking", "bank": "HDFC",
			"error_code": "payment_failed", "error_source": "bank", "error_step": "authorization",
		},
		"telemetry": map[string]any{
			"issuer_key": "netbanking:HDFC", "success_rate": 0.12,
			"baseline_rate": 0.94, "samples": 140, "breaker_state": "CLOSED",
			"sampled_at": vectorNow,
		},
		"available_rails": []string{"card", "netbanking", "upi"},
	}
	for k, v := range over {
		req[k] = v
	}
	return req
}
