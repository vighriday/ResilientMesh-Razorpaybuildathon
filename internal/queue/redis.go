// Package queue implements the asynchronous work channel between the outbox
// relay and the worker pool, on Redis Streams with consumer groups.
//
// Streams are chosen over a list because a consumer group gives at-least-once
// delivery with explicit acknowledgement and a pending-entries list, which is
// what allows a worker that dies mid-message to have its work reclaimed rather
// than silently lost. A list would lose the message the instant it was popped.
//
// The stream is not the durable record. The outbox table in PostgreSQL is.
// That distinction matters operationally: if Redis loses data, the relay
// re-publishes from the outbox, so this package is allowed to be lossy in a way
// the database is not.
package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// Stream and group names. Everything this system owns is prefixed so it can
// share a Redis instance with other tenants without collision.
const (
	StreamIncidents  = "mesh:stream:incidents"
	StreamDeadLetter = "mesh:stream:dead_letter"
	GroupWorkers     = "mesh-workers"
)

// Field names on a stream entry.
const (
	fieldIncidentID = "incident_id"
	fieldTopic      = "topic"
	fieldPayload    = "payload"
	fieldOutboxID   = "outbox_id"
	fieldAttempts   = "attempts"
	fieldCause      = "cause"
	fieldOrigID     = "original_id"
)

// ErrClosed is returned once Close has run.
var ErrClosed = errors.New("queue: closed")

// Config tunes stream retention and read behaviour.
type Config struct {
	// MaxLen bounds the stream so a stalled worker pool cannot exhaust Redis
	// memory. Trimming is approximate (XADD MAXLEN ~) because exact trimming
	// forces Redis to walk the radix tree on every write, and the exactness
	// buys nothing here: the outbox, not the stream, is the durable record.
	MaxLen int64
	// ReadBlock is how long Consume parks waiting for work. Long blocks are
	// cheap on the server and avoid a busy poll, but must stay well below any
	// shutdown deadline so a drain does not stall on an idle read.
	ReadBlock time.Duration
	// ClaimMinIdle is how long a message must sit unacknowledged before
	// another consumer may take it over. Too short and a slow-but-alive worker
	// has its work stolen and processed twice; too long and a crashed worker's
	// messages sit idle. It should exceed the p99 processing time comfortably.
	ClaimMinIdle time.Duration
}

// DefaultConfig returns settings sized for the demo and for CI.
func DefaultConfig() Config {
	return Config{
		MaxLen:       100_000,
		ReadBlock:    2 * time.Second,
		ClaimMinIdle: 30 * time.Second,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.MaxLen <= 0 {
		c.MaxLen = d.MaxLen
	}
	if c.ReadBlock <= 0 {
		c.ReadBlock = d.ReadBlock
	}
	if c.ClaimMinIdle <= 0 {
		c.ClaimMinIdle = d.ClaimMinIdle
	}
	return c
}

// Redis implements domain.Queue.
type Redis struct {
	rdb    *redis.Client
	cfg    Config
	log    *slog.Logger
	closed bool
}

// New returns a queue bound to rdb. It does not create the consumer group;
// call EnsureGroup first, so group creation is an explicit startup step that
// can fail loudly rather than a side effect of the first read.
func New(rdb *redis.Client, cfg Config, log *slog.Logger) *Redis {
	return &Redis{rdb: rdb, cfg: cfg.withDefaults(), log: log}
}

// EnsureGroup creates the consumer group if it does not exist, creating the
// stream alongside it.
//
// Starting the group at "0" rather than "$" is deliberate: "$" would skip every
// entry already in the stream, so a group created after a relay has begun
// publishing would silently drop that backlog. Starting at zero costs a little
// redelivery and loses nothing.
func (q *Redis) EnsureGroup(ctx context.Context, group string) error {
	if group == "" {
		group = GroupWorkers
	}
	err := q.rdb.XGroupCreateMkStream(ctx, StreamIncidents, group, "0").Err()
	if err == nil || isBusyGroup(err) {
		return nil
	}
	return fmt.Errorf("queue: creating consumer group %q: %w", group, err)
}

// isBusyGroup reports the benign "already exists" response. Redis signals it
// with an error string rather than a distinct type, so string matching is the
// only option the protocol offers.
func isBusyGroup(err error) bool {
	return err != nil && strings.Contains(err.Error(), "BUSYGROUP")
}

// Publish appends one outbox event to the stream.
func (q *Redis) Publish(ctx context.Context, topic string, ev domain.OutboxEvent) error {
	if q.closed {
		return ErrClosed
	}
	if len(ev.Payload) == 0 {
		return fmt.Errorf("queue: refusing to publish outbox event %d with an empty payload", ev.ID)
	}
	args := &redis.XAddArgs{
		Stream: StreamIncidents,
		MaxLen: q.cfg.MaxLen,
		Approx: true,
		Values: map[string]any{
			fieldIncidentID: ev.IncidentID,
			fieldTopic:      topic,
			fieldPayload:    string(ev.Payload),
			fieldOutboxID:   ev.ID,
		},
	}
	if err := q.rdb.XAdd(ctx, args).Err(); err != nil {
		return fmt.Errorf("queue: publishing incident %s: %w", ev.IncidentID, err)
	}
	return nil
}

// Consume reads undelivered messages for this consumer.
//
// The ">" identifier asks only for entries never delivered to this group.
// Messages this consumer already holds but has not acknowledged are recovered
// through Reclaim, which keeps the two concerns separate: normal flow here,
// failure recovery there.
func (q *Redis) Consume(ctx context.Context, group, consumer string, count int, block time.Duration) ([]domain.QueueMessage, error) {
	if q.closed {
		return nil, ErrClosed
	}
	if group == "" {
		group = GroupWorkers
	}
	if count <= 0 {
		count = 16
	}
	if block <= 0 {
		block = q.cfg.ReadBlock
	}

	res, err := q.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    group,
		Consumer: consumer,
		Streams:  []string{StreamIncidents, ">"},
		Count:    int64(count),
		Block:    block,
	}).Result()

	if err != nil {
		// An idle block expiring is the normal case, not a failure.
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("queue: reading group %q as %q: %w", group, consumer, err)
	}

	var out []domain.QueueMessage
	for _, stream := range res {
		for _, m := range stream.Messages {
			out = append(out, decode(m, 1))
		}
	}
	return out, nil
}

// Reclaim takes over messages stranded by a consumer that stopped
// acknowledging, and returns their true delivery count.
//
// XAUTOCLAIM is used rather than XPENDING followed by XCLAIM because it is a
// single round trip and, more importantly, atomic: the read-then-claim pair
// races with another reclaiming worker and can hand the same message to two
// consumers at once.
func (q *Redis) Reclaim(ctx context.Context, group, consumer string, minIdle time.Duration, count int) ([]domain.QueueMessage, error) {
	if q.closed {
		return nil, ErrClosed
	}
	if group == "" {
		group = GroupWorkers
	}
	// Negative means "use the configured default"; an explicit zero means
	// "claim regardless of idle time". Collapsing both to the default would
	// make zero unreachable, and zero is exactly what a test or an operator
	// draining a dead consumer needs.
	if minIdle < 0 {
		minIdle = q.cfg.ClaimMinIdle
	}
	if count <= 0 {
		count = 16
	}

	msgs, _, err := q.rdb.XAutoClaim(ctx, &redis.XAutoClaimArgs{
		Stream:   StreamIncidents,
		Group:    group,
		Consumer: consumer,
		MinIdle:  minIdle,
		Start:    "0",
		Count:    int64(count),
	}).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("queue: reclaiming for group %q: %w", group, err)
	}
	if len(msgs) == 0 {
		return nil, nil
	}

	// Delivery counts are not carried by XAUTOCLAIM's reply, and they decide
	// whether a message is poison. One XPENDING covers the whole batch.
	deliveries := q.deliveryCounts(ctx, group, msgs)

	out := make([]domain.QueueMessage, 0, len(msgs))
	for _, m := range msgs {
		n := deliveries[m.ID]
		if n < 1 {
			n = 1
		}
		out = append(out, decode(m, n))
	}
	return out, nil
}

func (q *Redis) deliveryCounts(ctx context.Context, group string, msgs []redis.XMessage) map[string]int {
	counts := make(map[string]int, len(msgs))
	pending, err := q.rdb.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream: StreamIncidents,
		Group:  group,
		Start:  "-",
		End:    "+",
		Count:  int64(len(msgs)) * 2,
	}).Result()
	if err != nil {
		// A missing delivery count degrades poison detection but must not stop
		// the message being processed, so this is logged rather than fatal.
		q.log.Debug("queue: pending lookup failed; delivery counts unavailable", "error", err)
		return counts
	}
	for _, p := range pending {
		counts[p.ID] = int(p.RetryCount)
	}
	return counts
}

func decode(m redis.XMessage, deliveries int) domain.QueueMessage {
	return domain.QueueMessage{
		ID:         m.ID,
		IncidentID: str(m.Values[fieldIncidentID]),
		Topic:      str(m.Values[fieldTopic]),
		Payload:    domain.RawJSON(str(m.Values[fieldPayload])),
		Deliveries: deliveries,
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// Ack removes messages from the pending list.
func (q *Redis) Ack(ctx context.Context, group string, ids ...string) error {
	if q.closed {
		return ErrClosed
	}
	if len(ids) == 0 {
		return nil
	}
	if group == "" {
		group = GroupWorkers
	}
	if err := q.rdb.XAck(ctx, StreamIncidents, group, ids...).Err(); err != nil {
		return fmt.Errorf("queue: acknowledging %d message(s) in group %q: %w", len(ids), group, err)
	}
	return nil
}

// DeadLetter moves a message that cannot be processed onto the dead-letter
// stream together with its failure history, then acknowledges it.
//
// The order matters. Writing to the dead-letter stream before acknowledging
// means a crash between the two leaves the message pending and it is reclaimed
// later, producing a duplicate dead-letter entry. Acknowledging first would
// instead lose the message entirely. A visible duplicate is recoverable; a
// silent loss is not.
func (q *Redis) DeadLetter(ctx context.Context, group string, msg domain.QueueMessage, cause string) error {
	if q.closed {
		return ErrClosed
	}
	if group == "" {
		group = GroupWorkers
	}
	err := q.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: StreamDeadLetter,
		MaxLen: q.cfg.MaxLen,
		Approx: true,
		Values: map[string]any{
			fieldOrigID:     msg.ID,
			fieldIncidentID: msg.IncidentID,
			fieldTopic:      msg.Topic,
			fieldPayload:    string(msg.Payload),
			fieldAttempts:   msg.Deliveries,
			fieldCause:      truncateCause(cause),
		},
	}).Err()
	if err != nil {
		return fmt.Errorf("queue: dead-lettering incident %s: %w", msg.IncidentID, err)
	}
	if err := q.Ack(ctx, group, msg.ID); err != nil {
		return fmt.Errorf("queue: acknowledging dead-lettered incident %s: %w", msg.IncidentID, err)
	}
	q.log.Warn("message dead-lettered",
		"incident_id", msg.IncidentID, "deliveries", msg.Deliveries, "cause", truncateCause(cause))
	return nil
}

// truncateCause bounds an error string before it is stored. Error text can
// carry an entire response body, and an unbounded field in a shared stream is
// a memory-exhaustion vector.
func truncateCause(s string) string {
	const max = 512
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "..."
}

// DeadLetterDepth reports how many messages are parked for human attention.
func (q *Redis) DeadLetterDepth(ctx context.Context) (int64, error) {
	n, err := q.rdb.XLen(ctx, StreamDeadLetter).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("queue: reading dead-letter depth: %w", err)
	}
	return n, nil
}

// ListDeadLetters returns parked messages, newest last, for the operator
// console and meshctl.
func (q *Redis) ListDeadLetters(ctx context.Context, limit int) ([]DeadLetter, error) {
	if limit <= 0 {
		limit = 50
	}
	msgs, err := q.rdb.XRevRangeN(ctx, StreamDeadLetter, "+", "-", int64(limit)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("queue: listing dead letters: %w", err)
	}
	out := make([]DeadLetter, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, DeadLetter{
			ID:         m.ID,
			OriginalID: str(m.Values[fieldOrigID]),
			IncidentID: str(m.Values[fieldIncidentID]),
			Topic:      str(m.Values[fieldTopic]),
			Payload:    domain.RawJSON(str(m.Values[fieldPayload])),
			Cause:      str(m.Values[fieldCause]),
		})
	}
	return out, nil
}

// DeadLetter is one parked message.
type DeadLetter struct {
	ID         string         `json:"id"`
	OriginalID string         `json:"original_id"`
	IncidentID string         `json:"incident_id"`
	Topic      string         `json:"topic"`
	Payload    domain.RawJSON `json:"payload"`
	Cause      string         `json:"cause"`
}

// Requeue puts a dead-lettered message back on the main stream and removes it
// from the dead-letter stream.
//
// Requeuing without first fixing the cause simply re-poisons the pool, so this
// is deliberately a manual operation exposed through meshctl rather than an
// automatic retry.
func (q *Redis) Requeue(ctx context.Context, id string) error {
	msgs, err := q.rdb.XRangeN(ctx, StreamDeadLetter, id, id, 1).Result()
	if err != nil {
		return fmt.Errorf("queue: reading dead letter %s: %w", id, err)
	}
	if len(msgs) == 0 {
		return fmt.Errorf("queue: dead letter %s not found", id)
	}
	m := msgs[0]
	err = q.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: StreamIncidents,
		MaxLen: q.cfg.MaxLen,
		Approx: true,
		Values: map[string]any{
			fieldIncidentID: str(m.Values[fieldIncidentID]),
			fieldTopic:      str(m.Values[fieldTopic]),
			fieldPayload:    str(m.Values[fieldPayload]),
			fieldOutboxID:   "0",
		},
	}).Err()
	if err != nil {
		return fmt.Errorf("queue: requeuing dead letter %s: %w", id, err)
	}
	if err := q.rdb.XDel(ctx, StreamDeadLetter, id).Err(); err != nil {
		return fmt.Errorf("queue: removing requeued dead letter %s: %w", id, err)
	}
	return nil
}

// Depth reports the number of entries currently in the main stream.
func (q *Redis) Depth(ctx context.Context) (int64, error) {
	n, err := q.rdb.XLen(ctx, StreamIncidents).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("queue: reading stream depth: %w", err)
	}
	return n, nil
}

// Lag reports how many delivered-but-unacknowledged messages the group holds.
// It is the number that predicts an incident before users notice one.
func (q *Redis) Lag(ctx context.Context, group string) (int64, error) {
	if group == "" {
		group = GroupWorkers
	}
	res, err := q.rdb.XPending(ctx, StreamIncidents, group).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		// A group that does not exist yet has no lag; that is a startup
		// ordering condition, not a failure.
		if strings.Contains(err.Error(), "NOGROUP") {
			return 0, nil
		}
		return 0, fmt.Errorf("queue: reading pending count for group %q: %w", group, err)
	}
	return res.Count, nil
}

// Ping reports whether Redis is reachable.
func (q *Redis) Ping(ctx context.Context) error {
	if q.closed {
		return ErrClosed
	}
	if err := q.rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("queue: ping: %w", err)
	}
	return nil
}

// Close releases the client. It is safe to call more than once, because
// shutdown paths routinely run twice under a signal handler plus a defer.
func (q *Redis) Close() error {
	if q.closed {
		return nil
	}
	q.closed = true
	if err := q.rdb.Close(); err != nil {
		return fmt.Errorf("queue: closing redis client: %w", err)
	}
	return nil
}

// Compile-time proof that the concrete type satisfies the port.
var _ domain.Queue = (*Redis)(nil)
