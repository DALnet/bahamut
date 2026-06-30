# Gossip consistency model

How Bahamut 3.0's gossip mesh keeps replicated state convergent — i.e. how every
server ends up agreeing on the same nicks, channels, topics, and modes even
though events arrive in different orders at different servers.

## The setting

Gossip is an **eventual-consistency, event-flood mesh**:

- Each server emits events (`EVT_USER_JOIN`, `EVT_CHAN_JOIN`, `EVT_CHAN_TOPIC`,
  `EVT_CHAN_MODE`, …), each tagged with its **origin** (`gossip-id = name:seq`).
- Events flood to all peers (`fanout = 0`); the exact-dedup table
  (`(origin, seq)`) prevents loops and re-processing.
- Because every event reaches every server (via some path), and dedup makes
  apply idempotent, the only thing that can make servers disagree is **applying
  conflicting events in different orders**.

So the consistency rules below are all about making conflict resolution
**order-independent** (commutative) or settling it with a **deterministic
tiebreaker** that every server computes identically.

## The cardinal rule for tiebreakers

Any tiebreaker MUST key on the globally-stable **server name** — never the
in-memory dense server index, which is assigned per-process and differs between
servers (see issue #260). Keying on the index would make two servers pick
different winners → permanent divergence.

## Per-state rules

| State | Rule | Convergent? |
|-------|------|-------------|
| **Nick ownership** | Older `tsinfo` wins. Equal TS → the user on the lexicographically-smaller **server name** wins (the loser is killed). Missing TS → kill both. | ✅ deterministic |
| **Channel identity / TS** | `min(channelts)` wins (the older channel). | ✅ commutative (min) |
| **Channel membership** | Additive: joins add, parts/quits remove; a given user's join/part is LWW by that user's own event order (a user lives on exactly one server). | ✅ |
| **Channel topic** | LWW by `topic_time` (newer wins); equal `topic_time` tiebreaks on the topic string (greater wins). | ✅ deterministic |
| **Channel modes / ops** | **Applied in arrival order today — NOT yet order-independent.** | ⚠️ see below |

### Nick collisions (detail)

`gossip_materialize_user` (`src/gossip.c`):
- same server + same TS → duplicate (burst replay), ignored;
- older `tsinfo` wins; the newer one is dropped/killed;
- **equal TS → deterministic name tiebreaker** (smaller `user->server` wins),
  so a single survivor converges on every node instead of both being killed
  (issue #264 Tier 2). Missing TS still kills both (cannot compare).

### Topic (detail)

`gossip_apply_chan_topic` only applies an incoming topic when it is newer by
`topic_time` (or equal time with a greater topic string), so two servers that
saw two topic changes in different orders converge on the same topic
(issue #264 Tier 3).

### Channel modes / ops — known limitation

Concurrent channel **mode** and **op** changes are currently applied in arrival
order, so they can transiently (or, for a genuine split-recreate, persistently)
diverge. TS5 solves the analogous case at netjoin with an atomic SJOIN TS-reset;
gossip's events are decoupled, so the fix is a native design — per-event
`channelts` gating plus per-mode last-writer-wins — tracked in **issue #265**.
Until then, treat channel mode convergence as best-effort.

## Why the rest converges

Flood delivery + exact dedup means every server eventually applies the same
*set* of events. For each state above, the outcome is a pure function of that
set (min, LWW by a monotonic timestamp, or a name tiebreaker) — independent of
arrival order — so all servers settle on the same value.
