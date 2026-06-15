# Task: Commit fixes + close IRCv3 gossip-relay gaps + simplify gossip docs

## A. Commit verified fixes (topic burst + fanout) + gossip/fanout docs
- [ ] Simplify default: gossip_fanout default 0 (= flood all peers) so admins just set gopeers.
- [ ] reference.conf: accurate, simple gossip{} (fanout) + gopeer{} docs.
- [ ] template.conf: same.
- [ ] Commit 1: topic + fanout fixes + default + docs.

## B. IRCv3 enrichment over gossip relay (6 gaps)
Make gossip apply-handlers use cap-aware send paths; add EVT types where missing.
- [ ] server-time/msgid on relayed channel PRIVMSG/NOTICE (EVT_CHANMSG apply).
- [ ] extended-join on relayed JOIN (gossip_apply_chan_join).
- [ ] away-notify on relayed AWAY (gossip_apply_user_away -> notify common chans).
- [ ] setname cross-server (new EVT_SETNAME + emit + apply+notify + burst).
- [ ] tagmsg cross-server (new EVT_TAGMSG + emit + apply).
- [ ] invite-notify cross-server (relay INVITE + notify channel members).
- [ ] Commit 2: IRCv3 cap enrichment over gossip.

## C. Verify — DONE
- [x] ircv3 23/23 (all 6 gaps closed; relayed PRIVMSG carries origin msgid+time).
- [x] No regressions: matrix 4/4, chain 4/4, smoke 7/7, burst topic ✓.

## Result
Commit 742b663: topic+fanout fixes, config simplification (server_id removed,
fanout default=all), docs, away-notify+extended-join relay.
Commit 2 (this): server-time/msgid on relayed CHANMSG (carry origin out-tags),
setname/tagmsg/invite-notify over gossip (new EVT_SETNAME/TAGMSG/INVITE +
relaxed cap-module hooks + eventlog emit hooks). All IRCv3 caps now propagate
cap-aware to remote members across the gossip chain.

## D. server_id removal — test harness + docs (DONE)
- [x] Removed server_id param/key from tests/harness/{config,server}.py + conftest.py
      (all 5 gossip fixtures). py_compile clean, grep clean, dicts well-formed.
- [x] Fixed stale server_id docs: src/s_conf.c gopeer/gossip block comments,
      doc/MIGRATION.md cluster example.
- [x] Verified NO fnv1a_6bit (0-63) id collision within any fixture's server set
      (cluster 28/51; triangle 28/51/42; dual_hub 14/63/56/41; tls/bridge 28/51).
      Live tailnet node1-4 = 52/45/26/59, also collision-free.
      Commits: f836eb1 (harness), 661e803 (docs).

## Notes
- EVT pattern: enum (gossip_event.h) + payload struct + serialize (gossip.c) + parse + apply + emit at local cmd + (burst in s_gopeer.c if stateful). Lessons #13 (gossip_event for immediate prop), #17 (sparse clock), #18 (unique seq in burst).
- Reference: gossip_apply_user_nick uses sendto_common_channels — model for notify-from-apply.
- Build once on node1 (bahamut-latest), distribute matched binary, restart, test.
