---------------------------- MODULE WriteRetry ----------------------------
(***************************************************************************)
(* The write loop (app/write.go changeResource, app/publish.go writeState *)
(* and acceptPublished): read the merged heads, apply the change, look     *)
(* again, check the Control before and after publishing, and retry a      *)
(* bounded number of times. The revisions this call published are passed *)
(* to later reads (`also`), because a stale listing may not show them yet, *)
(* and a change already contained in what is read is not applied again.  *)
(*                                                                         *)
(* Each writer makes one change: it adds its own key. Content merges by    *)
(* union, which is what the 3-way merge does for keys added on different  *)
(* sides. The environment moves the Control (a member change) and lets    *)
(* the storage listing catch up; storage itself is honest here.           *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS Writers, MaxAttempts, MaxCtl, Bug

Bugs == {"none", "no_published_tracking", "no_also", "merge_latest_heads", "unbounded", "F5"}
ASSUME Bug \in Bugs

VARIABLES
  rev,        \* revisions: [parents, applied, content]
  listed,     \* revisions the storage listing shows (it may lag)
  ctlv,       \* the Control version; a member change bumps it
  pc,         \* pc[w]
  sess,       \* sess[w]: the Control version w's session verified
  cur,        \* cur[w]: the heads w read
  content,    \* content[w]: what w is about to publish
  applied,    \* applied[w]: what w's change adds to it ({} once already contained)
  published,  \* published[w]: revisions this call published
  attempt,    \* attempt[w]: the loop counter
  outcome     \* outcome[w]: "", "ok", "conflict", "internal"

vars == <<rev, listed, ctlv, pc, sess, cur, content, applied, published, attempt, outcome>>

Revs == 1..Len(rev)

RECURSIVE Anc(_)
Anc(r) == {r} \cup UNION {Anc(p) : p \in rev[r].parents}

\* LoadStates: what the listing shows plus `also`, and their ancestors.
ViewOf(w) ==
  LET also == IF Bug \in {"no_also", "no_published_tracking"} THEN {} ELSE published[w]
  IN UNION {Anc(r) : r \in listed \cup also}

HeadsIn(V) == {r \in V : ~\E s \in V : r \in rev[s].parents}
Merged(H) == UNION {rev[h].content : h \in H}

\* publishedInRead: a revision of this call is already in what was read.
PublishedInRead(w, H) ==
  /\ Bug # "no_published_tracking"
  /\ \E h \in H : published[w] \cap Anc(h) # {}

Init ==
  /\ rev = <<>>
  /\ listed = {}
  /\ ctlv = 0
  /\ pc = [w \in Writers |-> "read"]
  /\ sess = [w \in Writers |-> 0]
  /\ cur = [w \in Writers |-> {}]
  /\ content = [w \in Writers |-> {}]
  /\ applied = [w \in Writers |-> {}]
  /\ published = [w \in Writers |-> {}]
  /\ attempt = [w \in Writers |-> 0]
  /\ outcome = [w \in Writers |-> ""]

Last(w) == Bug # "unbounded" /\ attempt[w] = MaxAttempts - 1

\* `continue` in the loop: the next attempt, or the conflict after the last.
NextAttempt(w) ==
  IF Bug # "unbounded" /\ attempt[w] + 1 >= MaxAttempts
  THEN /\ pc' = [pc EXCEPT ![w] = "end"]
       /\ outcome' = [outcome EXCEPT ![w] = "conflict"]
       /\ attempt' = [attempt EXCEPT ![w] = attempt[w] + 1]
  ELSE /\ pc' = [pc EXCEPT ![w] = "read"]
       /\ attempt' = [attempt EXCEPT ![w] = attempt[w] + 1]
       /\ UNCHANGED outcome

\* errControlMoved: reopen the session; the last attempt is a conflict (F5:
\* before the fix it surfaced as an internal error).
ControlMoved(w) ==
  /\ sess' = [sess EXCEPT ![w] = ctlv]
  /\ IF Last(w)
     THEN /\ pc' = [pc EXCEPT ![w] = "end"]
          /\ outcome' = [outcome EXCEPT ![w] = IF Bug = "F5" THEN "internal" ELSE "conflict"]
          /\ UNCHANGED attempt
     ELSE NextAttempt(w)

Read(w) ==
  LET V == ViewOf(w) H == HeadsIn(V) IN
  /\ pc[w] = "read"
  /\ cur' = [cur EXCEPT ![w] = H]
  /\ applied' = [applied EXCEPT ![w] = IF PublishedInRead(w, H) THEN {} ELSE {w}]
  /\ content' = [content EXCEPT ![w] = Merged(H) \cup (IF PublishedInRead(w, H) THEN {} ELSE {w})]
  /\ pc' = [pc EXCEPT ![w] = IF V = {} THEN "publish" ELSE "recheck"]
  /\ UNCHANGED <<rev, listed, ctlv, sess, published, attempt, outcome>>

\* Look once more before publishing; heads that changed mean another attempt.
Recheck(w) ==
  LET H == HeadsIn(ViewOf(w)) IN
  /\ pc[w] = "recheck"
  /\ IF Bug = "merge_latest_heads"
     THEN /\ cur' = [cur EXCEPT ![w] = H]   \* publish on the newest heads, content as read
          /\ pc' = [pc EXCEPT ![w] = "publish"]
          /\ UNCHANGED <<attempt, outcome>>
     ELSE IF H # cur[w]
     THEN NextAttempt(w) /\ UNCHANGED cur
     ELSE pc' = [pc EXCEPT ![w] = "publish"] /\ UNCHANGED <<cur, attempt, outcome>>
  /\ UNCHANGED <<rev, listed, ctlv, sess, content, applied, published>>

\* writeState: the Control check before publishing, then publish.
Publish(w) ==
  /\ pc[w] = "publish"
  /\ IF sess[w] # ctlv
     THEN ControlMoved(w) /\ UNCHANGED <<rev, published>>
     ELSE /\ rev' = Append(rev, [parents |-> cur[w], applied |-> applied[w], content |-> content[w]])
          /\ published' = [published EXCEPT ![w] = published[w] \cup {Len(rev) + 1}]
          /\ pc' = [pc EXCEPT ![w] = "check"]
          /\ UNCHANGED <<sess, attempt, outcome>>
  /\ UNCHANGED <<listed, ctlv, cur, content, applied>>

\* writeState: the Control check after publishing; the revision stays either way.
Check(w) ==
  /\ pc[w] = "check"
  /\ IF sess[w] # ctlv
     THEN ControlMoved(w)
     ELSE /\ pc' = [pc EXCEPT ![w] = "end"]
          /\ outcome' = [outcome EXCEPT ![w] = "ok"]
          /\ UNCHANGED <<sess, attempt>>
  /\ UNCHANGED <<rev, listed, ctlv, cur, content, applied, published>>

\* Another admin changes members.
MoveControl ==
  /\ ctlv < MaxCtl
  /\ ctlv' = ctlv + 1
  /\ UNCHANGED <<rev, listed, pc, sess, cur, content, applied, published, attempt, outcome>>

\* The listing catches up with a published revision.
List ==
  \E r \in Revs \ listed :
    /\ listed' = listed \cup {r}
    /\ UNCHANGED <<rev, ctlv, pc, sess, cur, content, applied, published, attempt, outcome>>

WStep(w) == Read(w) \/ Recheck(w) \/ Publish(w) \/ Check(w)

Next == (\E w \in Writers : WStep(w)) \/ MoveControl \/ List

Spec == Init /\ [][Next]_vars
LiveSpec == Spec /\ \A w \in Writers : WF_vars(WStep(w))

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
Done == \A w \in Writers : pc[w] = "end"
Final == Merged(HeadsIn(Revs))

\* SYNC-1: no lost update: once every write returned, the merged content
\* holds every change whose write succeeded.
SYNC_1 == Done => \A w \in Writers : outcome[w] = "ok" => w \in Final

\* SYNC-2: no double application: a change is applied by one revision at most.
SYNC_2 == \A w \in Writers : Cardinality({r \in Revs : w \in rev[r].applied}) <= 1

\* SYNC-3: the retries are bounded.
SYNC_3 == \A w \in Writers : attempt[w] <= MaxAttempts

\* SYNC-4: members that keep changing end a write as a conflict, a code the
\* caller can act on, never an internal error.
SYNC_4 == \A w \in Writers : outcome[w] \in {"", "ok", "conflict"}

\* SYNC-5 (liveness): every write returns.
SYNC_5 == <>Done

=============================================================================
