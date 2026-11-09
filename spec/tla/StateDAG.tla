----------------------------- MODULE StateDAG -----------------------------
(***************************************************************************)
(* Revisions of one resource (pkg/wsp/state.go, pkg/wsp/checkpoint.go) and *)
(* how a device reads them (app/resource.go loadResource, readResource,    *)
(* trustedHeads).                                                          *)
(*                                                                         *)
(* Each revision names its parents, its Generation and the Control it was  *)
(* written under. Honest members write on top of what they read; an admin  *)
(* deletes old revisions with no record (history compact). The attacker    *)
(* holds the key of a removed member (Compromised), forges signatures, and *)
(* names Controls the reader does not know. Storage shows the reader any   *)
(* subset of everything ever published, deleted revisions included.        *)
(*                                                                         *)
(* The Control DAG is a fixed linear chain here (ControlDAG.tla checks     *)
(* it): Members[i] are the principals of the i-th Control and Now is the   *)
(* index of the head the reader verified.                                  *)
(*                                                                         *)
(* Property names carry the IDs of spec/INVARIANTS.md.                     *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Writers,        \* honest members who write
    Compromised,    \* removed members whose signing key the attacker holds
    Reader,         \* the honest device whose reads storage attacks
    Members,        \* Seq(SUBSET devices): principals of each Control
    MaxRevisions,   \* bound on revisions ever published
    MaxAttacks,     \* bound on revisions the attacker publishes
    MaxGen,         \* highest Generation the attacker writes
    Compaction,     \* whether an admin deletes old revisions
    Witnessing,     \* whether reads record what they reached (witness runs only)
    Mutant          \* "none" or a seeded bug, see Mutants

Devices == Writers \cup Compromised
Ghost == -1         \* a parent digest no revision has
UnknownControl == Len(Members) + 1

Mutants == {"none", "count-untrusted", "abort-on-unknown-control", "skip-continuity",
            "trust-every-signed", "skip-checkpoint", "no-fallback", "skip-generation"}

ASSUME Reader \in Writers /\ Writers \cap Compromised = {}
ASSUME \A i \in 1..Len(Members) : Reader \in Members[i]
ASSUME Mutant \in Mutants

VARIABLES
    now,        \* index of the current Control
    store,      \* every revision ever published
    live,       \* ids storage still holds (compaction removes some)
    attacks,
    cp,         \* Reader's accepted Generation (its checkpoint)
    seen,       \* every revision Reader ever adopted as a head
    violated,   \* names of the read properties some read broke (normally {})
    reached     \* situations reads reached, for the reachability witnesses

vars == <<now, store, live, attacks, cp, seen, violated, reached>>

Ids(S) == {s.id : s \in S}
ById(I) == {s \in store : s.id \in I}
MaxOf(S) == IF S = {} THEN 0 ELSE CHOOSE m \in S : \A x \in S : x <= m
TopGen(S) == MaxOf({s.gen : s \in S})

RECURSIVE AncestorIds(_, _)
\* Ids of the revisions of V reachable from S through parents, S excluded.
AncestorIds(S, V) ==
    LET P == {p \in V : \E s \in S : p.id \in s.parents} IN
    IF P = {} THEN {} ELSE Ids(P) \cup AncestorIds(P, V)

(***************************************************************************)
(* Verification of what storage shows (VerifyRevision, LoadStates).       *)
(***************************************************************************)
Known(c) == c \in 1..Len(Members) /\ c <= now
Signed(s) == s.sig /\ Known(s.ctl) /\ s.author \in Members[s.ctl]

\* An unsigned object or one naming a Control the reader does not know.
Junk(S) == {s \in S : ~s.sig \/ ~Known(s.ctl)}

\* dropWrongGenerations: a revision whose parents are all present must carry
\* the Generation they imply. One pass over the verified set.
GenerationOK(s, V) ==
    LET P == {p \in V : p.id \in s.parents} IN
    Ids(P) # s.parents \/ s.gen = TopGen(P) + 1 \/ Mutant = "skip-generation"

Verified(S) ==
    LET V == {s \in S : Signed(s)} IN {s \in V : GenerationOK(s, V)}

Heads(V) == {s \in V : ~\E k \in V : s.id \in k.parents}

\* AuthorIsCurrent: a current principal never removed since the Control the
\* revision names (MembershipUnbroken on a linear chain).
Unbroken(s) == \A j \in s.ctl..now : s.author \in Members[j]
Trusted(s) ==
    \/ Mutant = "trust-every-signed"
    \/ /\ s.author \in Members[now]
       /\ Unbroken(s) \/ Mutant = "skip-continuity"

\* trustedHeads: a head failing Trusted is set aside and its present parents
\* stand in for it; a stand-in covered by another candidate is dropped.
RECURSIVE StandIns(_, _, _)
StandIns(queue, V, done) ==
    IF queue = {} THEN {} ELSE
    LET s == CHOOSE x \in queue : TRUE
        rest == queue \ {s} IN
    IF s.id \in done THEN StandIns(rest, V, done)
    ELSE IF Trusted(s) THEN {s} \cup StandIns(rest, V, done \cup {s.id})
    ELSE IF Mutant = "no-fallback" THEN StandIns(rest, V, done \cup {s.id})
    ELSE StandIns(rest \cup {p \in V : p.id \in s.parents}, V, done \cup {s.id})

TrustedHeads(V) ==
    LET C == StandIns(Heads(V), V, {}) IN
    {h \in C : ~\E o \in C : o # h /\ h.id \in AncestorIds({o}, V)}

\* What the checkpoint compares with: the highest Generation of the verified
\* revisions storage shows. Only revisions of trusted authors count; a removed
\* member's key must not vouch for freshness (F2).
Freshness(V) ==
    IF Mutant = "count-untrusted" THEN TopGen(V) ELSE TopGen({s \in V : Trusted(s)})

\* The outcome of reading what storage shows, without the checkpoint update.
Outcome(S) ==
    IF Mutant = "abort-on-unknown-control" /\ \E s \in S : ~Known(s.ctl)
    THEN [res |-> "rollback_detected", heads |-> {}]
    ELSE LET V == Verified(S) T == TrustedHeads(V) IN
         IF V = {} THEN [res |-> "artifact_not_found", heads |-> {}]
         ELSE IF Freshness(V) < cp /\ Mutant # "skip-checkpoint" THEN [res |-> "rollback_detected", heads |-> {}]
         ELSE IF T = {} THEN [res |-> "untrusted_state", heads |-> {}]
         ELSE [res |-> "ok", heads |-> T]

-----------------------------------------------------------------------------
Init ==
    /\ now = 1
    /\ store = {}
    /\ live = {}
    /\ attacks = 0
    /\ cp = 0
    /\ seen = {}
    /\ violated = {}
    /\ reached = {}

NextId == Cardinality(store)

\* Ids of every revision in store a new revision with parents P descends from.
Anc(P) == P \cup UNION {s.anc : s \in {x \in store : x.id \in P}}

\* A member writes on top of the trusted heads of what it reads: all of
\* storage, or a stale listing that misses some heads (a concurrent sibling).
\* H0 are the heads it sees; their ancestors are fetched by digest. A device
\* whose key later leaks writes honestly while it is a member.
Write(w, H0) ==
    /\ Cardinality(store) < MaxRevisions
    /\ w \in Members[now]
    /\ LET view == ById(H0 \cup AncestorIds(ById(H0), ById(live)))
           V == Verified(view)
           T == TrustedHeads(V) IN
       /\ V = {} \/ T # {}
       /\ LET s == [id |-> NextId, parents |-> Ids(T), gen |-> TopGen(T) + 1, ctl |-> now,
                    author |-> w, sig |-> TRUE, evil |-> FALSE, anc |-> Anc(Ids(T))] IN
          /\ store' = store \cup {s}
          /\ live' = live \cup {s.id}
    /\ UNCHANGED <<now, attacks, cp, seen, violated, reached>>

\* The next Control of the chain is published.
ControlStep ==
    /\ now < Len(Members)
    /\ now' = now + 1
    /\ UNCHANGED <<store, live, attacks, cp, seen, violated, reached>>

\* history compact: an admin deletes a revision that is not a head.
Compact(i) ==
    /\ Compaction
    /\ i \in live
    /\ \E k \in ById(live) : i \in k.parents
    /\ live' = live \ {i}
    /\ UNCHANGED <<now, store, attacks, cp, seen, violated, reached>>

\* The attacker signs with a removed member's key under a Control that still
\* listed it (one it was removed from since), forges an honest author's
\* signature, or names a Control the reader does not know. Its parents are
\* any revisions or a digest that does not exist.
AttackParents ==
    {{}, {Ghost}, Ids(Heads(ById(live)))} \cup {{i} : i \in Ids(store)} \cup {{i, Ghost} : i \in Ids(store)}

AttackControls(a) ==
    {c \in 1..now : a \in Members[c] /\ \E j \in c..now : a \notin Members[j]}

Attack ==
    /\ attacks < MaxAttacks
    /\ Cardinality(store) < MaxRevisions
    /\ \E a \in Compromised \cup {Reader}, P \in AttackParents, g \in 1..MaxGen :
       \E c \in AttackControls(a) \cup {1, UnknownControl} :
         LET sig == a \in Compromised /\ c \in AttackControls(a)
             s == [id |-> NextId, parents |-> P, gen |-> g, ctl |-> c,
                   author |-> a, sig |-> sig, evil |-> TRUE, anc |-> Anc(P \ {Ghost})] IN
         /\ (a \in Writers) => ~sig
         /\ store' = store \cup {s}
         /\ live' = live \cup {s.id}
         /\ attacks' = attacks + 1
    /\ UNCHANGED <<now, cp, seen, violated, reached>>

\* GEN-2 / GEN-6: a revision h adopted now covers a revision a adopted before
\* when it is a, descends from a, or is a branch a does not descend from with
\* an equal or higher Generation (the accepted limitation GEN-5).
Covers(h, a) ==
    \/ h.id = a.id
    \/ a.id \in h.anc
    \/ (h.id \notin a.anc /\ h.gen >= a.gen)

\* The read properties, judged on one read of S with outcome o.
ReadViolations(S, o) ==
    \* REJOIN-1 / STATE-1: never adopt what the attacker wrote.
    {"NoAttackerContentAdopted" : x \in {h \in o.heads : h.evil}}
    \* GEN-2 / GEN-6: never go back behind an adopted revision whose author is
    \* still trusted; a removed author's content is set aside on purpose.
    \cup (IF o.res = "ok" /\ \E a \in ById(seen) : Trusted(a) /\ ~\E h \in o.heads : Covers(h, a)
          THEN {"NoUndetectedRollback"} ELSE {})
    \* AVAIL-1: objects without a valid signature or naming an unknown Control
    \* change nothing a read decides.
    \cup (IF Junk(S) # {} /\ o.res # Outcome(S \ Junk(S)).res THEN {"JunkDoesNotInterfere"} ELSE {})
    \* AVAIL-2: a read shown a trusted author's revision is not refused for
    \* lack of a trusted head.
    \cup (IF o.res = "untrusted_state" /\ \E s \in Verified(S) : Trusted(s)
          THEN {"TrustedContentReadable"} ELSE {})

ReadReached(o) ==
    {o.res}
    \cup (IF o.res = "ok" /\ \E s \in ById(seen) : ~Trusted(s) THEN {"set-aside"} ELSE {})
    \cup (IF Cardinality(o.heads) > 1 THEN {"concurrent-heads"} ELSE {})
    \cup (IF o.res = "ok" /\ Cardinality(seen) > 1 THEN {"adopted-twice"} ELSE {})

\* Reader reads what storage shows and, on success, raises its checkpoint to
\* the Generation of the heads it adopted (readResource with record).
Read(S) ==
    LET o == Outcome(S) IN
    /\ violated' = violated \cup ReadViolations(S, o)
    /\ reached' = IF Witnessing THEN reached \cup ReadReached(o) ELSE reached
    /\ IF o.res = "ok" THEN
          /\ seen' = seen \cup Ids(o.heads)
          /\ cp' = MaxOf({cp, TopGen(o.heads)})
       ELSE UNCHANGED <<seen, cp>>
    /\ UNCHANGED <<now, store, live, attacks>>

WriteStep == \E w \in Devices, H0 \in SUBSET Ids(Heads(ById(live))) : Write(w, H0)
CompactStep == \E i \in live : Compact(i)
ReadStep == \E S \in SUBSET store : Read(S)

Next == WriteStep \/ ControlStep \/ CompactStep \/ Attack \/ ReadStep

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                            *)

TypeOK ==
    /\ now \in 1..Len(Members)
    /\ cp \in Nat

NoAttackerContentAdopted == "NoAttackerContentAdopted" \notin violated
NoUndetectedRollback == "NoUndetectedRollback" \notin violated
JunkDoesNotInterfere == "JunkDoesNotInterfere" \notin violated
TrustedContentReadable == "TrustedContentReadable" \notin violated

\* STATE-2: honest members never build on what the attacker wrote.
HonestNeverBuildsOnAttacker ==
    \A s \in store : ~s.evil => \A p \in store : p.id \in s.parents => ~p.evil

\* GEN-1: honest revisions carry 1 + the highest parent Generation.
HonestGenerations ==
    \A s \in store : ~s.evil =>
        s.gen = TopGen({p \in store : p.id \in s.parents}) + 1

(* Reachability witnesses (must be violated). *)
WitnessNoAdoption == "adopted-twice" \notin reached
WitnessNoRollbackRefused == "rollback_detected" \notin reached
WitnessNoSetAside == "set-aside" \notin reached
WitnessNoConcurrentHeads == "concurrent-heads" \notin reached
WitnessNoCompaction == live = Ids(store)
=============================================================================
