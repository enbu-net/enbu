----------------------------- MODULE StateDAG -----------------------------
(***************************************************************************)
(* The revision DAG of one environment (pkg/wsp/state.go, checkpoint.go;  *)
(* app/resource.go readResource / trustedHeads; app/compact.go;           *)
(* app/members.go RemoveMember and app/reencrypt.go reencryptHeads).       *)
(*                                                                         *)
(* A revision is a record; its index in `rev` stands for its digest, and  *)
(* parent 0 is a digest storage never held. The Control is linear and     *)
(* fixed: C1 lists M, C2 removes it, C3 approves it again with the same   *)
(* key. Readers are the honest members in Writers; A is also the admin    *)
(* that removes M and compacts history (keep 1).                          *)
(*                                                                         *)
(* M writes honestly while a member and can sign anything with its key at *)
(* any time (MSign): the key of a removed member is the interesting case.  *)
(* The Outsider can only write storage. Storage may hide and replay any    *)
(* revision.                                                               *)
(*                                                                         *)
(* Each property is checked at the step that reads: a violated check adds *)
(* its name to the ghost set `bad`, and the invariants say `bad` lacks it. *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS Writers, A, M, Outsider, MaxRevs, MaxGen, MaxAdv, Bug,
          RemovalRace  \* may M write between a removal's re-encryption and its Control?

ASSUME A \in Writers /\ M \notin Writers

Bugs == {"none", "F1", "F2", "F3", "skip_gen_check", "lower_checkpoint",
         "no_rejoin_check", "no_checkpoint"}
ASSUME Bug \in Bugs

CtlM == <<Writers \cup {M}, Writers, Writers \cup {M}>>
Ghost == 0          \* a parent digest storage never held
Unknown == 99       \* a Control digest outside the verified DAG

VARIABLES
  rev,       \* every revision ever signed
  stored,    \* indices storage serves
  hidden,    \* revisions storage withholds (not compaction's deletions)
  tampered,  \* ghost: storage has withheld a revision at some point
  ctlHead,   \* index of the current Control in CtlM
  removal,   \* "none", "reencrypted" (heads re-encrypted, Control not yet published), "done"
  cp,        \* cp[d]: accepted Generation (the checkpoint)
  accepted,  \* ghost: revisions d read as current heads or published
  forged,    \* ghost: M signed outside the protocol
  bad,       \* ghost: names of the checks some step violated
  adv        \* adversary steps left

vars == <<rev, stored, hidden, tampered, ctlHead, removal, cp, accepted, forged, bad, adv>>

Max(S) == IF S = {} THEN 0 ELSE CHOOSE x \in S : \A y \in S : y <= x
Gen(r) == rev[r].gen
NextGen(P) == 1 + Max({Gen(p) : p \in P})
Revs == 1..Len(rev)

(***************************************************************************)
(* Verification as LoadStates does it.                                     *)
(***************************************************************************)
\* Before F3 nothing bounded Generation but the integer width; 2 * MaxGen
\* plays the role of 2^64 - 1 there, and a child of it wraps to 0.
GenCap == IF Bug = "F3" THEN 2 * MaxGen ELSE MaxGen
Valid(r) ==
  /\ Gen(r) >= 1 /\ Gen(r) <= GenCap
  /\ (Gen(r) = 1) = (rev[r].parents = {})

KnownCtl(r) == rev[r].ctl \in 1..ctlHead
\* VerifyRevision: a Control the DAG holds, and its principal as the author.
Verifies(r) == Valid(r) /\ KnownCtl(r) /\ rev[r].author \in CtlM[rev[r].ctl]

\* dropWrongGenerations, in index order (a parent has a lower index).
RECURSIVE KeepUpTo(_, _)
KeepUpTo(V0, n) ==
  IF n = 0 THEN {}
  ELSE LET K == KeepUpTo(V0, n - 1)
           P == rev[n].parents
       IN IF n \in V0
             /\ P \cap (V0 \ K) = {}
             /\ (P \subseteq K => (Bug = "skip_gen_check" \/ Gen(n) = NextGen(P)))
          THEN K \cup {n} ELSE K

LoadV(S) == KeepUpTo({r \in S : Verifies(r)}, Len(rev))

HeadsIn(V) == {r \in V : ~\E c \in V : r \in rev[c].parents}

RECURSIVE AncIn(_, _)
AncIn(r, V) == {r} \cup UNION {AncIn(p, V) : p \in rev[r].parents \cap V}

\* AuthorIsCurrent: a principal now and never removed since the Control it names.
Trusted(r) ==
  /\ rev[r].author \in CtlM[ctlHead]
  /\ Bug = "no_rejoin_check" \/ \A i \in rev[r].ctl..ctlHead : rev[r].author \in CtlM[i]

\* trustedHeads: set-aside heads are replaced by their parents in the view.
RECURSIVE USet(_, _, _)
USet(V, H, n) ==
  IF n > Len(rev) THEN {}
  ELSE LET Up == USet(V, H, n + 1) IN
       IF n \in V /\ ~Trusted(n) /\ (n \in H \/ \E c \in Up : n \in rev[c].parents)
       THEN Up \cup {n} ELSE Up

TrustedHeads(V) ==
  LET H == HeadsIn(V)
      U == USet(V, H, 1)
      T0 == {h \in H : Trusted(h)} \cup {p \in V : Trusted(p) /\ \E u \in U : p \in rev[u].parents}
  IN {t \in T0 : ~\E t2 \in T0 \ {t} : t \in AncIn(t2, V)}

\* A Generation the view proves: every ancestor down to a first revision is present.
RECURSIVE Proven(_, _)
Proven(r, V) == rev[r].parents \subseteq V /\ \A p \in rev[r].parents : Proven(p, V)

\* shownGeneration; before F2 every verified revision counted.
Shown(V, T) ==
  IF Bug = "F2" THEN Max({Gen(r) : r \in V})
  ELSE Max({Gen(t) : t \in T} \cup {Gen(r) : r \in {q \in V : Proven(q, V)}})

\* Before F1 a State naming an unknown Control was reported as a rollback.
UnknownCtlStored == \E r \in stored : ~KnownCtl(r)

ReadResult(d, V, T) ==
  IF Bug = "F1" /\ UnknownCtlStored THEN "rollback"
  ELSE IF Bug # "no_checkpoint" /\ Shown(V, T) < cp[d] THEN "rollback"
  ELSE IF V = {} THEN "empty"
  ELSE IF T = {} THEN "untrusted"
  ELSE "ok"

(***************************************************************************)
(* Ground truth the checks are judged by.                                  *)
(***************************************************************************)
RECURSIVE RealAnc(_)
RealAnc(r) == {r} \cup UNION {RealAnc(p) : p \in rev[r].parents \ {Ghost}}

RECURSIVE HonestGen(_)
HonestGen(r) == Ghost \notin rev[r].parents /\ \A p \in rev[r].parents : HonestGen(p)
                /\ Gen(r) = NextGen(rev[r].parents)

\* r is still shown: present, superseded by a present descendant, or matched
\* by a present revision of at least its Generation that a current member
\* signed (the documented limit: storage may hide a head behind a member's
\* sibling) or, in the weak form, whose Generation is honest.
Covered(r, V, weak) ==
  \/ r \in V
  \/ \E s \in V : r \in RealAnc(s)
  \/ \E s \in V : Gen(s) >= Gen(r) /\ (Trusted(s) \/ (weak /\ HonestGen(s)))

\* The names of the properties a successful read of V, reading T, violates.
ReadViolations(d, V, T) ==
     {"GEN_1" : x \in {r \in accepted[d] : ~Covered(r, V, TRUE)}}
  \cup {"GEN_1_strict" : x \in {r \in accepted[d] : ~Covered(r, V, FALSE)}}
  \cup {"REJOIN_1" : x \in {t \in T : rev[t].author = M /\ ctlHead >= 2 /\ rev[t].ctl # 3}}
  \cup {"AUTH_3" : x \in {t \in T : rev[t].author \notin CtlM[ctlHead]}}

FailViolations(why) ==
  IF why = "rollback" /\ ~tampered
  THEN IF forged THEN {"GEN_2_strict"} ELSE {"GEN_2", "GEN_2_strict"}
  ELSE {}

\* A step that reads. ok: what to do when the read succeeds (or finds an empty
\* resource when allowEmpty); otherwise only the failure is recorded.
Accept(d, V, T) ==
  /\ cp' = [cp EXCEPT ![d] = IF Bug = "lower_checkpoint" THEN Max({Gen(t) : t \in T})
                             ELSE Max({cp[d]} \cup {Gen(t) : t \in T})]
  /\ accepted' = [accepted EXCEPT ![d] = accepted[d] \cup T]

Read(d) ==
  LET V == LoadV(stored) T == TrustedHeads(V) r == ReadResult(d, V, T) IN
  /\ IF r = "ok"
     THEN /\ Accept(d, V, T)
          /\ bad' = bad \cup ReadViolations(d, V, T)
     ELSE /\ bad' = bad \cup FailViolations(r)
          /\ UNCHANGED <<cp, accepted>>
  /\ UNCHANGED <<rev, stored, hidden, tampered, ctlHead, removal, forged, adv>>

NewRev(parents, gen, author, ctl) ==
  [parents |-> parents, gen |-> gen, author |-> author, ctl |-> ctl]

LatestCtlOf(d) == CHOOSE i \in 1..ctlHead : d \in CtlM[i] /\ \A j \in i + 1..ctlHead : d \notin CtlM[j]

(***************************************************************************)
(* An honest member writes: read, publish a revision on the trusted heads, *)
(* and accept the view holding it (changeResource, one attempt; WriteRetry *)
(* models the retries). Above MaxGeneration it is a conflict.              *)
(***************************************************************************)
Write(d) ==
  LET V == LoadV(stored) T == TrustedHeads(V) r == ReadResult(d, V, T)
      g == IF r = "ok" THEN NextGen(T) ELSE 1
      g2 == IF Bug = "F3" THEN g % (GenCap + 1) ELSE g
      i == Len(rev) + 1
  IN
  /\ d \in CtlM[ctlHead]
  /\ Len(rev) < MaxRevs
  /\ r \in {"ok", "empty"}
  /\ Bug = "F3" \/ g <= MaxGen
  /\ rev' = Append(rev, NewRev(IF r = "ok" THEN T ELSE {}, g2, d, ctlHead))
  /\ stored' = stored \cup {i}
  /\ cp' = [cp EXCEPT ![d] = IF Bug = "lower_checkpoint" THEN g2 ELSE Max({cp[d], g2})]
  /\ accepted' = [accepted EXCEPT ![d] = accepted[d] \cup {i}]
  \* GEN-4: what an honest device publishes must verify.
  /\ bad' = bad \cup (IF r = "ok" THEN ReadViolations(d, V, T) ELSE {})
                \cup (IF g2 >= 1 /\ g2 <= GenCap THEN {} ELSE {"GEN_4"})
  /\ UNCHANGED <<hidden, tampered, ctlHead, removal, forged, adv>>

(***************************************************************************)
(* RemoveMember: A re-encrypts every trusted head on its own under the     *)
(* Control that still lists M, then publishes the Control without M.      *)
(***************************************************************************)
RECURSIVE SyncAll(_, _)
SyncAll(s, T) ==
  IF T = {} THEN s
  ELSE LET t == CHOOSE x \in T : TRUE IN
       SyncAll(Append(s, NewRev({t}, Gen(t) + 1, A, ctlHead)), T \ {t})

ReencryptForRemoval ==
  LET V == LoadV(stored) T == TrustedHeads(V) r == ReadResult(A, V, T)
      New == Len(rev) + 1..Len(rev) + Cardinality(T)
  IN
  /\ ctlHead = 1 /\ removal = "none"
  /\ r \in {"ok", "empty"}
  /\ Len(rev) + Cardinality(T) <= MaxRevs
  /\ \A t \in T : Gen(t) + 1 <= MaxGen
  /\ rev' = SyncAll(rev, T)
  /\ stored' = stored \cup New
  /\ cp' = [cp EXCEPT ![A] = Max({cp[A]} \cup {Gen(t) + 1 : t \in T})]
  /\ accepted' = [accepted EXCEPT ![A] = accepted[A] \cup New]
  /\ removal' = "reencrypted"
  /\ UNCHANGED <<hidden, tampered, ctlHead, forged, bad, adv>>

PublishRemoval ==
  /\ removal = "reencrypted"
  /\ ctlHead' = 2 /\ removal' = "done"
  /\ UNCHANGED <<rev, stored, hidden, tampered, cp, accepted, forged, bad, adv>>

Rejoin ==
  /\ ctlHead = 2
  /\ ctlHead' = 3
  /\ UNCHANGED <<rev, stored, hidden, tampered, removal, cp, accepted, forged, bad, adv>>

\* CompactHistory --keep 1: keep the single trusted head and every head
\* storage shows; delete the other verified revisions and unverifiable junk.
Compact ==
  LET V == LoadV(stored) T == TrustedHeads(V) IN
  /\ ReadResult(A, V, T) = "ok"
  /\ Cardinality(T) = 1
  /\ adv > 0
  /\ stored' = stored \ ((V \ (T \cup HeadsIn(V))) \cup {r \in stored : ~Verifies(r)})
  /\ adv' = adv - 1
  /\ Accept(A, V, T)
  /\ bad' = bad \cup ReadViolations(A, V, T)
  /\ UNCHANGED <<rev, hidden, tampered, ctlHead, removal, forged>>

(***************************************************************************)
(* M and the adversaries                                                   *)
(***************************************************************************)
InWindow == removal = "reencrypted"

\* M writes like any member while it is one.
MWrite ==
  LET V == LoadV(stored) T == TrustedHeads(V) g == NextGen(T) IN
  /\ M \in CtlM[ctlHead]
  /\ RemovalRace \/ ~InWindow
  /\ Len(rev) < MaxRevs
  /\ T # {} /\ g <= MaxGen
  /\ rev' = Append(rev, NewRev(T, g, M, ctlHead))
  /\ stored' = stored \cup {Len(rev) + 1}
  /\ UNCHANGED <<hidden, tampered, ctlHead, removal, cp, accepted, forged, bad, adv>>

AdvStep == adv > 0 /\ adv' = adv - 1

\* M signs any revision with its key, on a real parent or a missing one,
\* with any Generation, naming the latest Control that listed it.
MSign ==
  \E P \in {{p} : p \in Revs} \cup {{Ghost}}, g \in 2..GenCap + 1 :
    /\ RemovalRace \/ ~InWindow
    /\ AdvStep
    /\ Len(rev) < MaxRevs
    /\ rev' = Append(rev, NewRev(P, g, M, LatestCtlOf(M)))
    /\ stored' = stored \cup {Len(rev) + 1}
    /\ forged' = TRUE
    /\ UNCHANGED <<hidden, tampered, ctlHead, removal, cp, accepted, bad>>

\* The Outsider publishes a State naming a Control the DAG does not hold.
Junk ==
  /\ AdvStep
  /\ Len(rev) < MaxRevs
  /\ rev' = Append(rev, NewRev({}, 1, Outsider, Unknown))
  /\ stored' = stored \cup {Len(rev) + 1}
  /\ UNCHANGED <<hidden, tampered, ctlHead, removal, cp, accepted, forged, bad>>

Hide == \E r \in stored :
          /\ AdvStep
          /\ stored' = stored \ {r}
          /\ hidden' = hidden \cup {r}
          /\ tampered' = TRUE
          /\ UNCHANGED <<rev, ctlHead, removal, cp, accepted, forged, bad>>

Replay == \E r \in hidden :
            /\ stored' = stored \cup {r}
            /\ hidden' = hidden \ {r}
            /\ UNCHANGED <<rev, tampered, ctlHead, removal, cp, accepted, forged, bad, adv>>

Init ==
  /\ rev = <<>>
  /\ stored = {}
  /\ hidden = {}
  /\ tampered = FALSE
  /\ ctlHead = 1
  /\ removal = "none"
  /\ cp = [d \in Writers |-> 0]
  /\ accepted = [d \in Writers |-> {}]
  /\ forged = FALSE
  /\ bad = {}
  /\ adv = MaxAdv

Next ==
  \/ \E d \in Writers : Read(d) \/ Write(d)
  \/ MWrite
  \/ ReencryptForRemoval \/ PublishRemoval \/ Rejoin \/ Compact
  \/ MSign \/ Junk \/ Hide \/ Replay

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
\* GEN-1: a read never succeeds on a view that lost a revision the device
\* accepted, unless a present revision of at least its Generation stands in
\* for it: one a current member signed, or one whose Generation is honest.
GEN_1 == "GEN_1" \notin bad

\* GEN-1, strict form (expected to FAIL, StateDAG_finding_removed_sibling.cfg):
\* a revision a removed member signed does not stand in, even with an honest
\* Generation.
GEN_1_strict == "GEN_1_strict" \notin bad

\* GEN-2: a rollback is reported only when storage withheld a revision at
\* some point, or M signed something outside the protocol.
GEN_2 == "GEN_2" \notin bad

\* GEN-2, strict form (expected to FAIL, StateDAG_finding_member_poison.cfg):
\* not even M signing outside the protocol produces a false rollback.
GEN_2_strict == "GEN_2_strict" \notin bad

\* GEN-3: the checkpoint never goes down.
GEN_3 == [][\A d \in Writers : cp'[d] >= cp[d]]_vars

\* GEN-4: an honest write never publishes a revision readers must reject.
GEN_4 == "GEN_4" \notin bad

\* REJOIN-1: once M was removed, a revision it signed under a Control from
\* before its removal is never read as current, even after it rejoined.
REJOIN_1 == "REJOIN_1" \notin bad

\* AUTH-3: content from a non-member is never read as current.
AUTH_3 == "AUTH_3" \notin bad

=============================================================================
