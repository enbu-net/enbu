--------------------------- MODULE MemberChange ---------------------------
(***************************************************************************)
(* Member changes against concurrent writes (app/members.go RemoveMember, *)
(* ApproveMember, changeMembers; app/reencrypt.go reencryptAll /          *)
(* reencryptHeads; app/session.go resolveFork; app/publish.go writeState). *)
(*                                                                         *)
(* Admin R1 removes M: it re-encrypts every head without M under the      *)
(* Control that still lists M, then publishes the Control without M on    *)
(* the view it re-encrypted under. Admin R2 approves N concurrently: it   *)
(* publishes the Control first, then re-encrypts for the new set. Member  *)
(* W writes. When the Control forks, an admin of every head joins it with *)
(* the intersection and re-encrypts (openControl). Everyone is honest;    *)
(* only storage errors (a failed re-encryption) and timing vary.          *)
(*                                                                         *)
(* A Control is [parents, author, mem]; a revision is [parents, author,   *)
(* ctl, rcpt, cur, win]: the Control it names, its recipients, and (ghost) *)
(* the Control heads current when it was published and whether R1's       *)
(* removal was between re-encrypting and publishing then. Index = digest. *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS R1, R2, W, M, N, MaxAttempts, Writes, Bug

Admins == {R1, R2}
Procs == {R1, R2, W}

Bugs == {"none", "reverse_removal_order", "no_control_check", "approve_no_reencrypt",
         "removal_includes_member", "resolve_no_reencrypt"}
ASSUME Bug \in Bugs

VARIABLES
  ctl,       \* the Control DAG (no forgery here; every Control verifies)
  rev,       \* the revisions of the one environment
  pc,        \* pc[p]: where each process is
  sess,      \* sess[p]: the Control head the process's session verified
  read,      \* read[W]: the heads W read and merges
  before,    \* the Control head R1 re-encrypted under
  attempts,  \* W's attempts at its current write
  wleft      \* writes W has still to start

vars == <<ctl, rev, pc, sess, read, before, attempts, wleft>>

CHeads == {c \in 1..Len(ctl) : ~\E d \in 1..Len(ctl) : c \in ctl[d].parents}
Forked == Cardinality(CHeads) > 1
CHead == CHOOSE c \in CHeads : TRUE
Mem(c) == ctl[c].mem
AdminOf(a, c) == a \in Mem(c)   \* R1 and R2 are admins wherever they are members

RHeads == {r \in 1..Len(rev) : ~\E s \in 1..Len(rev) : r \in rev[s].parents}

RemovalInProgress == pc[R1] \in {"reencrypt", "publish"}

NewRev(parents, author, c, rcpt) ==
  [parents |-> parents, author |-> author, ctl |-> c, rcpt |-> rcpt, cur |-> CHeads,
   win |-> RemovalInProgress /\ author # R1]

\* Re-encrypt every head on its own (reencryptHeads) or merge them all into
\* one revision (changeResource sync); both name Control c.
RECURSIVE SyncEach(_, _, _, _, _)
SyncEach(s, H, a, c, rcpt) ==
  IF H = {} THEN s
  ELSE LET h == CHOOSE x \in H : TRUE IN
       SyncEach(Append(s, NewRev({h}, a, c, rcpt)), H \ {h}, a, c, rcpt)

SyncMerge(a, c) ==
  IF RHeads = {} THEN rev ELSE Append(rev, NewRev(RHeads, a, c, Mem(c)))

Genesis == [parents |-> {}, author |-> R1, mem |-> {R1, R2, W, M}]

Init ==
  /\ ctl = <<Genesis>>
  /\ rev = <<[parents |-> {}, author |-> W, ctl |-> 1, rcpt |-> {R1, R2, W, M}, cur |-> {1}, win |-> FALSE]>>
  /\ pc = [p \in Procs |-> "start"]
  /\ sess = [p \in Procs |-> 0]
  /\ read = {}
  /\ before = 0
  /\ attempts = 0
  /\ wleft = Writes - 1

(***************************************************************************)
(* openControl on a fork: an admin of every head publishes the            *)
(* intersection and re-encrypts (resolveFork). Others fail with           *)
(* control_forked. Joining and re-encrypting are one step here.            *)
(***************************************************************************)
Resolution(a) == [parents |-> CHeads, author |-> a,
                  mem |-> {d \in Mem(CHead) : \A h \in CHeads : d \in Mem(h)}]

Resolve(a) ==
  /\ Forked
  /\ \A h \in CHeads : AdminOf(a, h)
  /\ ctl' = Append(ctl, Resolution(a))
  /\ LET c == Len(ctl) + 1 IN
     rev' = IF Bug = "resolve_no_reencrypt" \/ RHeads = {} THEN rev
            ELSE Append(rev, [parents |-> RHeads, author |-> a, ctl |-> c,
                              rcpt |-> Resolution(a).mem, cur |-> {c}, win |-> RemovalInProgress /\ a # R1])

\* Any admin may open the workspace at any time (enbu pull, enbu member ...).
AdminOpen(a) ==
  /\ Resolve(a)
  /\ UNCHANGED <<pc, sess, read, before, attempts, wleft>>

(***************************************************************************)
(* R1: RemoveMember(M).                                                    *)
(***************************************************************************)
RemoveOpen ==
  /\ pc[R1] = "start" /\ ~Forked
  /\ before' = CHead
  /\ pc' = [pc EXCEPT ![R1] = IF Bug = "reverse_removal_order" THEN "publish" ELSE "reencrypt"]
  /\ UNCHANGED <<ctl, rev, sess, read, attempts, wleft>>

\* reencryptHeads: under the current Control, every head re-encrypted on its
\* own without M. A storage failure stops the removal here.
RemoveReencrypt ==
  /\ pc[R1] = "reencrypt" /\ ~Forked
  /\ \/ /\ rev' = SyncEach(rev, RHeads, R1, CHead,
                           IF Bug = "removal_includes_member" THEN Mem(CHead) ELSE Mem(CHead) \ {M})
        /\ pc' = [pc EXCEPT ![R1] = IF Bug = "reverse_removal_order" THEN "done" ELSE "publish"]
     \/ /\ pc' = [pc EXCEPT ![R1] = "failed"]
        /\ UNCHANGED rev
  /\ UNCHANGED <<ctl, sess, read, before, attempts, wleft>>

\* changeMembers on the view it re-encrypted under; a Control another admin
\* published meanwhile forks the DAG on purpose.
RemovePublish ==
  /\ pc[R1] = "publish"
  /\ M \in Mem(before)
  /\ ctl' = Append(ctl, [parents |-> {before}, author |-> R1, mem |-> Mem(before) \ {M}])
  /\ pc' = [pc EXCEPT ![R1] = IF Bug = "reverse_removal_order" THEN "reencrypt" ELSE "done"]
  /\ UNCHANGED <<rev, sess, read, before, attempts, wleft>>

\* A fork in the way of R1's session: join it if R1 can, or fail.
R1Forked ==
  /\ pc[R1] \in {"start", "reencrypt"} /\ Forked
  /\ IF \A h \in CHeads : AdminOf(R1, h)
     THEN Resolve(R1) /\ UNCHANGED pc
     ELSE pc' = [pc EXCEPT ![R1] = "failed"] /\ UNCHANGED <<ctl, rev>>
  /\ UNCHANGED <<sess, read, before, attempts, wleft>>

(***************************************************************************)
(* R2: ApproveMember(N): publish the Control, then re-encrypt everything.  *)
(***************************************************************************)
ApprovePublish ==
  /\ pc[R2] = "start" /\ ~Forked
  /\ N \notin Mem(CHead) /\ AdminOf(R2, CHead)
  /\ ctl' = Append(ctl, [parents |-> {CHead}, author |-> R2, mem |-> Mem(CHead) \cup {N}])
  /\ pc' = [pc EXCEPT ![R2] = IF Bug = "approve_no_reencrypt" THEN "done" ELSE "reencrypt"]
  /\ UNCHANGED <<rev, sess, read, before, attempts, wleft>>

ApproveReencrypt ==
  /\ pc[R2] = "reencrypt" /\ ~Forked
  /\ rev' = SyncMerge(R2, CHead)
  /\ pc' = [pc EXCEPT ![R2] = "done"]
  /\ UNCHANGED <<ctl, sess, read, before, attempts, wleft>>

R2Forked ==
  /\ pc[R2] \in {"start", "reencrypt"} /\ Forked
  /\ IF \A h \in CHeads : AdminOf(R2, h)
     THEN Resolve(R2) /\ UNCHANGED pc
     ELSE pc' = [pc EXCEPT ![R2] = "failed"] /\ UNCHANGED <<ctl, rev>>
  /\ UNCHANGED <<sess, read, before, attempts, wleft>>

(***************************************************************************)
(* W: changeResource, with both control checks of writeState.              *)
(***************************************************************************)

ControlUnchanged == Bug = "no_control_check" \/ (~Forked /\ CHead = sess[W])

WRetry(next) ==
  IF attempts + 1 >= MaxAttempts
  THEN pc' = [pc EXCEPT ![W] = "conflict"] /\ attempts' = attempts + 1
  ELSE pc' = [pc EXCEPT ![W] = next] /\ attempts' = attempts + 1

WOpen ==
  /\ pc[W] = "start"
  /\ IF Forked
     THEN pc' = [pc EXCEPT ![W] = "forked"] /\ UNCHANGED <<sess, read>>
     ELSE /\ sess' = [sess EXCEPT ![W] = CHead]
          /\ read' = RHeads
          /\ pc' = [pc EXCEPT ![W] = "recheck"]
  /\ UNCHANGED <<ctl, rev, before, attempts, wleft>>

\* Look once more just before publishing: heads that moved mean read again.
WRecheck ==
  /\ pc[W] = "recheck"
  /\ IF RHeads # read THEN WRetry("start") ELSE pc' = [pc EXCEPT ![W] = "publish"] /\ UNCHANGED attempts
  /\ UNCHANGED <<ctl, rev, sess, read, before, wleft>>

\* writeState: encrypt for the session's set, check the Control, publish.
WPublish ==
  /\ pc[W] = "publish"
  /\ IF ~ControlUnchanged
     THEN WRetry("start") /\ UNCHANGED rev               \* errControlMoved before publishing
     ELSE /\ rev' = Append(rev, NewRev(read, W, sess[W], Mem(sess[W])))
          /\ pc' = [pc EXCEPT ![W] = "check"]
          /\ UNCHANGED attempts
  /\ UNCHANGED <<ctl, sess, read, before, wleft>>

WCheck ==
  /\ pc[W] = "check"
  /\ IF ~ControlUnchanged
     THEN WRetry("start")                                  \* published, but publish again for the new set
     ELSE pc' = [pc EXCEPT ![W] = "done"] /\ UNCHANGED attempts
  /\ UNCHANGED <<ctl, rev, sess, read, before, wleft>>

\* W starts its next write.
WNext ==
  /\ pc[W] \in {"done", "conflict"} /\ wleft > 0
  /\ pc' = [pc EXCEPT ![W] = "start"]
  /\ wleft' = wleft - 1
  /\ attempts' = 0
  /\ UNCHANGED <<ctl, rev, sess, read, before>>

Next ==
  \/ RemoveOpen \/ RemoveReencrypt \/ RemovePublish \/ R1Forked
  \/ ApprovePublish \/ ApproveReencrypt \/ R2Forked
  \/ WOpen \/ WRecheck \/ WPublish \/ WCheck \/ WNext
  \/ \E a \in Admins : AdminOpen(a)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
Terminal == {"done", "failed", "conflict", "forked"}
Quiescent == (\A p \in Procs : pc[p] \in Terminal) /\ wleft = 0 /\ ~Forked

\* RCPT-1: recipients come only from the Control a revision names.
RCPT_1 == \A r \in 1..Len(rev) : rev[r].rcpt \subseteq Mem(rev[r].ctl)

\* RCPT-2: nothing is published encrypted for a device that is not a member
\* of every Control head current at that moment: a revision published after
\* a removal is never encrypted for the removed member.
RCPT_2 == \A r \in 1..Len(rev) : \A h \in rev[r].cur : rev[r].rcpt \subseteq Mem(h)

\* RCPT-3: a removal whose re-encryption fails leaves the Control unchanged.
RCPT_3 == pc[R1] = "failed" => ~\E c \in 1..Len(ctl) : ctl[c].author = R1 /\ M \notin Mem(c) /\ Cardinality(ctl[c].parents) = 1

\* RCPT-4: once the changes settle, no head is encrypted for a non-member,
\* except one published while a removal was between re-encrypting and
\* publishing its Control: that one was written while the member still was
\* one, and stays readable by it until the next write.
RCPT_4 == Quiescent => \A h \in RHeads : rev[h].rcpt \subseteq Mem(CHead) \/ rev[h].win

\* RCPT-4 without the exception (expected to FAIL, MemberChange_example_removal_window.cfg).
RCPT_4_strict == Quiescent => \A h \in RHeads : rev[h].rcpt \subseteq Mem(CHead)

\* RESOLVE-1: joining a fork re-encrypts: once the changes settle, every head
\* names the latest fork resolution or a later Control.
RESOLVE_1 == Quiescent => \A h \in RHeads, c \in 1..Len(ctl) :
               Cardinality(ctl[c].parents) > 1 => rev[h].ctl >= c

\* APPROVE-1: once the changes settle without a failure, every member can
\* read every head.
APPROVE_1 == (Quiescent /\ pc[R1] # "failed" /\ pc[R2] # "failed") =>
               \A h \in RHeads : Mem(CHead) \subseteq rev[h].rcpt

=============================================================================
