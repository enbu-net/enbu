---------------------------- MODULE ControlDAG ----------------------------
(***************************************************************************)
(* The signed Control DAG (pkg/wsp/chain.go, control.go) and how devices   *)
(* open it (app/session.go openControl / verifyControl / resolveFork).     *)
(*                                                                         *)
(* A Control is a record; its index in `ctl` stands for its digest. The    *)
(* genesis is ctl[1], the digest enbu.toml names. Storage is untrusted: it *)
(* may hide (delete) and replay any Control, and anyone may publish one.   *)
(* Signatures are modelled by a `signer` field: a device signs only as     *)
(* itself, so a Control whose signer is not its author has a bad           *)
(* signature.                                                              *)
(*                                                                         *)
(* Actors: honest admins (Admins), a malicious admin Evil (an admin of the *)
(* genesis that an honest admin may remove), the honest non-admin Member,  *)
(* which may also forge, and the Outsider, which can only write storage.   *)
(* Nobody honest ever grants the Outsider membership or Member an admin    *)
(* right, so AUTH_2 is ground truth, not a restatement of the verifier.    *)
(*                                                                         *)
(* Bug selects one deliberate defect for the mutant configs; "none" is the *)
(* implementation.                                                         *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS Admins, Evil, Member, Outsider, MaxSteps, Bug

Devices == Admins \cup {Evil, Member, Outsider}
Honest == Admins \cup {Member}
Keys == 1..2  \* a device that rejoins may come back with another key
NoKey == 0

Bugs == {"none", "no_admin_check", "admin_any_parent", "F4", "no_sig_check",
         "no_checkpoint", "proceed_on_fork", "no_auto_resolve"}
ASSUME Bug \in Bugs

VARIABLES
  ctl,      \* sequence of every Control ever signed (published or not)
  stored,   \* indices storage currently serves
  cp,       \* cp[d]: accepted Control heads (the local checkpoint)
  acc,      \* ghost: every Control d accepted so far
  status,   \* status[d]: result of d's last open
  okView,   \* ghost: the verified view d last proceeded on
  seen,     \* seen[a]: the single head an honest admin's session holds, or 0
  budget    \* adversary and membership-change steps left

vars == <<ctl, stored, cp, acc, status, okView, seen, budget>>

Genesis == [parents |-> {}, author |-> CHOOSE a \in Admins : TRUE,
            signer |-> CHOOSE a \in Admins : TRUE,
            mem |-> [d \in Devices |-> IF d \in Admins \cup {Evil, Member} THEN 1 ELSE NoKey],
            adm |-> Admins \cup {Evil}]

Members(c) == {d \in Devices : c.mem[d] # NoKey}

(***************************************************************************)
(* Verification: LoadControl accepts a Control once all its parents are    *)
(* accepted and VerifyChild passes. Parents always have a lower index (a   *)
(* digest cannot be named before it exists), so one pass in index order    *)
(* computes the fixpoint.                                                  *)
(***************************************************************************)
WellFormed(c) == c.adm \subseteq Members(c) /\ c.adm # {}

SigOK(c) == Bug = "no_sig_check" \/ c.signer = c.author

AuthorOK(c, P) ==
  CASE Bug = "no_admin_check"   -> TRUE
    [] Bug = "admin_any_parent" -> \E p \in P : c.author \in p.adm
    [] OTHER                    -> \A p \in P : c.author \in p.adm

\* checkResolution: keep only principals every parent lists with the same key,
\* admin only if admin in every parent. Before F4 the verifier accepted any
\* subset of the union, admin if an admin in some parent.
ResolutionOK(c, P) ==
  IF Bug = "F4"
  THEN /\ \A d \in Members(c) : \E p \in P : p.mem[d] = c.mem[d]
       /\ \A d \in c.adm : \E p \in P : d \in p.adm
  ELSE /\ \A d \in Members(c) : \A p \in P : p.mem[d] = c.mem[d]
       /\ \A d \in c.adm : \A p \in P : d \in p.adm

ChildOK(c, P) ==
  /\ WellFormed(c)
  /\ SigOK(c)
  /\ AuthorOK(c, P)
  /\ Cardinality(P) > 1 => ResolutionOK(c, P)

RECURSIVE VerifiedUpTo(_, _)
VerifiedUpTo(S, n) ==
  IF n = 0 THEN {}
  ELSE LET V == VerifiedUpTo(S, n - 1) IN
       IF n \in S /\ (n = 1 \/ (ctl[n].parents # {} /\ ctl[n].parents \subseteq V
                                /\ ChildOK(ctl[n], {ctl[p] : p \in ctl[n].parents})))
       THEN V \cup {n} ELSE V

Verified(S) == IF 1 \in S THEN VerifiedUpTo(S, Len(ctl)) ELSE {}
View == Verified(stored)
HeadsOf(V) == {v \in V : ~\E w \in V : v \in ctl[w].parents}
Heads == HeadsOf(View)
Forked == Cardinality(Heads) > 1
AdminOfAll(d, H) == \A h \in H : d \in ctl[h].adm
Hidden == \E i \in 1..Len(ctl) : i \notin stored /\ ctl[i].signer \in Admins \cup {Evil}

\* A Control's digest is its content: publishing one that exists again only
\* makes storage serve it.
IndexOf(c) == IF \E i \in 1..Len(ctl) : ctl[i] = c
              THEN CHOOSE i \in 1..Len(ctl) : ctl[i] = c ELSE Len(ctl) + 1
Publish(c) ==
  /\ ctl' = IF IndexOf(c) = Len(ctl) + 1 THEN Append(ctl, c) ELSE ctl
  /\ stored' = stored \cup {IndexOf(c)}

Init ==
  /\ ctl = <<Genesis>>
  /\ stored = {1}
  /\ cp = [d \in Honest |-> {}]
  /\ acc = [d \in Honest |-> {}]
  /\ status = [d \in Honest |-> "idle"]
  /\ okView = [d \in Honest |-> {}]
  /\ seen = [a \in Admins |-> 0]
  /\ budget = MaxSteps

(***************************************************************************)
(* An honest device opens the workspace: verifyControl, then openControl's *)
(* fork handling. An admin of every head joins them with the intersection  *)
(* (wsp.ResolveFork), which is not budgeted: it is the protocol's own      *)
(* response. Reading and publishing the resolution are one step; see the  *)
(* README for this abstraction.                                            *)
(***************************************************************************)
Resolution(d, H) ==
  LET any == CHOOSE h0 \in H : TRUE IN
  [parents |-> H, author |-> d, signer |-> d,
   mem |-> [x \in Devices |-> IF \A h \in H : ctl[h].mem[x] = ctl[any].mem[x]
                              THEN ctl[any].mem[x] ELSE NoKey],
   adm |-> {x \in Devices : \A h \in H : x \in ctl[h].adm}]

Open(d) ==
  LET V == View
      H == HeadsOf(V)
  IN
  IF 1 \notin stored
  THEN /\ status' = [status EXCEPT ![d] = "unavailable"]
       /\ UNCHANGED <<ctl, stored, cp, acc, okView, seen, budget>>
  ELSE IF ~(cp[d] \subseteq V) /\ Bug # "no_checkpoint"
  THEN /\ status' = [status EXCEPT ![d] = "rollback"]
       /\ UNCHANGED <<ctl, stored, cp, acc, okView, seen, budget>>
  ELSE IF Cardinality(H) = 1
  THEN /\ cp' = [cp EXCEPT ![d] = H]
       /\ acc' = [acc EXCEPT ![d] = acc[d] \cup V]
       /\ status' = [status EXCEPT ![d] = "ok"]
       /\ okView' = [okView EXCEPT ![d] = V]
       /\ seen' = IF d \in Admins THEN [seen EXCEPT ![d] = CHOOSE h \in H : TRUE] ELSE seen
       /\ UNCHANGED <<ctl, stored, budget>>
  ELSE IF d \in Admins /\ AdminOfAll(d, H) /\ Bug # "no_auto_resolve"
  THEN \* resolveFork, then acceptControlHead reloads and checkpoints
       LET r == IndexOf(Resolution(d, H))
           V2 == V \cup {r}
       IN /\ Publish(Resolution(d, H))
          /\ cp' = [cp EXCEPT ![d] = {r}]
          /\ acc' = [acc EXCEPT ![d] = acc[d] \cup V2]
          /\ status' = [status EXCEPT ![d] = "ok"]
          /\ okView' = [okView EXCEPT ![d] = V2]
          /\ seen' = [seen EXCEPT ![d] = r]
          /\ UNCHANGED budget
  ELSE /\ cp' = [cp EXCEPT ![d] = H]   \* AcceptControl records the forked heads
       /\ acc' = [acc EXCEPT ![d] = acc[d] \cup V]
       /\ IF Bug = "proceed_on_fork"
          THEN /\ status' = [status EXCEPT ![d] = "ok"]
               /\ okView' = [okView EXCEPT ![d] = V]
          ELSE /\ status' = [status EXCEPT ![d] = "forked"]
               /\ UNCHANGED okView
       /\ UNCHANGED <<ctl, stored, seen, budget>>

(***************************************************************************)
(* An honest admin changes members on the head its session read           *)
(* (UpdateControl). The session may be stale, which is how forks arise;    *)
(* RemoveMember appends to the view it re-encrypted under on purpose.      *)
(***************************************************************************)
Update(a, c) ==
  LET h == ctl[seen[a]] IN
  /\ budget > 0
  /\ Publish([parents |-> {seen[a]}, author |-> a, signer |-> a,
              mem |-> c.mem, adm |-> c.adm])
  /\ budget' = budget - 1
  /\ seen' = [seen EXCEPT ![a] = 0]
  /\ status' = [status EXCEPT ![a] = "idle"]
  /\ UNCHANGED <<cp, acc, okView>>

AdminChange(a) ==
  /\ seen[a] # 0
  /\ LET h == ctl[seen[a]] IN
     /\ a \in h.adm
     /\ \/ \E d \in Members(h) \ {a} :           \* RemoveMember / RemoveAdmin
             LET adm2 == h.adm \ {d} IN
             /\ adm2 # {}
             /\ Update(a, [mem |-> [h.mem EXCEPT ![d] = NoKey], adm |-> adm2])
        \/ \E k \in Keys :                       \* ApproveMember (rejoin)
             /\ h.mem[Member] = NoKey
             /\ Update(a, [mem |-> [h.mem EXCEPT ![Member] = k], adm |-> h.adm])

(***************************************************************************)
(* Adversaries. Evil signs children of any verified Control it is an admin *)
(* of, including ones its own removal superseded, and resolutions keeping  *)
(* the union. Member and Outsider forge Controls granting themselves admin, *)
(* signed by themselves or claiming an honest admin as author.             *)
(***************************************************************************)
Adv(c) == /\ budget > 0
          /\ IndexOf(c) = Len(ctl) + 1
          /\ Publish(c)
          /\ budget' = budget - 1
          /\ UNCHANGED <<cp, acc, status, okView, seen>>

EvilFork ==
  \E p \in View : \E d \in Members(ctl[p]) \ {Evil} :
    LET h == ctl[p] IN
    /\ Evil \in h.adm
    /\ h.adm \ {d} # {}
    /\ Adv([parents |-> {p}, author |-> Evil, signer |-> Evil,
            mem |-> [h.mem EXCEPT ![d] = NoKey], adm |-> h.adm \ {d}])

\* Evil joins two heads keeping the union, or exactly what an honest
\* resolution keeps, even when it is not an admin of every head.
EvilResolve ==
  \E H \in SUBSET Heads :
    /\ Cardinality(H) = 2
    /\ \E h \in H : Evil \in ctl[h].adm
    /\ \/ Adv([parents |-> H, author |-> Evil, signer |-> Evil,
               mem |-> [x \in Devices |-> IF \E h \in H : ctl[h].mem[x] # NoKey
                                          THEN ctl[CHOOSE h0 \in H : ctl[h0].mem[x] # NoKey].mem[x]
                                          ELSE NoKey],
               adm |-> UNION {ctl[h].adm : h \in H}])
       \/ Adv(Resolution(Evil, H))

Forge ==
  \E f \in {Member, Outsider}, p \in View, au \in {Member, Outsider, CHOOSE a \in Admins : TRUE} :
    /\ au \in {f, CHOOSE a \in Admins : TRUE}
    /\ Adv([parents |-> {p}, author |-> au, signer |-> f,
            mem |-> [ctl[p].mem EXCEPT ![f] = 1], adm |-> ctl[p].adm \cup {f}])

Hide == \E i \in stored : /\ budget > 0
                          /\ stored' = stored \ {i}
                          /\ budget' = budget - 1
                          /\ UNCHANGED <<ctl, cp, acc, status, okView, seen>>

Replay == \E i \in (1..Len(ctl)) \ stored :
            /\ stored' = stored \cup {i}
            /\ UNCHANGED <<ctl, budget, cp, acc, status, okView, seen>>

Next ==
  \/ \E d \in Honest : Open(d)
  \/ \E a \in Admins : AdminChange(a)
  \/ EvilFork \/ EvilResolve \/ Forge
  \/ Hide \/ Replay

Spec == Init /\ [][Next]_vars

\* Liveness: honest admins keep opening the workspace.
LiveSpec == Spec /\ \A a \in Admins : WF_vars(Open(a))

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
TypeOK ==
  /\ stored \subseteq 1..Len(ctl)
  /\ budget \in 0..MaxSteps
  /\ \A d \in Honest : status[d] \in {"idle", "ok", "forked", "rollback", "unavailable"}

\* AUTH-1: authority only flows from the parents: every accepted Control
\* other than the genesis was signed by its author, an admin of every parent.
AUTH_1 ==
  \A n \in View \ {1} :
    /\ ctl[n].signer = ctl[n].author
    /\ \A p \in ctl[n].parents : ctl[n].author \in ctl[p].adm

\* AUTH-2: storage write access grants nothing. Nobody honest grants the
\* Outsider membership or Member admin, so no accepted Control does.
AUTH_2 == \A n \in View : Outsider \notin Members(ctl[n]) /\ Member \notin ctl[n].adm

\* FORK-1: a resolution keeps only what every head agrees on.
FORK_1 ==
  \A n \in View :
    Cardinality(ctl[n].parents) > 1 =>
      /\ \A d \in Members(ctl[n]) : \A p \in ctl[n].parents : ctl[p].mem[d] = ctl[n].mem[d]
      /\ \A d \in ctl[n].adm : \A p \in ctl[n].parents : d \in ctl[p].adm

\* FORK-2: no device proceeds on a forked Control.
FORK_2 == \A d \in Honest : status[d] = "ok" => Cardinality(HeadsOf(okView[d])) = 1

\* CP-1: losing an accepted Control is detected: a device only proceeds on a
\* view holding every Control it accepted before.
CP_1 == \A d \in Honest : status[d] = "ok" => acc[d] \subseteq okView[d]

\* FORK-3 (liveness): a fork does not stay forever while an honest admin of
\* every head exists, unless storage withholds a published Control.
CommonAdminFork == Forked /\ \E a \in Admins : AdminOfAll(a, Heads)
FORK_3 == []<>(~CommonAdminFork \/ Hidden)

\* Example (expected to FAIL): without an admin of every head a fork is
\* never joined. Checked by ControlDAG_example_permanent.cfg.
EveryForkJoined == []<>(~Forked \/ Hidden)

\* Finding (expected to FAIL): an admin an honest admin removed still signs
\* Controls that verify, as children of the Controls that listed it, so it
\* can fork the DAG after its removal, and by removing the other admins in
\* its branch make the fork permanent. Checked by
\* ControlDAG_finding_removed_admin.cfg.
RemovedAdminSignsNothing ==
  \A r, c \in View :
    (ctl[r].author \in Admins /\ Evil \notin Members(ctl[r]) /\ c > r) => ctl[c].author # Evil

\* Finding (expected to FAIL): worse, the honest resolution of such a fork
\* keeps only what both heads list, so a member the removed admin dropped in
\* its branch leaves the workspace although no current admin removed it.
\* Checked by ControlDAG_finding_removed_admin_drops.cfg.
EvilOutAt == IF \E r \in 1..Len(ctl) : ctl[r].author \in Admins /\ Evil \notin Members(ctl[r])
             THEN CHOOSE r \in 1..Len(ctl) : ctl[r].author \in Admins /\ Evil \notin Members(ctl[r])
                                              /\ \A q \in 1..r - 1 : ~(ctl[q].author \in Admins /\ Evil \notin Members(ctl[q]))
             ELSE Len(ctl) + 1
Drops(c) == UNION {Members(ctl[p]) \ Members(ctl[c]) : p \in ctl[c].parents}
LegitDrops == UNION {Drops(c) : c \in {i \in 1..Len(ctl) : Cardinality(ctl[i].parents) = 1
                                    /\ (ctl[i].author \in Admins \/ (ctl[i].author = Evil /\ i < EvilOutAt))}}
LateEvilDrops == UNION {Drops(c) : c \in {i \in 1..Len(ctl) : ctl[i].author = Evil /\ i > EvilOutAt}}
RemovedAdminRemovesNobody ==
  Cardinality(Heads) = 1 =>
    \A d \in LateEvilDrops \ LegitDrops : d \in Members(ctl[CHOOSE h \in Heads : TRUE])

=============================================================================
