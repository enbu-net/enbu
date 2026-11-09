---------------------------- MODULE ControlDAG ----------------------------
(***************************************************************************)
(* The signed Control DAG (pkg/wsp/control.go, pkg/wsp/chain.go) and the  *)
(* way the app opens it (app/session.go openControl, verifyControl).      *)
(*                                                                         *)
(* Storage is untrusted. The attacker publishes Controls of its own,       *)
(* signed with a key in Compromised or carrying a forged signature, and    *)
(* shows the reader any subset of what was ever published. Honest admins   *)
(* change members on top of the view they opened last, which may be stale  *)
(* (RemoveMember appends to the view it re-encrypted under), so two of     *)
(* them fork the DAG; an admin of every head joins the fork with the       *)
(* principals and admin rights every head agrees on (ADR-25).             *)
(*                                                                         *)
(* Property names carry the IDs of spec/INVARIANTS.md.                     *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Devices,        \* every device identity in the model
    Honest,         \* devices of honest admins and members
    Compromised,    \* devices whose signing key the attacker holds
    Reader,         \* the honest device whose checkpoint storage attacks
    GenesisRoles,   \* [Devices -> Roles]: the trusted genesis Control
    MaxControls,    \* bound on Controls in storage, genesis included
    MaxChanges,     \* bound on honest membership changes
    MaxAttacks,     \* bound on Controls the attacker publishes
    ReaderActs,     \* whether Reader opens views storage chooses
    PromoteCompromised, \* whether honest admins may make a leaked key an admin
    Mutant          \* "none" or a seeded bug, see Mutants

Roles == {"none", "member", "admin"}

Mutants == {"none", "any-parent-admin", "skip-signature", "skip-resolution-check",
            "skip-checkpoint", "resolve-union", "forked-proceeds"}

ASSUME Honest \subseteq Devices /\ Compromised \subseteq Devices /\ Honest \cap Compromised = {}
ASSUME Reader \in Honest
ASSUME GenesisRoles \in [Devices -> Roles]
ASSUME Mutant \in Mutants

VARIABLES
    store,      \* every Control ever published
    ver,        \* Verified(store), kept so properties need not recompute it
    honestIds,  \* ids of the Controls honest admins published
    nextId,
    changes,    \* honest membership changes so far
    attacks,    \* Controls the attacker published so far
    snap,       \* [Honest -> SUBSET ids]: verified DAG an admin opened last
    cp,         \* accepted Control heads of Reader (its checkpoint)
    everCp,     \* every Control head Reader ever accepted
    rview,      \* ids of the verified DAG of Reader's last open
    rsession    \* head of Reader's last session, or -1 when it has none

vars == <<store, ver, honestIds, nextId, changes, attacks, snap, cp, everCp, rview, rsession>>

Genesis == [id |-> 0, parents |-> {}, height |-> 0, roles |-> GenesisRoles,
            author |-> CHOOSE d \in Devices : GenesisRoles[d] = "admin", sig |-> TRUE]

Ids(S) == {c.id : c \in S}
ById(I) == {c \in store : c.id \in I}
IsAdmin(c, d) == d \in Devices /\ c.roles[d] = "admin"
IsPrincipal(c, d) == d \in Devices /\ c.roles[d] # "none"
HasAdmin(r) == \E d \in Devices : r[d] = "admin"
MaxHeight(P) == CHOOSE h \in {p.height : p \in P} : \A p \in P : p.height <= h

(***************************************************************************)
(* Verification, as VerifyChild and checkResolution do it.                 *)
(***************************************************************************)
ResolutionOK(c, P) ==
    \A d \in Devices :
        /\ IsPrincipal(c, d) => \E p \in P : IsPrincipal(p, d)
        /\ IsAdmin(c, d) => \E p \in P : IsAdmin(p, d)

ValidChild(c, V) ==
    LET P == {p \in V : p.id \in c.parents} IN
    /\ c.parents # {}
    /\ Ids(P) = c.parents
    /\ c.height = MaxHeight(P) + 1
    /\ IF Mutant = "any-parent-admin"
         THEN \E p \in P : IsAdmin(p, c.author)
         ELSE \A p \in P : IsAdmin(p, c.author)
    /\ c.sig \/ Mutant = "skip-signature"
    /\ HasAdmin(c.roles)
    /\ (Cardinality(P) > 1 /\ Mutant # "skip-resolution-check") => ResolutionOK(c, P)

RECURSIVE Close(_, _)
Close(S, V) ==
    LET new == {c \in S \ V : ValidChild(c, V)} IN
    IF new = {} THEN V ELSE Close(S, V \cup new)

\* The verified DAG of what storage shows. The genesis is fetched by its
\* trusted digest; without it nothing verifies.
Verified(S) == IF Genesis \in S THEN Close(S, {Genesis}) ELSE {}

Heads(V) == {c \in V : ~\E k \in V : c.id \in k.parents}

\* What every head agrees on (app.resolveFork) and what any head grants.
Intersection(H) ==
    [d \in Devices |->
        IF \A h \in H : IsAdmin(h, d) THEN "admin"
        ELSE IF \A h \in H : IsPrincipal(h, d) THEN "member" ELSE "none"]

Union(H) ==
    [d \in Devices |->
        IF \E h \in H : IsAdmin(h, d) THEN "admin"
        ELSE IF \E h \in H : IsPrincipal(h, d) THEN "member" ELSE "none"]

-----------------------------------------------------------------------------
Init ==
    /\ store = {Genesis}
    /\ ver = {Genesis}
    /\ honestIds = {0}
    /\ nextId = 1
    /\ changes = 0
    /\ attacks = 0
    /\ snap = [d \in Honest |-> {}]
    /\ cp = {}
    /\ everCp = {}
    /\ rview = {}
    /\ rsession = -1

Publish(c) ==
    /\ store' = store \cup {c}
    /\ ver' = Verified(store \cup {c})
    /\ nextId' = nextId + 1

\* An honest admin opens the workspace on what storage holds now. It acts on
\* this snapshot later, possibly after others moved on.
Snapshot(d) ==
    /\ snap' = [snap EXCEPT ![d] = Ids(ver)]
    /\ UNCHANGED <<store, ver, honestIds, nextId, changes, attacks, cp, everCp, rview, rsession>>

\* wsp.UpdateControl: one principal changes on top of the single head of the
\* snapshot. Honest admins never promote a device whose key the attacker holds.
Update(d, t, r) ==
    /\ nextId < MaxControls
    /\ changes < MaxChanges
    /\ LET H == Heads(ById(snap[d])) IN
       /\ Cardinality(H) = 1
       /\ LET h == CHOOSE k \in H : TRUE
              roles == [h.roles EXCEPT ![t] = r] IN
          /\ IsAdmin(h, d)
          /\ h.roles[t] # r
          /\ (r = "admin" /\ ~PromoteCompromised) => t \notin Compromised
          /\ HasAdmin(roles)
          /\ Publish([id |-> nextId, parents |-> {h.id}, height |-> h.height + 1,
                      roles |-> roles, author |-> d, sig |-> TRUE])
          /\ honestIds' = honestIds \cup {nextId}
          /\ changes' = changes + 1
          /\ UNCHANGED <<attacks, snap, cp, everCp, rview, rsession>>

\* app.resolveFork: an admin of every head of its snapshot joins them.
Resolve(d) ==
    /\ nextId < MaxControls
    /\ LET H == Heads(ById(snap[d])) IN
       /\ Cardinality(H) > 1
       /\ \A h \in H : IsAdmin(h, d)
       /\ LET roles == IF Mutant = "resolve-union" THEN Union(H) ELSE Intersection(H) IN
          /\ HasAdmin(roles)
          /\ Publish([id |-> nextId, parents |-> Ids(H), height |-> MaxHeight(H) + 1,
                      roles |-> roles, author |-> d, sig |-> TRUE])
          /\ honestIds' = honestIds \cup {nextId}
          /\ UNCHANGED <<changes, attacks, snap, cp, everCp, rview, rsession>>

\* The attacker builds on any Controls in storage: it makes any device an
\* admin or removes it, or claims everything the parents granted. It signs
\* with a key it holds, or claims an honest author with a forged signature.
AttackRoles(P) ==
    {[p.roles EXCEPT ![t] = r] : p \in P, t \in Devices, r \in {"admin", "none"}}
    \cup {Union(P)}

Attack ==
    /\ attacks < MaxAttacks
    /\ nextId < MaxControls
    /\ \E P \in (SUBSET store) \ {{}}, a \in Devices :
         \E roles \in AttackRoles(P) :
           /\ HasAdmin(roles)
           /\ Publish([id |-> nextId, parents |-> Ids(P), height |-> MaxHeight(P) + 1,
                       roles |-> roles, author |-> a, sig |-> a \in Compromised])
           /\ attacks' = attacks + 1
           /\ UNCHANGED <<honestIds, changes, snap, cp, everCp, rview, rsession>>

\* Reader opens the workspace on whatever subset storage shows (LoadControl,
\* Checkpoints.AcceptControl, openControl). A forked view gives no session.
ReaderOpen(S) ==
    LET V == Verified(S) H == Heads(V) IN
    /\ IF V # {} /\ (cp \subseteq Ids(V) \/ Mutant = "skip-checkpoint") THEN
          /\ cp' = Ids(H)
          /\ everCp' = everCp \cup Ids(H)
          /\ rview' = Ids(V)
          /\ rsession' = IF Cardinality(H) = 1 THEN (CHOOSE h \in H : TRUE).id
                         ELSE IF Mutant = "forked-proceeds" THEN (CHOOSE h \in H : \A k \in H : h.id <= k.id).id
                         ELSE -1
       ELSE \* incompatible_storage or rollback_detected: nothing is accepted
          /\ rsession' = -1
          /\ UNCHANGED <<cp, everCp, rview>>
    /\ UNCHANGED <<store, ver, honestIds, nextId, changes, attacks, snap>>

ReaderStep == ReaderActs /\ \E S \in SUBSET store : ReaderOpen(S)

Next ==
    \/ \E d \in Honest : Snapshot(d)
    \/ \E d \in Honest, t \in Devices, r \in Roles : Update(d, t, r)
    \/ \E d \in Honest : Resolve(d)
    \/ Attack
    \/ ReaderStep

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                            *)

TypeOK ==
    /\ cp \subseteq Nat /\ everCp \subseteq Nat /\ rview \subseteq Nat
    /\ rsession \in Nat \cup {-1}
    /\ snap \in [Honest -> SUBSET Nat]

AttackerHoldsAdminKey == \E c \in ver, k \in Compromised : IsAdmin(c, k)

\* AUTH-1: storage access, member keys and forged signatures make no Control
\* verify: every principal and admin right comes from an honest admin.
OnlyHonestControlsVerify ==
    ~AttackerHoldsAdminKey => Ids(ver) \subseteq honestIds

\* AUTH-2: only an admin of every parent can sign a verified child.
ChildrenSignedByAdminsOfEveryParent ==
    \A c \in ver :
        c.parents # {} =>
            \A p \in ver : p.id \in c.parents => IsAdmin(p, c.author)

\* FORK-1: a verified resolution keeps only what its parents listed.
ResolutionsStayInsideParents ==
    \A c \in ver :
        Cardinality(c.parents) > 1 =>
            ResolutionOK(c, {p \in ver : p.id \in c.parents})

\* FORK-4: an honest resolution keeps exactly what every head agrees on, so a
\* device removed or demoted on any branch stays removed or demoted.
HonestResolutionIsIntersection ==
    \A c \in store :
        (c.id \in honestIds /\ Cardinality(c.parents) > 1) =>
            c.roles = Intersection({p \in store : p.id \in c.parents})

\* FORK-2: no session runs on a forked view.
NoSessionWhileForked ==
    rsession # -1 => Cardinality(Heads(ById(rview))) = 1

\* CP-1: a session's view contains every Control Reader ever accepted.
AcceptedNeverHidden ==
    rsession # -1 => everCp \subseteq rview

\* CP-2: the checkpoint names only Controls that verified.
CheckpointOnlyVerified == cp \subseteq Ids(ver)

\* FORK-3: whenever storage holds a fork and an honest device is an admin of
\* every head, its join verifies and leaves a single head.
ForkCanBeJoined ==
    LET H == Heads(ver) IN
    (Cardinality(H) > 1) =>
        \A d \in Honest :
            (\A h \in H : IsAdmin(h, d)) =>
                LET j == [id |-> nextId, parents |-> Ids(H), height |-> MaxHeight(H) + 1,
                          roles |-> Intersection(H), author |-> d, sig |-> TRUE] IN
                ~HasAdmin(j.roles) \/ Heads(Verified(store \cup {j})) = {j}

(* Reachability witnesses: formalcheck expects TLC to violate each of these,
   which proves the configuration reaches the situation the properties are
   about instead of passing vacuously. *)
WitnessNoFork == Cardinality(Heads(ver)) <= 1
WitnessNoJoin == ~\E c \in ver : Cardinality(c.parents) > 1
WitnessNoForkedOpen == ~(ReaderActs /\ rview # {} /\ Cardinality(Heads(ById(rview))) > 1)
WitnessNoAttackStored == attacks = 0
=============================================================================
