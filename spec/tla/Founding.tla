----------------------------- MODULE Founding -----------------------------
(***************************************************************************)
(* Founding a workspace and pinning trust roots (app/init.go               *)
(* ensureControl, foundGenesis; app/session.go verifyControl;              *)
(* pkg/wsp/trust.go; ADR-27).                                              *)
(*                                                                         *)
(* Device D runs `enbu init` and later commands in one repository. It can  *)
(* crash after any step and start over; files (enbu.toml, trust.json,      *)
(* storage) survive. The attacker commits any workspace ID and genesis to  *)
(* enbu.toml through Git and publishes geneses of its own; another honest  *)
(* device O may found the same workspace in the same storage at once.      *)
(* D replaces a pin (--accept-new-genesis) only for a genesis an honest    *)
(* admin re-founded and confirmed out of band.                             *)
(*                                                                         *)
(* Before D's first successful pin, enbu.toml is trusted on first use: the *)
(* properties hold from D's first pin on.                                  *)
(*                                                                         *)
(* Property names carry the IDs of spec/INVARIANTS.md.                     *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Workspaces,     \* workspace IDs enbu.toml may name
    AttackerActs,   \* whether the attacker edits enbu.toml and storage
    OtherFounds,    \* whether O founds the same workspace concurrently
    MaxCrashes,     \* bound on crashes of D
    MaxEdits,       \* bound on attacker edits
    Mutant          \* "none" or a seeded bug, see Mutants

D == "D"  O == "O"  X == "X"   \* founder, other honest device, attacker
None == 0          \* no genesis (ids start at 1)
NoWs == ""         \* no workspace
NoSession == [ws |-> NoWs, genesis |-> None]

Mutants == {"none", "split-pin", "found-over-others", "adopt-any-genesis",
            "pin-before-verify", "founded-without-author-check", "toml-before-publish"}
ASSUME Mutant \in Mutants

VARIABLES
    storage,    \* geneses published: [id, ws, author]
    requests,   \* workspaces storage holds join requests for
    toml,       \* enbu.toml: [ws, genesis] (genesis is an id or None)
    wsPin,      \* trust.json workspaces: [Workspaces -> id or None]
    repoPin,    \* trust.json repositories, for this one enbu.toml: ws or NoWs
    pc,         \* D's step
    local,      \* D's in-memory state: enbu.toml as loaded (ws, genesis), founded
    session,    \* root of D's last successful session, or NoSession
    crashes, edits,
    everPinned, \* whether D ever pinned anything
    firstHonest,\* whether the first root D pinned was made by an honest device
    confirmed   \* geneses an honest admin re-founded and confirmed

vars == <<storage, requests, toml, wsPin, repoPin, pc, local, session, crashes, edits, everPinned, firstHonest, confirmed>>

Ids == {g.id : g \in storage}
G(i) == CHOOSE g \in storage : g.id = i
NextId == Cardinality(storage) + 1
Honest(i) == i \in Ids /\ G(i).author \in {D, O}

Init ==
    /\ storage = {}
    /\ requests = {}
    /\ toml = [ws |-> CHOOSE w \in Workspaces : TRUE, genesis |-> None]
    /\ wsPin = [w \in Workspaces |-> None]
    /\ repoPin = NoWs
    /\ pc = "start"
    /\ local = [ws |-> NoWs, founded |-> FALSE, genesis |-> None, sawOthers |-> FALSE]
    /\ session = NoSession
    /\ crashes = 0
    /\ edits = 0
    /\ everPinned = FALSE
    /\ firstHonest = FALSE
    /\ confirmed = {}

Goto(s) == pc' = s
Fail(r) == /\ pc' = "done" /\ session' = NoSession
Keep == UNCHANGED <<storage, requests, toml, wsPin, repoPin, crashes, edits, everPinned, firstHonest, confirmed>>

\* A command loads enbu.toml once and works on that copy (s.cfg).
\* ensureControl, first branch: enbu.toml names no genesis.
Start ==
    /\ pc = "start"
    /\ local' = [ws |-> toml.ws, founded |-> FALSE, genesis |-> toml.genesis, sawOthers |-> FALSE]
    /\ IF toml.genesis = None
       THEN IF wsPin[toml.ws] # None
            THEN Fail("trust_root_changed")       \* a pinned device never founds again
            ELSE /\ Goto("find") /\ UNCHANGED session
       ELSE /\ Goto("own-check") /\ UNCHANGED session
    /\ Keep

\* foundGenesis: adopt a genesis of this workspace this device signed (a lost
\* publish reply); otherwise storage must hold nothing of the workspace.
Find ==
    /\ pc = "find"
    /\ LET own == {g \in storage : g.ws = local.ws /\ (g.author = D \/ Mutant = "adopt-any-genesis")} IN
       IF own # {}
       THEN /\ local' = [local EXCEPT !.genesis = (CHOOSE g \in own : \A h \in own : g.id <= h.id).id]
            /\ Goto("save")
            /\ UNCHANGED session
       ELSE IF (\E g \in storage : g.ws = local.ws) \/ local.ws \in requests
            THEN IF Mutant = "found-over-others"
                 THEN /\ Goto("publish") /\ UNCHANGED session
                      /\ local' = [local EXCEPT !.sawOthers = TRUE]
                 ELSE /\ Fail("incompatible_storage") /\ UNCHANGED local
            ELSE /\ Goto(IF Mutant = "toml-before-publish" THEN "save-early" ELSE "publish")
                 /\ UNCHANGED <<local, session>>
    /\ Keep

Publish ==
    /\ pc = "publish"
    /\ storage' = storage \cup {[id |-> NextId, ws |-> local.ws, author |-> D]}
    /\ local' = [local EXCEPT !.genesis = NextId]
    /\ Goto(IF Mutant = "toml-before-publish" THEN "verify" ELSE "save")
    /\ UNCHANGED <<requests, toml, wsPin, repoPin, session, crashes, edits, everPinned, firstHonest, confirmed>>

\* enbu.toml names the genesis only after its publish returned.
Save ==
    /\ pc = "save"
    /\ toml' = [ws |-> local.ws, genesis |-> local.genesis]
    /\ local' = [local EXCEPT !.founded = TRUE]
    /\ Goto("verify")
    /\ UNCHANGED <<storage, requests, wsPin, repoPin, session, crashes, edits, everPinned, firstHonest, confirmed>>

\* The seeded bug: enbu.toml names a genesis before it is published.
SaveEarly ==
    /\ pc = "save-early"
    /\ toml' = [ws |-> local.ws, genesis |-> NextId]
    /\ local' = [local EXCEPT !.founded = TRUE, !.genesis = NextId]
    /\ Goto("publish")
    /\ UNCHANGED <<storage, requests, wsPin, repoPin, session, crashes, edits, everPinned, firstHonest, confirmed>>

\* A genesis this device signed and has not pinned is its own founding, left
\* by an attempt that stopped before pinning it.
OwnCheck ==
    /\ pc = "own-check"
    /\ local' = [local EXCEPT !.founded =
                    wsPin[local.ws] = None /\ local.genesis \in Ids /\ G(local.genesis).ws = local.ws
                    /\ (G(local.genesis).author = D \/ Mutant = "founded-without-author-check")]
    /\ Goto("verify")
    /\ UNCHANGED session
    /\ Keep

Conflict(ws, g, mode) ==
    \/ (mode # "replace" /\ wsPin[ws] # None /\ wsPin[ws] # g)
    \/ (mode = "first" /\ repoPin # NoWs /\ repoPin # ws)

\* verifyControl: check the pins, verify the genesis in storage, then pin.
Verify(mode) ==
    /\ pc = "verify"
    /\ LET ws == local.ws g == local.genesis
           exists == g \in Ids /\ G(g).ws = ws IN
       IF Conflict(ws, g, mode) THEN /\ Fail("trust_root_changed") /\ Keep
       ELSE IF ~exists /\ Mutant # "pin-before-verify" THEN /\ Fail("incompatible_storage") /\ Keep
       ELSE IF Mutant = "split-pin" THEN
            \* two files written one after the other (the design ADR-27 replaced)
            /\ wsPin' = [wsPin EXCEPT ![ws] = g]
            /\ everPinned' = TRUE
            /\ firstHonest' = IF everPinned THEN firstHonest ELSE Honest(g)
            /\ Goto("pin-repo")
            /\ UNCHANGED <<storage, requests, toml, repoPin, session, crashes, edits, confirmed>>
       ELSE /\ wsPin' = [wsPin EXCEPT ![ws] = g]
            /\ repoPin' = ws
            /\ everPinned' = TRUE
            /\ firstHonest' = IF everPinned THEN firstHonest ELSE Honest(g)
            /\ IF exists THEN /\ session' = [ws |-> ws, genesis |-> g] /\ Goto("done")
               ELSE /\ Fail("incompatible_storage")
            /\ UNCHANGED <<storage, requests, toml, crashes, edits, confirmed>>
    /\ UNCHANGED local

VerifyStep ==
    \/ Verify(IF local.founded THEN "founded" ELSE "first")

PinRepo ==
    /\ pc = "pin-repo"
    /\ repoPin' = local.ws
    /\ session' = [ws |-> local.ws, genesis |-> local.genesis]
    /\ Goto("done")
    /\ UNCHANGED <<storage, requests, toml, wsPin, local, crashes, edits, everPinned, firstHonest, confirmed>>

\* D runs a command again later, or after an error.
Rerun ==
    /\ pc = "done"
    /\ Goto("start")
    /\ UNCHANGED <<storage, requests, toml, wsPin, repoPin, local, session, crashes, edits, everPinned, firstHonest, confirmed>>

\* enbu init --accept-new-genesis, for a re-founding an admin confirmed.
AcceptNew ==
    /\ pc \in {"done", "start"}
    /\ toml.genesis \in confirmed
    /\ wsPin[toml.ws] # toml.genesis
    /\ wsPin' = [wsPin EXCEPT ![toml.ws] = toml.genesis]
    /\ repoPin' = toml.ws
    /\ session' = [ws |-> toml.ws, genesis |-> toml.genesis]
    /\ everPinned' = TRUE
    /\ firstHonest' = IF everPinned THEN firstHonest ELSE TRUE
    /\ Goto("done")
    /\ UNCHANGED <<storage, requests, toml, local, crashes, edits, confirmed>>

Crash ==
    /\ crashes < MaxCrashes
    /\ pc \notin {"start", "done"}
    /\ crashes' = crashes + 1
    /\ Goto("start")
    /\ UNCHANGED <<storage, requests, toml, wsPin, repoPin, local, session, edits, everPinned, firstHonest, confirmed>>

\* The attacker commits another workspace ID or genesis, or publishes a
\* genesis or a join request of its own.
Edit(w, g) ==
    /\ AttackerActs /\ edits < MaxEdits
    /\ toml # [ws |-> w, genesis |-> g]
    /\ toml' = [ws |-> w, genesis |-> g]
    /\ edits' = edits + 1
    /\ UNCHANGED <<storage, requests, wsPin, repoPin, pc, local, session, crashes, everPinned, firstHonest, confirmed>>

AttackPublish(w) ==
    /\ AttackerActs /\ edits < MaxEdits
    /\ storage' = storage \cup {[id |-> NextId, ws |-> w, author |-> X]}
    /\ edits' = edits + 1
    /\ UNCHANGED <<requests, toml, wsPin, repoPin, pc, local, session, crashes, everPinned, firstHonest, confirmed>>

AttackRequest(w) ==
    /\ AttackerActs /\ edits < MaxEdits /\ w \notin requests
    /\ requests' = requests \cup {w}
    /\ edits' = edits + 1
    /\ UNCHANGED <<storage, toml, wsPin, repoPin, pc, local, session, crashes, everPinned, firstHonest, confirmed>>

\* O founds a workspace in the same storage; an admin may confirm it as a
\* re-founding and commit it to enbu.toml.
OtherFound(w) ==
    /\ OtherFounds
    /\ ~\E g \in storage : g.author = O
    /\ storage' = storage \cup {[id |-> NextId, ws |-> w, author |-> O]}
    /\ UNCHANGED <<requests, toml, wsPin, repoPin, pc, local, session, crashes, edits, everPinned, firstHonest, confirmed>>

Confirm ==
    /\ OtherFounds
    /\ \E g \in storage :
         /\ g.author = O /\ g.id \notin confirmed
         /\ confirmed' = confirmed \cup {g.id}
         /\ toml' = [ws |-> g.ws, genesis |-> g.id]
    /\ UNCHANGED <<storage, requests, wsPin, repoPin, pc, local, session, crashes, edits, everPinned, firstHonest>>

EditStep == \E w \in Workspaces, g \in Ids \cup {None, NextId} : Edit(w, g)
AttackStep == \E w \in Workspaces : AttackPublish(w) \/ AttackRequest(w)
OtherStep == \E w \in Workspaces : OtherFound(w)

Next ==
    \/ Start \/ Find \/ Publish \/ Save \/ SaveEarly \/ OwnCheck \/ VerifyStep \/ PinRepo
    \/ Rerun \/ AcceptNew \/ Crash
    \/ EditStep \/ AttackStep \/ OtherStep \/ Confirm

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                            *)

TypeOK == pc \in {"start", "find", "publish", "save", "save-early", "own-check", "verify", "pin-repo", "done"}

\* TRUST-1: once D pinned an honest root, it never runs a session on a root
\* the attacker made. (A first contact with an enbu.toml the attacker already
\* controls is trust on first use and cannot be detected.)
NoAttackerRootAfterPin ==
    (firstHonest /\ session # NoSession) => Honest(session.genesis)

\* TRUST-1: a session always runs on the pinned genesis of its workspace.
SessionOnPinnedRoot ==
    session # NoSession => wsPin[session.ws] = session.genesis

\* TRUST-2: what D founds or adopts as its own is signed by D.
FoundedIsOwn ==
    (local.founded /\ local.genesis \in Ids) => G(local.genesis).author = D

\* TRUST-2: D does not found a workspace when its check found another device's
\* genesis or a join request for it. (Another device can still publish between
\* the check and D's publish: storage has no compare-and-swap. Each enbu.toml
\* then names its own genesis; see the witness WitnessNoConcurrentFounding.)
NeverFoundOverOthers == ~(local.sawOthers /\ pc \in {"publish", "save", "verify"})

\* TRUST-3: D pins only a genesis that verified in storage.
OnlyVerifiedPinned ==
    \A w \in Workspaces : wsPin[w] # None => wsPin[w] \in Ids /\ G(wsPin[w]).ws = w

\* TRUST-4: enbu.toml never names a genesis D chose before it was published.
TomlNamesPublished ==
    (local.founded /\ toml.genesis # None /\ local.genesis = toml.genesis) => toml.genesis \in Ids

\* AVAIL-4: without an attacker or another founder, D ends with a session
\* whatever its crashes.
HonestFoundingSucceeds ==
    (~AttackerActs /\ ~OtherFounds /\ pc = "done") => session # NoSession

(* Reachability witnesses (must be violated). *)
WitnessNoLostReply == ~(\E g \in storage : g.author = D) \/ toml.genesis # None \/ pc # "start" \/ crashes = 0
WitnessNoSession == session = NoSession
WitnessNoRefusal == ~(pc = "done" /\ session = NoSession /\ everPinned)
WitnessNoConcurrentFounding ==
    ~\E g, h \in storage : g.ws = h.ws /\ g.author = D /\ h.author # D
WitnessNoReplace == confirmed = {} \/ ~\E w \in Workspaces : wsPin[w] \in confirmed
=============================================================================
