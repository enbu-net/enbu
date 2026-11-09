----------------------------- MODULE Founding -----------------------------
(***************************************************************************)
(* Founding a workspace and pinning trust roots (app/init.go              *)
(* initializeRepository / ensureControl / foundGenesis; app/session.go    *)
(* verifyControl; pkg/wsp/trust.go Pin / Check; pkg/wsp/chain.go          *)
(* FindGenesis).                                                           *)
(*                                                                         *)
(* Device F runs `enbu init` in a fresh repository, may crash at any step *)
(* and run it again. Storage replies may be lost: the genesis is stored    *)
(* but F sees an error. The attacker Att can write storage (publish its   *)
(* own genesis for any workspace, delete everything) and the repository   *)
(* (rewrite enbu.toml), but cannot sign as F. `--accept-new-genesis`      *)
(* (PinReplace) is not modelled: nobody confirms a new root here.         *)
(*                                                                         *)
(* A genesis is [ws, author, n]: the record is its digest (n tells apart *)
(* the ones F signs on different runs). Checks are evaluated at the step  *)
(* that acts; a violation adds its name to `bad`.                        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS F, Att, W1, W2, MaxRuns, MaxCrashes, MaxAtt, Bug

WS == {W1, W2}
NoWS == "none"
NoG == [ws |-> "none", author |-> "none", n |-> 0]   \* no control_genesis
None == [ws |-> "none", g |-> NoG]                 \* no enbu.toml

Bugs == {"none", "adopt_any_genesis", "toml_before_publish", "no_find_genesis",
         "founding_repins", "no_repo_pin", "founded_by_storage"}
ASSUME Bug \in Bugs

VARIABLES
  stored,    \* the genesis Controls storage holds
  requests,  \* storage holds a join request
  cfg,       \* enbu.toml: [ws, g], or None
  mcfg,      \* the enbu.toml this run loaded, as it holds it in memory
  tws,       \* trust.json workspaces: ws -> pinned genesis (NoG: none)
  trepo,     \* trust.json repositories: the workspace this enbu.toml is pinned to, or NoWS
  pc,        \* F's step
  g,         \* the genesis this run settled on
  founded,   \* this run founded the workspace (session.founded)
  runs, crashes, att,
  published, \* ghost: every genesis that was ever stored
  bad        \* ghost: names of violated checks

vars == <<stored, requests, cfg, mcfg, tws, trepo, pc, g, founded, runs, crashes, att, published, bad>>

Init ==
  /\ stored = {}
  /\ requests = FALSE
  /\ cfg = None
  /\ mcfg = None
  /\ tws = [w \in WS |-> NoG]
  /\ trepo = NoWS
  /\ pc = "idle"
  /\ g = NoG
  /\ founded = FALSE
  /\ runs = 0 /\ crashes = 0 /\ att = 0
  /\ published = {}
  /\ bad = {}

Own(x) == x.author = F
OwnGenesis(w) == {x \in stored : x.ws = w /\ (Own(x) \/ Bug = "adopt_any_genesis")}
\* "the smallest digest wins": any fixed choice
Min(S) == CHOOSE x \in S : \A y \in S : x.n <= y.n

Go(step) == pc' = step
Fail(why) == pc' = why

(***************************************************************************)
(* F's `enbu init`                                                         *)
(***************************************************************************)
Start ==
  /\ pc \in {"idle", "ok", "trust_root_changed", "incompatible", "failed"}
  /\ runs < MaxRuns
  /\ runs' = runs + 1
  \* loadProject; a missing enbu.toml gets a new workspace and is saved first.
  /\ cfg' = IF cfg = None THEN [ws |-> W1, g |-> NoG] ELSE cfg
  /\ mcfg' = cfg'
  /\ g' = NoG /\ founded' = FALSE
  /\ Go("ensure")
  /\ UNCHANGED <<stored, requests, tws, trepo, crashes, att, published, bad>>

\* Founding refuses storage holding only F's own genesis of the workspace.
WronglyRefused ==
  LET w == mcfg.ws IN
  /\ mcfg.g = NoG
  /\ ~(tws[w] # NoG /\ Bug # "founding_repins")
  /\ ~(Bug # "no_find_genesis" /\ OwnGenesis(w) # {})
  /\ stored # {}
  /\ ~requests
  /\ \A x \in stored : Own(x) /\ x.ws = w

\* ensureControl
Ensure ==
  LET w == mcfg.ws pinned == tws[w] IN
  /\ pc = "ensure"
  /\ IF mcfg.g = NoG
     THEN IF pinned # NoG /\ Bug # "founding_repins"
          THEN Fail("trust_root_changed") /\ UNCHANGED <<g, founded>>
          \* foundGenesis: a genesis F signed for this workspace is its own founding
          ELSE IF Bug # "no_find_genesis" /\ OwnGenesis(w) # {}
          THEN /\ g' = Min(OwnGenesis(w))
               /\ Go("save") /\ UNCHANGED founded
          ELSE IF stored # {} \/ requests
          THEN /\ Fail("incompatible")
               /\ UNCHANGED <<g, founded>>
          ELSE /\ g' = [ws |-> w, author |-> F, n |-> runs]
               /\ Go(IF Bug = "toml_before_publish" THEN "save" ELSE "publish")
               /\ UNCHANGED founded
     ELSE /\ founded' = (pinned = NoG /\ mcfg.g \in stored /\ mcfg.g.ws = w
                         /\ (Own(mcfg.g) \/ Bug = "founded_by_storage"))
          /\ g' = mcfg.g
          /\ Go("verify")
  /\ UNCHANGED <<stored, requests, cfg, mcfg, tws, trepo, runs, crashes, att, published>>
  /\ bad' = bad \cup (IF WronglyRefused THEN {"TRUST_4"} ELSE {})

\* PublishGenesis; the reply may be lost after storage kept it.
Publish ==
  /\ pc = "publish"
  /\ \/ /\ stored' = stored \cup {g}
        /\ published' = published \cup {g}
        /\ Go(IF Bug = "toml_before_publish" THEN "verify" ELSE "save")
     \/ /\ stored' = stored \cup {g}
        /\ published' = published \cup {g}
        /\ Fail("failed")                  \* lost reply
     \/ /\ Fail("failed")                  \* nothing stored
        /\ UNCHANGED <<stored, published>>
  /\ UNCHANGED <<requests, cfg, mcfg, tws, trepo, g, founded, runs, crashes, att, bad>>

\* enbu.toml names the genesis, and this run founded it.
Save ==
  /\ pc = "save"
  /\ mcfg' = [mcfg EXCEPT !.g = g]
  /\ cfg' = mcfg'
  /\ founded' = TRUE
  /\ Go(IF Bug = "toml_before_publish" THEN "publish" ELSE "verify")
  \* TRUST-3: enbu.toml names a genesis only once its publish returned.
  /\ bad' = bad \cup (IF g \in published THEN {} ELSE {"TRUST_3"})
  /\ UNCHANGED <<stored, requests, tws, trepo, g, runs, crashes, att, published>>

\* verifyControl: Check the pins, LoadControl, Pin, AcceptControl.
Conflict(w, gg, mode) ==
  \/ tws[w] # NoG /\ tws[w] # gg
  \/ Bug # "no_repo_pin" /\ mode # "founded" /\ trepo # NoWS /\ trepo # w

Verify ==
  LET w == mcfg.ws mode == IF founded THEN "founded" ELSE "first"
      gg == mcfg.g
  IN
  /\ pc = "verify"
  /\ IF Conflict(w, gg, mode) /\ ~(Bug = "founding_repins" /\ mode = "founded")
     THEN Fail("trust_root_changed") /\ UNCHANGED <<tws, trepo, bad>>
     ELSE IF ~(gg \in stored /\ gg.ws = w)
     THEN Fail("incompatible") /\ UNCHANGED <<tws, trepo, bad>>
     ELSE /\ tws' = [tws EXCEPT ![w] = gg]
          /\ trepo' = w
          /\ Go("ok")
          /\ bad' = bad
               \* TRUST-2: founding pins only a genesis F signed.
               \cup (IF mode = "founded" /\ ~Own(gg) THEN {"TRUST_2"} ELSE {})
               \* TRUST-5: a repository pinned to one workspace never moves to
               \* one the attacker founded (first use, with no pin, is TOFU).
               \cup (IF ~Own(gg) /\ trepo # NoWS /\ trepo # w THEN {"TRUST_5"} ELSE {})
  /\ UNCHANGED <<stored, requests, cfg, mcfg, g, founded, runs, crashes, att, published>>

\* F stops anywhere: a crash or Ctrl-C.
Crash ==
  /\ pc \in {"ensure", "publish", "save", "verify"}
  /\ crashes < MaxCrashes
  /\ crashes' = crashes + 1
  /\ Go("idle")
  /\ UNCHANGED <<stored, requests, cfg, mcfg, tws, trepo, g, founded, runs, att, published, bad>>

(***************************************************************************)
(* The attacker                                                            *)
(***************************************************************************)
AttStep == att < MaxAtt /\ att' = att + 1

AttGenesis == \E w \in WS :
  LET x == [ws |-> w, author |-> Att, n |-> att] IN
  /\ AttStep
  /\ stored' = stored \cup {x}
  /\ published' = published \cup {x}
  /\ UNCHANGED <<requests, cfg, mcfg, tws, trepo, pc, g, founded, runs, crashes, bad>>

AttRequest ==
  /\ AttStep /\ ~requests
  /\ requests' = TRUE
  /\ UNCHANGED <<stored, cfg, mcfg, tws, trepo, pc, g, founded, runs, crashes, published, bad>>

AttWipe ==
  /\ AttStep /\ (stored # {} \/ requests)
  /\ stored' = {} /\ requests' = FALSE
  /\ UNCHANGED <<cfg, mcfg, tws, trepo, pc, g, founded, runs, crashes, published, bad>>

\* A commit rewrites enbu.toml: any workspace, any genesis or none.
AttConfig == \E w \in WS, x \in published \cup {NoG} :
  /\ AttStep
  /\ cfg' = [ws |-> w, g |-> x]
  /\ UNCHANGED <<stored, requests, mcfg, tws, trepo, pc, g, founded, runs, crashes, published, bad>>

Next ==
  \/ Start \/ Ensure \/ Publish \/ Save \/ Verify \/ Crash
  \/ AttGenesis \/ AttRequest \/ AttWipe \/ AttConfig

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
\* TRUST-1: a pinned genesis is never replaced (without --accept-new-genesis).
TRUST_1 == [][\A w \in WS : tws[w] # NoG => tws'[w] = tws[w]]_vars

\* TRUST-2: founding never adopts a genesis someone else signed.
TRUST_2 == "TRUST_2" \notin bad

\* TRUST-3: enbu.toml names a genesis only after its publish returned.
TRUST_3 == "TRUST_3" \notin bad

\* TRUST-4: a founding retry after a crash or a lost reply is never refused
\* for a storage that holds only what F published.
TRUST_4 == "TRUST_4" \notin bad

\* TRUST-5: the repository pin never moves to a workspace F did not found.
TRUST_5 == "TRUST_5" \notin bad

=============================================================================
