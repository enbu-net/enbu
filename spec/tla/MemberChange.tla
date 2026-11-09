---------------------------- MODULE MemberChange ----------------------------
(***************************************************************************)
(* A member removal racing concurrent writers and a concurrent approval   *)
(* (app/members.go RemoveMember, changeMembers; app/reencrypt.go          *)
(* reencryptHeads; app/write.go changeResource; app/publish.go writeState; *)
(* app/session.go resolveFork).                                           *)
(*                                                                         *)
(* Admin A removes R: it re-encrypts every head of the resource without R  *)
(* under the Control that still lists R, then appends the Control without  *)
(* R to the view it opened first (ADR-26). Writers W and R each add one    *)
(* key at the same time; each write re-checks the Control just before and  *)
(* just after publishing and starts over when it moved. Admin B may        *)
(* approve N meanwhile, which forks the Control; the next operation of an  *)
(* admin of every head joins it and re-encrypts (ADR-25).                 *)
(*                                                                         *)
(* Storage is honest and its listings are current here: StateDAG.tla and   *)
(* ControlDAG.tla cover adversarial storage. Content is the set of keys a  *)
(* revision holds; a merge of concurrent heads is their union, because     *)
(* every writer adds a key of its own.                                     *)
(*                                                                         *)
(* Property names carry the IDs of spec/INVARIANTS.md.                     *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    ApproveConcurrently,  \* whether B approves N while A removes R
    RemovedWrites,        \* whether R writes while it is removed
    MaxAttempts,          \* attempts of one write (maxRetries in app/write.go)
    Mutant                \* "none" or a seeded bug, see Mutants

A == "A"  B == "B"  W == "W"  R == "R"  N == "N"
Writers == {W, R}
Admins0 == {A, B}

Mutants == {"none", "control-before-reencrypt", "skip-recheck-after-publish",
            "moved-is-internal", "forget-published", "reencrypt-for-everyone"}
ASSUME Mutant \in Mutants

VARIABLES
    ctls,       \* Control records published
    sts,        \* State records published
    removed,    \* whether a Control without R has been published
    pc,         \* [process -> step]
    wctx,       \* [Writers -> local state of the write]
    actx,       \* local state of the removal
    res,        \* [process -> result]
    rDoneEarly, \* whether R's write had completed before the removal began
    syncDue     \* admins that joined a fork and still owe its re-encryption

vars == <<ctls, sts, removed, pc, wctx, actx, res, rDoneEarly, syncDue>>

Genesis == [id |-> 0, parents |-> {}, members |-> {A, B, W, R}, admins |-> Admins0]

CtlById(i) == CHOOSE c \in ctls : c.id = i
CtlIds == {c.id : c \in ctls}
Heads == {c \in ctls : ~\E k \in ctls : c.id \in k.parents}
Single == Cardinality(Heads) = 1
Head == CHOOSE c \in Heads : TRUE

RECURSIVE CtlAnc(_)
CtlAnc(i) == {i} \cup UNION {CtlAnc(p) : p \in CtlById(i).parents}

\* MembershipUnbroken on the Control DAG: d was not removed by any Control
\* between from and head.
Unbroken(head, from, d) ==
    /\ from \in CtlAnc(head)
    /\ \A c \in CtlAnc(head) \ CtlAnc(from) :
         d \in CtlById(c).members \/ \A p \in CtlById(c).parents : d \notin CtlById(p).members

StById(i) == CHOOSE s \in sts : s.id = i
RECURSIVE StAnc(_)
StAnc(i) == UNION {{p} \cup StAnc(p) : p \in StById(i).parents}

StHeads == {s \in sts : ~\E k \in sts : s.id \in k.parents}

\* trustedHeads under the session head h: a head whose author is not a member
\* of h, or was removed since the Control it names, is set aside and its
\* parents stand in for it.
RECURSIVE StandIns(_, _, _)
StandIns(queue, h, done) ==
    IF queue = {} THEN {} ELSE
    LET s == CHOOSE x \in queue : TRUE
        rest == queue \ {s} IN
    IF s.id \in done THEN StandIns(rest, h, done)
    ELSE IF s.author \in CtlById(h).members /\ Unbroken(h, s.ctl, s.author)
         THEN {s} \cup StandIns(rest, h, done \cup {s.id})
         ELSE StandIns(rest \cup {StById(p) : p \in s.parents}, h, done \cup {s.id})

Trusted(h) ==
    LET C == StandIns(StHeads, h, {}) IN
    {t \in C : ~\E o \in C : o # t /\ t.id \in StAnc(o.id)}

TIds(T) == {t.id : t \in T}
Content(T) == UNION {t.content : t \in T}

\* late: written by an operation that began after the Control without R was
\* published. raced: written by another device's operation that began before
\* it, so it may overlap the removal.
NewSt(parents, ctl, author, rcpt, content, late) ==
    [id |-> Cardinality(sts), parents |-> parents, ctl |-> ctl, author |-> author,
     rcpt |-> rcpt, content |-> content, late |-> late, raced |-> author # A /\ ~late]

Publish(s) == sts' = sts \cup {s}

\* The code a write reports when the members kept changing until its last
\* attempt (F5: it must say conflict, not internal).
MovedCode == IF Mutant = "moved-is-internal" THEN "internal" ELSE "conflict"

-----------------------------------------------------------------------------
Init ==
    /\ ctls = {Genesis}
    /\ sts = {[id |-> 0, parents |-> {}, ctl |-> 0, author |-> A, rcpt |-> {A, B, W, R},
               content |-> {"base"}, late |-> FALSE, raced |-> FALSE]}
    /\ removed = FALSE
    /\ pc = [p \in {A, B, W, R} |->
                IF (p = B /\ ~ApproveConcurrently) \/ (p = R /\ ~RemovedWrites) THEN "done" ELSE "open"]
    /\ wctx = [w \in Writers |-> [att |-> 0, head |-> -1, read |-> {}, content |-> {}, pub |-> {}, late |-> FALSE]]
    /\ actx = [before |-> -1, head |-> -1, todo |-> {}, att |-> 0]
    /\ res = [p \in {A, B, W, R} |-> "none"]
    /\ rDoneEarly = FALSE
    /\ syncDue = {}

\* An admin of every head of a forked Control joins it with what every head
\* agrees on and re-encrypts the resource for the result (resolveFork). Any
\* operation of such an admin starts with this.
Resolve(d) ==
    /\ ~Single
    /\ pc[d] \in {"open", "reenc-open", "sync"}
    /\ \A h \in Heads : d \in h.admins
    /\ LET j == [id |-> Cardinality(ctls), parents |-> {h.id : h \in Heads},
                 members |-> {x \in {A, B, W, R, N} : \A h \in Heads : x \in h.members},
                 admins |-> {x \in Admins0 : \A h \in Heads : x \in h.admins}]
           T == Trusted(j.id) IN
       /\ ctls' = ctls \cup {j}
       /\ removed' = (removed \/ R \notin j.members)
       /\ syncDue' = syncDue \cup {d}  \* the re-encryption follows as its own step
       /\ UNCHANGED <<sts, pc, wctx, actx, res, rDoneEarly>>

\* reencryptAll("") after a join: a sync of the resource under the new head.
Sync(d) ==
    /\ d \in syncDue
    /\ syncDue' = syncDue \ {d}
    /\ IF Single
       THEN LET T == Trusted(Head.id) IN
            Publish(NewSt(TIds(T), Head.id, d, Head.members, Content(T), removed))
       ELSE UNCHANGED sts \* forked again: the next join re-encrypts
    /\ UNCHANGED <<ctls, removed, pc, wctx, actx, res, rDoneEarly>>

(* The write of w: changeResource adding one key. *)
SetW(w, f) == wctx' = [wctx EXCEPT ![w] = f]
Finish(p, r) ==
    /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ res' = [res EXCEPT ![p] = r]

\* Members changed while writing: start over on the new member list, or give
\* up after the last attempt.
Moved(w) ==
    IF wctx[w].att + 1 >= MaxAttempts
    THEN /\ Finish(w, MovedCode) /\ UNCHANGED wctx
    ELSE /\ SetW(w, [wctx[w] EXCEPT !.att = @ + 1])
         /\ pc' = [pc EXCEPT ![w] = "open"]
         /\ UNCHANGED res

WOpen(w) ==
    /\ pc[w] = "open"
    /\ IF ~Single THEN /\ Finish(w, "control_forked") /\ UNCHANGED wctx
       ELSE IF w \notin Head.members THEN /\ Finish(w, "not_member") /\ UNCHANGED wctx
       ELSE /\ SetW(w, [wctx[w] EXCEPT !.head = Head.id,
                                        !.late = IF wctx[w].att = 0 /\ wctx[w].pub = {} THEN removed ELSE @])
            /\ pc' = [pc EXCEPT ![w] = "read"]
            /\ UNCHANGED res
    /\ UNCHANGED <<ctls, sts, removed, actx, rDoneEarly, syncDue>>

\* readResource, then the change unless a revision this call published is
\* already part of what it read (publishedInRead).
WRead(w) ==
    /\ pc[w] = "read"
    /\ LET T == Trusted(wctx[w].head)
           mine == \E t \in T : \E p \in wctx[w].pub : p = t.id \/ p \in StAnc(t.id)
           applied == mine /\ Mutant # "forget-published" IN
       IF ~applied /\ w \in Content(T)
       THEN /\ Finish(w, "secret_already_exists") /\ UNCHANGED wctx
       ELSE /\ SetW(w, [wctx[w] EXCEPT !.read = TIds(T),
                                        !.content = IF applied THEN Content(T) ELSE Content(T) \cup {w}])
            /\ pc' = [pc EXCEPT ![w] = "recheck"]
            /\ UNCHANGED res
    /\ UNCHANGED <<ctls, sts, removed, actx, rDoneEarly, syncDue>>

\* Look once more before publishing: new heads are merged now.
WRecheck(w) ==
    /\ pc[w] = "recheck"
    /\ IF TIds(Trusted(wctx[w].head)) # wctx[w].read
       THEN IF wctx[w].att + 1 >= MaxAttempts
            THEN /\ Finish(w, "conflict") /\ UNCHANGED wctx
            ELSE /\ SetW(w, [wctx[w] EXCEPT !.att = @ + 1])
                 /\ pc' = [pc EXCEPT ![w] = "read"]
                 /\ UNCHANGED res
       ELSE /\ pc' = [pc EXCEPT ![w] = "publish"]
            /\ UNCHANGED <<wctx, res>>
    /\ UNCHANGED <<ctls, sts, removed, actx, rDoneEarly, syncDue>>

\* writeState: encrypt for the session's members and check the Control has not
\* moved; signing and publishing follow as a separate step, so the Control can
\* move in between.
WCheckBefore(w) ==
    /\ pc[w] = "publish"
    /\ IF ~Single \/ Head.id # wctx[w].head
       THEN Moved(w)
       ELSE /\ pc' = [pc EXCEPT ![w] = "publish2"]
            /\ UNCHANGED <<wctx, res>>
    /\ UNCHANGED <<ctls, sts, removed, actx, rDoneEarly, syncDue>>

WPublish(w) ==
    /\ pc[w] = "publish2"
    /\ LET s == NewSt(wctx[w].read, wctx[w].head, w, CtlById(wctx[w].head).members,
                      wctx[w].content, wctx[w].late) IN
       /\ Publish(s)
       /\ SetW(w, [wctx[w] EXCEPT !.pub = @ \cup {s.id}])
       /\ pc' = [pc EXCEPT ![w] = "check"]
    /\ UNCHANGED <<ctls, removed, actx, res, rDoneEarly, syncDue>>

\* writeState's second check: the revision stays, and a moved Control means
\* writing again for the new members on top of it.
WCheck(w) ==
    /\ pc[w] = "check"
    /\ IF (~Single \/ Head.id # wctx[w].head) /\ Mutant # "skip-recheck-after-publish"
       THEN /\ Moved(w)
            /\ UNCHANGED rDoneEarly
       ELSE /\ Finish(w, "ok") /\ UNCHANGED wctx
            /\ rDoneEarly' = (rDoneEarly \/ (w = R /\ pc[A] = "open"))
    /\ UNCHANGED <<ctls, sts, removed, actx, syncDue>>

(* The removal of R by A. *)
AOpen ==
    /\ pc[A] = "open"
    /\ Single
    /\ actx' = [actx EXCEPT !.before = Head.id]
    /\ pc' = [pc EXCEPT ![A] = IF Mutant = "control-before-reencrypt" THEN "remove" ELSE "reenc-open"]
    /\ UNCHANGED <<ctls, sts, removed, wctx, res, rDoneEarly, syncDue>>

\* reencryptHeads opens a session and takes every trusted head.
AReencOpen ==
    /\ pc[A] = "reenc-open"
    /\ Single
    /\ actx' = [actx EXCEPT !.head = Head.id, !.todo = TIds(Trusted(Head.id))]
    /\ pc' = [pc EXCEPT ![A] = "reenc"]
    /\ UNCHANGED <<ctls, sts, removed, wctx, res, rDoneEarly, syncDue>>

\* One head re-encrypted without R under the Control that still lists R, with
\* the Control checks of writeState before and after.
AReenc ==
    /\ pc[A] = "reenc"
    /\ IF actx.todo = {} THEN
          /\ pc' = [pc EXCEPT ![A] = IF Mutant = "control-before-reencrypt" THEN "done-ok" ELSE "remove"]
          /\ UNCHANGED <<sts, actx, res>>
       ELSE IF ~Single \/ Head.id # actx.head THEN
          IF actx.att + 1 >= MaxAttempts
          THEN /\ Finish(A, "conflict") /\ UNCHANGED <<sts, actx>>
          ELSE /\ actx' = [actx EXCEPT !.att = @ + 1]
               /\ pc' = [pc EXCEPT ![A] = "reenc-open"]
               /\ UNCHANGED <<sts, res>>
       ELSE \E t \in actx.todo :
          LET ts == StById(t)
              rcpt == IF Mutant = "reencrypt-for-everyone" THEN CtlById(actx.head).members
                      ELSE CtlById(actx.head).members \ {R} IN
          /\ Publish(NewSt({t}, actx.head, A, rcpt, ts.content, removed))
          /\ actx' = [actx EXCEPT !.todo = @ \ {t}]
          /\ UNCHANGED <<pc, res>>
    /\ UNCHANGED <<ctls, removed, wctx, rDoneEarly, syncDue>>

\* changeMembers on the view opened first: another admin's change made
\* meanwhile forks the Control.
ARemove ==
    /\ pc[A] = "remove"
    /\ LET b == CtlById(actx.before)
           c == [id |-> Cardinality(ctls), parents |-> {b.id}, members |-> b.members \ {R},
                 admins |-> b.admins] IN
       /\ ctls' = ctls \cup {c}
       /\ removed' = TRUE
       /\ IF Mutant = "control-before-reencrypt"
          THEN /\ pc' = [pc EXCEPT ![A] = "reenc-open"] /\ UNCHANGED res
          ELSE /\ Finish(A, IF Cardinality({k \in ctls' : ~\E x \in ctls' : k.id \in x.parents}) > 1
                            THEN "control_forked" ELSE "ok")
    /\ UNCHANGED <<sts, wctx, actx, rDoneEarly, syncDue>>

ADoneOk ==
    /\ pc[A] = "done-ok"
    /\ Finish(A, "ok")
    /\ UNCHANGED <<ctls, sts, removed, wctx, actx, rDoneEarly, syncDue>>

(* The approval of N by B, then its re-encryption. *)
BApprove ==
    /\ pc[B] = "open"
    /\ Single
    /\ ctls' = ctls \cup {[id |-> Cardinality(ctls), parents |-> {Head.id},
                           members |-> Head.members \cup {N}, admins |-> Head.admins]}
    /\ pc' = [pc EXCEPT ![B] = "sync"]
    /\ UNCHANGED <<sts, removed, wctx, actx, res, rDoneEarly, syncDue>>

BSync ==
    /\ pc[B] = "sync"
    /\ IF ~Single THEN /\ Finish(B, "control_forked") /\ UNCHANGED sts
       ELSE LET T == Trusted(Head.id) IN
            /\ Publish(NewSt(TIds(T), Head.id, B, Head.members, Content(T), removed))
            /\ Finish(B, "ok")
    /\ UNCHANGED <<ctls, removed, wctx, actx, rDoneEarly, syncDue>>

AllDone == (\A p \in {A, B, W, R} : pc[p] = "done") /\ syncDue = {}

Next ==
    \/ \E d \in Admins0 : Resolve(d) \/ Sync(d)
    \/ \E w \in Writers : WOpen(w) \/ WRead(w) \/ WRecheck(w) \/ WCheckBefore(w) \/ WPublish(w) \/ WCheck(w)
    \/ AOpen \/ AReencOpen \/ AReenc \/ ARemove \/ ADoneOk
    \/ BApprove \/ BSync
    \/ (AllDone /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                            *)

TypeOK == res \in [{A, B, W, R} -> {"none", "ok", "conflict", "internal", "control_forked",
                                     "not_member", "secret_already_exists"}]

\* RCPT-1: every revision is encrypted only for members of the Control it
\* names.
RecipientsWithinControl == \A s \in sts : s.rcpt \subseteq CtlById(s.ctl).members

\* RCPT-2: a write that began after the Control without R was published never
\* encrypts for R. (A write that overlaps the removal may, as if it had been
\* made before it.)
NoNewCiphertextForRemoved == \A s \in sts : s.late => R \notin s.rcpt

\* RCPT-3: once everything settled, a head a remaining member reads is still
\* encrypted for R only if another device's write overlapped the removal: it
\* began before the Control without R, after A took the heads to re-encrypt.
\* Its content predates that Control, so R could have read it then; the next
\* write or sync re-encrypts it.
SettledHeadsExcludeRemovedUnlessRaced ==
    (AllDone /\ removed /\ Single) => \A t \in Trusted(Head.id) : R \in t.rcpt => t.raced

\* The stronger statement does not hold: the race above leaves such a head
\* (recorded as a reachability witness, see spec/INVARIANTS.md RCPT-3).
SettledHeadsExcludeRemoved ==
    (AllDone /\ removed /\ Single) => \A t \in Trusted(Head.id) : R \notin t.rcpt

\* AVAIL-3: once everything settled, every current member can decrypt every
\* head it reads, unless a write gave up after publishing because members
\* kept changing: its revision stays for the old members until the next
\* write or sync (F7, recorded as the witness SettledHeadsReadableStrict).
GaveUpAfterPublishing == \E w \in Writers : res[w] = MovedCode /\ wctx[w].pub # {}

SettledHeadsReadable ==
    (AllDone /\ Single /\ ~GaveUpAfterPublishing) =>
        \A t \in Trusted(Head.id) : Head.members \subseteq t.rcpt

SettledHeadsReadableStrict ==
    (AllDone /\ Single) => \A t \in Trusted(Head.id) : Head.members \subseteq t.rcpt

\* SYNC-1: a write that reported success is part of what remaining members
\* read once everything settled, and so is a removed member's write that
\* completed before the removal began (the removal takes it over).
NoLostUpdate ==
    (AllDone /\ Single) =>
        /\ res[W] = "ok" => W \in Content(Trusted(Head.id))
        /\ rDoneEarly => R \in Content(Trusted(Head.id))

\* SYNC-2: success is reported only for a write storage holds.
NoFalseSuccess == \A w \in Writers : res[w] = "ok" => \E s \in sts : w \in s.content

\* SYNC-3: a write never fails because of its own earlier attempt.
NoSelfConflict == \A w \in Writers : res[w] # "secret_already_exists"

\* ERR-1: running out of attempts because members kept changing is a
\* conflict a person can act on, never an internal error.
NoInternalErrors == \A p \in {A, B, W, R} : res[p] # "internal"

\* FORK-5: a concurrent approval never revives a removed member.
RemovedStaysRemoved == (removed /\ Single) => R \notin Head.members

(* Reachability witnesses (must be violated). *)
WitnessNoRetry == \A w \in Writers : wctx[w].att = 0
WitnessNoOverlap == ~\E s \in sts : s.author \in Writers /\ ~s.late /\ R \in s.rcpt /\ removed
WitnessNoFork == Cardinality(Heads) = 1 \/ ~ApproveConcurrently
WitnessNoJoin == ~\E c \in ctls : Cardinality(c.parents) > 1
WitnessNotSettled == ~(AllDone /\ res[W] = "ok" /\ res[A] = "ok")
=============================================================================
