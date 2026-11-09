---- MODULE MCControlDAG_TTrace_1794191243 ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, MCControlDAG

_expression ==
    LET MCControlDAG_TEExpression == INSTANCE MCControlDAG_TEExpression
    IN MCControlDAG_TEExpression!expression
----

_trace ==
    LET MCControlDAG_TETrace == INSTANCE MCControlDAG_TETrace
    IN MCControlDAG_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        nextId = (2)
        /\
        view = ([a |-> {}, b |-> {}])
        /\
        session = ([a |-> -1, b |-> -1])
        /\
        changes = (0)
        /\
        honestIds = ({0})
        /\
        store = ({[id |-> 0, parents |-> {}, height |-> 0, roles |-> [a |-> "admin", b |-> "admin", m |-> "member", x |-> "none"], author |-> "a", sig |-> TRUE], [id |-> 1, parents |-> {0}, height |-> 1, roles |-> [a |-> "none", b |-> "admin", m |-> "member", x |-> "none"], author |-> "forger", sig |-> FALSE]})
        /\
        everCp = ([a |-> {}, b |-> {}])
        /\
        cp = ([a |-> {}, b |-> {}])
        /\
        outcome = ([a |-> "none", b |-> "none"])
    )
----

_init ==
    /\ honestIds = _TETrace[1].honestIds
    /\ everCp = _TETrace[1].everCp
    /\ outcome = _TETrace[1].outcome
    /\ store = _TETrace[1].store
    /\ cp = _TETrace[1].cp
    /\ nextId = _TETrace[1].nextId
    /\ view = _TETrace[1].view
    /\ session = _TETrace[1].session
    /\ changes = _TETrace[1].changes
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ honestIds  = _TETrace[i].honestIds
        /\ honestIds' = _TETrace[j].honestIds
        /\ everCp  = _TETrace[i].everCp
        /\ everCp' = _TETrace[j].everCp
        /\ outcome  = _TETrace[i].outcome
        /\ outcome' = _TETrace[j].outcome
        /\ store  = _TETrace[i].store
        /\ store' = _TETrace[j].store
        /\ cp  = _TETrace[i].cp
        /\ cp' = _TETrace[j].cp
        /\ nextId  = _TETrace[i].nextId
        /\ nextId' = _TETrace[j].nextId
        /\ view  = _TETrace[i].view
        /\ view' = _TETrace[j].view
        /\ session  = _TETrace[i].session
        /\ session' = _TETrace[j].session
        /\ changes  = _TETrace[i].changes
        /\ changes' = _TETrace[j].changes

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("MCControlDAG_TTrace_1794191243.json", _TETrace)

=============================================================================

 Note that you can extract this module `MCControlDAG_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `MCControlDAG_TEExpression.tla` file takes precedence 
  over the module `MCControlDAG_TEExpression` below).

---- MODULE MCControlDAG_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, Naturals, TLC, MCControlDAG

expression == 
    [
        \* To hide variables of the `MCControlDAG` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        honestIds |-> honestIds
        ,everCp |-> everCp
        ,outcome |-> outcome
        ,store |-> store
        ,cp |-> cp
        ,nextId |-> nextId
        ,view |-> view
        ,session |-> session
        ,changes |-> changes
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_honestIdsUnchanged |-> honestIds = honestIds'
        
        \* Format the `honestIds` variable as Json value.
        \* ,_honestIdsJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(honestIds)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_honestIdsModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].honestIds # _TETrace[s-1].honestIds
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE MCControlDAG_TETrace ----
\*EXTENDS IOUtils, TLC, MCControlDAG
\*
\*trace == IODeserialize("MCControlDAG_TTrace_1794191243.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE MCControlDAG_TETrace ----
EXTENDS TLC, MCControlDAG

trace == 
    <<
    ([nextId |-> 1,view |-> [a |-> {}, b |-> {}],session |-> [a |-> -1, b |-> -1],changes |-> 0,honestIds |-> {0},store |-> {[id |-> 0, parents |-> {}, height |-> 0, roles |-> [a |-> "admin", b |-> "admin", m |-> "member", x |-> "none"], author |-> "a", sig |-> TRUE]},everCp |-> [a |-> {}, b |-> {}],cp |-> [a |-> {}, b |-> {}],outcome |-> [a |-> "none", b |-> "none"]]),
    ([nextId |-> 2,view |-> [a |-> {}, b |-> {}],session |-> [a |-> -1, b |-> -1],changes |-> 0,honestIds |-> {0},store |-> {[id |-> 0, parents |-> {}, height |-> 0, roles |-> [a |-> "admin", b |-> "admin", m |-> "member", x |-> "none"], author |-> "a", sig |-> TRUE], [id |-> 1, parents |-> {0}, height |-> 1, roles |-> [a |-> "none", b |-> "admin", m |-> "member", x |-> "none"], author |-> "forger", sig |-> FALSE]},everCp |-> [a |-> {}, b |-> {}],cp |-> [a |-> {}, b |-> {}],outcome |-> [a |-> "none", b |-> "none"]])
    >>
----


=============================================================================

---- CONFIG MCControlDAG_TTrace_1794191243 ----
CONSTANTS
    Devices = { "a" , "b" , "m" , "x" }
    Honest = { "a" , "b" }
    Compromised = { "m" , "x" }
    GenesisRoles <- MCGenesisRoles
    MaxControls = 5
    MaxChanges = 2
    AttackerActs = TRUE
    Mutant = "none"

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Mon Nov 09 11:27:23 JST 2026