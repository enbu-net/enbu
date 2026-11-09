---------------------------- MODULE MCControlDAG ----------------------------
\* Model values for ControlDAG that a .cfg file cannot express.
EXTENDS ControlDAG

\* Two admins and a member whose key leaked.
MCGenesisRoles == [a |-> "admin", b |-> "admin", m |-> "member"]

\* Two honest admins and a third admin whose key leaked.
MCGenesisInsider == [a |-> "admin", b |-> "admin", m |-> "admin"]
=============================================================================
