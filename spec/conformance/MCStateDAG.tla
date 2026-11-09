----------------------------- MODULE MCStateDAG -----------------------------
\* Model values for StateDAG that a .cfg file cannot express.
EXTENDS StateDAG

\* r is removed by the second Control.
MCRemoval == <<{"a", "b", "r"}, {"a", "b"}>>

\* r is removed, then approved again with the same key.
MCReadmission == <<{"a", "b", "r"}, {"a", "b"}, {"a", "b", "r"}>>
=============================================================================
