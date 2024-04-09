/**
 * @name pickfun
 * @description pick function from FlatBuffers
 * @kind problem
 * @id cpp-flatbuffer-func
 * @problem.severity warning
 */

import cpp

from Function f
where
  f.getName() = "MakeBinaryRegion" or
  f.getName() = "microprotocols_add"
select f, "definition of MakeBinaryRegion"
