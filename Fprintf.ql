/**
 * @name findPrintf
 * @description find calls to plain fprintf
 * @kind problem
 * @id cpp-fprintf-call
 * @problem.severity warning
 */

import cpp

from FunctionCall fc
where
  fc.getTarget().getName() = "fprintf"
select fc, "call of fprintf"
