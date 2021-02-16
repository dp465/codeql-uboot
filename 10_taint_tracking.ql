/**
* @kind path-problem
*/

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph
 
class NetworkByteSwap extends Expr
{
    NetworkByteSwap(){
       exists(MacroInvocation mi | mi.getMacro().getName() in ["ntohs", "ntohl", "ntohll"]| this = mi.getExpr() )
    }
 }
 
class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap
    // TODO
  }
  override predicate isSink(DataFlow::Node sink) {
        //if sink.getFunction().getName() = "memcpy"
        exists(FunctionCall c | c.getTarget().getName() = "memcpy" and sink.asExpr() = c.getArgument(2))
    // TODO
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
