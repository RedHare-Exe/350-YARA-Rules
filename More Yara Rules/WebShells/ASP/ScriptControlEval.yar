rule ScriptControlEval {
  
  meta:
        description = "Checks if a file contains the function ScriptControl.Eval"
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "ScriptControl.Eval"
  
  condition:
        $fun1

}
