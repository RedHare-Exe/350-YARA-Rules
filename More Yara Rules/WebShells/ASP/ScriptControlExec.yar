rule ScriptControlExec {
  
  meta:
        description = "Checks if a file contains the function ScriptControl.ExecuteStatement"
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "ScriptControl.ExecuteStatement"
  
  condition:
        $fun1

}
