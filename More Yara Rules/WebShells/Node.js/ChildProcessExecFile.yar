rule ChildProceesExecFile {
  
  meta:
        description = "Checks if a file contains the function require('child_process').execFile("
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "require('child_process').execFile("
  
  condition:
        $fun1

}
