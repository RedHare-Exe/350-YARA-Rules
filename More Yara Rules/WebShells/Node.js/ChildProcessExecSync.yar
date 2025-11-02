rule ChildProceesExecSync {
  
  meta:
        description = "Checks if a file contains the function require('child_process').execSync("
        author = "Benjaimn Ware"
        date = "2025-11-22"
        version = "1.0"
    
  strings:
        $fun1 = "require('child_process').execSync("
  
  condition:
        $fun1

}
