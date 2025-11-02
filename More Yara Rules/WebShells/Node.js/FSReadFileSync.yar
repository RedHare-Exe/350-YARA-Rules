rule FSReadFileSync {
  
  meta:
        description = "Checks if a file contains the function require('fs').readFileSync("
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "require('fs').readFileSync("
  
  condition:
        $fun1

}
