rule FSReadFile {
  
  meta:
        description = "Checks if a file contains the function require('fs').readFile("
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "require('fs').readFile("
  
  condition:
        $fun1

}
