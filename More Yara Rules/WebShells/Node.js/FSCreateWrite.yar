rule FSCreateWrite {
  
  meta:
        description = "Checks if a file contains the function require('fs').createWriteStream("
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "require('fs').createWriteStream("
  
  condition:
        $fun1

}
