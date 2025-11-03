rule FSWriteFile {
  
  meta:
        description = "Checks if a file contains the function require('fs').writeFile("
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "require('fs').writeFile("
  
  condition:
        $fun1

}
