rule evalchecker {
  
  meta:
        description = "Checks if a file contains the function eval("
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "eval("
  
  condition:
        $fun1

}
