rule ExecuteChecker {
  
  meta:
        description = "Checks if a file contains the function Execute("
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "Execute("
  
  condition:
        $fun1

}
