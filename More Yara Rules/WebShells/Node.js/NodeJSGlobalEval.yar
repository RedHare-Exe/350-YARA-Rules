rule GlobalEvalChecker {
  
  meta:
        description = "Checks if a file contains the function global.eval("
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "global.eval("
  
  condition:
        $fun1

}
