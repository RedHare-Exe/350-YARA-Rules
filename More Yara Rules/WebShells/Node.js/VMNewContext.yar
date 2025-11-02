rule VMNewContext {
  
  meta:
        description = "Checks if a file contains the function require('vm').runInNewContext("
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "require('vm').runInNewContext("
  
  condition:
        $fun1

}
