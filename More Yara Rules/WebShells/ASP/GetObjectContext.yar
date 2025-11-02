rule GetObjectContext {
  
  meta:
        description = "Checks if a file contains the function GetObjectContext("
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "GetObjectContext("
  
  condition:
        $fun1

}
