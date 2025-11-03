rule ServerExecute {
  
  meta:
        description = "Checks if a file contains the function Server.Execute("
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "Server.Execute("
  
  condition:
        $fun1

}
