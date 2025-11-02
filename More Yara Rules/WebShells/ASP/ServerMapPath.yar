rule ServerMapPath {
  
  meta:
        description = "Checks if a file contains the function Server.MapPath("
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "Server.MapPath("
  
  condition:
        $fun1

}
