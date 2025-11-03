rule COShellApp {
  
  meta:
        description = "Checks if a file contains the function Server.CreateObject(\"Shell.Application\")"
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "Server.CreateObject(\"Shell.Application\")"
  
  condition:
        $fun1

}
