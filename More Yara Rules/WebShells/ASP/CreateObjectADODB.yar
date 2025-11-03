rule COADODB {
  
  meta:
        description = "Checks if a file contains the function Server.CreateObject(\"ADODB.Stream\")"
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "Server.CreateObject(\"ADODB.Stream\")"
  
  condition:
        $fun1

}
