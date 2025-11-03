rule ResponseWrite {
  
  meta:
        description = "Checks if a file contains the function Response.Write("
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "Response.Write("
  
  condition:
        $fun1

}
