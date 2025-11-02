rule CreateServer {
  
  meta:
        description = "Checks if a file contains the function require('http').createServer(. Used for reverse shells."
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "require('http').createServer("
  
  condition:
        $fun1

}
