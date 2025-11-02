rule NetSocket {
  
  meta:
        description = "Checks if a file contains the function require('net').Socket(. Used for outboud connections."
        author = "Benjaimn Ware"
        date = "2025-11-02"
        version = "1.0"
    
  strings:
        $fun1 = "require('net').Socket("
  
  condition:
        $fun1

}
