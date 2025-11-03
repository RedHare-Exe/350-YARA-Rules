rule php
{
    meta:
        description = "Checks if a file is a PHP file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $php1 = "<?php"
        $php2 = "<?="
        $php3 = "<? "
        
    condition:
        any of them
}
