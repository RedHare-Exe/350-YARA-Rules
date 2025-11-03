rule jar
{
    meta:
        description = "Checks if a file is a Java JAR file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $var1 = {4A 41 52 43 53 00}
        $var2 = {50 4B 03 04}
        $var3 = {50 4B 03 04 14 00 08 00}
        $var4 = {5F 27 A8 89}
        
    condition:
        $var1 at 0 or
        $var2 at 0 or
        $var3 at 0 or
        $var4 at 0
}
