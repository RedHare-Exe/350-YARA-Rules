import "pe"
rule WeirdSYSsections
{
    meta:
        description= "Checks for an abnormal nmumber of sections in a sys file."
        author= "Ellis Tomsen"
        date= "2025-09-19"
    strings:
        $sys = {4D 5A}
    condition:
     $sys and 
   ( pe.number_of_sections < 9 or 
    pe.number_of_sections > 13 )
}