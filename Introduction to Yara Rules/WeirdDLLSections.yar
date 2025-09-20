import "pe"
rule WeirdSYSsections
{
    meta:
        description= "Checks for an abnormal nmumber of sections in a sys file."
        author= "Ellis Tomsen"
        date= "2025-09-19"
    strings:
        $dll = {4D 5A}
    condition:
     $dll and 
   ( pe.number_of_sections < 9 or 
    pe.number_of_sections > 13 )
}