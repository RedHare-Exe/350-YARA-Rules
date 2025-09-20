import "pe"
rule CheckMuiImports{
    meta:
        description= "Checks the number of dll imports for mui files"
        author= "Ellis Tomsen"
        date= "2025-09-19"
    strings:
        $magic = {4D 5A}
    condition:
        $magic and 
        (pe.number_of_sections!=2) or
        (pe.number_of_imports!=0)
}