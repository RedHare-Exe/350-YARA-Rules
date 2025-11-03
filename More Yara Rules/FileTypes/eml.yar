rule eml
{
    meta:
        description = "Checks if a file is an Outlook email EML file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $eml1 = "From:"
        $eml2 = "To:"
        $eml3 = "Subject:"
        $eml4 = "Date:"
        $eml5 = "MIME-Version:"
        
    condition:
        3 of them
}
