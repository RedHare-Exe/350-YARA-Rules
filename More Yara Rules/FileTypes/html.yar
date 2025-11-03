rule html
{
    meta:
        description = "Checks if a file is an HTML file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $html1 = "<!DOCTYPE html"
        $html2 = "<html"
        $html3 = "<head>"
        $html4 = "<body>"
        
    condition:
        any of them
}
