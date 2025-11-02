rule pdf
{
    meta:
    description = "Checks if a file contains the .pdf file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = "pdf"

    condition:
    	$ext
}
