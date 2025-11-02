rule docx
{
    meta:
    description = "Checks if a file contains the .docx file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = "docx"

    condition:
    	$ext
}
