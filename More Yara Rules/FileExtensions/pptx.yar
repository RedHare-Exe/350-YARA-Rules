rule pptx
{
    meta:
    description = "Checks if a file contains the .pptx file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = "pptx"

    condition:
    	$ext
}
