rule html
{
    meta:
    description = "Checks if a file contains the .html file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = "html"

    condition:
    	$ext
}
