rule rtf
{
    meta:
    description = "Checks if a file is an .rtf file."
    author = "Avery Luther"
    date = "2025-11-1"

    strings:
	$sig = { 7B 5C 72 74 66}
    condition:
    	$sig at 0
}
