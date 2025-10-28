rule SevenZ
{
    meta:
    description = "Checks if a file is an .7z file."
    author = "Avery Luther"
    date = "2025-10-27"

    strings:
	$sig = {37 7A BC AF 27 1C}
    condition:
    	$sig at 0
}
