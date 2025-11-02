rule zip
{
    meta:
    description = "Checks if a file is an .zip file."
    author = "Avery Luther"
    date = "2025-10-27"

    strings:
	$sig = {50 4B 03 04}
    condition:
    	$sig at 0
}
