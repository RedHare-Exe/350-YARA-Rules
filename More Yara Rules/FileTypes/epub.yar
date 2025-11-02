rule epub
{
    meta:
    description = "Checks if a file is an .epub file."
    author = "Avery Luther"
    date = "2025-11-1"

    strings:
	$sig = { 50 4B 03 04}
	$sig2 = "epub+zipPK"
    condition:
    	$sig at 0 and $sig2 in (0..100)
}
