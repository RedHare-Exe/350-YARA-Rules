rule isOpen{
	meta:
		author = "Ellis Tomsen"
		description = "Perl file includes system function"
		date = "11/1/25"
	strings:
		$var1 = "open([2-10] |"
	condition:
		$var1
}