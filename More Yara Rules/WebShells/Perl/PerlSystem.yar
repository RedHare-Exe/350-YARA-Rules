rule isSystem{
	meta:
		author = "Ellis Tomsen"
		description = "Perl file includes system function"
		date = "11/1/25"
	strings:
		$var1 = "system("
	condition:
		$var1
}