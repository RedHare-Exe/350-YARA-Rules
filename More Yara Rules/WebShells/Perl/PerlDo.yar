rule isDo{
	meta:
		author = "Ellis Tomsen"
		description = "Perl file includes do function"
		date = "11/1/25"
	strings:
		$var1 = "do("
	condition:
		$var1
}