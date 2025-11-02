rule isUse{
	meta:
		author = "Ellis Tomsen"
		description = "Perl file includes use function"
		date = "11/1/25"
	strings:
		$var1 = "use("
	condition:
		$var1
}