rule isBackticks{
	meta:
		author = "Ellis Tomsen"
		description = "Perl file includes backticks"
		date = "11/1/25"
	strings:
		$var1 = "`"
	condition:
		$var1
}