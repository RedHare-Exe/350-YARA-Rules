rule isEval{
	meta:
		author = "Ellis Tomsen"
		description = "Perl file includes eval function"
		date = "11/1/25"
	strings:
		$var1 = "eval("
	condition:
		$var1
}