rule isExec{
	meta:
		author = "Ellis Tomsen"
		description = "Perl file includes exec function"
		date = "11/1/25"
	strings:
		$var1 = "exec("
	condition:
		$var1
}