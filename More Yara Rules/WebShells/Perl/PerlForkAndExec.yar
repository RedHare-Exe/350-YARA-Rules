rule isForkAndExec{
	meta:
		author = "Ellis Tomsen"
		description = "Perl file includes both the fork and exec functions"
		date = "11/1/25"
	strings:
		$var1 = "fork("
		$var2 = "exec("
	condition:
		$var1 and $var2
}