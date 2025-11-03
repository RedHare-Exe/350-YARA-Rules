rule isSocket{
	meta:
		author = "Ellis Tomsen"
		description = "Perl file includes socket function"
		date = "11/1/25"
	strings:
		$var1 = "socket("
	condition:
		$var1
}