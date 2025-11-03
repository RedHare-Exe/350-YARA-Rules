rule isIOSocket{
	meta:
		author = "Ellis Tomsen"
		description = "Perl file includes IO::Socket"
		date = "11/1/25"
	strings:
		$var1 = "IO::Socket"
	condition:
		$var1
}