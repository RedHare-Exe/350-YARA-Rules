rule isReadPipe{
	meta:
		author = "Ellis Tomsen"
		description = "Perl file includes readpipe function"
		date = "11/1/25"
	strings:
		$var1 = "readpipe("
	condition:
		$var1
}