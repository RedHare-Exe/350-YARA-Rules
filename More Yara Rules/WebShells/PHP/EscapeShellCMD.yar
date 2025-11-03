rule isEscapeShellCMD{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes escapeshellcmd function"
		date = "11/1/25"
	strings:
		$var1 = "escapeshellcmd("
	condition:
		$var1
}