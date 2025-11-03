rule isPregReplace{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes preg_replace function"
		date = "11/1/25"
	strings:
		$var1 = "preg_replace("
		$var2 = "/e"
	condition:
		$var1 and $var2
}