rule isEscapeShellARG{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes escapeshellarg function"
		date = "11/1/25"
	strings:
		$var1 = "escapeshellarg("
	condition:
		$var1
}