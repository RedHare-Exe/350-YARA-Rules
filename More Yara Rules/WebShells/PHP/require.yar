rule isRequire{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes require function"
		date = "11/1/25"
	strings:
		$var1 = "require("
	condition:
		$var1
}