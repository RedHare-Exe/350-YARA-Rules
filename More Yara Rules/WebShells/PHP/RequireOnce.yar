rule isRequireOnce{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes require_once function"
		date = "11/1/25"
	strings:
		$var1 = "require_once("
	condition:
		$var1
}