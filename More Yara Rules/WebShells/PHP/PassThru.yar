rule isPassThru{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes pass_thru function"
		date = "11/1/25"
	strings:
		$var1 = "passthru("
	condition:
		$var1
}