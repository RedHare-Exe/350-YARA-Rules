import "pe"

rule DllExportCheck {
	meta:
		author="Elizabeth Chadbourne"
		description="Checks the amount of Dll exports in a file. Flags suspicious amounts."
		date="2025-09-16"
	condition:
		pe.number_of_exports < 5 or 
        pe.number_of_exports > 10
}