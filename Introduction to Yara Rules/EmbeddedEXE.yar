rule EmbeddedEXE {
	meta:
		author="Elizabeth Chadbourne"
		description="Checks for embedded executables"
		date="2025-09-17"
	strings:
		$executable = "!This program cannot be run in DOS mode."
condition:
		#executable > 1
}