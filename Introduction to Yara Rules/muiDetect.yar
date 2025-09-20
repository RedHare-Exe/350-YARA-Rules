import "pe"
import "console"

rule muiDetected 
{
        meta: 
            description= "Checks if a file is an MUI"
            author="Avery Luther"
            date="2025-09-18"
		strings:
			$muiID = "MUI" wide
        condition:
			pe.is_pe and
			pe.DLL and
			pe.number_of_imports == 0 and
			pe.number_of_exports == 0 and
			pe.number_of_sections == 2 and
			(for any section in pe.sections:((section.name == ".rdata") or (section.name == ".rsrc"))) and 
			$muiID in (0..2000)
}