import "pe"

rule foundWeirdSectionNumber{
    meta:
        author="Avery Luther, Benjamin McKeever"
		description="Tests if a file is a PE with less than 6 or more than 8 sections."
		date="2025-09-15"

    condition:
        pe.number_of_sections >= 8 or
        pe.number_of_sections <= 6
}
