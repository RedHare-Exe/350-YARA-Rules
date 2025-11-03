import "pe"
rule packman
{
    meta:
    description = "Checks if a PE file was packed with PackMan"
    author = "Avery Luther"
    date = "2025-11-2"

    condition:
    	for any section in pe.sections : ( section.name matches /.PACKMA/ )
}
