import "pe"
rule yodasCrypter
{
    meta:
    description = "Checks if a PE file was packed with MEW"
    author = "Avery Luther"
    date = "2025-11-2"

    condition:
    	for any section in pe.sections : ( section.name == "yC" )
}
