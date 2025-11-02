import "pe"
rule upx
{
    meta:
    description = "Checks if a PE file was packed with UPX"
    author = "Avery Luther"
    date = "2025-11-2"

    condition:
    	pe.sections[0].name == "UPX0"
}
