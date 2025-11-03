import "pe"
rule ASPack
{
    meta:
    description = "Checks if a PE file was packed with ASPack"
    author = "Avery Luther"
    date = "2025-11-2"

    condition:
    	for any section in pe.sections : ( section.name matches /.aspack/ )
	and for any section in pe.sections : ( section.name matches /.adata/ )
}
