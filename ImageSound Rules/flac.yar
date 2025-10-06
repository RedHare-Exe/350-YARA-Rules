rule flacDetected 
{
        meta: 
            description= "Checks if a file is a flac file"
            author="Avery Luther"
            date="2025-10-6"
		strings:
			$flacID = {66 4C 61 43 00 00 00 22}
        condition:
			$flac at 0
}