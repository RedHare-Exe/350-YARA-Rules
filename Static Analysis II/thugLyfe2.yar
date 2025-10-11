rule thug_JPEG_Dropper {
    meta:
        description="Finds JPEG files that contain a specific Base64 string associated with Thug Lyfe droppers."
            author="Benjamin McKeever"
            date="2025-10-11"
            threatFamily="Thug Lyfe"

    strings:
        $JPEG = { FF D8 FF E0 }
        $badString = "Y21kIC9jIHBvd2Vyc2hlbGwgaW52b2tlLXdlYnJlcXVlc3QgLXVyaSAnaHR0cDovLzEwOC4xODEuMTU1LjMxL2FzZWZhLmJhdCcgLW91dGZpbGUgJ2M6XHByb2dyYW1kYXRhXGFzZWZhLmJhdCcK"

    condition:
        $JPEG at 0 and
        $badString
}


rule thug_EXE_Dropper {
        meta: 
            description= "Finds EXE files that contain a URL used in Thug Lyfe droppers."
            author="Benjamin McKeever"
            date="2025-10-11"
            threatFamily="Thug Lyfe"

        strings:
            $url = "http://165.73.244.11/img/frontpage.jpg"

        condition:
            $url
}

rule thug_DOCM_Dropper_Flag {
        meta:
            description="Flags DOCM files that contain a reference to vbaProject.bin. This is used in Thug Lyfe DOCM droppers, and indicates that the vbaProject.bin file should be extracted from the DOCM, and the rule thug_VBA_scan should be run."
            author="Benjamin McKeever"
            date="2025-10-11"
            threatFamily="Thug Lyfe"
        
        strings:
            $vba = "vbaProject.bin"
        
        condition:
            $vba
}

rule thug_VBA_Scan {
        meta:
                description= "Finds extracted vbaProject.bin files that contain a URL used in Thug Lyfe droppers."
                author="Benjamin McKeever"
                date="2025-10-11"
                threatfamily="Thug Lyfe"
        
        strings:
                $url = "http://192.168.1.2/image_downloader.exe"

        condition:
                $url
}