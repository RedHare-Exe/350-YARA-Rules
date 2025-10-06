rule OGG_ID{
    meta:
        description = "Idetifies a file as an OGG"
        author = "Ellis Tomsen"

    strings:
        $ogg_header_1 = {4F 67 67 53 00 02 00 00}
        $ogg_header_2 = {00 00 00 00 00 00}

    condition:
        ($ogg_header_1 at 0) or ($ogg_header_2 at 0)
}