rule JPEG_ID{
    meta:
        description = "Idetifies a file as an JPEG"
        author = "Ellis Tomsen"

    strings:
        $jpeg_header_1 = {00 00 00 0C 6A 50 20 20}
        $jpeg_header_2 = {FF D8}
        $jpeg_header_3 = {FF D8 FF}

    condition:
        ($jpeg_header_1 at 0) or ($jpeg_header_2 at 0) or ($jpeg_header_3 at 0)
}