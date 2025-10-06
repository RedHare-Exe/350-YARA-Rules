rule HEIC_ID{
    meta:
        description = "Idetifies a file as an HEIC"
        author = "Ellis Tomsen"

    strings:
        $heic_header = {00 00 00 20 66 74 79 70 68 65 69 63}

    condition:
        $jpeg_header_1 at 0
}