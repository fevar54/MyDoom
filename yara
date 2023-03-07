rule MyDoom {
    meta:
        description = "Identifies the MyDoom worm"
        author = "FEVAR54"
    strings:
        $string1 = "The document contains macros."
        $string2 = "Content-Type: application/octet-stream; name="
        $string3 = "This program cannot be run in DOS mode."
    condition:
        any of them
}
