rule Sleptuviu_Sarasas_HiddenCell_PowerShell
{
    meta:
        description = "PowerShell WebDAV document stealer hidden in xlsm cells (scan unpacked OOXML, e.g. xl/sharedStrings.xml)"
        author = "Lukas Apynis"
        reference = "https://github.com/Wortexz"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        date = "2026-10-13"
        hash = "128aad8cd1ec33907a77acf9b62c88ca3bfa07562815308821beef160d9ddc85"
    strings:
        $cmd = "powershell.exe -EncodedCommand" ascii nocase
        $p1  = "OpenDriveBackupLogs" wide base64
        $p2  = "webdavUrl" wide base64
        $p3  = "alwaysdata.net" wide base64
        $p4  = "-Method Put" wide base64
        $p5  = "sent_files.json" wide base64
    condition:
        $cmd and 2 of ($p*)
}

rule Sleptuviu_Sarasas_VBA_Project
{
    meta:
        description = "vbaProject.bin: Cyrillic (cp1251) sheet name lookup + hidden cell read + WScript.Shell"
        author = "Lukas Apynis"
        reference = "https://github.com/Wortexz"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        date = "2026-10-13"
        hash = "55704d17d5f05019b5f616b89f8ebb0aebf7dbb38433f8b231a9c8219600c17d"
    strings:
        $sheet = { CB E8 F1 F2 31 }            // "Лист1" in cp1251
        $book  = { DD F2 E0 CA ED E8 E3 E0 }   // "ЭтаКнига" in cp1251
        $a350  = "A350" ascii
        $wsh   = "WScript.Shell" ascii nocase
    condition:
        uint32(0) == 0xE011CFD0 and all of them
}
