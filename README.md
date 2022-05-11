# Links to YARA rules

This page contains links to malware-related YARA rules which have been provided by the community and which can be used to hunt for certain malware families using tools such as [ClamAV](https://docs.clamav.net/manual/Signatures/YaraRules.html).

Use at your own risk. Some rules may be outdated, others may lead to false positives.

## Emotet rules

- https://docs.velociraptor.app/exchange/artifacts/pages/windows.carving.emotet/
- https://github.com/StrangerealIntel/DailyIOC/blob/master/2021-11-16/MAL_Emotet_Nov_2021_1.yara
-  https://www.bka.de/SharedDocs/Downloads/DE/IhreSicherheit/Warnhinweise/WarnhinweisEMOTET_technischeIndikatoren.asc;jsessionid=35B4FB86F41696A00FAB52EA50CB9D96.live0612?__blob=publicationFile&v=4 (via https://www.bka.de/SharedDocs/Kurzmeldungen/DE/Warnhinweise/210416_Emotet.html?nn=3806)
- https://github.com/JPCERTCC/MalConfScan/blob/master/yara/rule.yara
- https://github.com/Neo23x0/signature-base/blob/master/yara/crime_emotet.yar
- https://github.com/Yara-Rules/rules/blob/master/malware/MALW_Emotet.yar
- https://github.com/advanced-threat-research/Yara-Rules/blob/master/malware/MALW_emotet.yar
- https://github.com/bartblaze/Yara-rules/blob/master/rules/crimeware/Unk_Crime_Downloader_1.yar
- https://github.com/ctxis/CAPE/blob/master/data/yara/CAPE/Emotet.yar
- https://github.com/ctxis/CAPE/blob/master/data/yara/CAPE/Emotet_Loader.yar
- https://github.com/elektr0ninja/maldoc-rules/blob/master/Maldoc_Emotet_Base64_PowerShell.yar
- https://github.com/mikesxrs/Open-Source-YARA-rules/blob/master/GoDaddy/emotet.yara (likely a copy of https://github.com/godaddy/yara-rules/blob/master/emotet.yara)
- https://github.com/mikesxrs/Open-Source-YARA-rules/blob/master/PL%20CERT/emotet.yara
- https://github.com/mikesxrs/Open-Source-YARA-rules/blob/master/carbon%20black/emotet.yar
- https://github.com/plushed/Yara-Rules/blob/master/emotet_pe_fuck_sophos.yar
- https://github.com/reversinglabs/reversinglabs-yara-rules/blob/develop/yara/trojan/Win32.Trojan.Emotet.yara
- https://github.com/sirpedrotavares/SI-LAB-Yara_rules/blob/master/EMOTET_Chile_20190410.yar
- https://github.com/zourick/yrepo/blob/master/Suspicious/ClamAV_Emotet_String_Aggregrate.yar
- https://malpedia.caad.fkie.fraunhofer.de/yara/win.emotet
- https://www.binarydefense.com/emotet-evolves-with-new-wi-fi-spreader/
- https://github.com/netskopeoss/NetskopeThreatLabsIOCs/blob/main/Emotet/IOCs/2022-05-06/Emotet.yar
