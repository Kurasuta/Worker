# Worker
Wollen wir folgendes aus den PEs extrahieren:
* Sha256, md5 und sha1 der Datei selbst
* Sha256 aller sections
* debugging info (guids und pdb path, https://github.com/erocarrera/pefile/issues/62) 
* file magic+
  * aut2exe
  * py2exe
  * PE32
  * PE64
  * DLL vs. exe
  * .NET executable
  * ...
* Export und Import Namen und Symbol namen (https://github.com/erocarrera/pefile/issues/201, fix https://github.com/erocarrera/pefile/issues/58)
* build time stamp (https://gist.github.com/geudrik/03152ba1a148d9475e81, https://github.com/tomchop/metastamp/blob/master/metastamp.py) 
* DLL Export timestamp
* signing certificate hashes (https://blog.didierstevens.com/programs/authenticode-tools/) 
* .NET guid (https://www.codeproject.com/Articles/12585/The-NET-File-Format)
