# Worker

## extracts from PEs
* sha256, md5 and sha1 of file itself
* sha256 of each section (also record section position)
* debugging info (GUID and pdb path, https://github.com/erocarrera/pefile/issues/62) 
* file magic++
  * aut2exe
  * py2exe
  * PE32
  * PE64
  * DLL vs. exe
  * .NET executable
  * ...
* Export und Import Namen und Symbol Namen (with position, https://github.com/erocarrera/pefile/issues/201, fix https://github.com/erocarrera/pefile/issues/58)
* build time stamp (https://gist.github.com/geudrik/03152ba1a148d9475e81, https://github.com/tomchop/metastamp/blob/master/metastamp.py) 
* signing certificate hashes (https://blog.didierstevens.com/programs/authenticode-tools/) 
* .NET GUIDs (https://www.codeproject.com/Articles/12585/The-NET-File-Format)
