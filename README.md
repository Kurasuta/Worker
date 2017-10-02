# Worker

## extracts from PEs
* [x] sha256, md5 and sha1 of file itself
* [x] sha256 of each section (also record section position and name)
* [x] debugging info (https://github.com/erocarrera/pefile/issues/62)
* [ ] file magic++: aut2exe, py2exe, PE32, PE64, DLL vs. exe, .NET executable, compiler / packer (http://sumtips.com/2012/05/detect-identify-exe-compiler-packer.html), ...
* [ ] Export und Import Namen und Symbol Namen (with position, https://github.com/erocarrera/pefile/issues/201, fix https://github.com/erocarrera/pefile/issues/58)
* [ ] build time stamp (https://gist.github.com/geudrik/03152ba1a148d9475e81, https://github.com/tomchop/metastamp/blob/master/metastamp.py)
* [ ] signing certificate hashes (https://blog.didierstevens.com/programs/authenticode-tools/)
* [ ] .NET GUIDs (https://www.codeproject.com/Articles/12585/The-NET-File-Format)
* [ ] Export table timestamp, Debugger section timestamp, Resources timestamp (https://github.com/smarttechnologies/peparser/blob/master/README.md)
* [ ] file size, entry point, overlay size and hash
* [ ] debugging GUID
* [ ] debug_timestamp vs pdb_timestamp
* [ ] pdb_age
* [ ] ssdeep
* [ ] Nilsimsa
* [ ] TLSH
* [ ] Sdhash
* [ ] file magic++ of all resources
* [ ] entropy of whole file and of all sections and all resources
* [ ] histogram over bytes of all .text sections
* [ ] number of strings extracted by `strings` command, also number of strings of size at least 10
* [ ] some heuristics reg. extracted strings
* [ ] full PE header (https://stackoverflow.com/questions/8193862/the-size-of-a-pe-header) and min. first KB of file
* [ ] import table and symbols
