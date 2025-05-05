# Usage


debrel search 
debrel fetch
debrel unpack
debrel manifest update-locks
debrel bootstrap "target-dir"
  -s, --source    "http://source-uri release component*"
      The release source, may be specified multiple times. 
      Must not be used together with --manifest
  -r, --requirement "package-requirements"
      Requirement in format of Depends field:
         "package"
         "package (=version)"
         "package (<=version)"
         "package | other"
      Requirement is the list of version sets to be bootstrapped.
  -c, --constraint "package-constraint"
      Constraint in format of the Conflicts field:
         "package"
         "package (=version)"
      Constraints is the list of version set to not be installed.
  -m, --manifest  "file"
      The list of sources and packages. Must not be used 
      together with --source, --requirement and --constraint
  -U, --dont-map-user  
      do not use separate user namespeace when unpacking and configuring
      packages when run by normal user.
  -k, --keyring debian|system|"file"
  -n, --no-verify
      do not verify release files
cmd fetch "target-dir"
   

cmd update "manifest"
  updates manifest file

# manifest format

```
```

```
[[source]]
url:
components:
release:

```
