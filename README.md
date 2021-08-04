# frida-scan
A small utilities to scan process memory and search patterns using frida with a single line of command


## Usage
```
Usage: frida-scan.py [options] <process_to_hook> <ASCII pattern> 

Options:
  --version     show program's version number and exit
  -h, --help    show this help message and exit
  -A, --attach  Attach to a running process
  -S, --spawn   Spawn a new process and attach
  -P, --pid     Attach to a pid process
  -o, --output  Output folder
```

## Roadmap
The roadmap below give overview of incoming features
- add an option to allow frida pattern instead of string pattern
- add an option to select a specific memory range
- add an option to select the function where start scan  
- add color

## Author
@FrenchYeti
