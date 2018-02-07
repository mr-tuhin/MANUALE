The full updated Radare2 (official) cheatsheet can be found here: https://github.com/radare/radare2/blob/master/doc/intro.md

I use this gist to gather the Radare2's commands I use the most and add some notes that the official cheatsheet is missing.

# Radare2

## Command line options
```
-w: Write mode enabled
-p [prj]: Creates a project for the file being analyzed (CC add a comment when opening a file as a project)
-: Opens r2 with the malloc plugin that gives a 512 bytes memory area to play with (size can be changed)
	Similar to r2 malloc://512
```

## Configuration properties
They can be used in evaluations:`? ${asm.tabs}`

```
e: Returns configuration properties
e <property>: Checks a specific property:
	e asm.tabs => false
e <property>=<value>: Change property value
	e asm.arch=ppc
e? help about a configuration property
	e? cmd.stack
```

There is an easier interface accessible from the Visual mode, just typing `Ve`

Some interesting properties:
```
asm.describe: Show opcode description
asm.pseudo: Enable pseudo syntax
rop.len: Maximum ROP gadget length
dbg.profile: Path to RRunProfile file (see debug section)
dbg.follow.child: Continue tracing the child process on fork. By default the parent process is traced
search.flags All search results are flagged, otherwise only printed
```

## Basic Commands
Command syntax: `[.][times][cmd][~grep][@[@iter]addr!size][|>pipe]`
* `;` Command chaining: `x 3;s+3;pi 3;s+3;pxo 4;`
* `|` Pipe with shell commands: `pd | less`
* `` ` `` Radare commands: `` wx `!ragg2 -i exec` ``
* `~` grep
* `.cmd` Interprets command output, ex:
    is* prints symbols
    .is* interprets output and define the symbols in radare (normally they are already loaded if r2 was not invoked with -n)
* `..` repeats last commands (same as enter \n)
* `?` Evaluate expression
* `$$`: Here
* `@` : At (Offsets `@` are absolute, we can use $$ for relative ones: `cmd @ $$+4`)
* `@@`: Used for iterations
```
wx ff @@10 20 30      Writes ff at offsets 10, 20 and 30
wx ff @@`?s  1 10 2`  Writes ff at offsets 1, 2 and 3
wx 90 @@ sym.*        Writes a nop on every symbol
```

## Positioning
```
s address: Move cursor to address or symbol
	s-5 (5 bytes backwards)
	s- undo seek
	s+ redo seek
```
Positioning (visual mode)

```
 uU:    undo/redo seek
 Enter: follow address of jump/call
```

## Block size
The block size is the default view size for radare. All commands will work with this constraint, but you can always temporally change the block size just giving a numeric argument to the print commands for example (px 20)
```
b size: Change block size
```

## Analyze
```
aa: Analyze all (fcns + bbs) same that running r2 with -A
ad: Analyze data
	ad@rsp (analyze the stack)
```

Function analysis (normal mode)

```
af: Analyze functions
afl: List all functions
	number of functions: afl~?
afn: Rename function
afvn: Rename argumenet/local
afvt: Change type argument/local
axt: Returns cross references to (xref to)
axf: Returns cross references from (xref from)
```

## Information
```
i:  File info
iz: Strings in data section
izz: Strings in the whole binary
iS: Sections
	iS~w returns writable sections
is: Symbols
	is~FUNC exports
il: Linked libraries
ii: Imports
ie: Entrypoint
```

Get function address in GOT table:
`pd 1 @ sym.imp<funct>`
Returns a `jmp [addr]` where `addr` is the address of function in the GOT. Similar to `objdump -R | grep <func>`

# Print
```
psz n @ offset: Print n zero terminated String
px n @ offset: Print hexdump (or just x) of n bytes
pxw n @ offset: Print hexdump of n words
	pxw size@offset  prints hexadecimal words at address
pd n @ offset: Print n opcodes disassembled
pD n @ offset: Print n bytes disassembled
pi n @ offset: Print n instructions disassembled (no address, XREFs, etc. just instructions)
pdf @ offset: Print disassembled function
	pdf~XREF (grep: XREFs)
	pdf~call (grep: calls)
```

## Write
```
wx: Write hex values in current offset
	wx 123456
	wx ff @ 4
wa: Write assembly
	wa jnz 0x400d24
wc: Write cache commit
wv: Writes value doing endian conversion and padding to byte
wo[x]: Write result of operation
	wow 11223344 @102!10
		write looped value from 102 to 102+10
		0x00000066  1122 3344 1122 3344 1122 0000 0000 0000
	wox 0x90
		XOR the current block with 0x90. Equivalent to wox 0x90 $$!$b (write from current position, a whole block)
	wox 67 @4!10
		XOR from offset 4 to 10 with value 67
wf file: Writes the content of the file at the current address or specified offset (ASCII characters only)
wF file: Writes the content of the file at the current address or specified offset
wt file [sz]: Write to file (from current seek, blocksize or sz bytes)
	Eg: Dump ELF files with wt @@ hit0* (after searching for ELF headers: \x7fELF)
woO 41424344 : get the index in the De Bruijn Pattern of the given word
```



## Visual Mode:
`V` enters visual mode

```
hjkl: move around (or HJKL) (left-down-up-right)
<enter>: Follow address of the current jump/call
:cmd: Enter radare commands. Eg: x @ esi
d[f?]: Define cursor as a string, data, code, a function, or simply to undefine it.
	dr: Rename a function
	df: Define a function
v: Get into the visual code analysis menu to edit/look closely at the current function.
p/P: Rotate print (visualization) modes
c: Changes to cursor mode or exits the cursor mode
    select: Shift+[hjkl]
    i: Insert mode
    a: assembly inline
    A: Assembly in visual mode
    y: Copy
    Y: Paste
    f: Creates a flag where cursor points to
    <tab> in the hexdump view to toggle between hex and strings columns
V: View ascii-art basic block graph of current function
;[-]cmt: Add/remove comment
```

## ROP
```
/R opcodes: Search opcodes
	/R pop eax
  "/R pop e[ab]x;ret"
/a: Assemble opcode and search its bytes
	/a jmp eax
pda: Returns a library of gadgets that can be use. These gadgets are obtained by disassembling byte per byte instead of obeying to opcode length
```
Search depth can be configure with following properties:

```
e search.roplen = 4  (change the depth of the search, to speed-up the hunt)
```

## Searching
```
/ bytes: Search bytes
	\x7fELF
```
Example: Searching function preludes:

```
push ebp
mov ebp, esp

Opcodes: 5589e5

/x 5589e5
	[# ]hits: 54c0f4 < 0x0804c600  hits = 1
	0x08049f70 hit0_0 5589e557565383e4f081ec
	0x0804c31a hit0_1 5589e583ec18c704246031
	0x0804c353 hit0_2 5589e583ec1889442404c7
	0x0804c379 hit0_3 5589e583ec08e87cffffff
	0x0804c3a2 hit0_4 5589e583ec18c70424302d

pi 5 @@hit* (Print 5 first instructions of every hit)
```
Its possible to run a command for each hit. Use the `cmd.hit` property:

```
e cmd.hit=px
```

## Comments and defines
```
Cd [size]: Define as data
C- [size]: Define as code
Cs [size]: Define as String
Cf [size]: Define as struct
	We can define structures to be shown in the disassembly
CC: List all comments or add a new comment in console mode
	C* Show all comments/metadata
	CC <comment> add new comment
	CC- remove comment
```

## Flags
Flags are labels for offsets. They can be grouped in namespaces as `sym` for symbols ...
```
f: List flags
f label @ offset: Define a flag `label` at offset
	f str.pass_len @ 0x804999c
f-label: Removes flag
fr: Rename flag
fd: Returns position from nearest flag (looking backwards). Eg => entry+21
fs: Show all flag spaces
fs flagspace: Change to the specified flag space
```

## Compare files
```
r2 -m 0xf0000 /etc/fstab	; Open source file
o /etc/issue  				; Open file2 at offset 0
o  							      ; List both files
cc offset: Diff by columns between current offset address and "offset"
```


## Debugger
Start r2 in debugger mode. r2 will fork and attach

```
r2 -d [pid|cmd|ptrace] (if command contains spaces use quotes: r2 -d "ls /")

ptrace://pid (debug backend does not notice, only access to mapped memory)

```
Using a rr2 profile (so far the best way):
```
r2 -d myprog -e dbg.profile=myprog.r2
cat myprog.r2       # Run "rarun2" to see all the options availables 
 program=./myprog
 arg1=1234
```

Passing arguments direclty:
```
r2 -d ls /home
```

Using rarun2 (Need to `dc` once to enter into the program's loader):
Symbols of the program will be missing (https://github.com/radare/radare2/issues/2146)
```
r2 -d rarun2 program=pwn1 arg1=1234 
r2 -d rarun2 program=/bin/ls stdin=$(python exploit.py)
```

Commands

```
do: Reopen program
dp: Shows debugged process, child processes and threads
dc: Continue
dcu <address or symbol>: Continue until symbol (sets bp in address, continua until bp and remove bp)
dc[sfcp]: Continue until syscall(eg: write), fork, call, program address (To exit a library)
ds: Step in
dso: Step out
dss: Skip instruction
dr register=value: Change register value
dr(=)?: Show register values
db address: Sets a breakpoint at address
	db sym.main add breakpoint into sym.main
	db 0x804800 add breakpoint
	db -0x804800 remove breakpoint
dsi (conditional step): Eg: "dsi eax==3,ecx>0"
dbt: Shows backtrace
drr: Display in colors and words all the refs from registers or memory
dm: Shows memory map (* indicates current section)
	[0xb776c110]> dm
	sys 0x08048000 - 0x08062000 s r-x /usr/bin/ls
	sys 0x08062000 - 0x08064000 s rw- /usr/bin/ls
	sys 0xb776a000 - 0xb776b000 s r-x [vdso]
	sys 0xb776b000 * 0xb778b000 s r-x /usr/lib/ld-2.17.so
	sys 0xb778b000 - 0xb778d000 s rw- /usr/lib/ld-2.17.so
	sys 0xbfe5d000 - 0xbfe7e000 s rw- [stack]
```

To follow child processes in forks (set-follow-fork-mode in gdb)
```
dcf until a fork happen
then use dp to select what process you want to debug.
```

## ESIL emulation

Set emu environment:
```
e asm.emu=true 		# Run ESIL emulation analysis on disasm
e asm.emu.str=true	# Show only strings if any in the asm.emu output (much less verbose)
e asm.esil=true 	# Shows ESIL code
e asm.emu.write=true
e io.cache=true
```

Also, make sure r2 knows what you are emulating:
```
e asm.bits=32
e asm.arch=x86
```

Deinitialize ESIL env
```
ar0
aeim-
aei-
```

Reinitialize ESIL env
```
aei
aeim
aeip
```

Start emulating!




# Radare2 suite commands
All suite commands include a `-r` flag to generate instructions for r2

## rax2 - Base conversion
```
-e: Change endian
-k: random ASCII art to represent a number/hash. Similar to how SSH represents keys
-s: ASCII to hex
	rax2 -S hola (from string to hex)
	rax2 -s 686f6c61 (from hex to string)
-S: binary to hex (for files)
```

## rahash2 - Entropy, hashes and checksums
```
-a: Specify the algorithm
-b XXX: Block size
-B: Print all blocks
-a entropy: Show file entropy or entropy per block (-B -b 512 -a entropy)
```

## radiff2 - File diffing
```
-s: Calculate text distance from two files.
-d: Delta diffing (For files with different sizes. Its not byte per byte)
-C: Code diffing (instead of data)
```
Examples:

```
Diff original and patched on x86_32, using graphdiff algorithm
	radiff2 -a x86 -b32 -C original patched
Show differences between original and patched on x86_32
	radiff2 -a x86 -b32 original patched :
```

## rasm2 - Assembly/Disassembly
```
-L: Supported architectures
-a arch instruction: Sets architecture
	rasm2 -a x86 'mov eax,30' => b81e000000
-b tam: Sets block size
-d: Disassembly
	rasm2 -d b81e000000 => mov eax, 0x1e
-C: Assembly in C output
	rasm2 -C 'mov eax,30' => "\xb8\x1e\x00\x00\x00"
-D:	Disassemble showing hexpair and opcode
	rasm2 -D b81e0000 => 0x00000000   5               b81e000000  mov eax, 0x1e
-f: Read data from file instead of ARG.
-t: Write data to file
```

## rafind2 - Search
```
-Z: Look for Zero terminated strings
-s str: Look for specifc string
```

## ragg2 - Shellcode generator, C/opcode compiler
```
-P: Generate De Bruijn patterns
	ragg2 -P 300 -r
-a arch: Configure architecture
-b bits: Specify architecture bits (32/64)
-i shellcode: Specify shellcode to generate
-e encoder: Specify encoder
```
Example:
```
Generate a x86, 32 bits exec shellcode
	ragg2 -a x86 -b 32 -i exec
```

## rabin2 - Executable analysis: symbols, imports, strings ...
```
-I: Executable information
-C: Returns classes. Useful to list Java Classes
-l: Dynamic linked libraries
-s: Symbols
-z: Strings
```

## rarun2 - Launcher to run programs with different environments, args, stdin, permissions, fds
Examples:

```
r2 -b 32 -d rarun2 program=pwn1 arg1=$(ragg2 -P 300 -r) : runs pwn1 with a De Bruijn Pattern as first argument, inside radare2's debugger, and force 32 bits
r2 -d rarun2 program=/bin/ls stdin=$(python exploit.py) : runs /bin/ls with the output of exploit.py directed to stdin
```


