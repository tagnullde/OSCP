ldd <binary> (shows linked libs like libc)
checksec.sh
objdump -R <binary> (Read GOT Entry)
objdump -x <binary> (Examine Headers -> Search for Write-Access)
objdump -d <binary> | grep <function>
objdump -d <libc_path> | grep _read (searches libc for offset of _read from start of libc)

# Leak address of system()
addr_of_system() = addr_of_read()_in_libc - libc_read()_offset + libc_system()_offset
