from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from hashlib import sha256
from capstone import *
import time

def vaddr_to_offset(elffile,address):
    load_address = address #??
    for segment in elffile.iter_segments():
        begin = segment['p_vaddr']
        size = segment['p_memsz']
        end = begin + size
        if begin <= load_address and load_address <= end:
            return segment['p_offset'] + load_address - begin

    
    
def readELF(fname):
    rDict = {}
    stream = open(fname,"rb")
    elffile = ELFFile(stream)
    rawStream = open(fname,"rb")
    rawBinary = rawStream.read()
    rawStream.close()

    
    if elffile.elfclass != 64:
        assert('not elf x64!')
        exit()
    section = elffile.get_section_by_name('.symtab')
    if section:
        if isinstance(section, SymbolTableSection):
            num_symbols = section.num_symbols()
            for i in xrange(0,num_symbols):
                if section.get_symbol(i).entry.st_info.type == "STT_FUNC":
                    Func = section.get_symbol(i).entry.st_value
                    Size = section.get_symbol(i).entry.st_size
                    Name = str(section.get_symbol(i).name)
                    
                    if Name.find("@@GLIBC") == -1 and Size > 6:
	                    offset = vaddr_to_offset(elffile,Func)
	                    binCode = ""
	                    Sig = ""
	                    cnt = 0
	                    
	                    for i in xrange(0,Size):
	                        binCode += rawBinary[offset+i]
	                    md = Cs(CS_ARCH_X86, CS_MODE_64)
	                    
	                    for i in md.disasm(binCode, Func):                    	
	                    	iSize = i.size
	                    	Sig += str(iSize)+(binCode[cnt])+(binCode[cnt+iSize-1])
	                    	cnt += iSize
	                    rDict[Name] = str(sha256(Sig).hexdigest())
    return rDict

def main():
    rDict = readELF("test\\test")
    f = open("Signature.rust","wb")
    f.write(str(rDict))
    f.close
    
if __name__ == "__main__":
    main()
