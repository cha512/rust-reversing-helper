#-*- coding: utf-8 -*-
from idc import *
import idautils
import ctypes

class Demangle:
	
	def __init__(self, libraryPath):
		
		self.libRustcDemangle = ctypes.CDLL(libraryPath)
		self.libRustcDemangle.argtype = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int)
		self.libRustcDemangle.restype = ctypes.c_int

	def setLibFunc(self, name,addr,flag=False):
		
		libNameList = ["core::","alloc::","std::","builtins::","std_unicode::"]
		if flag:
			libNameList.append("sub_")
			libNameList.append("_Unwind_Resume")
		for chk in libNameList:
			if chk in name:
				flags = get_func_flags(addr)
				flags = flags | FUNC_LIB
				set_func_flags(addr,flags)

	def _demangle(self, func_list):
				
		ret = []
		
		for idx, func_name in enumerate(func_list):
			
			ret.append(func_name)
			func_name = func_list[idx].encode("latin-1")
			
			c_input_1 = ctypes.create_string_buffer(func_name ,len(func_name) + 1)
			c_input_2 = ctypes.create_string_buffer(b"", 0x100)
			
			result = self.libRustcDemangle.rustc_demangle(c_input_1, c_input_2, 0x100)
			
			if result == 1:
				ret[-1] = c_input_2.raw.split(b"\x00")[0].decode()
			
		return ret

	def demangle(self):
		
		FuncNameList = []
		demangleList = []
		FuncList = []

		for func in idautils.Functions():
			name = get_func_name(func)
			FuncList += [func]
			FuncNameList += [name]
		demangleList = self._demangle(FuncNameList)
		
		for i in range(len(FuncList)):
			addr = FuncList[i]
			old_name = FuncNameList[i]
			full_name = demangleList[i]
			self.setLibFunc(full_name,addr)
			if full_name != old_name :
				set_name(addr, full_name, SN_NOCHECK | 0x800) #SN_FORCE
				set_func_cmt(addr, full_name, 1)

def main():
	
	demangle = Demangle("rustc_demangle.dll")
	demangle.demangle()
	
if __name__ == "__main__":
	main()