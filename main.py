#-*- coding: utf-8 -*-
from idc import *
import idautils
import idaapi

import demangle
import return_type


def get_string(addr,Len):
  out = ""
  if Len < 1024:
	  for i in range(Len):
	  	out += chr(get_wide_byte(addr+i))
  return out
  
def MyMakeStr(a,b):
	idaapi.create_strlit(a,  b, get_inf_attr(INF_STRTYPE))
	
def nameMake(name):
	name = name.replace("<","(")
	name = name.replace(">",")")
	return name

def nameFilter(name):
	table = "<>:()&[]"
	for c in table:
		name = name.replace(c,"_")
	return name 

def getUserFunctions(is_dwarf=False):
	ret = []
	if is_dwarf:
		for func in idautils.Functions():
			if chkFlagsin(func,FUNC_LIB) == False and chkFlagsin(func,FUNC_STATIC) == False:
				if idaapi.get_visible_segm_name(idaapi.getseg(func)) == "_text":
					if "main::" in get_func_name(func):
						ret += [func]
	else:
		main_addr = 0
		for func in idautils.Functions():
			if get_func_name(func) == "main":
				main_addr = func
				break
		if main_addr != 0:
			lea_addr = main_addr
			while print_insn_mnem(lea_addr) != "lea":
				lea_addr = find_code(lea_addr, SEARCH_DOWN)
			main_main = get_operand_value(lea_addr,1)
			for func in idautils.Functions(main_main,main_addr):
				ret += [func]
	return ret

def setLibFunc(name,addr,flag=False):
	libNameList = ["core::","alloc::","std::","builtins::","std_unicode::"]
	if flag:
		libNameList.append("sub_")
		libNameList.append("_Unwind_Resume")
	for chk in libNameList:
		if chk in name:
			flags = get_func_flags(addr)
			flags = flags | FUNC_LIB
			set_func_flags(addr,flags)

def chkFlagsin(a,b):
	if (get_func_flags(a) | b) == get_func_flags(a):
		return True
	return False

def paramRecovery():
	#x64 fastcall in Linux
	reg_rdi = ['rdi','edi','di','dil']
	reg_rsi = ['rsi','esi','si','sil']
	reg_rdx = ['rdx','edx','dx','dl']
	reg_rcx = ['rcx','ecx','cx','cl']
	reg_r8  = ['r8','r8d','r8w','r8b']
	reg_r9  = ['r9','r9d','r9w','r9b']
	xmm     = ['xmm0','xmm1','xmm2','xmm3']
	
	regs    = [reg_rdi, reg_rsi, reg_rdx, reg_rcx, reg_r8, reg_r9,xmm]
	bits    = [64,32,16,8]
	dType   = ["_QWORD","_DWORD","_WORD","_BYTE"]
	ChkDict_0 = {}
	ChkDict_1 = {}
	MAX_ADDR = 0xffffffffffffffff
	
	
	for seg in idautils.Segments():
		segname = get_segm_name(seg)
		if "text" in segname:
			
			for func in idautils.Functions(seg, get_segm_end(seg)):
				pCount = 0
				for i in range(0,len(regs)):
					ChkDict_0[i] = [MAX_ADDR,""]
					ChkDict_1[i] = [MAX_ADDR,""]
				inst = func
				while inst < find_func_end(func):
					if "mov" in print_insn_mnem(inst) or "lea" in print_insn_mnem(inst):
						for i in range(len(regs)):
							for reg in regs[i]:
								if print_operand(inst,0) in reg and ChkDict_0[i][0] == MAX_ADDR:
									ChkDict_0[i] = [inst,dType[regs[i].index(reg)]]
								if print_operand(inst,1) in regs[i] and ChkDict_1[i][0] == MAX_ADDR:
									ChkDict_1[i] = [inst,dType[regs[i].index(reg)]]
					elif "push" in print_insn_mnem(inst):
						for i in range(len(regs)):
							for reg in regs[i]:
								if print_operand(inst,0) in regs[i] and ChkDict_1[i][0] == MAX_ADDR:
									ChkDict_1[i] = [inst,dType[regs[i].index(reg)]]
					inst = find_code(inst, SEARCH_DOWN)
				for i in range(0,6):
					if ChkDict_0[i][0] > ChkDict_1[i][0] and ChkDict_1[i][0] != MAX_ADDR:
						pCount +=1
				#if pCount == 6 probably uses stack
				if type(get_type(func)) != type(None):
					if pCount < 6:
						fName = get_func_name(func)
						realType = "__int64 __fastcall " + nameFilter(fName) + " ("
						for i in range(pCount):
							if ChkDict_1[i][1] == "":
								ChkDict_1[i][1] = "_QWORD"
							realType += (ChkDict_1[i][1] + ",")
						if realType[-1:] == ",":
							realType = realType[:-1]
						realType += ")"
						
						if SetType(func,realType) != True:
							print (realType)
		
def main():
	demangle.main()
	paramRecovery()
	return_type.main()


if __name__ == "__main__":
	main()
