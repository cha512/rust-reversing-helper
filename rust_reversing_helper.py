#-*- coding: cp949 -*-
from idc import *
import idautils
import idaapi
import subprocess
import os
from hashlib import sha256




def get_string(addr,Len):
  out = ""
  if Len < 1024:
	  for i in range(Len):
	  	out += chr(get_wide_byte(addr+i))
  return out
  
def MyMakeStr(a,b):
	idaapi.create_strlit(a,  b, get_inf_attr(INF_STRTYPE))
	#idaapi.create_strlit(a,  b, ASCSTR_C)
	
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

def _demangle(func_list):
	#input your rustfilt directory
	proc = subprocess.Popen("C:\\Users\\Soo\\.cargo\\bin\\rustfilt.exe",stdout=subprocess.PIPE,stdin=subprocess.PIPE)
	stdout = proc.communicate(input="\n".join(func_list).encode())
	return stdout[0].decode().split('\n')

def demangle():
	FuncNameList = []
	demangleList = []
	FuncList = []

	for func in idautils.Functions():
		name = get_func_name(func)
		FuncList += [func]
		FuncNameList += [name]
	demangleList = _demangle(FuncNameList)
	
	for i in range(len(FuncList)):
		addr = FuncList[i]
		old_name = FuncNameList[i]
		full_name = demangleList[i]
		setLibFunc(full_name,addr)
		if full_name != old_name :
			set_name(addr, nameMake(full_name), SN_NOCHECK | 0x800) #SN_FORCE
			set_func_cmt(addr, full_name, 1)
	uFunc = getUserFunctions()
	
	for i in range(0,len(FuncList)):
		if not FuncList[i] in uFunc:
			setLibFunc(FuncNameList[i],FuncList[i],True)

def stringRecoveryA():
	_rodata = idaapi.get_segm_by_name(".rodata")
	_data_rel_ro = idaapi.get_segm_by_name(".data.rel.ro")
	_rodata_name = "_rodata"
	
	#for exe
	if not _rodata:
		_rodata = idaapi.get_segm_by_name(".rdata")
		_data_rel_ro = idaapi.get_segm_by_name(".rdata")
		_rodata_name = "_rdata"
	StringDict = {}
	start_ea = _data_rel_ro.start_ea
	loopcount = _data_rel_ro.end_ea - start_ea
	for addr in range(0,loopcount,8):
		Len = get_qword(start_ea+addr)
		Addr =  get_qword(start_ea+addr-8)
		if Len < 1024 and Addr + Len < 2**64:
			if get_wide_byte(Addr+Len) == 0:
				Len +=1
			if idaapi.get_visible_segm_name(idaapi.getseg(Addr)) == _rodata_name:
				StringDict[Addr] = Len
	for k in StringDict.keys():
		MyMakeStr(k,StringDict[k])

def stringRecoveryB():
	
	#for exe
	_rodata_name = "_rodata"
	if not idaapi.get_segm_by_name(".rodata"):
		_rodata_name = "_rdata"
	
	userfunc = getUserFunctions(False)
	for func in userfunc:
		addr_list = []
		inst = func
		while inst < find_func_end(func):
			addr_list += [inst]
			inst = find_code(inst, SEARCH_DOWN)
		for i in range(len(addr_list)-2):
			if print_insn_mnem(addr_list[i]) == "lea" and print_insn_mnem(addr_list[i+1]) == "mov" and print_insn_mnem(addr_list[i+2]) == "mov":
				if "qword ptr [" in print_operand(addr_list[i+1],0) and "qword ptr [" in print_operand(addr_list[i+2],0):
					if get_operand_value(addr_list[i+2],0) - get_operand_value(addr_list[i+1],0) == 8:
						Addr = get_operand_value(addr_list[i],1)
						Len  = get_operand_value(addr_list[i+2],1)
						seg_name = idaapi.get_visible_segm_name(idaapi.getseg(Addr))
						if seg_name == _rodata_name:
							if get_wide_byte(Addr+Len) != 0:
								MyMakeStr(Addr,Len)
								#print hex(Addr), Len
				elif print_operand(addr_list[i+1],0) == "eax" and print_operand(addr_list[i+2],1) == "eax":
					Addr = get_operand_value(addr_list[i],1)
					Len  = get_operand_value(addr_list[i+1],1)
					seg_name = idaapi.get_visible_segm_name(idaapi.getseg(Addr))
					if seg_name == _rodata_name:
						if get_wide_byte(Addr+Len) == 0:
							Len +=1
						MyMakeStr(Addr,Len)
							#print hex(addr_list[i]), hex(Addr), Len
			if print_insn_mnem(addr_list[i]) == "lea":
				 if "ref_" in print_operand(addr_list[i],1) or "off_" in print_operand(addr_list[i],1):
				 	Addr = get_operand_value(addr_list[i],1)
				 	seg_name = idaapi.get_visible_segm_name(idaapi.getseg(Addr))
				 	if seg_name ==  _rodata_name or seg_name == "_data_rel_ro":
				 		Len = get_qword(Addr+8)
				 		Cmt = get_string(get_qword(Addr),Len)
				 		if Cmt != "":
				 			#print hex(addr_list[i]),Len,get_string(get_qword(Addr),Len)
				 			set_cmt(addr_list[i],Cmt,1)

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

	for func in idautils.Functions():
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
			if pCount < 6 and get_type(func).count(",") >= 3:
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
def LoadSignature(fname):
	
	print ('InFunc')
	stream = open(fname,"rb")
	sig = stream.read()
	stream.close()
	sig = b"rDict = " + sig
	exec(sig)
	
	
	FuncNameList = []
	demangleList = []
	FuncList = []

	for func in idautils.Functions():
		name = get_func_name(func)
		fEnd = find_func_end(func)
		fSize = fEnd-func
		inst = func
		Sig = ""
		
		while inst < fEnd:
			iSize = get_item_size(inst)
			Sig += str(iSize)+chr(get_wide_byte(inst))+chr(get_wide_byte(inst+iSize-1))
			inst = find_code(inst, SEARCH_DOWN)	
		
		cHash = str(sha256(Sig.encode('utf-8')).hexdigest())
		try:
			FuncNameList += [rDict.keys()[rDict.values().index(cHash)]]
			FuncList += [func]
			#print cHash
		except:
			pass
	demangleList = _demangle(FuncNameList)
	print ("Total Recovered :", len(FuncList))
	for i in range(len(FuncList)):
		addr = FuncList[i]
		old_name = FuncNameList[i]
		full_name = demangleList[i]
		setLibFunc(full_name,addr)
		if full_name != old_name :
			set_name(addr, nameMake(full_name), SN_NOCHECK | 0x800)
			set_func_cmt(addr, full_name, 1)
		
def main():
	LoadSignature("Signature.rust")
	
	demangle()
	for i in range(0,5):
		stringRecoveryA()
		stringRecoveryB()

	#Experimental Feature
	paramRecovery()
	for i in getUserFunctions():
          print (hex(i),)
	print ("")

if __name__ == "__main__":
	main()
