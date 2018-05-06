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
	  for i in xrange(Len):
	  	out += chr(Byte(addr+i))
  return out
  
def MyMakeStr(a,b):
	idaapi.make_ascii_string(a,  b, GetLongPrm(INF_STRTYPE))
	#idaapi.make_ascii_string(a,  b, ASCSTR_C)
	
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
					if "main::" in GetFunctionName(func):
						ret += [func]
	else:
		main_addr = 0
		for func in idautils.Functions():
			if GetFunctionName(func) == "main":
				main_addr = func
				break
		if main_addr != 0:
			lea_addr = main_addr
			while GetMnem(lea_addr) != "lea":
				lea_addr = FindCode(lea_addr, SEARCH_DOWN)
			main_main = GetOperandValue(lea_addr,1)
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
	stdout = proc.communicate(input="\n".join(func_list))
	return stdout[0].split('\n')

def demangle():
	FuncNameList = []
	demangleList = []
	FuncList = []

	for func in idautils.Functions():
		name = GetFunctionName(func)
		FuncList += [func]
		FuncNameList += [name]
	demangleList = _demangle(FuncNameList)
	
	for i in xrange(len(FuncList)):
		addr = FuncList[i]
		old_name = FuncNameList[i]
		full_name = demangleList[i]
		setLibFunc(full_name,addr)
		if full_name != old_name :
			MakeNameEx(addr, nameMake(full_name), SN_NOCHECK | 0x800) #SN_FORCE
			SetFunctionCmt(addr, full_name, 1)
	uFunc = getUserFunctions()
	
	for i in xrange(0,len(FuncList)):
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
	startEA = _data_rel_ro.startEA
	loopcount = _data_rel_ro.endEA - startEA
	for addr in xrange(0,loopcount,8):
		Len = Qword(startEA+addr)
		Addr =  Qword(startEA+addr-8)
		if Len < 1024:
			if Byte(Addr+Len) == 0:
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
		while inst < FindFuncEnd(func):
			addr_list += [inst]
			inst = FindCode(inst, SEARCH_DOWN)
		for i in xrange(len(addr_list)-2):
			if GetMnem(addr_list[i]) == "lea" and GetMnem(addr_list[i+1]) == "mov" and GetMnem(addr_list[i+2]) == "mov":
				if "qword ptr [" in GetOpnd(addr_list[i+1],0) and "qword ptr [" in GetOpnd(addr_list[i+2],0):
					if GetOperandValue(addr_list[i+2],0) - GetOperandValue(addr_list[i+1],0) == 8:
						Addr = GetOperandValue(addr_list[i],1)
						Len  = GetOperandValue(addr_list[i+2],1)
						seg_name = idaapi.get_visible_segm_name(idaapi.getseg(Addr))
						if seg_name == _rodata_name:
							if Byte(Addr+Len) != 0:
								MyMakeStr(Addr,Len)
								#print hex(Addr), Len
				elif GetOpnd(addr_list[i+1],0) == "eax" and GetOpnd(addr_list[i+2],1) == "eax":
					Addr = GetOperandValue(addr_list[i],1)
					Len  = GetOperandValue(addr_list[i+1],1)
					seg_name = idaapi.get_visible_segm_name(idaapi.getseg(Addr))
					if seg_name == _rodata_name:
						if Byte(Addr+Len) == 0:
							Len +=1
						MyMakeStr(Addr,Len)
							#print hex(addr_list[i]), hex(Addr), Len
			if GetMnem(addr_list[i]) == "lea":
				 if "ref_" in GetOpnd(addr_list[i],1) or "off_" in GetOpnd(addr_list[i],1):
				 	Addr = GetOperandValue(addr_list[i],1)
				 	seg_name = idaapi.get_visible_segm_name(idaapi.getseg(Addr))
				 	if seg_name ==  _rodata_name or seg_name == "_data_rel_ro":
				 		Len = Qword(Addr+8)
				 		Cmt = get_string(Qword(Addr),Len)
				 		if Cmt != "":
				 			#print hex(addr_list[i]),Len,get_string(Qword(Addr),Len)
				 			MakeRptCmt(addr_list[i],Cmt)

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
		for i in xrange(0,len(regs)):
			ChkDict_0[i] = [MAX_ADDR,""]
			ChkDict_1[i] = [MAX_ADDR,""]
		inst = func
		while inst < FindFuncEnd(func):
			if "mov" in GetMnem(inst) or "lea" in GetMnem(inst):
				for i in xrange(len(regs)):
					for reg in regs[i]:
						if GetOpnd(inst,0) in reg and ChkDict_0[i][0] == MAX_ADDR:
							ChkDict_0[i] = [inst,dType[regs[i].index(reg)]]
						if GetOpnd(inst,1) in regs[i] and ChkDict_1[i][0] == MAX_ADDR:
							ChkDict_1[i] = [inst,dType[regs[i].index(reg)]]
			elif "push" in GetMnem(inst):
				for i in xrange(len(regs)):
					for reg in regs[i]:
						if GetOpnd(inst,0) in regs[i] and ChkDict_1[i][0] == MAX_ADDR:
							ChkDict_1[i] = [inst,dType[regs[i].index(reg)]]
			inst = FindCode(inst, SEARCH_DOWN)
		for i in xrange(0,6):
			if ChkDict_0[i][0] > ChkDict_1[i][0] and ChkDict_1[i][0] != MAX_ADDR:
				pCount +=1
		#if pCount == 6 probably uses stack
		if type(GetType(func)) != type(None):
			if pCount < 6 and GetType(func).count(",") >= 3:
				fName = GetFunctionName(func)
				realType = "__int64 __fastcall " + nameFilter(fName) + " ("
				for i in xrange(pCount):
					if ChkDict_1[i][1] == "":
						ChkDict_1[i][1] = "_QWORD"
					realType += (ChkDict_1[i][1] + ",")
				if realType[-1:] == ",":
					realType = realType[:-1]
				realType += ")"
				
				if SetType(func,realType) != True:
					print realType
def LoadSignature(fname):
	
	print 'InFunc'
	stream = open(fname,"rb")
	sig = stream.read()
	stream.close()
	sig = "rDict = " + sig
	exec(sig)
	
	
	FuncNameList = []
	demangleList = []
	FuncList = []

	for func in idautils.Functions():
		name = GetFunctionName(func)
		fEnd = FindFuncEnd(func)
		fSize = fEnd-func
		inst = func
		Sig = ""
		
		while inst < fEnd:
			iSize = ItemSize(inst)
			Sig += str(iSize)+chr(Byte(inst))+chr(Byte(inst+iSize-1))
			inst = FindCode(inst, SEARCH_DOWN)	
		
		cHash = str(sha256(Sig).hexdigest())
		try:
			FuncNameList += [rDict.keys()[rDict.values().index(cHash)]]
			FuncList += [func]
			#print cHash
		except:
			pass
	demangleList = _demangle(FuncNameList)
	print "Total Recovered :", len(FuncList)
	for i in xrange(len(FuncList)):
		addr = FuncList[i]
		old_name = FuncNameList[i]
		full_name = demangleList[i]
		setLibFunc(full_name,addr)
		if full_name != old_name :
			MakeNameEx(addr, nameMake(full_name), SN_NOCHECK | 0x800)
			SetFunctionCmt(addr, full_name, 1)
		
def main():
	LoadSignature("Signature.rust")
	
	demangle()
	for i in xrange(0,5):
		stringRecoveryA()
		stringRecoveryB()

	#Experimental Feature
	paramRecovery()
	for i in getUserFunctions():
          print hex(i), 

if __name__ == "__main__":
	main()
