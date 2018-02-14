#-*- coding: cp949 -*-
import idc
import idautils
import idaapi
import subprocess

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
def getUserFunctions(is_dwarf):
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
				lea_addr = FindCode(lea_addr , SEARCH_DOWN)
			main_main = GetOperandValue(lea_addr,1)
			for func in idautils.Functions(main_main,main_addr):
				ret += [func]
	return ret
def setLibFunc(name,addr):
	libNameList = ["core::","alloc::","std::","builtins::","std_unicode::"]
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
def stringRecoveryA():
	_rodata = idaapi.get_segm_by_name(".rodata")
	_data_rel_ro = idaapi.get_segm_by_name(".data.rel.ro")
	StringDict = {}
	startEA = _data_rel_ro.startEA
	loopcount = _data_rel_ro.endEA - startEA
	for addr in xrange(0,loopcount,8):
		Len = Qword(startEA+addr)
		Addr =  Qword(startEA+addr-8)
		if Len < 1024:
			if Byte(Addr+Len) == 0:
				Len +=1
			if idaapi.get_visible_segm_name(idaapi.getseg(Addr)) == "_rodata":
				StringDict[Addr] = Len
	for k in StringDict.keys():
		MyMakeStr(k,StringDict[k])

def stringRecoveryB():
	userfunc = getUserFunctions(False)
	for func in userfunc:
		addr_list = []
		func_ = func
		while func < FindFuncEnd(func_):
			addr_list += [func]
			func = FindCode(func , SEARCH_DOWN)
		for i in xrange(len(addr_list)-2):
			if GetMnem(addr_list[i]) == "lea" and GetMnem(addr_list[i+1]) == "mov" and GetMnem(addr_list[i+2]) == "mov":
				if "qword ptr [" in GetOpnd(addr_list[i+1],0) and "qword ptr [" in GetOpnd(addr_list[i+2],0):
					if GetOperandValue(addr_list[i+2],0) - GetOperandValue(addr_list[i+1],0) == 8:
						Addr = GetOperandValue(addr_list[i],1)
						Len  = GetOperandValue(addr_list[i+2],1)
						seg_name = idaapi.get_visible_segm_name(idaapi.getseg(Addr))
						if seg_name == "_rodata":
							if Byte(Addr+Len) != 0:
								MyMakeStr(Addr,Len)
								#print hex(Addr), Len
				elif GetOpnd(addr_list[i+1],0) == "eax" and GetOpnd(addr_list[i+2],1) == "eax":
					Addr = GetOperandValue(addr_list[i],1)
					Len  = GetOperandValue(addr_list[i+1],1)
					seg_name = idaapi.get_visible_segm_name(idaapi.getseg(Addr))
					if seg_name == "_rodata":
						if Byte(Addr+Len) == 0:
							Len +=1
						MyMakeStr(Addr,Len)
							#print hex(addr_list[i]), hex(Addr), Len
			if GetMnem(addr_list[i]) == "lea":
				 if "ref_" in GetOpnd(addr_list[i],1) or "off_" in GetOpnd(addr_list[i],1):
				 	Addr = GetOperandValue(addr_list[i],1)
				 	seg_name = idaapi.get_visible_segm_name(idaapi.getseg(Addr))
				 	if seg_name ==  "_rodata" or seg_name == "_data_rel_ro":
				 		Len = Qword(Addr+8)
				 		Cmt = get_string(Qword(Addr),Len)
				 		if Cmt != "":
				 			#print hex(addr_list[i]),Len,get_string(Qword(Addr),Len)
				 			MakeRptCmt(addr_list[i],Cmt)
				 		
				
demangle()
stringRecoveryB()
stringRecoveryA()
stringRecoveryA()


for addr in getUserFunctions(False):
	print hex(addr)
#print getUserFunctions(False)
