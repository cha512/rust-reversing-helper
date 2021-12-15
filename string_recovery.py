#-*- coding: utf-8 -*-
from idc import *
import idautils
import idaapi
import subprocess
import os
import demangle

from hashlib import sha256

"""
will be deprecated...
"""

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