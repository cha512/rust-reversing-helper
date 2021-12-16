#-*- coding: utf-8 -*-
from idc import *
import idautils
import idaapi

def set_type(ea, type_str):
    _type = parse_decl(type_str, 0)  
    if apply_type(ea, _type, 1) == False:
    	print("set_type failed on 0x%016lx"%(ea))

def main():
	
	for seg in idautils.Segments():
		segname = get_segm_name(seg)
		if "text" in segname:
			
			for func_ea in idautils.Functions(seg, get_segm_end(seg)):
				f = idaapi.get_func(func_ea)
				blocks = list(idaapi.FlowChart(f))
				last_block = (0, 0)
				
				bint128_call = False
				
				for block in blocks:
					
					start_addr = block.start_ea
					end_addr = block.end_ea
					bisRetbb = False
					
					new_start_addr = start_addr

					while start_addr < end_addr:
						if print_insn_mnem(start_addr) == "call":
							new_start_addr = find_code(start_addr, SEARCH_DOWN)
						start_addr = find_code(start_addr, SEARCH_DOWN)
					
					start_addr = new_start_addr
					
					while start_addr < end_addr:
						if print_insn_mnem(start_addr) == "retn":
							bisRetbb = True
						start_addr = find_code(start_addr, SEARCH_DOWN)
					
					start_addr = new_start_addr
										
					if bisRetbb:
						
						used_reg = set()
						print_insn_mnem(start_addr) 
						
						while start_addr < end_addr:
							
							mnemonic = print_insn_mnem(start_addr)
							op1 = print_operand(start_addr, 0)
							op2 = print_operand(start_addr, 1)
							
							if mnemonic == "pop":
								if op1 in used_reg:
									used_reg.remove(op1)
								if op1 == "rsp":
									break
							
							if mnemonic in ["mov", "sub", "xor", "lea"]:
								if op1 in ["rax", "rdx"]:
									used_reg.add(op1)
								if op1.find("[") != -1 and op2 in ["rax", "rdx"]:
									if op2 in used_reg:
										used_reg.remove(op2)
							start_addr = find_code(start_addr, SEARCH_DOWN)
						
						start_addr = new_start_addr
						if "rdx" in used_reg:
							bint128_call = True
							
				
				if bint128_call:			
										
					type_str = get_type(func_ea)
					
				
					if type_str == None:
						
						idaapi.decompile(func_ea, flags = idaapi.DECOMP_NO_WAIT)
						type_str = get_type(func_ea)
						if type_str == None:
							print("get_type Failed on 0x%016lx"%(func_ea))
							continue
					
					idx = type_str.find("(")
					
					ret_type = type_str[:idx]
					if ret_type.find("__fastcall") != -1:
						ret_type = "__int128 __fastcall"
						type_str = ret_type + " temp" + type_str[idx:]
						#print(type_str)
						set_type(func_ea, type_str)
		
if __name__ == "__main__":
	main()