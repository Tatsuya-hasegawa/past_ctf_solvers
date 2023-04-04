#Solver for MagroCTF - DECODE17 (Ghidra Python Script)
#@author hackeT
#@category hacket CTF/ELF
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here
from __main__ import *


# decode function for getting input Key Arrays to membuf
def decode(embedded_array,size):
	flag_key_array = []
	print("embedded_array",len(embedded_array),embedded_array) #[77, 250, 11, 41, 190, 54, 248, 201, 47, 15, 1, 240, 5, 207, 57, 203, 42, 254, 212, 59, 213, 44, 213, 33, 204, 1, 75]
	print("size",size)

	# embedded_array[i] = Keychar - prevKeychar
	# formula inversing to solve !
	# Keychar = embedded_array[i] + prevKeychar

	prevKeychar = 0
	i = 0
	while i < size:
		Keychar = embedded_array[i] + prevKeychar	
		if Keychar > 256: Keychar-=256
		try: flag_key_array.append(chr(Keychar))
		except Exception as e: print(e,flag_key_array[i])
		prevKeychar = Keychar
		i+=1

	print(flag_key_array)
	return flag_key_array
		
# solver function
def main():
	main_addr = toAddr(0x08048450)
	main_func = getFunctionAt(main_addr)
	inst = getFirstInstruction(main_func)


	embedded_array = []

	# get encoded flag code array
	while inst is not None:
		if getFunctionContaining(inst.getAddress()) == main_func:
			if inst.getMnemonicString() == "MOV":
				try: 
					embedded_array.append(int(inst.getOpObjects(1)[0].getValue()))
				except Exception as e: 
					print(e,inst)
			elif inst.getMnemonicString() == "JLE":
				break
			inst = getInstructionAfter(inst)


	# (Ghidra) __size = strlen(*(char **)(key + 4));
	# (Ghidra) memset(membuf,0x58,__size)
	size = len(embedded_array)
	# (not used val) membuf = [ 0x58 ] * size

	# (Ghidra) compareResult = memcmp(&local_3b,membuf,0x1b); &local_3b = embedded_array
	flag_key_array = decode(embedded_array,size)
	print("".join(flag_key_array))


if __name__ == "__main__":
	main()
