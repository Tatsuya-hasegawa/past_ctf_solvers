#Solver for CpawCTF rev100 (Ghidra Python Script)
#@author hackeT
#@category hacket CTF/ELF
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here
from __main__ import *
import struct

        
# solver function
def main():
    main_addr = toAddr(0x0804849d)
    main_func = getFunctionAt(main_addr)
    inst = getFirstInstruction(main_func)


    flag_array = []
    # get encoded flag code array
    while inst is not None:
        if getFunctionContaining(inst.getAddress()) == main_func:
            if inst.getMnemonicString() == "MOV":
                try: 
                    if struct.pack("<L",inst.getOpObjects(1)[0].getValue())=="cpaw":
                        #print("pass1")
                        flag_array.append("craw")
                    elif struct.pack("b",inst.getOpObjects(1)[0].getValue())=="{":
                        flag_array.append("{")
                    elif struct.pack("b",inst.getOpObjects(1)[0].getValue())=="}":
                        #print("pass2")
                        flag_array.append("}")
                        break
                    else: # get chars of flag
                        flag_array.append(struct.pack("b",inst.getOpObjects(1)[0].getValue()))
                except Exception as e: 
                    print(e,inst)
            elif inst.getMnemonicString() == "LEA":
                break
            inst = getInstructionAfter(inst)


    print("flag = ","".join(flag_array))


if __name__ == "__main__":
    main()