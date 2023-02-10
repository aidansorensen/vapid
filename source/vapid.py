#!/usr/bin/env python

import os, sys
import pefile

"""
Assignment 1: Vapid

Aidan Sorensen

Used pefile, a Python package that, very conveniently, seems to do a lot of the bit-reading for me. I used it's website and looked at the code base in their 
github to help me learn the ways I could use their data structures to access the information.

"""


def find_image_base(pe):
    """

    You can find the image's base address by looking for the field ImageBase in the IMAGE_OPTIONAL_HEADER (see above for information about the location of this structure 
     a PE-32 file). To convert a relative virtual address to a(n) "absolute" virtual address, add the value of the virtual address to the value of the field ImageBase in
      the IMAGE_OPTIONAL_HEADER. Note: Unless qualified with the word "relative", assume that "virtual address" means "absolute virtual address."

    This function finds th imagebase of the rva
    """
    #nice little package function call to do my job for me
    image_base = pe.OPTIONAL_HEADER.ImageBase
    return pe, image_base

def find_target_section(va, *args):
    """
    pe is the peData read from the executable
    
    """

    try:
        pe = args[0][0]
        image_base = args[0][1]
    except Exception:
        print("something went wrong with *args")

    #need to find the section, and their relative starting/ending addresses so I can find the section in which my rva input is.
    #find the start of the section that contains our rva. then just add the offset(the image base) and the calculation should be complete.
    headers = pe.sections
    
    #for loop that logs the addresses of the sections, and compares them to the target address in parallel.
    # If found, returns the final calculation to find the location on disk.
    for idx, i in enumerate(headers):
        section_addresses = (i.VirtualAddress, (i.VirtualAddress + i.Misc_VirtualSize))
        if section_addresses[0] < (va - image_base) and section_addresses[1] > (va - image_base):
            return (va - image_base) - section_addresses[0] + i.PointerToRawData
    
        
    
    



def main(args):
    """
    main function. Take user input from the command line, check if input is valid, then call functions to compute address on disk
    """
    # try/catch for reading the first argument, which must be the pe file executable/dll
    try:
        peData = pefile.PE(args[1])
    except Exception:
        print(f"pe filesystem didn't read into the variable correctly {Exception}")
        sys.exit(1)
    
    # try/catch for the second argument, which must be the RVA to be considered for conversion to address on disk
    try:
        va = args[2]
    except Exception:
        print(f"Must input address as 2nd command line argument: {Exception}")
        quit()

    #check if input address is in hex or decimal(only allowed inputs according to assignment)
    if va.startswith("0x"): # base 16
        va = int(va, 16)
    else:
        va = int(va)

 
    # calls find_target_section, which first calles find_image_base to then calculate the target section. Returns a simple calculation of the 
    # (input RVA - base image) - section starting virtual address + BasePointerData(for that section)
    answer = find_target_section(va, find_image_base(peData))
    if answer:
        print(f"{hex(va)} -> {hex(answer)}")
    else:
        print(f"{hex(va)} -> ??")



if __name__ == "__main__":
    main(sys.argv)
