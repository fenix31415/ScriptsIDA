"""
This script helps with finding REL::ID and offset of function spot and vice versa

Set offsets_path to your file.

Functions:
    `help()`
        Print usage
    `get_offset(_id, offset=0)`
        Prints IDA offset for the given REL::ID and offset
    `get_id()`
        Prints REL::ID + offset for the cursor position within the current function
"""

import idaapi
import idc
import idautils
import sys
import ida_funcs
import UselessFenixUtils

## --- SETTINGS --- ##

offsets_path = 'offsets-1.5.97.0.txt'

## ^^^ SETTINGS ^^^ ##

def log(msg, error = False):
    return UselessFenixUtils.log('REL_ID_Offset', msg, error)

def find_id(ea):
    with open(UselessFenixUtils.get_script_dir(offsets_path), 'r') as inp:
        for line in inp:
            _id, offset = line.strip().split('\t')
            if (offset == ea):
                return _id
    return ""

def find_offset(_id):
    with open(UselessFenixUtils.get_script_dir(offsets_path), 'r') as inp:
        for line in inp:
            __id, offset = line.strip().split('\t')
            if (int(__id) == _id):
                return offset
    return ""


def get_id():
    ea = idc.get_screen_ea()
    offset = ea - 0x140000000
    func = ida_funcs.get_func(ea)
    if func != None:
        start_ea = func.start_ea
    else:
        start_ea = ea
    
    _id = find_id(f'{start_ea - 0x140000000:x}')
    if _id != "":
        if func != None:
            log('Function found:')
            print(f'SkyrimSE.exe+{offset:x}  --  {ea:x}')
            print(f'REL::ID({_id}).address() + 0x{ea - start_ea:x}')
        else:
            log('Object found:')
            print(f'SkyrimSE.exe+{offset:x}  --  {ea:x}')
            print(f'REL::ID({_id})')
    else:
        log('Object NOT FOUND', True)
        print(f'SkyrimSE.exe+{offset:x}')


def get_offset(_id, offset=0):
    offs = find_offset(_id)
    if offs != '':
        log(f'{0x140000000 + int(offs, 16) + offset:x}')
    else:
        log(f'ID {_id} not found')

def set_hotkey(hotkey):
    if idaapi.add_hotkey(hotkey, get_id) != None:
        log(f'Hotkey {hotkey} registered')
    else:
        log(f'Hotkey {hotkey} NOT registered', True)

def help():
    strings = [
        f'Welcome to REL_ID_Offset!',
        '    To get REL::ID and offset from the cursor position, use `get_id()` function.',
        '    To get IDA offset from REL::ID and offset, use get_offset(id, offset=0) function.',
    ]
    log("\n".join(strings))
