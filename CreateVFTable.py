"""
This script helps with creating/updating structs for vftables

Functions:
    `help()`
        Print usage
    `createVftable()`
        Reads functions starting from the cursor position
        Creates/Updates vftable struct
"""

import idaapi
import idc
import idautils
from ida_bytes import *
from ida_struct import *
import UselessFenixUtils

## --- SETTINGS --- ##

## ^^^ SETTINGS ^^^ ##

def log(msg, error = False):
    return UselessFenixUtils.log('CreateVFTable', msg, error)


def change_type(s):
    if s == None:
        return "void*"
    if '__usercall' in s:
        return "void*"
    if '#' in s:
        return "void*"
    balance = 1
    ind = len(s)-2
    while balance > 0:
        if ind > len(s) or ind < 0:
            log(f'badtype: {s}', True)
            return "void*"
        if s[ind] == ")":
            balance += 1
        if s[ind] == "(":
            balance -= 1
        ind -= 1
    ind += 1
    return s[:ind] + "(*)" + s[ind:]


def is_rtti(ea):
    name = demangle_name(get_name(ea), get_inf_attr(INF_LONG_DN))
    return name != None and 'RTTI Complete Object Locator' in name


def get_count():
    ea = idc.get_screen_ea()
    
    flags = get_flags(ea)
    is_ok = has_xref(flags) and has_any_name(flags) and (is_qword(flags) or is_unknown(flags) or has_name(flags))
    if not is_ok:
        log("Flags checks not passed", True)
        return 0
    
    start = ea
    while True:
        indexFlags = get_flags(ea)
        if not (is_qword(indexFlags) or is_unknown(indexFlags)):
            break
        
        memberPtr = get_64bit(ea)
        if (memberPtr == 0 or memberPtr == idaapi.BADADDR):
            break
        
        flags = get_flags(memberPtr)
        if not is_code(flags) and not is_unknown(flags):
            s = idaapi.getseg(memberPtr)
            if s != None:
                if (s.type != idaapi.SEG_CODE):
                    break
            else:
                break
        
        if ea != start:
            if (has_xref(indexFlags)):
                break;

            if is_rtti(memberPtr):
                break
        
        ea += 8
    
    size = (ea - start) // 8
    return size if size > 0 else 0


def is_vftable(sid, count):
    struct = get_struc(sid)
    for i in range(count):
        member = get_member(struct, i * 8)
        if member == None:
            log(f'Bad member at {i * 8}')
            return False
        mem_size = get_member_size(member)
        if mem_size != 8:
            log(f'Bad member size {mem_size} at {i * 8}')
            return False
    
    member = get_member(struct, count * 8)
    if member != None:
        log(f'Bad size: {member}')
        return False
    else:
        return True


def check_vftable(sid, count, str_size_):
    str_size = str_size_ // 8
    if str_size * 8 != str_size_:
        log(f'It has bad align: {str_size_}')
        return False
    
    if count != str_size:
        log(f'Sizes are different: {count} != {str_size}')
        return False
    
    if not is_vftable(sid, count):
        log('Structure is not a vftable')
        return False
    
    return True


def get_vftable_name():
    ea = idc.get_screen_ea()
    name = demangle_name(get_name(ea), get_inf_attr(INF_LONG_DN))
    name_ = get_name(ea)
    if name != None:
        name = name.replace('const', '')
        name = name.replace('class', '')
        name = name.replace("::`vftable'", '')
        name = name.replace('<', '_')
        name = name.replace('>', '_')
        name = name.replace('(*)', '')
        name = name.replace('(', '_')
        name = name.replace(')', '_')
        name = name.replace(',', '_')
        name = name.replace(':', '_')
        name = name.replace('*', '_')
        name = name.strip()
        name = name.replace(' ', '_')
        
        ind = name_.rfind('@_')
        if ind != -1:
            name = name + name_[ind + 1:]
    
    if not name.endswith('__'):
        name = name + '__'
    return name + "VFTable"


def create_new_struct(count):
    str_name = get_vftable_name()
    sid = ida_struct.get_struc_id(str_name)
    if sid != BADADDR:
        log(f'Found already defined struct {str_name}')
        if check_vftable(sid, count, get_struc_size(sid)):
            log(f'Updating it')
            del_struc_members(get_struc(sid), 0, 8 * count)
            return sid
    
    str_name = UselessFenixUtils.get_unique_name(str_name)
    log(f'Creating new {str_name}')
    return add_struc(-1, str_name, 0)


def createVftable():
    ea = idc.get_screen_ea()
    _type = get_type(ea)
    sid = ida_struct.get_struc_id(_type)
    
    count = get_count() if sid == BADADDR else get_struc_size(sid) // 8
    if count == 0:
        log("VFTable not found at cursor", True)
        return
    
    log(f'Found {count} vfunctions')
    
    sid = create_new_struct(count)
    
    if sid == BADADDR:
        log(f'Cannot create new struct', True)
        return
    
    ida_bytes.del_items(ea)
    
    for i in range(count):
        if count > 20 and i % 20 == 0:
            print(f'Working... {i}/{count}')
        
        addr = get_64bit(ea + 8 * i)
        name = get_name(addr)
        
        type_ = get_type(addr)
        if type_ == None:
            type_ = guess_type(addr)
        type_ = change_type(type_)
        
        if UselessFenixUtils.append_member(sid, name, 8, type_):
            UselessFenixUtils.append_member(sid, f'func_{i:x}', 8, 'void(*)()')
        
        addr += 8
    
    UselessFenixUtils.set_type(ea, get_struc_name(sid))


def help():
    log(f'Welcome to CreateVFTable!\n     Put cursor to the start of vftable and use createVftable() command')
