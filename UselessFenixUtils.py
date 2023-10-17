import os
import ida_struct
import ida_idaapi
import idc
import ida_bytes
import idaapi
import ida_typeinf
import idautils
import ida_name

"""
Log `msg` with script name
Possibly indicate it as a error
"""
def log(name, msg, error = False):
    print(f'[{name}] [{"ERROR" if error else "INFO"}]: {msg}')

"""
Return relative to script path
"""
def get_script_dir(path=""):
    dirname = os.path.dirname(os.path.realpath(__file__))
    return path if path == "" else os.path.join(dirname, path)

"""
Return tinfo by string type
Return None if error
"""
def try_str2tif(type_str, silent=False):
    if type_str[-1] != ';':
        type_str = type_str + ';'

    tinfo = idaapi.tinfo_t()
    if idaapi.parse_decl(tinfo, ida_typeinf.get_idati(), type_str, idc.PT_SILENT if silent else 0) == None:
        return None
    return tinfo

"""
Return tinfo by string type, asserts all correct
"""
def str2tif(type_str):
    tinfo = try_str2tif(type_str, True)
    assert tinfo != None and tinfo.is_correct(), f'Wrong type {type_str}'
    return tinfo

"""
Append member `mem_name` with size `mem_size` and type `type_str` to struct `sid`
Uses padding, allows to set type by string
"""
def append_member(sid, mem_name, mem_size, type_str, pad=1):
    def set_member_type_str(strid, mem_name, tinfo):
        sptr = ida_struct.get_struc(strid)
        mptr = ida_struct.get_member_by_name(sptr, mem_name)
        if tinfo != None:
            assert tinfo.is_correct(), f'Wrong type {type_str}'
            ida_struct.set_member_tinfo(sptr, mptr, 0, tinfo, ida_struct.SET_MEMTI_COMPATIBLE | ida_struct.SET_MEMTI_MAY_DESTROY)
    
    pad = 1
    if mem_size % 2 == 0:
        pad = 2
    if mem_size % 4 == 0:
        pad = 4
    if mem_size % 8 == 0:
        pad = 8
    
    struc_size = ida_struct.get_struc_size(sid)
    needed_strict_size = ((struc_size - 1) // pad + 1) * pad
    rest = needed_strict_size - struc_size
    
    if rest > 0:
        idc.add_struc_member(sid, f'__pad{struc_size}', struc_size, ida_bytes.FF_DATA, -1, rest)
    
    ans = idc.add_struc_member(sid, mem_name, -1, ida_bytes.FF_DATA, -1, mem_size)
    if type_str != '':
        set_member_type_str(sid, mem_name, str2tif(type_str))
    return ans


"""
Adds `_{i}` until name become unique struct name
"""
def get_unique_name(name):
    prefix = name
    sid = ida_struct.get_struc_id(prefix)
    if sid == ida_idaapi.BADADDR:
        return prefix
    
    i = 0
    while sid != ida_idaapi.BADADDR:
        i += 1
        prefix = name + f'_{i}'
        sid = ida_struct.get_struc_id(prefix)
    return name + f'_{i}'


"""
Set type at `ea` with `type_str`
"""
def set_type(ea, type_str):
    _type = idc.parse_decl(type_str, 0)
    idc.apply_type(ea, _type, ida_typeinf.TINFO_DEFINITE)


"""
Set string type and name at `ea`
"""
def set_type_name(ea, _type, name):
    set_type(ea, _type)
    idc.set_name(ea, name)


"""
Reverse bytes (hex)
"""
def bigendian(val):
  little_hex = bytearray.fromhex(val)
  little_hex.reverse()
  str_little = ''.join(format(x, '02x') for x in little_hex)
  return str_little


"""
Return hex asm code of function
"""
def get_func_asm(startea):
    def get_func_bounds(funcea):
        for (startea, endea) in idautils.Chunks(funcea):
            return endea
        return None
    
    endea = get_func_bounds(startea)
    if endea:
        return idc.get_bytes(startea, endea - startea, False).hex()
    else:
        return ''


"""
Make string be an identifier
"""
def fix_name(name):
    return ''.join(letter for letter in name if letter.isidentifier())


"""
Return ea of instruction argument
"""
def get_jmp_addr(ins_ea, ins_size, opcode):
    jmp_offset = int(bigendian(opcode), 16)
    assert(jmp_offset < 0xf0000000)
    return ins_ea + ins_size + jmp_offset


"""
Adds `_{i}` until name become unique ea name
"""
def get_unique_var_name(name):
    prefix = name
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, prefix)
    if ea == ida_idaapi.BADADDR:
        return prefix
    
    i = 0
    while ea != ida_idaapi.BADADDR:
        i += 1
        prefix = name + f'_{i}'
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, prefix)
    return name + f'_{i}'

