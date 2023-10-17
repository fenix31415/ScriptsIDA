"""
This script populates your db with structs for settings, global variables, ctors and dtors

Functions:
    `help()`
        Print usage
    `run_all()`
        Run script
"""

import idaapi
import idc
import idautils
from ida_bytes import *
from collections import defaultdict
import UselessFenixUtils
import re

types_map = {
    'b': 'bool',
    'f': 'float',
    'i': 'int',
    'u': 'uint',
    'r': 'uint',
    's': 'string'
}

prefixes = {
    0x141520C38 : 'gGameSetting',
    0x141535bf8 : 'gIniPref',
    0x1415311e0 : 'gIni',
    0x14164d708 : 'gReg'
}

known_functions = []

class Stats:
    def __init__(self):
        self.data = defaultdict(int)
    
    def add(self, vtable_ea):
        self.data[vtable_ea] += 1
    
    def get_stats(self):
        print(f'STATS: ({sum(self.data.values())} total)')
        for k, v in sorted(self.data.items(), key=lambda x: -x[1]):
            print(f'  {k}: {v}')


stats = Stats()


def log(msg, error = False):
    return UselessFenixUtils.log('GameSettings', msg, error)


def get_setting_name(ea):
    name = int(UselessFenixUtils.bigendian(get_bytes(ea + 0x10, 8).hex()), 16)
    name = get_strlit_contents(name, -1, STRTYPE_C).decode("utf-8")
    assert name[0] in types_map, f'Unknown setting at {ea:x}'
    name = UselessFenixUtils.fix_name(name)
    return f'{name}_{ea:x}'


def run_function(vtable_ea, ea):
    data = UselessFenixUtils.get_func_asm(ea)
    match = re.match('^4883ec3848c7442420feffffff488d..........488905(?P<setting>........)e8........488b..........488b01488d..........ff..10488d0d........e8........904883c438c3', data)
    if match:
        setting_addr = UselessFenixUtils.get_jmp_addr(ea + 0x14, 0x7, match.group('setting'))
        name = get_setting_name(setting_addr)
        
        prefix = prefixes[vtable_ea]
        
        UselessFenixUtils.set_type_name(setting_addr, f'SettingT_{types_map[name[0]]}_', f'{prefix}_{name}')
        stats.add(f'Setting: {prefix}')
        
        UselessFenixUtils.set_type_name(ea, 'void f()', f'dynamic_atexit_destructor_for__{name}__')
        stats.add(f'Function: {prefix}')
        
        xrefs = []
        for xref in XrefsTo(ea):
            func = ida_funcs.get_func(xref.frm)
            if func != None:
                xrefs.append(func.start_ea)
        
        assert len(xrefs) == 1, f'{ea:x}'
        UselessFenixUtils.set_type_name(xrefs[0], 'void f()', f'dynamic_initializer_for__{name}__')
        stats.add(f'Function: {prefixes[vtable_ea]}')
        
        return
    
    if not ea in known_functions:
        print(f'Unknown function {ea:x}')


def run_functions(vtable_ea):
    for xref in XrefsTo(vtable_ea):
        func = ida_funcs.get_func(xref.frm)
        if func != None:
            run_function(vtable_ea, func.start_ea)


def run_prepare():
    def set_known_function(ea, _type, name):
        UselessFenixUtils.set_type_name(ea, _type, name)
        known_functions.append(ea)

    idaapi.idc_parse_types(UselessFenixUtils.get_script_dir("GameSettingsTypes.h"), idc.PT_FILE)
    
    # SettingT<T>::`scalar deleting destructor'
    # GameSettingCollection
    set_known_function(0x1400F95E0, 'void * f(void *_this, char a2)', '??_G?$SettingT@VGameSettingCollection@@@@UEAAPEAXI@Z')
    # INIPrefSettingCollection
    set_known_function(0x140164EF0, 'void * f(void *_this, char a2)', '??_G?$SettingT@VINIPrefSettingCollection@@@@UEAAPEAXI@Z')
    # INISettingCollection
    set_known_function(0x14014D4E0, 'void * f(void *_this, char a2)', '??_G?$SettingT@VINISettingCollection@@@@UEAAPEAXI@Z')
    # RegSettingCollection
    set_known_function(0x1405BBAF0, 'void * f(void *_this, char a2)', '??_E?$SettingT@VRegSettingCollection@@@@UEAAPEAXI@Z')
    
    # SettingT<T>::~SettingT<T>
    # INIPrefSettingCollection
    set_known_function(0x1402ce210, 'void * f(void *_this)', '??1?$SettingT@VINIPrefSettingCollection@@@@UEAA@XZ')
    # INISettingCollection
    set_known_function(0x140DF9850, 'void * f(void *_this)', '??1?$SettingT@VINISettingCollection@@@@UEAA@XZ')
    # Missing: GameSettingCollection, RegSettingCollection
    
    # SettingT<T>::InitCollection
    # INIPrefSettingCollection
    set_known_function(0x140165830, 'void __fastcall f()', '?InitCollection@?$SettingT@VINIPrefSettingCollection@@@@KAXXZ')
    # INISettingCollection
    set_known_function(0x14014EB90, 'void __fastcall f()', '?InitCollection@?$SettingT@VINISettingCollection@@@@KAXXZ')
    # GameSettingCollection
    set_known_function(0x1400F9980, 'void __fastcall f()', '?InitCollection@?$SettingT@VGameSettingCollection@@@@KAXXZ')
    # RegSettingCollection
    set_known_function(0x1405BCC20, 'void __fastcall f()', '?InitCollection@?$SettingT@VRegSettingCollection@@@@KAXXZ')
    
    # Collections
    UselessFenixUtils.set_type_name(0x142EC58B0, 'GameSettingCollection *', 'gGameSettingCollection')
    UselessFenixUtils.set_type_name(0x142F6BA48, 'INIPrefSettingCollection *', 'gINIPrefSettingCollection')
    UselessFenixUtils.set_type_name(0x14301D758, 'INISettingCollection *', 'gINISettingCollection')
    UselessFenixUtils.set_type_name(0x143025D80, 'RegSettingCollection *', 'gRegSettingCollection')
    
    
    # Setting::~Setting
    UselessFenixUtils.set_type_name(0x140D28BD0, 'void __fastcall f(void* setting)', '??1Setting@@UEAA@XZ')


def run_all():
    global stats
    
    stats = Stats()

    run_prepare()
    
    for k in prefixes:
        run_functions(k)
    
    stats.get_stats()
