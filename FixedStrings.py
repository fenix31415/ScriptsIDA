"""
This script populates your db with fixed string global variables, ctors and dtors

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


class Stats:
    def __init__(self):
        self.data = defaultdict(int)
    
    def add(self, key):
        self.data[key] += 1
    
    def get_stats(self):
        log(f'STATS: ({sum(self.data.values())} total)')
        for k, v in sorted(self.data.items(), key=lambda x: -x[1]):
            log(f'  {k}: {v}')


stats = Stats()


def log(msg, error = False):
    return UselessFenixUtils.log('FixedStrings', msg, error)


def run_prepare():
    # BSFixedString::BSFixedString(char*)
    UselessFenixUtils.set_type_name(0x140C28BF0, 'BSFixedString *f(BSFixedString*, char*)', '??0BSFixedString@@QEAA@PEBD@Z')
    
    # BSFixedString::~BSFixedString()
    UselessFenixUtils.set_type_name(0x140C28D40, 'void f(BSFixedString*)', '??1BSFixedString@@QEAA@XZ')
    
    # BSStringPool::Entry::Release
    UselessFenixUtils.set_type_name(0x140C29E80, 'void f(BSFixedString*)', '?Release@Entry@BSStringPool@@SAXAEAPEAV12@@Z')


def get_fstr_name(ea):
    name = get_strlit_contents(ea, -1, STRTYPE_C)
    if name == None:
        name = "__EMPTY__"
    else:
        name = name.decode("utf-8")
    name = UselessFenixUtils.fix_name(name)
    return UselessFenixUtils.get_unique_var_name(f'fs{name}')[2:]


def run_ctor(ea):
    data = UselessFenixUtils.get_func_asm(ea)
    match = re.match('^4883ec28488d15(?P<name>........)488d0d(?P<fstr>........)e8........488d0d(?P<dtor>........)4883c428e9........$', data)
    if match:
        name_addr = UselessFenixUtils.get_jmp_addr(ea + 0x4, 0x7, match.group('name'))
        fstr_addr = UselessFenixUtils.get_jmp_addr(ea + 0xB, 0x7, match.group('fstr'))
        dtor_addr = UselessFenixUtils.get_jmp_addr(ea + 0x17, 0x7, match.group('dtor'))
        name = get_fstr_name(name_addr)
        
        UselessFenixUtils.set_type_name(fstr_addr, 'BSFixedString', f'fs{name}')
        UselessFenixUtils.set_type_name(dtor_addr, 'void f()', f'dynamic_atexit_destructor_for__fs{name}__')
        UselessFenixUtils.set_type_name(ea, 'void f()', f'dynamic_initializer_for__fs{name}__')
        
        stats.add('Ctor');
        stats.add('Dtor');


def run_all():
    global stats
    
    stats = Stats()

    run_prepare()
    
    # BSFixedString::BSFixedString
    for xref in XrefsTo(0x140C28BF0):
        func = ida_funcs.get_func(xref.frm)
        if func != None:
            run_ctor(func.start_ea)
    
    stats.get_stats();
