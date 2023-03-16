#IDA 6.7+, 7.0+ plugin for Il2CppDumper
#Loads extracted types and function definitions into currently opened database
#
#Copy this file to IDA plugins folder
#Open the DLL to work on then run this from Edit->Plugins->Il2CppDumper
#Provide script.json and il2cpp.h when prompted
#If il2cpp.h is not provided, then names can still be loaded, but no type information
#
#You'll probably get a warning from UNDO at some point about reaching its buffer size limit
#This just means too many things have happened to single-step undo them all
#and can be safely ignored.  Disabling UNDO while this is running would speed things up a bit,
#but I can't for the life of me figure out how to then reenable it

import idaapi
import idc
from idc import ida_funcs, SN_NOWARN, SN_NOCHECK, FUNCATTR_START
import json

#Load missing definitions from cstdtypes into IDA database that il2cpp.h might use
class cstdtypes:
    #Standard types -- ('integral type', (aliases))
    cstd =  (('signed char', ('int8', 'int8_t', 'int_fast8_t', 'int_least8_t')),
            ('short', ('int16', 'int16_t', 'int_fast16_t', 'int_least16_t')),
            ('int', ('int32', 'int32_t', 'int_fast32_t', 'int_least32_t')),
            ('long long', ('int64', 'int64_t', 'int_fast64_t', 'int_least64_t', 'intmax_t')),
            ('unsigned char', ('uint8', 'uint8_t', 'uint_fast8_t', 'uint_least8_t')),
            ('unsigned short', ('uint16', 'uint16_t', 'uint_fast16_t', 'uint_least16_t')),
            ('unsigned int', ('uint32', 'uint32_t', 'uint_fast32_t', 'uint_least32_t')),
            ('unsigned long long', ('uint64', 'uint64_t', 'uint_fast64_t', 'uint_least64_t', 'uintmax_t')))

    #32-bit specific std types
    cstd32 = (('int', ('intptr_t',)),
              ('unsigned int', ('uintptr_t',)))

    #64-bit specific std types
    cstd64 = (('long long', ('intptr_t',)),
              ('unsigned long long', ('uintptr_t',)))

    #Build typedefs from a single entry in cstd, cstd32, or cstd64
    @staticmethod
    def build_typedefs_single(alias_entry):
        expanded = ((' '.join(('typedef', alias_entry[0], t)) + ';') for t in alias_entry[1])
        return '\n'.join(expanded)

    #Build typedefs
    @staticmethod
    def build_typedefs(alias_info):
        return '\n'.join((cstdtypes.build_typedefs_single(types) for types in alias_info))

    #Load the cstd type definitions into current IDA database
    @staticmethod
    def load():
        idc.parse_decls(cstdtypes.build_typedefs(cstdtypes.cstd))       #Load common types
        
        inf = idaapi.get_inf_structure()
        if (inf.is_32bit() and not inf.is_64bit()):                     #Have to check both to get around a bug in some versions
            idc.parse_decls(cstdtypes.build_typedefs(cstdtypes.cstd32)) #Load 32-bit types
        else:
            idc.parse_decls(cstdtypes.build_typedefs(cstdtypes.cstd64)) #Load 64-bit types

#Database writing
imageBase = idaapi.get_imagebase()

def get_addr(addr):
    return imageBase + addr

def set_name(addr, name):
    ret = idc.set_name(addr, name, SN_NOWARN | SN_NOCHECK)
    if ret == 0:
        new_name = name + '_' + str(addr)
        ret = idc.set_name(addr, new_name, SN_NOWARN | SN_NOCHECK)

def make_function(start, end):
    next_func = idc.get_next_func(start)
    if next_func < end:
        end = next_func
    if idc.get_func_attr(start, FUNCATTR_START) == start:
        ida_funcs.del_func(start)
    ida_funcs.add_func(start, end)

#Plugin class
class Il2CppDumper(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_MOD   #Keep plugin loaded, modifies database
    comment = 'Load definitions extracted by Il2CppDumper'
    help = 'Load definitions extracted by Il2CppDumper'
    wanted_name = 'Il2CppDumper'
    wanted_hotkey = ''

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        print('[Il2CppDumper] Waiting for file information...')

        #Load input files
        path = idaapi.ask_file(False, '*.json', 'script.json from Il2CppDumper')
        hpath = idaapi.ask_file(False, '*.h', 'il2cpp.h from Il2CppDumper')

        print('[Il2CppDumper] Loading script file: ' + path)
        data = json.loads(open(path, 'rb').read().decode('utf-8'))
        print('[Il2CppDumper] Done')

        #Load types into database
        cstdtypes.load()

        #Including those in il2cpp.h if provided
        load_types = False
        if hpath is not None:
            print('[Il2CppDumper] Loading types from header file: ' + hpath)
            idc.parse_decls(open(hpath, 'rb').read(), 0) #Load structs if header file provided
            load_types = True                            #Can load type declarations
            print('[Il2CppDumper] Done')

        #Define function addresses
        if "Addresses" in data:
            addresses = data["Addresses"]
            print('[Il2CppDumper] Defining addresses for ' + str(len(addresses)) + ' functions...')
            ten_pct = len(addresses) // 10
            
            for index in range(len(addresses) - 1):
                start = get_addr(addresses[index])
                end = get_addr(addresses[index + 1])
                make_function(start, end)
                if (index + 1) % ten_pct == 0:
                    print('[Il2CppDumper]     Defined ' + str(index + 1) + ' addresses')

            print('[Il2CppDumper] Done')
    
        #Apply function definitions
        if "ScriptMethod" in data:
            scriptMethods = data["ScriptMethod"]
            print('[Il2CppDumper] Importing declarations for ' + str(len(scriptMethods)) + ' functions...')
            ten_pct = len(scriptMethods) // 10

            index = 1
            for index, scriptMethod in enumerate(scriptMethods):
                addr = get_addr(scriptMethod["Address"])
                name = scriptMethod["Name"].encode("utf-8")
                set_name(addr, name)
    
                if load_types:
                    signature = scriptMethod["Signature"].encode("utf-8")
                    if idc.apply_type(addr, idc.parse_decl(signature, 0), 1) == False:
                            print('[Il2CppDumper] apply_type failed for ScriptMethod: ' + hex(addr) + ' -- ' + signature)

                if (index + 1) % ten_pct == 0:
                    print('[Il2CppDumper]     Imported ' + str(index + 1) + ' functions')

            print('[Il2CppDumper] Done')

        #Label string literals
        if "ScriptString" in data:
            scriptStrings = data["ScriptString"]
            print('[Il2CppDumper] Importing labels for ' + str(len(scriptStrings)) + ' string literals...')
            ten_pct = len(scriptStrings) // 10
            
            for index, scriptString in enumerate(scriptStrings):
                addr = get_addr(scriptString["Address"])
                value = scriptString["Value"].encode("utf-8")
                name = "StringLiteral_" + str(index + 1)
                idc.set_name(addr, name, SN_NOWARN)
                idc.set_cmt(addr, value, 1)

                if (index + 1) % ten_pct == 0:
                    print('[Il2CppDumper]     Labeled ' + str(index + 1) + ' strings')
                    
            print('[Il2CppDumper] Done')

        #.NET metadata type definitions
        if "ScriptMetadata" in data:
            scriptMetadatas = data["ScriptMetadata"]
            print('[Il2CppDumper] Importing ' + str(len(scriptStrings)) + ' metadata types...')
            ten_pct = len(scriptStrings) // 10

            for index, scriptMetadata in enumerate(scriptMetadatas):
                addr = get_addr(scriptMetadata["Address"])
                name = scriptMetadata["Name"].encode("utf-8")
                set_name(addr, name)
                idc.set_cmt(addr, name, 1)
                                           
                if load_types and scriptMetadata["Signature"] is not None:
                    signature = scriptMetadata["Signature"].encode("utf-8")
                    if idc.apply_type(addr, idc.parse_decl(signature, 0), 1) == False:
                        print('[Il2CppDumper] apply_type failed for ScriptMetadata: ' + hex(addr) + ' -- ' + signature)

                if (index + 1) % ten_pct == 0:
                    print('[Il2CppDumper]     Imported ' + str(index + 1) + ' types')

            print('[Il2CppDumper] Done')

        #.NET metadata function definitions
        if "ScriptMetadataMethod" in data:
            scriptMetadataMethods = data["ScriptMetadataMethod"]
            print('[Il2CppDumper] Importing ' + str(len(scriptStrings)) + ' metadata functions...')
            ten_pct = len(scriptStrings) // 10
            
            for index, scriptMetadataMethod in enumerate(scriptMetadataMethods):
                addr = get_addr(scriptMetadataMethod["Address"])
                name = scriptMetadataMethod["Name"].encode("utf-8")
                methodAddr = get_addr(scriptMetadataMethod["MethodAddress"])
                set_name(addr, name)
                idc.set_cmt(addr, name, 1)
                idc.set_cmt(addr, '{0:X}'.format(methodAddr), 0)

            if (index + 1) % ten_pct == 0:
                print('[Il2CppDumper]     Imported ' + str(index + 1) + ' functions')

        print('[Il2CppDumper] Finished')
        return

    def term(self):
        pass

def PLUGIN_ENTRY():
    return Il2CppDumper()
