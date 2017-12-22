import binascii
import struct

from hexdump import hexdump
from unicorn import *
from unicorn.arm_const import *
from capstone import *

'''
{'type': 'send', 'payload': '0::::3A7692A804DB3B12072AEFBCF67A18BBC776C8393DA74DD3763D6226B5FB8310'}
PK:3A7692A804DB3B12072AEFBCF67A18BBC776C8393DA74DD3763D6226B5FB8310
{'type': 'send', 'payload': '1::::5009F6C763D71D15A307375480D342E47B95149C33DEB515C16F577A132D7DFB'}
SK:5009F6C763D71D15A307375480D342E47B95149C33DEB515C16F577A132D7DFB
attaching blake
{'type': 'send', 'payload': '2::::B10CD28E5E70EBB8AEF02A25BBCF44F9242083909059D482AF5CDD94B2C58704'}
PKS:B10CD28E5E70EBB8AEF02A25BBCF44F9242083909059D482AF5CDD94B2C58704
b2hash: 18000000C266A28A85C051186B68348368F52EF20701BA22464FE5BB4C343814
Entering pt5 at 0xf0f0db70
Base at: 0xf0b2e000
Image end at: 0xf1400684
r0: 0xe0ffe178
r1: 0x16e
r2: 0xf29b9620
r3: 0x17e
r4: 0xf05c279c
r5: 0xe0fff278
r6: 0xe0ffe2e8
r7: 0xe0fff668
r8: 0xf29b9600
r9: 0x17e
r10: 0xf05c27bc
r11: 0x19e
r12: 0xf411a944
sp: 0xe0ffe168
pc: 0xf0ee2f27
'''

LIBG_ADDRESS = 0xf0cf3000

libg = open('libg.so', 'rb').read()
sp_img = open('sp.bin', 'rb').read()
extra_high_img = open('extra_high_1.bin', 'rb').read()
extra_high_img_t = open('extra_high_2.bin', 'rb').read()
extra_low_image = open('extra_low_1.bin', 'rb').read()

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

enc_memcpy = [0x3EC7F6, 0x3ec8f8, 0x3EC9FA, 0x3ECAFC, 0x3ecc4c, 0x3eabe2, 0x3ec298, 0x3EC39A,
              0x3EC49C, 0x3EC59E, 0x3e0c0a, 0x2F5C1E, 0x3E0C4C, 0x3E0D3E, 0x3E0D5A, 0x3E8D22,
              0x3E8DAA, 0x3EE838]

hook_c = False


def jump(uc, address, size):
    j = address + size
    print("jumping to: " + str(hex(j - LIBG_ADDRESS)))
    uc.reg_write(UC_ARM_REG_PC, j)


def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))


def hook_code(uc, address, size, user_data):
    global hook_c
    ad = address - LIBG_ADDRESS
    if ad == 0x3EE838:
        hook_c = True
    if hook_c:
        print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (ad, size))
        for i in md.disasm(bytes(uc.mem_read(address, size)), address):
            print("0x%x:\t%s\t%s" % (i.address - LIBG_ADDRESS, i.mnemonic, i.op_str))

    # malloc replace
    if ad == 0x485E0A:
        malloc_replace(uc)

    # payload memcpy
    if ad == 0x3DFC54:
        memcpy_replace(uc)

    # priv key memcpy
    if ad == 0x3ebbaa:
        priv_key_addr = 0x400000 + 0x500 + 0x40
        uc.reg_write(UC_ARM_REG_R1, priv_key_addr)
        memcpy_replace(uc)

    # encryption memcpy calls:
    if ad in enc_memcpy:
        memcpy_replace(uc)


def hook_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
              % (address, size, value))
    else:  # READ
        print(">>> Memory is being READ at 0x%x, data size = %u" \
              % (address, size))


def hook_mem_invalid(uc, access, address, size, value, user_data):
    print("[ HOOK_MEM_INVALID - Address: %s ]" % hex(address))
    if access == UC_MEM_WRITE_UNMAPPED:
        print(
            ">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        return True
    else:
        print(
            ">>> Missing memory is being READ at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        if uc.reg_read(UC_ARM_REG_R0) == 0xd38cac1f:
            uc.reg_write(UC_ARM_REG_R0, uc.reg_read(UC_ARM_REG_SP) - 0x500)

        print(hex(uc.reg_read(UC_ARM_REG_R0)))
        print(hex(uc.reg_read(UC_ARM_REG_R1)))
        print(hex(uc.reg_read(UC_ARM_REG_R2)))
        print(hex(uc.reg_read(UC_ARM_REG_R3)))
        print(hex(uc.reg_read(UC_ARM_REG_R4)))
        print(hex(uc.reg_read(UC_ARM_REG_R5)))
        print(hex(uc.reg_read(UC_ARM_REG_R6)))
        print(hex(uc.reg_read(UC_ARM_REG_R7)))
        print(hex(uc.reg_read(UC_ARM_REG_R8)))
        print(hex(uc.reg_read(UC_ARM_REG_R9)))
        print(hex(uc.reg_read(UC_ARM_REG_R10)))
        print(hex(uc.reg_read(UC_ARM_REG_R11)))
        print(hex(uc.reg_read(UC_ARM_REG_R12)))
        return True


def hook_mem_fetch_unmapped(uc, access, address, size, value, user_data):
    print("[ HOOK_MEM_FETCH - Address: %s ]" % hex(address))
    print("[ mem_fetch_unmapped: faulting address at %s ]" % hex(address).strip("L"))
    return True


def hook_err(uc, address, data):
    print("[ HOOK_ERROR - Address: %s ]" % hex(address))
    print("[ HOOK_ERROR: faulting address at %s ]" % hex(address).strip("L"))
    return True


def malloc_replace(uc):
    l = uc.reg_read(UC_ARM_REG_R0)
    uc.mem_map(0x500000, l)
    uc.reg_write(UC_ARM_REG_R0, 0x500000)


def memcpy_replace(uc):
    b = uc.mem_read(uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2))
    uc.mem_write(uc.reg_read(UC_ARM_REG_R0), bytes(b))


def start():
    try:
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        mu.mem_map(LIBG_ADDRESS, 1024 * 1024 * 512)
        mu.mem_write(LIBG_ADDRESS, libg)

        # PATCHES
        mu.mem_write(LIBG_ADDRESS + 0x3e162e, bytes.fromhex('00bf'))

        # nop stack check guard
        mu.mem_write(LIBG_ADDRESS + 0x3dfba6, bytes.fromhex('00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x2f5b5c, bytes.fromhex('00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x2F5C36, bytes.fromhex('00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3DFBFA, bytes.fromhex('00bf'))
        # nop malloc
        mu.mem_write(LIBG_ADDRESS + 0x485E0A, bytes.fromhex('00bf00bf'))
        # nop memcpy payload
        mu.mem_write(LIBG_ADDRESS + 0x3DFC54, bytes.fromhex('00bf00bf'))
        # nop memcpy private key
        mu.mem_write(LIBG_ADDRESS + 0x3ebbaa, bytes.fromhex('00bf00bf'))
        # nop encryptions memcpy
        mu.mem_write(LIBG_ADDRESS + 0x3EC7F6, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3ec8f8, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3EC9FA, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3ECAFC, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3ecc4c, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3eabe2, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3ec298, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3EC39A, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3EC49C, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3EC59E, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3e0c0a, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x2F5C1E, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3E0C4C, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3E0D3E, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3E0D5A, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3E8D22, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3E8DAA, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3EE838, bytes.fromhex('00bf00bf'))
        # nop memclr. do not clr a shit plz
        mu.mem_write(LIBG_ADDRESS + 0x3EC70C, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3ec80e, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3EC910, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3ECA12, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3ecb62, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3eaaf8, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3ec1ae, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3EC2B0, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3EC3B2, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3EC4B4, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x2F5B62, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3E0C64, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3E8BB0, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3E8BBA, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3E8C3A, bytes.fromhex('00bf00bf'))

        # map stack pointer
        mu.mem_map(0x100000, 1024 * 512)
        mu.mem_write(0x100000, sp_img)
        sp_addr = 0x100000 + 0x8000
        # map extra memory
        mu.mem_map(0x200000, 1024 * 512)
        mu.mem_write(0x200000, extra_high_img)
        r8_addr = 0x200000 + 0x200
        mu.mem_map(0x300000, 1024 * 512)
        mu.mem_write(0x300000, extra_high_img_t)
        r12_addr = 0x300000 + 0x200
        mu.mem_map(0x400000, 1024 * 512)
        mu.mem_write(0x400000, extra_low_image)
        r4_addr = 0x400000 + 0x500
        mu.reg_write(UC_ARM_REG_R0, sp_addr + 0x10)
        mu.reg_write(UC_ARM_REG_R1, 0x16e)
        mu.reg_write(UC_ARM_REG_R2, r8_addr + 0x20)
        mu.reg_write(UC_ARM_REG_R3, 0x17e)
        mu.reg_write(UC_ARM_REG_R4, r4_addr)
        mu.reg_write(UC_ARM_REG_R5, sp_addr + 0x1110)
        mu.reg_write(UC_ARM_REG_R6, sp_addr + 0x180)
        mu.reg_write(UC_ARM_REG_R7, sp_addr + 0x1500)
        mu.reg_write(UC_ARM_REG_R8, r8_addr)
        mu.reg_write(UC_ARM_REG_R9, 0x17e)
        mu.reg_write(UC_ARM_REG_R10, r4_addr + 0x20)
        mu.reg_write(UC_ARM_REG_R11, 0x19e)
        mu.reg_write(UC_ARM_REG_R12, r12_addr)
        mu.reg_write(UC_ARM_REG_SP, sp_addr)
        mu.reg_write(UC_ARM_REG_LR, LIBG_ADDRESS + 0x3B4F22)

        # patch memory
        mu.mem_write(mu.reg_read(UC_ARM_REG_R6) + 4, struct.pack("<I", r4_addr + 0x60))
        mu.mem_write(mu.reg_read(UC_ARM_REG_R6) + 8, struct.pack("<I", sp_addr + 0x10))
        mu.mem_write(mu.reg_read(UC_ARM_REG_R6) + 12, struct.pack("<I", r4_addr + 0x40))
        mu.mem_write(mu.reg_read(UC_ARM_REG_R6) + 16, struct.pack("<I", r4_addr + 0x20))
        mu.mem_write(mu.reg_read(UC_ARM_REG_SP), struct.pack("<I", sp_addr + 0x1110))
        mu.mem_write(mu.reg_read(UC_ARM_REG_SP) + 4, struct.pack("<I", r4_addr))
        mu.mem_write(mu.reg_read(UC_ARM_REG_SP) + 8, struct.pack("<I", r4_addr + 0x40))

        print('patched stackpointer is ready to rock :P')
        hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_SP), 400))

        # mu.hook_add(UC_ERR_HOOK, hook_err)
        #mu.hook_add(UC_HOOK_BLOCK, hook_block)
        mu.hook_add(UC_HOOK_CODE, hook_code)
        #mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_access)
        #mu.hook_add(UC_HOOK_MEM_READ, hook_mem_access)
        mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_fetch_unmapped)
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
        #mu.emu_start(LIBG_ADDRESS + 0x3DFB70 | 1, LIBG_ADDRESS + 0x040EC0)
        mu.emu_start(LIBG_ADDRESS + 0x3DFB70 | 1, LIBG_ADDRESS + 0x3dfc12)
        print("encryption emulation done")
        print(hex(mu.reg_read(UC_ARM_REG_R0)))
        print(hex(mu.reg_read(UC_ARM_REG_R1)))
        print(hex(mu.reg_read(UC_ARM_REG_R2)))
        print(hex(mu.reg_read(UC_ARM_REG_R3)))
        print(hex(mu.reg_read(UC_ARM_REG_R4)))
        print(hex(mu.reg_read(UC_ARM_REG_R5)))
        print(hex(mu.reg_read(UC_ARM_REG_R6)))
        print(hex(mu.reg_read(UC_ARM_REG_R7)))
        print(hex(mu.reg_read(UC_ARM_REG_R8)))
        print(hex(mu.reg_read(UC_ARM_REG_R9)))
        print(hex(mu.reg_read(UC_ARM_REG_R10)))
        print(hex(mu.reg_read(UC_ARM_REG_R11)))
        print(hex(mu.reg_read(UC_ARM_REG_R12)))
        hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R8), mu.reg_read(UC_ARM_REG_R2)))
        mu.emu_stop()
    except UcError as e:
        print("ERROR: %s" % e)


start()
