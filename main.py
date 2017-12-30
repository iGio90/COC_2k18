import binascii
import struct

from hexdump import hexdump
from unicorn import *
from unicorn.arm_const import *
from capstone import *

LIBG_ADDRESS = 0xea783000
R4_ADDR = 0xebd85c5c
R8_ADDR = 0xa2ed1bc0
R12_ADDR = 0xee631944
SP_ADDR = 0xda1f9330

libg = open('libg.so', 'rb').read()
dc_libg = open('base.bin', 'rb').read()
sp_img = open('sp.bin', 'rb').read()
extra_high_img = open('extra_high_1.bin', 'rb').read()
extra_high_img_t = open('extra_high_2.bin', 'rb').read()
extra_low_image = open('extra_low_1.bin', 'rb').read()

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

enc_memcpy = [0x3EC7F6, 0x3ec8f8, 0x3EC9FA, 0x3ECAFC, 0x3ecc4c, 0x3eabe2, 0x3ec298, 0x3EC39A,
              0x3EC49C, 0x3EC59E, 0x3e0c0a, 0x2F5C1E, 0x3E0C4C, 0x3E0D3E, 0x3E0D5A, 0x3E8D22,
              0x3E8DAA, 0x3EE838]
enc_memclr = [0x3EC70C, 0x3ec80e, 0x3EC910, 0x3ECA12, 0x3ecb62, 0x3eaaf8, 0x3ec1ae, 0x3EC2B0,
              0x3EC3B2, 0x3EC4B4, 0x2F5B62, 0x3E0C64, 0x3E8BB0, 0x3E8BBA, 0x3E8C3A]

# debug things
dbg = True
tr_dbg = False
last_jmp = 0x0
instr_map = {}
cur_block_dump = True
last_block = 0x0


def jump(uc, address, size):
    j = address + size
    print("jumping to: " + str(hex(j - LIBG_ADDRESS)))
    uc.reg_write(UC_ARM_REG_PC, j)


def hook_block(uc, address, size, user_data):
    # print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))
    pass


def hook_code(uc, address, size, user_data):
    ad = address - LIBG_ADDRESS

    global dbg
    global tr_dbg

    if ad == 0x3ECD34:
        uc.reg_write(UC_ARM_REG_R2, 0xB699)
    elif ad == 0x3E8EB8:
        uc.reg_write(UC_ARM_REG_R2, 0x8D95)
    elif ad == 0x3EE056:
        uc.reg_write(UC_ARM_REG_R1, 0x89E4)
    elif ad == 0x3EAABE:
        uc.reg_write(UC_ARM_REG_R1, 0xE6B0)
    elif ad == 0x3ED208:
        uc.reg_write(UC_ARM_REG_R2, 0x9A6E)
    elif ad == 0x3EE000:
        uc.reg_write(UC_ARM_REG_R2, 0xD6E1)
    elif ad == 0x3EE0AE:
        uc.reg_write(UC_ARM_REG_R2, 0xE75D)
    elif ad == 0x3EAF00:
        uc.reg_write(UC_ARM_REG_R1, 0x40C5)
    elif ad == 0x3EAA2A:
        uc.reg_write(UC_ARM_REG_R2, 0x24C2)
    elif ad == 0x3EB4AE:
        uc.reg_write(UC_ARM_REG_R2, 0xD8B4)
    elif ad == 0x3EDAF6:
        uc.reg_write(UC_ARM_REG_R2, 0x9FF3)
    elif ad == 0x3E062A:
        uc.reg_write(UC_ARM_REG_R2, 0xC25A)
    elif ad == 0x3EA9C6:
        uc.reg_write(UC_ARM_REG_R2, 0xEBCA)
    elif ad == 0x3EA4EE:
        uc.reg_write(UC_ARM_REG_R2, 0x42A3)
    elif ad == 0x3EAF5A:
        uc.reg_write(UC_ARM_REG_R2, 0xF8A8)
    elif ad == 0x3EA31C:
        uc.reg_write(UC_ARM_REG_R2, 0xCEFA)

    # svc
    if ad == 0x3e162e:
        uc.mem_write(uc.reg_read(UC_ARM_REG_R0), bytes.fromhex('FFFFFFFFFFFFFFFF'))

    if dbg:
        global last_jmp
        global jmp_count

        # enable flow builder
        if True:
            global cur_block_dump

            jc = ad - last_jmp
            if jc < 5 and jc > 0:
                if cur_block_dump:
                    for i in md.disasm(bytes(uc.mem_read(address, size)), address):
                        print("0x%x:\t%s\t%s" % (i.address - LIBG_ADDRESS, i.mnemonic, i.op_str))
            else:
                if ad in instr_map:
                    print('\ncall ' + instr_map[ad] + '\n\n')
                    cur_block_dump = False
                else:
                    # new block
                    cur_block_dump = True
                    print('\nnew block: ' + str(len(instr_map)) + '\n')
                    instr_map[ad] = "block " + str(len(instr_map))
                    for i in md.disasm(bytes(uc.mem_read(address, size)), address):
                        print("0x%x:\t%s\t%s" % (i.address - LIBG_ADDRESS, i.mnemonic, i.op_str))
            last_jmp = ad

    # malloc replace
    if ad == 0x485E0A:
        uc.reg_write(UC_ARM_REG_R0, 0x50000)
        uc.reg_write(UC_ARM_REG_R1, 0x64146c41)
        uc.reg_write(UC_ARM_REG_R2, 0x0)

    # payload memcpy
    if ad == 0x3DFC54:
        memcpy_replace(uc)

    # priv key memcpy
    if ad == 0x3ebbaa:
        memcpy_replace(uc)

    # encryption memcpy calls:
    if ad in enc_memcpy:
        memcpy_replace(uc)

    # encryption memclr calls:
    if ad in enc_memclr:
        memclr_replace(uc)

    # stack check
    if ad == 0x3dfba6:
        uc.reg_write(UC_ARM_REG_R0, 0x182028ea)
    if ad == 0x2F5B5C:
        uc.reg_write(UC_ARM_REG_R0, 0x182028ea)
    if ad == 0x2F5C36:
        uc.reg_write(UC_ARM_REG_R0, 0x182028ea)
    if ad == 0x3DFBFA:
        uc.reg_write(UC_ARM_REG_R0, 0x182028ea)


def print_regs(uc):
    print("r0 " + hex(uc.reg_read(UC_ARM_REG_R0)))
    print("r1 " + hex(uc.reg_read(UC_ARM_REG_R1)))
    print("r2 " + hex(uc.reg_read(UC_ARM_REG_R2)))
    print("r3 " + hex(uc.reg_read(UC_ARM_REG_R3)))
    print("r4 " + hex(uc.reg_read(UC_ARM_REG_R4)))
    print("r5 " + hex(uc.reg_read(UC_ARM_REG_R5)))
    print("r6 " + hex(uc.reg_read(UC_ARM_REG_R6)))
    print("r7 " + hex(uc.reg_read(UC_ARM_REG_R7)))
    print("r8 " + hex(uc.reg_read(UC_ARM_REG_R8)))
    print("r9 " + hex(uc.reg_read(UC_ARM_REG_R9)))
    print("r10 " + hex(uc.reg_read(UC_ARM_REG_R10)))
    print("r11 " + hex(uc.reg_read(UC_ARM_REG_R11)))
    print("r12 " + hex(uc.reg_read(UC_ARM_REG_R12)))
    print("sp " + hex(uc.reg_read(UC_ARM_REG_SP)))
    print("pc " + hex(uc.reg_read(UC_ARM_REG_PC)))
    print("lr " + hex(uc.reg_read(UC_ARM_REG_LR)))


def print_send(uc):
    hexdump(uc.mem_read(uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2)))


def hook_mem_access(uc, access, address, size, value, user_data):
    if cur_block_dump:
        if access == UC_MEM_WRITE:
            print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
                  % (address, size, value))
        else:
            print(">>> Memory is being READ at 0x%x, data size = %u, data value = 0x%x" \
                  % (address, size, value))


def hook_mem_invalid(uc, access, address, size, value, user_data):
    print("[ HOOK_MEM_INVALID - Address: %s ]" % hex(address))
    if access == UC_MEM_WRITE_UNMAPPED:
        print(
            ">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        print_regs(uc)
        return True
    else:
        print(
            ">>> Missing memory is being READ at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        print_regs(uc)
        return True


def hook_mem_fetch_unmapped(uc, access, address, size, value, user_data):
    print(hex(uc.reg_read(UC_ARM_REG_PC)))
    print("[ HOOK_MEM_FETCH - Address: %s ]" % hex(address))
    print("[ mem_fetch_unmapped: faulting address at %s ]" % hex(address).strip("L"))
    return True


def hook_err(uc, address, data):
    print("[ HOOK_ERROR - Address: %s ]" % hex(address))
    print("[ HOOK_ERROR: faulting address at %s ]" % hex(address).strip("L"))
    return True


def memcpy_replace(uc):
    b = uc.mem_read(uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2))
    uc.mem_write(uc.reg_read(UC_ARM_REG_R0), bytes(b))
    print("Copying " + str(hex(uc.reg_read(UC_ARM_REG_R2))) + " from " +
          str(hex(uc.reg_read(UC_ARM_REG_R1)) + " to " + str(hex(uc.reg_read(UC_ARM_REG_R0)))))
    print(hex(uc.reg_read(UC_ARM_REG_PC) - LIBG_ADDRESS))
    hexdump(uc.mem_read(uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2)))


def memclr_replace(uc):
    cl_pt = uc.reg_read(UC_ARM_REG_R0)
    l = uc.reg_read(UC_ARM_REG_R1)
    print("Clearing " + str(l) + " at " + str(hex(cl_pt)))
    print(hex(uc.reg_read(UC_ARM_REG_PC) - LIBG_ADDRESS))
    for i in range(0, l):
        uc.mem_write(cl_pt + i, bytes.fromhex('00'))


def start():
    try:
        # map libg
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        mu.mem_map(LIBG_ADDRESS, 1024 * 1024 * 15)
        mu.mem_write(LIBG_ADDRESS, libg)

        # map extra space
        mu.mem_map(0x50000, 1024 * 256)

        sp_img_start = SP_ADDR - 0x48000
        r4_img_start = R4_ADDR - 0x500
        r8_img_start = R8_ADDR - 0x200
        r12_img_start = R12_ADDR - 0x4000

        # write decrypted content
        mu.mem_write(LIBG_ADDRESS + 0x4A3FB4, dc_libg[0x4A3FB4:])

        # map stack pointer
        mu.mem_map(SP_ADDR & 0xFF000000, 1024 * 1024 * 24)
        mu.mem_write(sp_img_start, sp_img)
        # map extra memory
        mu.mem_map(R8_ADDR & 0xFFFF0000, 1024 * 1024 * 2)
        mu.mem_write(r8_img_start, extra_high_img)
        mu.mem_map(R12_ADDR & 0xFF000000, 1024 * 1024 * 24)
        mu.mem_write(r12_img_start, extra_high_img_t)
        mu.mem_map(R4_ADDR & 0xFFFF0000, 1024 * 1024)
        mu.mem_write(r4_img_start, extra_low_image)

        # PATCHES
        mu.mem_write(LIBG_ADDRESS + 0x3e162e, bytes.fromhex('00bf'))
        # nop jfree
        mu.mem_write(LIBG_ADDRESS + 0x485E84, bytes.fromhex('00bf00bf'))
        # nop stack check guard
        mu.mem_write(LIBG_ADDRESS + 0x3dfba6, bytes.fromhex('00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x2F5B5C, bytes.fromhex('00bf'))
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
        # nop memclr
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

        # registers
        mu.reg_write(UC_ARM_REG_R0, 0x18ed60)
        # mu.reg_write(UC_ARM_REG_R1, 0x16e)
        mu.reg_write(UC_ARM_REG_R1, 0x152)
        mu.reg_write(UC_ARM_REG_R2, R8_ADDR + 0x20)
        # mu.reg_write(UC_ARM_REG_R3, 0x17e)
        mu.reg_write(UC_ARM_REG_R3, 0x162)
        mu.reg_write(UC_ARM_REG_R4, R4_ADDR)
        mu.reg_write(UC_ARM_REG_R5, SP_ADDR + 0x4e48)
        mu.reg_write(UC_ARM_REG_R6, SP_ADDR + 0x4fb8)
        mu.reg_write(UC_ARM_REG_R7, SP_ADDR + 0x4E30)
        mu.reg_write(UC_ARM_REG_R8, R8_ADDR)
        # mu.reg_write(UC_ARM_REG_R9, 0x17e)
        mu.reg_write(UC_ARM_REG_R9, 0x162)
        mu.reg_write(UC_ARM_REG_R10, R4_ADDR + 0x20)
        # mu.reg_write(UC_ARM_REG_R11, 0x19e)
        mu.reg_write(UC_ARM_REG_R11, 0x182)
        mu.reg_write(UC_ARM_REG_R12, R12_ADDR)
        mu.reg_write(UC_ARM_REG_SP, SP_ADDR)
        mu.reg_write(UC_ARM_REG_PC, LIBG_ADDRESS + 0x3DFB7E)

        # todo: remove this
        mu.mem_write(SP_ADDR + 0x5E5C,
                     bytes.fromhex('99B61876F3FF18CAECA0AEC1F326D9981BBCAF64E7DAA317A7F10966867AF968'))
        mu.mem_write(SP_ADDR + 0x4e48, bytes.fromhex(
            'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000d007a90c1000000286563686d3373786b6e6d70703966736e6639777737386d6d7a736e62377065747a636570366534620300be0c0000002837346563643030353765393461656530663662343835343733656633613034376234363633653339000000000000001033386532373836363539313230373237ffffffff000000094c656e6f766f2050320000002466303662666436662d393333362d343666652d383839302d33303763353034386562323900000005372e312e320100000000000000103338653237383636353931323037323700000005656e2d474201040000002434653637393636362d656263612d343330322d623338302d63386131386266386634623901000000001d000000000000000000000000000000000000'))

        # add hooks
        mu.hook_add(UC_HOOK_CODE, hook_code)
        mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_fetch_unmapped)
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
        mu.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, hook_mem_access)

        # start emulation
        mu.emu_start(LIBG_ADDRESS + 0x3dfb86 | 1, LIBG_ADDRESS + 0x3B4F26)

        print_regs(mu)
        hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R8), 400))

    except UcError as e:
        print("ERROR: %s" % e)


start()
