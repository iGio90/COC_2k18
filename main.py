import binascii
import struct

from hexdump import hexdump
from unicorn import *
from unicorn.arm_const import *
from capstone import *

LIBG_ADDRESS = 0xf0f12000
R4_ADDR = 0xf240755c
R8_ADDR = 0xa94e29c0
R12_ADDR = 0xf411a944
SP_ADDR = 0xe0f7e168

libg = open('libg.so', 'rb').read()
sp_img = open('sp.bin', 'rb').read()
extra_high_img = open('extra_high_1.bin', 'rb').read()
extra_high_img_t = open('extra_high_2.bin', 'rb').read()
extra_low_image = open('extra_low_1.bin', 'rb').read()

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
arm_md = Cs(CS_ARCH_ARM, CS_ARCH_ARM)

enc_memcpy = [0x3EC7F6, 0x3ec8f8, 0x3EC9FA, 0x3ECAFC, 0x3ecc4c, 0x3eabe2, 0x3ec298, 0x3EC39A,
              0x3EC49C, 0x3EC59E, 0x3e0c0a, 0x2F5C1E, 0x3E0C4C, 0x3E0D3E, 0x3E0D5A, 0x3E8D22,
              0x3E8DAA, 0x3EE838]

# debug things
dbg = True
last_jmp = 0x0
jmp_count = 0
jmp_dbg = 4


def jump(uc, address, size):
    j = address + size
    print("jumping to: " + str(hex(j - LIBG_ADDRESS)))
    uc.reg_write(UC_ARM_REG_PC, j)


def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))


def hook_code(uc, address, size, user_data):
    ad = address - LIBG_ADDRESS

    if dbg:
        global last_jmp
        global jmp_count

        if last_jmp == 0x0 or ad - last_jmp < 5 or ad + last_jmp > 5:
            last_jmp = ad
        else:
            if jmp_count < jmp_dbg:
                print(">>> JUMP " + str(jmp_count))
                jmp_count += 1
                last_jmp = ad
            else:
                print(">>> JUMP BREAK")
                uc.emu_stop()
        print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (ad, size))
        for i in md.disasm(bytes(uc.mem_read(address, size)), address):
            print("0x%x:\t%s\t%s" % (i.address - LIBG_ADDRESS, i.mnemonic, i.op_str))

    # malloc replace
    if ad == 0x485E0A:
        malloc_replace(uc)
        uc.reg_write(UC_ARM_REG_R1, 0x64146c41)
        uc.reg_write(UC_ARM_REG_R2, 0x0)

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

    if ad == 0x3EC7F6:
        print_regs(uc)


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


def malloc_replace(uc):
    uc.reg_write(UC_ARM_REG_R0, 0x500000)


def memcpy_replace(uc):
    b = uc.mem_read(uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2))
    uc.mem_write(uc.reg_read(UC_ARM_REG_R0), bytes(b))
    print("Copying " + str(hex(uc.reg_read(UC_ARM_REG_R2))) + " from " +
          str(hex(uc.reg_read(UC_ARM_REG_R1)) + " to " + str(hex(uc.reg_read(UC_ARM_REG_R0)))))
    hexdump(uc.mem_read(uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2)))


def patch_img(uc, sp_addr, r4_addr, r8_addr, r12_addr, img, img_offset):
    rsp_i = struct.unpack("<H", struct.pack("<I", SP_ADDR)[2:4])[0]
    rr4_i = struct.unpack("<H", struct.pack("<I", R4_ADDR)[2:4])[0]
    rr8_i = struct.unpack("<H", struct.pack("<I", R8_ADDR)[2:4])[0]
    rr12_i = struct.unpack("<H", struct.pack("<I", R12_ADDR)[2:4])[0]
    for i in range(0, len(img)):
        # read in chunks of 4 bytes
        b = img[i:i + 4]
        if len(b) < 4:
            break
        b_i = b[2:4]
        b_i = struct.unpack("<H", b_i)[0]
        pp = struct.unpack("<I", b)[0]
        if b_i == rsp_i:
            ppd = SP_ADDR - pp
            ppt = sp_addr + ppd
            uc.mem_write(img_offset + i, struct.pack("<I", ppt))
        elif b_i == rr4_i:
            ppd = R4_ADDR - pp
            ppt = r4_addr + ppd
            uc.mem_write(img_offset + i, struct.pack("<I", ppt))
        elif b_i == rr8_i:
            ppd = R8_ADDR - pp
            ppt = r8_addr + ppd
            uc.mem_write(img_offset + i, struct.pack("<I", ppt))
        elif b_i == rr12_i:
            ppd = R12_ADDR - pp
            ppt = r12_addr + ppd
            uc.mem_write(img_offset + i, struct.pack("<I", ppt))


def start():
    try:
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        mu.mem_map(LIBG_ADDRESS, 1024 * 1024 * 512)
        mu.mem_write(LIBG_ADDRESS, libg)
        # PATCHES
        mu.mem_write(LIBG_ADDRESS + 0x3e162e, bytes.fromhex('00bf'))
        # nop jfree
        mu.mem_write(LIBG_ADDRESS + 0x485E84, bytes.fromhex('00bf00bf'))
        # nop stack check guard
        mu.mem_write(LIBG_ADDRESS + 0x3dfba6, bytes.fromhex('00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x2f5b5c, bytes.fromhex('00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x2F5C36, bytes.fromhex('00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3DFBFA, bytes.fromhex('00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3DFBFE, bytes.fromhex('00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x386388, bytes.fromhex('00bf00bf00bf00bf00bf00bf00bf00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3863f0, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x386412, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x0d3254, bytes.fromhex('00bf00bf00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x0D326A, bytes.fromhex('00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x0D326E, bytes.fromhex('00bf00bf00bf00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x38643C, bytes.fromhex('00bf00bf00bf00bf00bf00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3B4FA8, bytes.fromhex('00bf00bf00bf00bf00bf'))
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
        # map extra memory
        mu.mem_map(0x200000, 1024 * 512)
        mu.mem_write(0x200000, extra_high_img)
        mu.mem_map(0x300000, 1024 * 512)
        mu.mem_write(0x300000, extra_high_img_t)
        mu.mem_map(0x400000, 1024 * 512)
        mu.mem_write(0x400000, extra_low_image)
        # map extra space
        mu.mem_map(0x500000, 1024 * 512)

        # setup context
        sp_addr = 0x100000 + 0x24000
        r4_addr = 0x400000 + 0x500
        r8_addr = 0x200000 + 0x200
        r12_addr = 0x300000 + 0x200
        # registers
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
        mu.reg_write(UC_ARM_REG_LR, LIBG_ADDRESS + 0x3B4F27)
        # I need to patch with a loop... can't find any clean way so I will just code it the worst way
        patch_img(mu, sp_addr, r4_addr, r8_addr, r12_addr, sp_img, 0x100000)
        patch_img(mu, sp_addr, r4_addr, r8_addr, r12_addr, extra_high_img, 0x200000)
        patch_img(mu, sp_addr, r4_addr, r8_addr, r12_addr, extra_high_img_t, 0x300000)
        patch_img(mu, sp_addr, r4_addr, r8_addr, r12_addr, extra_low_image, 0x400000)
        # extra patches
        mu.mem_write(mu.reg_read(UC_ARM_REG_R6) + 4, struct.pack("<I", r4_addr + 0x60))
        mu.mem_write(mu.reg_read(UC_ARM_REG_R6) + 8, struct.pack("<I", sp_addr + 0x10))
        mu.mem_write(mu.reg_read(UC_ARM_REG_R6) + 12, struct.pack("<I", r4_addr + 0x40))
        mu.mem_write(mu.reg_read(UC_ARM_REG_R6) + 16, struct.pack("<I", 0x00))
        mu.mem_write(mu.reg_read(UC_ARM_REG_R6) + 20, struct.pack("<I", r4_addr + 0x20))
        mu.mem_write(mu.reg_read(UC_ARM_REG_SP), struct.pack("<I", sp_addr + 0x1110))
        mu.mem_write(mu.reg_read(UC_ARM_REG_SP) + 4, struct.pack("<I", r4_addr))
        mu.mem_write(mu.reg_read(UC_ARM_REG_SP) + 8, struct.pack("<I", r4_addr + 0x40))

        print('patched stackpointer is ready to rock :P')
        hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_SP), 400))

        # add hooks
        mu.hook_add(UC_HOOK_CODE, hook_code)
        mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_fetch_unmapped)
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)

        # start emulation
        #mu.emu_start(LIBG_ADDRESS + 0x3DFB70 | 1, LIBG_ADDRESS + 0x3B4F26)
        mu.emu_start(LIBG_ADDRESS + 0x3DFB70 | 1, LIBG_ADDRESS + 0x3B4F26)

        print_regs(mu)
        hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R8), 400))
        print("R0")
        #hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R0), 128))
        print("R1")
        #hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R1), 128))
        print("R2")
        #hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R2), 128))
        print("R3")
        #hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R3), 128))
        print("R4")
        #hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R4), 128))
        print("R5")
        hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R5), 128))
        print("R6")
        #hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R6), 128))
        print("R7")
        hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R7), 128))
        print("R8")
        hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R8), 128))
        print("R9")
        hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R9), 128))
        print("R10")
        hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R10), 128))
        print("R12")
        hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R12), 128))
        print("SP")
        hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_SP), 128))

    except UcError as e:
        print("ERROR: %s" % e)


start()
