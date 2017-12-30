import binascii
import struct

from hexdump import hexdump
from unicorn import *
from unicorn.arm_const import *
from capstone import *

LIBG_ADDRESS = 0xea4a8000
SP_ADDR = 0xd98fb310
R8_ADDR = 0xd8ddf980
R10_ADDR = 0xea0f17bc

libg = open('cr_libg.so', 'rb').read()
dc_libg = open('cr_base.bin', 'rb').read()
sp_img = open('cr_sp.bin', 'rb').read()
extra_high_img = open('cr_extra_high_1.bin', 'rb').read()
extra_high_img_2 = open('cr_extra_high_2.bin', 'rb').read()

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
arm_md = Cs(CS_ARCH_ARM, CS_ARCH_ARM)

enc_memcpy = [0x1aaece, 0x1aafd4, 0x1ab0da, 0x1ab1e6, 0x1a2588, 0x1ab8fc,
              0x1aa5d6, 0x1aa6e4, 0x1aa7f0, 0x1aa8fe, 0x1a2d38, 0x1308ae,
              0x1a2d7a, 0x1a2e78, 0x1a2e98, 0x1a945a, 0x1a94f6, 0x1a1e0e]
enc_memclr = [0x1aaddc, 0x1aaeea, 0x1aaff0, 0x1ab0f8, 0x1aaff0, 0x1a24a8,
              0x1ab80e, 0x1aa4e4, 0x1aa5f4, 0x1aa702, 0x1aa80e, 0x1307f2,
              0x1a2d92, 0x1a92de, 0x1a92e8, 0x1a9370]

# debug things
dbg = False
tr_dbg = False
last_jmp = 0x0
jmp_count = 0
jmp_dbg = -1


def jump(uc, address, size):
    j = address + size
    print("jumping to: " + str(hex(j - LIBG_ADDRESS)))
    uc.reg_write(UC_ARM_REG_PC, j)


def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))


test = 0


def hook_code(uc, address, size, user_data):
    ad = address - LIBG_ADDRESS

    global dbg
    global tr_dbg

    global test
    if ad == 0x1a4576 and test == 0:
        test += 1
        hexdump(uc.mem_read(uc.reg_read(UC_ARM_REG_SP) - 0x6000, 0x14000))

    if ad == 0x1a2e98:
        dbg = True
        tr_dbg = True

    if ad == 0x1a92de:
        uc.emu_stop()

    # svc
    if ad == 0x1a327a:
        uc.mem_write(uc.reg_read(UC_ARM_REG_R0), bytes.fromhex('FFFFFFFFFFFFFFFF'))

    if dbg:
        global last_jmp
        global jmp_count

        if jmp_dbg >= 0:
            jc = ad - last_jmp
            if last_jmp == 0x0 or (0 < jc < 5):
                last_jmp = ad
            else:
                if jmp_count < jmp_dbg:
                    print(">>> JUMP " + str(jmp_count) + " at -> " + str(hex(ad)))
                    jmp_count += 1
                    last_jmp = ad
                else:
                    print(">>> JUMP BREAK at -> " + str(hex(ad)))
                    uc.emu_stop()
        if tr_dbg:
            print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (ad, size))
            for i in md.disasm(bytes(uc.mem_read(address, size)), address):
                print("0x%x:\t%s\t%s" % (i.address - LIBG_ADDRESS, i.mnemonic, i.op_str))

    # malloc replace
    if ad == 0x419b7a:
        uc.reg_write(UC_ARM_REG_R0, 0x50000)
        uc.reg_write(UC_ARM_REG_R1, 0x64146c41)
        uc.reg_write(UC_ARM_REG_R2, 0x0)
    
    # payload memcpy
    if ad == 0x1a1e3c:
        memcpy_replace(uc)

    # priv key memcpy
    if ad == 0x1a2442:
        memcpy_replace(uc)

    # encryption memcpy calls:
    if ad in enc_memcpy:
        memcpy_replace(uc)

    # encryption memclr calls:
    if ad in enc_memclr:
        memclr_replace(uc)

    # stack check
    if ad == 0x1a1d5c:
        uc.reg_write(UC_ARM_REG_R0, 0x182028ea)
    if ad == 0x1307ec:
        uc.reg_write(UC_ARM_REG_R0, 0x182028ea)
    if ad == 0x1308c6:
        uc.reg_write(UC_ARM_REG_R0, 0x182028ea)
    if ad == 0x1ac646:
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
    global tr_dbg

    if tr_dbg:
        if access == UC_MEM_WRITE:
            print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
                  % (address, size, value))
        else:  # READ
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
        r8_img_start = R8_ADDR - 0x200
        r10_img_start = R10_ADDR - 0x200

        # write decrypted content
        mu.mem_write(LIBG_ADDRESS + 0x438040, dc_libg[0x438040:])

        # map stack pointer
        mu.mem_map(SP_ADDR & 0xFF000000, 1024 * 1024 * 24)
        mu.mem_write(sp_img_start, sp_img)
        # map extra memory
        mu.mem_map(R8_ADDR & 0xFFFF0000, 1024 * 1024 * 2)
        mu.mem_write(r8_img_start, extra_high_img)
        mu.mem_map(R10_ADDR & 0xFFFF0000, 1024 * 1024 * 2)
        mu.mem_write(r10_img_start, extra_high_img_2)

        # PATCHES
        mu.mem_write(LIBG_ADDRESS + 0x1a327a, bytes.fromhex('00bf'))
        # nop stack check guard
        mu.mem_write(LIBG_ADDRESS + 0x1a1d5c, bytes.fromhex('00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1307ec, bytes.fromhex('00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1308c6, bytes.fromhex('00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1ac646, bytes.fromhex('00bf'))
        # nop malloc
        mu.mem_write(LIBG_ADDRESS + 0x419b7a, bytes.fromhex('00bf00bf'))
        # nop memcpy payload
        mu.mem_write(LIBG_ADDRESS + 0x1a1e3c, bytes.fromhex('00bf00bf'))
        # nop memcpy private key
        mu.mem_write(LIBG_ADDRESS + 0x1a2442, bytes.fromhex('00bf00bf'))
        # nop encryptions memcpy
        mu.mem_write(LIBG_ADDRESS + 0x1aaece, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1aafd4, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1ab0da, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1ab1e6, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1a2588, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1ab8fc, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1aa5d6, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1aa6e4, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1aa7f0, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1aa8fe, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1a2d38, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1308ae, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1a2d7a, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1a2e78, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1a2e98, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1a945a, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1a94f6, bytes.fromhex('00bf00bf'))
        # nop memclr
        mu.mem_write(LIBG_ADDRESS + 0x1aaddc, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1aaeea, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1ab0f8, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1aaff0, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1a24a8, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1ab80e, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1aa4e4, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1aa5f4, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1aa702, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1aa80e, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1307f2, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1a2d92, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1a92de, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1a92e8, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1a9370, bytes.fromhex('00bf00bf'))
        # payload memcpy
        mu.mem_write(LIBG_ADDRESS + 0x1a1e0e, bytes.fromhex('00bf00bf'))

        # registers
        mu.reg_write(UC_ARM_REG_R0, 0x361bf0)
        mu.reg_write(UC_ARM_REG_R1, 0x152)
        mu.reg_write(UC_ARM_REG_R2, R8_ADDR + 0x20)
        mu.reg_write(UC_ARM_REG_R3, 0x162)
        mu.reg_write(UC_ARM_REG_R4, SP_ADDR + 0x32c8)
        mu.reg_write(UC_ARM_REG_R5, SP_ADDR + 0x3f68)
        mu.reg_write(UC_ARM_REG_R6, SP_ADDR + 0x3420)
        mu.reg_write(UC_ARM_REG_R7, SP_ADDR + 0x32B0)
        mu.reg_write(UC_ARM_REG_R8, R8_ADDR)
        mu.reg_write(UC_ARM_REG_R9, 0x162)
        mu.reg_write(UC_ARM_REG_R10, R10_ADDR)
        mu.reg_write(UC_ARM_REG_R11, 0x182)
        mu.reg_write(UC_ARM_REG_R12, 0x0)
        mu.reg_write(UC_ARM_REG_SP, SP_ADDR)
        mu.reg_write(UC_ARM_REG_PC, LIBG_ADDRESS + 0x1A1D3E)

        # add hooks
        mu.hook_add(UC_HOOK_CODE, hook_code)
        mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_fetch_unmapped)
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
        mu.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, hook_mem_access)

        # start emulation
        mu.emu_start(LIBG_ADDRESS + 0x1A1D3E | 1, LIBG_ADDRESS + 0x2CFC4E)

        print_regs(mu)
        hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_R8) + 32, 400))
    except UcError as e:
        print("ERROR: %s" % e)


start()
