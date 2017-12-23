import binascii
import struct

from hexdump import hexdump
from unicorn import *
from unicorn.arm_const import *
from capstone import *

'''
{'type': 'send', 'payload': '0::::266AF34B2B72A4EAA1D8503531C02114940BA918DC5E1B485BF26D2F6CB7C767'}
PK:266AF34B2B72A4EAA1D8503531C02114940BA918DC5E1B485BF26D2F6CB7C767
{'type': 'send', 'payload': '1::::3E0DB818DDC908928F7B670DDC4C3E2FEF0419BFFA160B5E9CF4CE33EC1D119D'}
SK:3E0DB818DDC908928F7B670DDC4C3E2FEF0419BFFA160B5E9CF4CE33EC1D119D
attaching blake
{'type': 'send', 'payload': '2::::B10CD28E5E70EBB8AEF02A25BBCF44F9242083909059D482AF5CDD94B2C58704'}
PKS:B10CD28E5E70EBB8AEF02A25BBCF44F9242083909059D482AF5CDD94B2C58704
b2hash: 180000001FAD0B43E3B8FD62A2ABFE8E91BAFC44068B5C712FA118DAD2F75155
Entering pt5 at 0xefec3b70
Base at: 0xefae4000
Image end at: 0xf03b6684
r0: 0xe08fe178
r1: 0x16e
r2: 0xa94dbf60
r3: 0x17e
r4: 0xf240589c
r5: 0xe08ff278
r6: 0xe08fe2e8
r7: 0xe08ff668
r8: 0xa94dbf40
r9: 0x17e
r10: 0xf24058bc
r11: 0x19e
r12: 0xf411a944
sp: 0xe08fe168
pc: 0xefe98f27
0xe08ff278
277500019E0009266AF34B2B72A4EAA1D8503531C02114940BA918DC5E1B485BF26D2F6CB7C7673AADA6143D9AE06A39AB7FC0B0BDC7C09DA9E
DD855987B3CCBD4EA4314B289C11E65289E4D9B1AAF0DABD20A81FF989F700835DB0F49691E4C0AE8D4A37E3BDA4C065F1F50F5A8264CD268DE
7E93FB6FF909B38F11DFDBEF4D24A462E0F2C00094DA89A0777052015985C889A52DB86A35E67A3B40B78221664641E878FA155861524982A7D
112638996C3A3771A0DBC34068737F014AEFA00081AB38B4A3F9E692312C7973A69D02E2F25A16DC7E9A1BB1EB81A41AFCB6947DA2AF8C0DA45
23BE6D9850E1DA333A5A818844DE70053614DFB152E1D1DF08C2B74387B9CAF5EC6AEC7A90D960DD90B3718CDA61FDC184F4CD1A1CD5317CA92
5483B2B9AD90611A1CF75637A6B22FEBB88C260A6B73027039B4FDB9A17D9F92B9F29043C572F670CA2D8187500BABF5CBCDC010E5FA622A346
11D9F1ADCF767F18931EC466BAFEFFDED905D37914BAA256AB00C53EC0C4DFCE0926E292BBB2EBAF9FA89C2E797C23175E5033E7F177C035DE2
5D2DC1E2D86538FB7BAEFAC5FC190183D88BE
'''

LIBG_ADDRESS = 0xefae4000

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

hook_c = False


def initialize_registers(mu):
    sp_addr = 0x100000 + 0x24000
    r8_addr = 0x200000 + 0x200
    r4_addr = 0x400000 + 0x500
    r12_addr = 0x300000 + 0x200

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


def jump(uc, address, size):
    j = address + size
    print("jumping to: " + str(hex(j - LIBG_ADDRESS)))
    uc.reg_write(UC_ARM_REG_PC, j)


def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))


def hook_arm(uc, address, size, user_data):
    ad = address - 0x350000
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (ad, size))
    for i in arm_md.disasm(bytes(uc.mem_read(address, size)), address):
        print("0x%x:\t%s\t%s" % (i.address - 0x350000, i.mnemonic, i.op_str))


def hook_code(uc, address, size, user_data):
    global hook_c
    ad = address - LIBG_ADDRESS
    if ad == 0x3B4F26:
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

    # post encryption memcpy call:
    if ad == 0x3b4f2e:
        initialize_registers(uc)

    # jfree
    if ad == 0x485E84 or ad == 0x3b4f32:
        uc.reg_write(UC_ARM_REG_R0, 0x00)

    # another jfree here. everything is nopped, just set the things up ->
    if ad == 0x3b4f3a:
        uc.reg_write(UC_ARM_REG_R4, 0x500000 + 0x200)

    # r6 + 0x14 still point to the hold image when entering 0x3b4f64 :S
    if ad == 0x3b4f62:
        uc.mem_write(uc.reg_read(UC_ARM_REG_R6) + 0x14, struct.pack("<I", 0x400000 + 0x500 - 0x9C))

    # patches for message version simplify
    if ad == 0x3b4f6a:
        print(hex(struct.unpack("<I", uc.mem_read(uc.reg_read(UC_ARM_REG_R5) + 0x98, 4))[0]))
    if ad == 0x26a9d4:
        uc.reg_write(UC_ARM_REG_R0, 0x09)

    # send
    if ad == 0x0D3266:
        print("hit send")
        print_send(uc)

    if ad == 0x3b4f94:
        uc.reg_write(UC_ARM_REG_R0, LIBG_ADDRESS + 0x331E2E)

    # we can jump straight and skip double recv
    if ad == 0xFB6DA:
        uc.reg_write(UC_ARM_REG_R0, 0x400000 + 0x500 - 0x5c)
        uc.reg_write(UC_ARM_REG_R1, 0x400000 + 0x500 - 0x9c)
        uc.reg_write(UC_ARM_REG_PC, LIBG_ADDRESS + 0x3A90F9)

    # write enc payload len
    if ad == 0x3a9150:
        uc.reg_write(UC_ARM_REG_R0, 0x19e)
    # these are safely 0
    if ad == 0x3a915c:
        uc.reg_write(UC_ARM_REG_R0, 0x00)
    if ad == 0x3A9194:
        uc.reg_write(UC_ARM_REG_R5, 0x00)
    # load msg id
    if ad == 0x3A918E:
        uc.reg_write(UC_ARM_REG_R0, 0x2775)


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
        if uc.reg_read(UC_ARM_REG_R0) == 0xd38cac1f:
            uc.reg_write(UC_ARM_REG_R0, uc.reg_read(UC_ARM_REG_SP) - 0x500)
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
        mu.mem_write(LIBG_ADDRESS + 0x1c0160, bytes.fromhex('00bf00bf00bf00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3a910c, bytes.fromhex('00bf00bf00bf00bf00bf00bf00bf00bf00bf00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3A9138, bytes.fromhex('00bf00bf00bf00bf00bf00bf00bf'))

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
        # nop memcpy's after encr
        mu.mem_write(LIBG_ADDRESS + 0x3B4F2E, bytes.fromhex('00bf00bf00bf00bf00bf'))
        # load msg id without reading ptr recursive
        mu.mem_write(LIBG_ADDRESS + 0x3b4f3a, bytes.fromhex('00bf00bf42f2757000bf00bf'))
        # nop message version
        mu.mem_write(LIBG_ADDRESS + 0x26a9d4, bytes.fromhex('00bf'))
        # hardcode this
        mu.mem_write(LIBG_ADDRESS + 0x1c176c, bytes.fromhex('006B'))
        # patch send
        mu.mem_write(LIBG_ADDRESS + 0x0D3266, bytes.fromhex('00bf00bf'))
        # patch mem clear loop functions
        mu.mem_write(LIBG_ADDRESS + 0x3b4f8a, bytes.fromhex('00bf00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x19ec34, bytes.fromhex('00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x3b4f9a, bytes.fromhex('00bf00bf'))
        mu.mem_write(LIBG_ADDRESS + 0x1c014c, bytes.fromhex('00bf00bf00bf00bf00bf00bf00bf00bf'))
        # sigil found :P
        # mu.mem_write(LIBG_ADDRESS + 0x4a346c, bytes.fromhex('00bf00bf'))
        # patch last things before final send
        mu.mem_write(LIBG_ADDRESS + 0x3A9146, bytes.fromhex('00bf00bf00bf00bf'))
        # patch payload len calc
        mu.mem_write(LIBG_ADDRESS + 0x3a9150, bytes.fromhex('00bf00bf'))
        # patch msg id
        mu.mem_write(LIBG_ADDRESS + 0x3A918E, bytes.fromhex('00bf00bf'))
        # patch the check for post login
        mu.mem_write(LIBG_ADDRESS + 0x3A9194, bytes.fromhex('00bf00bf00bf00bf00bf'))

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
        initialize_registers(mu)
        mu.reg_write(UC_ARM_REG_LR, LIBG_ADDRESS + 0x3B4F27)

        sp_addr = 0x100000 + 0x24000
        r4_addr = 0x400000 + 0x500
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

        mu.hook_add(UC_HOOK_CODE, hook_code)
        mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_fetch_unmapped)
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
        mu.emu_start(LIBG_ADDRESS + 0x3DFB70 | 1, LIBG_ADDRESS + 0x3A9132)
        print("first stage done")
        print_regs(mu)

        # now starting the second stage
        r0 = mu.reg_read(UC_ARM_REG_R0)
        r1 = mu.reg_read(UC_ARM_REG_R1)
        arm_mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        arm_mu.mem_map(0x350000, 1024 * 1024 * 512)
        arm_mu.mem_write(0x350000, libg)
        arm_mu.reg_write(UC_ARM_REG_R0, r0)
        arm_mu.reg_write(UC_ARM_REG_R1, r1)
        arm_mu.reg_write(UC_ARM_REG_LR, 0x00)
        arm_mu.reg_write(UC_ARM_REG_APSR, 0xFFFFFFFF)
        # patches
        arm_mu.mem_write(0x350000 + 0x4a3474, bytes.fromhex('00F020E3'))
        arm_mu.mem_write(0x350000 + 0x4a347c, bytes.fromhex('00F020E3'))
        arm_mu.emu_start(0x350000 + 0x4A346C, 0x350000 + 0x4A3488)
        print("second stage done")
        print_regs(arm_mu)

        # third stage
        r0 = arm_mu.reg_read(UC_ARM_REG_R0)
        r1 = arm_mu.reg_read(UC_ARM_REG_R1)
        r2 = arm_mu.reg_read(UC_ARM_REG_R2)
        r12 = arm_mu.reg_read(UC_ARM_REG_R12)
        mu.reg_write(UC_ARM_REG_R0, r0)
        mu.reg_write(UC_ARM_REG_R1, r1)
        mu.reg_write(UC_ARM_REG_R2, r2)
        mu.reg_write(UC_ARM_REG_R12, r12)
        mu.emu_start(LIBG_ADDRESS + 0x3A9136 | 1, LIBG_ADDRESS + 0x040EC0)

    except UcError as e:
        print("ERROR: %s" % e)


start()
