setTimeout(function() {
    inject();
}, 0)

function ba2hex(bufArray) {
    var uint8arr = new Uint8Array(bufArray);
    if (!uint8arr) {
        return '';
    }

    var hexStr = '';
    for (var i = 0; i < uint8arr.length; i++) {
        var hex = (uint8arr[i] & 0xff).toString(16);
        hex = (hex.length === 1) ? '0' + hex : hex;
        hexStr += hex;
    }

    return hexStr.toUpperCase();
}

function chainAttack(base) {
    Interceptor.detachAll();

    var pt4 = ptr(parseInt(base) + 1 + parseInt(0x3DFB70));

    var pt5 = ptr(parseInt(base) + parseInt(0x3dfb86));
    var pt7 = ptr(parseInt(base) + 1 + parseInt(0x3e8d22));

    var pt10 = ptr(parseInt(base) + 1 + parseInt(0x3ECD4A));
    var pt11 = ptr(parseInt(base) + 1 + parseInt(0x3E8EB4));
    var pt12 = ptr(parseInt(base) + 1 + parseInt(0x3EE052));
    var pt13 = ptr(parseInt(base) + 1 + parseInt(0x3EAABA));
    var pt14 = ptr(parseInt(base) + 1 + parseInt(0x3ED204));
    var pt15 = ptr(parseInt(base) + 1 + parseInt(0x3EDFFC));
    var pt16 = ptr(parseInt(base) + 1 + parseInt(0x3EE0AA));
    var pt17 = ptr(parseInt(base) + 1 + parseInt(0x3EAEFC));
    var pt18 = ptr(parseInt(base) + 1 + parseInt(0x3EAA26));
    var pt19 = ptr(parseInt(base) + 1 + parseInt(0x3EB4AA));
    var pt20 = ptr(parseInt(base) + 1 + parseInt(0x3EDAF2));
    var pt21 = ptr(parseInt(base) + 1 + parseInt(0x3E0626));
    var pt22 = ptr(parseInt(base) + 1 + parseInt(0x3EA9C2));
    var pt23 = ptr(parseInt(base) + 1 + parseInt(0x3EA4EA));
    var pt24 = ptr(parseInt(base) + 1 + parseInt(0x3EAF56));
    var pt25 = ptr(parseInt(base) + 1 + parseInt(0x3EA318));

    var scalar_mul_write = ptr(parseInt(base) + 1 + 0x3E0F08);
    var second_op_key = ptr(parseInt(base) + 1 + 0x3e12c8)

    var second_op_key_part_builder_1 = ptr(parseInt(base) + 1 + 0x3e105a)
    var second_op_key_part_builder_2 = ptr(parseInt(base) + 1 + 0x3e106c)
    var second_op_key_part_builder_3 = ptr(parseInt(base) + 1 + 0x3e10d8)
    var second_op_key_part_builder_4 = ptr(parseInt(base) + 1 + 0x3e137a)

    var hsalsa20_push_registers = ptr(parseInt(base) + 1 + 0x3e12a2)
    var hsalsa20_after_push = ptr(parseInt(base) + 1 + 0x3e12b4)

    var mid_check_ptr_1 = ptr(parseInt(base) + 1 + 0x3E10F6)

    var payload_memcpy = ptr(parseInt(base) + 1 + 0x3dfc54)

    // Everything before is solved, left for debugging purpose.

    var memcpy_44 = ptr(parseInt(base) + 1 + 0x3e8d22)
    var last_memcpy_44 = ptr(parseInt(base) + 1 + 0x3e8daa)
    var memclr8pt = ptr(parseInt(base) + parseInt(0x040D34));

    r8pt = 0;

    Interceptor.attach(payload_memcpy, function(args) {
        console.log("PAYLOAD MEMCPY")
        console.log(Memory.readByteArray(args[1], parseInt(args[2])))
        console.log("=======================")
        console.log("r0: " + this.context.r0)
        console.log("r1: " + this.context.r1)
        console.log("r2: " + this.context.r2)
        console.log("r3: " + this.context.r3)
        console.log("r4: " + this.context.r4)
        console.log("r5: " + this.context.r5)
        console.log("r6: " + this.context.r6)
        console.log("r7: " + this.context.r7)
        console.log("r8: " + this.context.r8)
        console.log("r9: " + this.context.r9)
        console.log("r10: " + this.context.r10)
        console.log("r11: " + this.context.r11)
        console.log("r12: " + this.context.r12)
        console.log("sp: " + this.context.sp)
        console.log("pc: " + this.context.pc)
        console.log("lr: " + this.context.lr)
        console.log("=======================")
    })
    Interceptor.attach(pt4, function(args) {
        Memory.writeByteArray(args[0], [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF])
    })

    Interceptor.attach(ptr(parseInt(pt5) + 1), {
        onEnter: function (args) {
            r8pt = this.context.r8;

            var tail = ptr(parseInt(base) + 0x8D2684);
            console.log("Entering at " + pt5)
            console.log("LIBG_ADDRESS = " + base)
            console.log("R4_ADDR = " + this.context.r4)
            console.log("R8_ADDR = " + this.context.r8)
            console.log("R12_ADDR = " + this.context.r12)
            console.log("SP_ADDR = " + this.context.sp)
            console.log("Image end at: " + tail)
            console.log("=======================")
            console.log("r0: " + this.context.r0)
            console.log("r1: " + this.context.r1)
            console.log("r2: " + this.context.r2)
            console.log("r3: " + this.context.r3)
            console.log("r4: " + this.context.r4)
            console.log("r5: " + this.context.r5)
            console.log("r6: " + this.context.r6)
            console.log("r7: " + this.context.r7)
            console.log("r8: " + this.context.r8)
            console.log("r9: " + this.context.r9)
            console.log("r10: " + this.context.r10)
            console.log("r11: " + this.context.r11)
            console.log("r12: " + this.context.r12)
            console.log("sp: " + this.context.sp)
            console.log("pc: " + this.context.pc)
            console.log("lr: " + this.context.lr)
            console.log("=======================")

            // dumping image base
            a = Memory.readByteArray(base, parseInt(tail) - parseInt(base))
            // dumping stackpointer
            var sp_start = parseInt(this.context.sp) - 0x48000
            var sp_end = parseInt(this.context.sp) + 0x48000
            b = Memory.readByteArray(ptr(sp_start), sp_end - sp_start)
            // dumping extra higher memory 1
            var e1_start = parseInt(this.context.r8) - 0x200
            var e1_end = parseInt(this.context.r8) + 0x200
            c = Memory.readByteArray(ptr(e1_start), e1_end - e1_start)
            // dumping extra higher memory 2
            var e2_start = parseInt(this.context.r12) - 0x4000
            var e2_end = parseInt(this.context.r12) + 0x5000
            d = Memory.readByteArray(ptr(e2_start), e2_end - e2_start)
            // dumping extra lower memory 1
            var e3_start = parseInt(this.context.r4) - 0x500
            var e3_end = parseInt(this.context.r4) + 0x500
            e = Memory.readByteArray(ptr(e3_start), e3_end - e3_start)
            send("5::::", a)
            send("6::::", b)
            send("7::::", c)
            send("8::::", d)
            send("9::::", e)

            if (true) {
                Interceptor.attach(scalar_mul_write, function(args) {
                    console.log("writing scalarmul")
                    console.log(this.context.r1)
                })
                Interceptor.attach(second_op_key, function(args) {
                    console.log("second op")
                    console.log(this.context.r2)
                })
                Interceptor.attach(hsalsa20_push_registers, function(args) {
                    console.log("HSALSA PUSH")
                    console.log("=======================")
                    console.log("r0: " + this.context.r0)
                    console.log("r1: " + this.context.r1)
                    console.log("r2: " + this.context.r2)
                    console.log("r3: " + this.context.r3)
                    console.log("r4: " + this.context.r4)
                    console.log("r5: " + this.context.r5)
                    console.log("r6: " + this.context.r6)
                    console.log("r7: " + this.context.r7)
                    console.log("r8: " + this.context.r8)
                    console.log("r9: " + this.context.r9)
                    console.log("r10: " + this.context.r10)
                    console.log("r11: " + this.context.r11)
                    console.log("r12: " + this.context.r12)
                    console.log("sp: " + this.context.sp)
                    console.log("pc: " + this.context.pc)
                    console.log("lr: " + this.context.lr)
                    console.log("=======================")
                })
                Interceptor.attach(hsalsa20_after_push, function(args) {
                    console.log("HSALSA AFTER PUSH")
                    console.log("=======================")
                    console.log("r0: " + this.context.r0)
                    console.log("r1: " + this.context.r1)
                    console.log("r2: " + this.context.r2)
                    console.log("r3: " + this.context.r3)
                    console.log("r4: " + this.context.r4)
                    console.log("r5: " + this.context.r5)
                    console.log("r6: " + this.context.r6)
                    console.log("r7: " + this.context.r7)
                    console.log("r8: " + this.context.r8)
                    console.log("r9: " + this.context.r9)
                    console.log("r10: " + this.context.r10)
                    console.log("r11: " + this.context.r11)
                    console.log("r12: " + this.context.r12)
                    console.log("sp: " + this.context.sp)
                    console.log("pc: " + this.context.pc)
                    console.log("lr: " + this.context.lr)
                    console.log("=======================")
                })
                Interceptor.attach(mid_check_ptr_1, function(args) {
                    console.log("MIDCHECK")
                    console.log(Memory.readByteArray(this.context.r0, 32))
                    console.log("=======================")
                    console.log("r0: " + this.context.r0)
                    console.log("r1: " + this.context.r1)
                    console.log("r2: " + this.context.r2)
                    console.log("r3: " + this.context.r3)
                    console.log("r4: " + this.context.r4)
                    console.log("r5: " + this.context.r5)
                    console.log("r6: " + this.context.r6)
                    console.log("r7: " + this.context.r7)
                    console.log("r8: " + this.context.r8)
                    console.log("r9: " + this.context.r9)
                    console.log("r10: " + this.context.r10)
                    console.log("r11: " + this.context.r11)
                    console.log("r12: " + this.context.r12)
                    console.log("sp: " + this.context.sp)
                    console.log("pc: " + this.context.pc)
                    console.log("lr: " + this.context.lr)
                    console.log("=======================")
                })
            }
        },
        onLeave: function(retval) {
            console.log("Leaving enc");
            console.log(Memory.readByteArray(r8pt, 200))
        }
    });

    Interceptor.attach(Module.findExportByName("libg.so", "send"), {
        onEnter: function (args) {
            var b = ba2hex(Memory.readByteArray(args[1], parseInt(args[2])));
            console.log("SEND " + b)
            if (b.length < 7) {
                return;
            }

            var msgId = parseInt("0x" + b.substring(0, 4));
            if (msgId < 10000 || msgId > 30000) {
                console.log(msgId + " blocked. " + b.substring(0, 14));
                return;
            }
            send("3::::" + b);
        }
    });

    var pl = null;
    var buf;
    var nLen = 0;
    var pLen = 0;
    Interceptor.attach(Module.findExportByName("libg.so", "recv"), {
        onEnter: function (args) {
            buf = args[1];
        },
        onLeave: function (retval) {
            var len = parseInt(retval);
            if (pl === null && len !== 7) {
                return;
            }

            if (pl === null) {
                pl = ba2hex(Memory.readByteArray(buf, len));
                nLen = parseInt("0x" + pl.substring(4, 10));
            } else {
                pl += ba2hex(Memory.readByteArray(buf, len));
                pLen += len;
                if (pLen === nLen) {
                    send("4::::" + pl);
                    pl = null;
                    nLen = 0;
                    pLen = 0;
                }
            }
        }
    });
}

function inject() {
    Process.enumerateModules({
        onMatch: function (module) {

            if (module.name === "libg.so") {
                var base = module.base;

                var pt1 = ptr(parseInt(base) + 1 + parseInt(0x3B3C5E));
                var pt2 = ptr(parseInt(base) + 1 + parseInt(0x0C4CDC));
                var pt3 = ptr(parseInt(base) + 1 + parseInt(0x1C6EE2));

                // attaching memclr8 to skip jump the crc :P
                var pt4 = ptr(parseInt(base) + parseInt(0x040D34));

                var pt6 = ptr(parseInt(base) + 1 + parseInt(0x1ADDA4))

                // kill new coc frida detection
                var fucked = false
                Interceptor.attach(Module.findExportByName("libg.so", "socket"), {
                    onEnter: function (args) {
                        if (args[0] == 2 && !fucked) {
                            fucked = true;
                            console.log("WOOP");
                            this.context.r0 = 0x20;
                        }
                    }
                });

                Interceptor.attach(Module.findExportByName("libg.so", "send"), {
                    onEnter: function (args) {
                        var msgId = parseInt("0x" + ba2hex(Memory.readByteArray(ptr(args[1]), 2)));
                        if (msgId < 10000 || msgId > 30000) {
                            return;
                        }
                        if (msgId === 10100) {
                            console.log(ba2hex(Memory.readByteArray(ptr(args[1]), parseInt(args[2]))))

                            Interceptor.detachAll();

                            var rbuf;
                            Interceptor.attach(Module.findExportByName("libg.so", "recv"), {
                                onEnter: function (args) {
                                    rbuf = args[1];
                                },
                                onLeave: function (retval) {
                                    console.log(ba2hex(Memory.readByteArray(rbuf, parseInt(retval))));
                                }
                            });

                            Interceptor.attach(pt1, {
                                onEnter: function (args) {
                                    var pk;
                                    var sk;

                                    Interceptor.attach(pt2, {
                                        onEnter: function (args) {
                                            pk = args[0];
                                            sk = args[1];
                                        },
                                        onLeave: function (retval) {
                                            Memory.writeByteArray(pk, [0x4C, 0xA4, 0x6C, 0x7B, 0xB1, 0xA1, 0xF4, 0x6B, 0x3F, 0x9F, 0x9C, 0x9B, 0x1D, 0x6A, 0xB4, 0x49, 0xB5, 0x17, 0x15, 0x65, 0x3B, 0x61, 0x75, 0xAE, 0x4B, 0x59, 0xF3, 0xE7, 0xA4, 0x71, 0x42, 0x5B])
                                            Memory.writeByteArray(sk, [0x8E, 0xEC, 0x28, 0x68, 0x87, 0xF8, 0x51, 0xB3, 0x03, 0xD2, 0x88, 0xED, 0xC5, 0x6A, 0x99, 0x49, 0xFA, 0xDD, 0x17, 0xFB, 0x33, 0x21, 0x21, 0xC8, 0x29, 0x96, 0x91, 0x66, 0x50, 0x8C, 0x31, 0x62])
                                            send("0::::" + ba2hex(Memory.readByteArray(pk, 32)));
                                            send("1::::" + ba2hex(Memory.readByteArray(sk, 32)));

                                            Interceptor.detachAll();

                                            var i = 0;
                                            Interceptor.attach(pt4, {
                                                onEnter: function (args) {
                                                    if (i == 40 && parseInt(args[1]) == 64) {
                                                        i++;
                                                        console.log("attaching blake")
                                                        Interceptor.detachAll();

                                                        Interceptor.attach(pt3, {
                                                            onEnter: function (args) {
                                                                b2ret = args[0];
                                                                send("2::::" + ba2hex(Memory.readByteArray(ptr(parseInt(b2ret) + 132), 32)));
                                                            },
                                                            onLeave: function (retval) {
                                                                Memory.writeByteArray(ptr(parseInt(b2ret) + 4), [0x8F, 0x63, 0x10, 0x34, 0x7F, 0x46, 0xD5, 0x2C, 0x14, 0xB7, 0xBB, 0x57, 0xD7, 0xFF, 0x67, 0x25, 0xEC, 0x53, 0xB7, 0xBA, 0x16, 0x57, 0x77, 0x22])
                                                                console.log("b2hash: " + ba2hex(Memory.readByteArray(b2ret, 32)));
                                                                chainAttack(base);
                                                            }
                                                        });
                                                    } else if (parseInt(args[1]) == 64) {
                                                        i++
                                                    }
                                                }
                                            });
                                        }
                                    });
                                }
                            });
                        }
                    }
                });
            }
        },
        onComplete: function () {
        }
    });
}