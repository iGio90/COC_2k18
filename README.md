# COC_2k18
A small effort to keep up the RE around SC. Merry Christmas and happy GNU year!

This is (WAS) an attempt to reverse engineer clash of clans which is now protected by a commercial llvm compiler (probably arxan) (and whatever it is, it lost)

The unique way I did found to understand the program flow is by emulation, mostly for the encryption which is obfuscated.
This is (was) a wip but with a lot of patience and work Im going to solve this somehow (and somehow I finally did it).

Due to SC request i won't reveal the final solution of the puzzle and wait a bit also to publish something on my blog. The 2 emulators i wrote for a timeless debugging environment takes as input some images from my device. These images can be taken using frida by intercepting and dumping at encryption offsets. You can follow my repo activity to meet a proxy written on top of frida which can be used as base to dump the necessary things. 

I've asked hints to SC and they didn't gave me :'(. 
I will give instead, keep an eye right after scalarmul while inside beforenm. Arxan makes it very trivial but, you don't f@!k with timeless :P. 

* Update, nevermind about the images, I just pushed also the frida scripts to force the same keypair, the same nonce etc etc. You have no excuses, you can't fail!
