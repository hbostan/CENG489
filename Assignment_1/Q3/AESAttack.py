import sys
import vulnerable

def createTestBlock(t_block, t_index, i):
    test_block = bytearray(16)
    for j in range(16):
        if j < 15-t_index:
            test_block[j] = t_block[j]
        elif j > 15-t_index:
            test_block[j] = t_block[j] ^ (t_index+1)
        else:
            test_block[j] = i ^ (t_index + 1)
    return test_block

def calculateTBlock(ct):
    t_block = bytearray([0xff]*16)
    ct_array = bytearray(ct)
    for t_index in range(16):
        c_index = 31-t_index
        for i in range(256):
            test_block = createTestBlock(t_block, t_index, i)
            fake_ct = str(ct[:16] +test_block +ct[32:])
            if  "SUCCESS" == vulnerable.decr(fake_ct) and i != ct[c_index]:
                t_block[15-t_index] = i 
                break
    return t_block

def createAttackBlock(dp, t_block):
    attack_block = bytearray(t_block)
    dp = bytearray(dp) + bytearray([1])
    offset = len(dp)
    for i in range(len(dp)):
        attack_block[16-offset+i] = t_block[16-offset+i] ^ dp[i]
    return attack_block

def attack(ct, dp):
    ct = bytearray(ct)
    t_block = calculateTBlock(ct)
    attack_block = createAttackBlock(dp, t_block)
    attack_ciphertext = str(ct[:16] + attack_block + ct[32:])
    return attack_ciphertext

if len(sys.argv) !=  3:
    print len(sys.argv)
    for i in sys.argv:
        print i
    exit()
pt = "_______________________________________________"
ct = sys.argv[1]
dp = sys.argv[2]
res = attack(ct, dp)
sys.stdout.write(res)
#print res,"HOAYDAA"
