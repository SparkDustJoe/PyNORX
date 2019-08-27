import hashlib;
from PyNORX import PyNORX;
from PyNORXTESTCASES import PyNORXTestCases;
import colorama;
from termcolor import cprint;

def RUN_TESTS():
    colorama.init();
    cprint("PyNORX Self-Tests:", 'cyan')
    
    #32-bit====================================================================================================
    cprint("--32-bit Tests--", 'cyan');
    test = PyNORX(Word_Size_Bits = 32, Rounds = 4, Lanes = 1, Tag_Size_Bits = 128);
    #internals
    S = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    test.__f_funct__(S, 2)
    expected = [ 
        0xA3D8D930, 0x3FA8B72C, 0xED84EB49, 0xEDCA4787, 
        0x335463EB, 0xF994220B, 0xBE0BF5C9, 0xD7C49104];
    if (S[8:] != expected): cprint("*32 F FUNCT FAIL!*", 'red');
    else: cprint("32 F FUNCT PASS!", 'green');

    #encryption
    cases = PyNORXTestCases(32);
    for i in range(0, len(cases)):
        cprint('--Test #' + str(i) + '--', 'yellow');
        case = cases[i];
        test = PyNORX(Word_Size_Bits=32, Rounds=case.R, Lanes=case.L, Tag_Size_Bits=int(len(case.Tag)*8));
        result = test.aead_encrypt(case.H, case.P, case.T, case.IV, case.K);
        expected = bytearray(case.C[:]);
        expected.extend(case.Tag[:]);
        if (expected != result):
            cprint("*PyNORX 32-" + str(case.R) + "-" + str(case.L) + " Encrypt FAILED!*", 'red');
            for j in range(0, len(result)):
                if (result[j] != expected[j]):
                    cprint(" Mismatch at index " + str(j), 'yellow');
                else: cprint(" Match at index " + str(j), 'blue');
        else: cprint("PyNORX 32-" + str(case.R) + "-" + str(case.L) + " Encrypt Pass!", 'green');
        result = test.aead_decrypt(case.H, result, case.T, case.IV, case.K);
        if (result[0]):
            cprint("PyNORX 32-" + str(case.R) + "-" + str(case.L) + " Validation Pass!", 'green');
        else: cprint("*PyNORX 32-" + str(case.R) + "-" + str(case.L) + " Validation FAILED!*", 'red');
        if (result[1] != case.P):
            cprint("*PyNORX 32-" + str(case.R) + "-" + str(case.L) + " Decrypt FAILED!*", 'red');
            for j in range(0, len(result[1])):
                if (result[1][j] != case.P[j]):
                    cprint(" Mismatch at index " + str(j), 'yellow');
                else: cprint(" Match at index " + str(j), 'blue');
        else: cprint("PyNORX 32-" + str(case.R) + "-" + str(case.L) + " Decrypt Pass!", 'green');

    #64-bit====================================================================================================
    cprint("--64-bit Tests--", 'cyan');
    test = PyNORX(Word_Size_Bits = 64, Rounds = 4, Lanes = 1, Tag_Size_Bits = 256);
    #internals
    S = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    test.__f_funct__(S, 2)
    expected = [ 
        0xB15E641748DE5E6B, 0xAA95E955E10F8410, 0x28D1034441A9DD40, 0x7F31BBF964E93BF5, 
        0xB5E9E22493DFFB96, 0xB980C852479FAFBD, 0xDA24516BF55EAFD4, 0x86026AE8536F1501];
    if (S[8:] != expected): cprint("*64 F FUNCT FAIL!*", 'red');
    else: cprint("64 F FUNCT PASS!", 'green');
    
    #encryption
    cases = PyNORXTestCases(64);
    for i in range(0, len(cases)):
        cprint('--Test #' + str(i) + '--', 'yellow');
        case = cases[i];
        test = PyNORX(Word_Size_Bits=64, Rounds=case.R, Lanes=case.L, Tag_Size_Bits=int(len(case.Tag)*8));
        result = test.aead_encrypt(case.H, case.P, case.T, case.IV, case.K);
        expected = bytearray(case.C[:]);
        expected.extend(case.Tag[:]);
        if (expected != result):
            cprint("*PyNORX 64-" + str(case.R) + "-" + str(case.L) + " Encrypt FAILED!*", 'red');
            for j in range(0, len(result)):
                if (result[j] != expected[j]):
                    cprint(" Mismatch at index " + str(j), 'yellow');
                else: cprint(" Match at index " + str(j), 'blue');
        else: cprint("PyNORX 64-" + str(case.R) + "-" + str(case.L) + " Encrypt Pass!", 'green');
        result = test.aead_decrypt(case.H, result, case.T, case.IV, case.K);
        if (result[0]):
            cprint("PyNORX 64-" + str(case.R) + "-" + str(case.L) + " Validation Pass!", 'green');
        else: cprint("*PyNORX 64-" + str(case.R) + "-" + str(case.L) + " Validation FAILED!*", 'red');
        if (result[1] != case.P):
            cprint("*PyNORX 64-" + str(case.R) + "-" + str(case.L) + " Decrypt FAILED!*", 'red');
            for j in range(0, len(result[1])):
                if (result[1][j] != case.P[j]):
                    cprint(" Mismatch at index " + str(j), 'yellow');
                else: cprint(" Match at index " + str(j), 'blue');
        else: cprint("PyNORX 64-" + str(case.R) + "-" + str(case.L) + " Decrypt Pass!", 'green');

if (__name__ == "__main__"):
    RUN_TESTS();
