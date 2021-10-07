import sys
from capstone import *

if len(sys.argv) < 2:
    print('Error: need fine name argument')
    exit()

filename = sys.argv[1]
file = open(filename, 'rb')
byteArray = []

try:
    byte = file.read(1)
    while byte != b'':
        byte = file.read(1)
        byteArray.append(byte)
finally:
    file.close()

potentialGadgets = []

for gadgetSize in range(1, 12):
    for index, byte in enumerate(byteArray):
        if byte == b'\xc3':
            potentialGadgets.append((byteArray[index - gadgetSize : index + 1], index - gadgetSize))

outFile = open('potentialGadgets.txt', 'w')
md = Cs(CS_ARCH_X86, CS_MODE_32)
count = 0
for gadget in potentialGadgets:
    code = b''.join(gadget[0])
    offset = gadget[1]

    instructions = []
    for i in md.disasm(code, 0x0):
        instructions.append(i)
    if len(instructions) > 1 and instructions[len(instructions) - 1].mnemonic == 'ret':
        outFile.write('Offset 0x%s:\n' % format(offset+1, 'x'))
        for i in instructions:
            outFile.write('{} {}\t{}\n'.format(i.mnemonic, i.op_str, '('+''.join([format(c, 'x') for c in i.bytes])+')'))
        count += 1
        outFile.write('\n')

outFile.close()

print('Found {} gadgets.'.format(count))
