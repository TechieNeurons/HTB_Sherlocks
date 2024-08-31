import os

key = b'bhUlIshutrea98liOp'

for name in os.listdir('./'):
    if name.endswith('.24bes'):
        cpt = 0
        with open(f'./{name}', 'rb') as rf:
            with open(f'./decrypted/{name[:-6]}', 'wb') as wf:
                while (byte := rf.read(1)):
                    wf.write(bytes([byte[0] ^ key[cpt % len(key)]]))
                    cpt += 1
        rf.close()
        wf.close()
        print(f'file {name} decrypted!')