import numpy as np
from Lookups import gmul,lookup,reverse_lookup,round_constant,mix_matrix,inv_mix_matrix
import codecs
class AES():
    def __init__(self,key:str):
        self.key = bytearray.fromhex(key)
        self.keys = self._expand_key(bytearray.fromhex(key))
    def _expand_key(self,key):
        keys = np.zeros(shape=(11, 4, 4), dtype="uint8")
        keys[0] = np.array([i for i in key], "uint8").reshape((4, 4))
        for k in range(10):
            for i in range(4):
                if i == 0:
                    t4,t1,t2,t3 = keys[k][i+3]
                    t1 = keys[k][i][0] ^ (lookup(t1)^round_constant(k))
                    t2 = keys[k][i][1] ^ (lookup(t2)^0)
                    t3 = keys[k][i][2] ^ (lookup(t3)^0)
                    t4 = keys[k][i][3] ^ (lookup(t4)^0)
                    keys[k+1][0] = (t1,t2,t3,t4)
                else:
                    t1 = keys[k][i][0] ^ keys[k + 1][i-1][0]
                    t2 = keys[k][i][1] ^ keys[k + 1][i-1][1]
                    t3 = keys[k][i][2] ^ keys[k + 1][i-1][2]
                    t4 = keys[k][i][3] ^ keys[k + 1][i-1][3]

                keys[k + 1][i] = (t1, t2, t3, t4)
        return (keys)

    def _pad(self,message:bytearray):
        message.append(0x80)
        while len(message)%16 != 0:
            message.append(0)
        return message
    def _depad(self,message:bytearray):
        return message[:message.rindex(0x80)]

    def _make_blocks(self,message:bytearray):
        message_block = np.array([i for i in message], "uint8").reshape((len(message) // 16,4, 4))
        return message_block

    def _add_round_key(self,key:np.array,block:np.array):
        temp = np.zeros(shape=(4, 4), dtype="uint8")
        for c in range(4):
            for r in range(4):
                temp[c][r] = key[c][r] ^ block[c][r]
        return temp

    def _sub_bytes(self,block:np.array):
        temp = np.zeros(shape=(4, 4), dtype="uint8")
        for c in range(4):
            for r in range(4):
                temp[c][r] = lookup(block[c][r])
        return temp
    def _inv_sub_bytes(self,block:np.array):
        temp = np.zeros(shape=(4, 4), dtype="uint8")
        for c in range(4):
            for r in range(4):
                temp[c][r] = reverse_lookup(block[c][r])
        return temp

    def _shift_rows(self,block:np.array):
        temp = np.zeros(shape=(4, 4), dtype="uint8")
        temp[:,0] = block[:,0]
        temp[:3,1] = block[1:4,1]
        temp[3, 1] = block[0, 1]
        temp[:2,2] = block[2:4,2]
        temp[2:4, 2] = block[:2, 2]
        temp[1:4, 3] = block[0:3, 3]
        temp[0, 3] = block[3, 3]
        return temp

    def _inv_shift_rows(self,block:np.array):
        temp = np.zeros(shape=(4, 4), dtype="uint8")
        temp[:,0] = block[:,0]
        temp[1:4,1] = block[:3,1]
        temp[0, 1] = block[3, 1]
        temp[2:4,2] = block[:2,2]
        temp[:2, 2] = block[2:4, 2]
        temp[0:3, 3] = block[1:4, 3]
        temp[3, 3] = block[0, 3]
        return temp

    def _mix_colums(self,block):
        temp = np.zeros(shape=(4, 4), dtype="uint8")
        block_T = np.transpose(block)
        for i in range(4):
          for j in range(4):
            for k in range(4):
                temp[j,i] = temp[j,i] ^ gmul(mix_matrix[i,k],block_T[k,j])
        return temp

    def _inv_mix_colums(self,block):
        temp = np.zeros(shape=(4, 4), dtype="uint8")
        block_T = np.transpose(block)
        for i in range(4):
          for j in range(4):
            for k in range(4):
                temp[j,i] = temp[j,i] ^ gmul(inv_mix_matrix[i,k],block_T[k,j])
        return temp

    def _encrypt_block(self,block, keys):
        temp = self._add_round_key(keys[0], block)
        for i in range(9):
            temp = self._sub_bytes(temp)
            temp = self._shift_rows(temp)
            temp = self._mix_colums(temp)
            temp = self._add_round_key(keys[i+1],temp)
        temp = self._sub_bytes(temp)
        temp = self._shift_rows(temp)
        temp = self._add_round_key(keys[10], temp)
        return temp

    def _dencrypt_block(self,block, keys):
        temp = self._add_round_key(keys[10], block)
        temp = self._inv_shift_rows(temp)
        temp = self._inv_sub_bytes(temp)
        for i in range(9):
            temp = self._add_round_key(keys[9 - i], temp)
            temp = self._inv_mix_colums(temp)
            temp = self._inv_shift_rows(temp)
            temp = self._inv_sub_bytes(temp)
        temp = self._add_round_key(keys[0], temp)
        return temp
    def encrypt(self,message:str):
        blocks = self._make_blocks(self._pad(bytearray(message)))
        for i,block in enumerate(blocks):
            blocks[i] = self._encrypt_block(block,self.keys)
        return codecs.encode(codecs.decode(bytearray(blocks.flatten().tolist()).hex(),"HEX"),"base64")
    def dencrypt(self,message:str):
        blocks = self._make_blocks(bytearray(codecs.decode(message,"base64")))
        for i, block in enumerate(blocks):
            blocks[i] = self._dencrypt_block(block, self.keys)
        return bytes(self._depad(bytearray(blocks.flatten().tolist())))
