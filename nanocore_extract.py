import codecs
import ctypes
import sys
import pefile

def BinaryToString(hexstr):
    bstr = codecs.decode(hexstr[2:], 'hex')
    return codecs.decode(bstr, 'UTF-8')

def assert_success(success):
	if not success:
		print(ctypes.FormatError())

def decrypt(key, data):
	data = codecs.decode(data[2:], 'hex')
	if type(key) != bytes:
		key = key.encode()
	a32 = ctypes.oledll.LoadLibrary('advapi32.dll')
	hproc = ctypes.c_void_p()
	success = a32.CryptAcquireContextA(ctypes.byref(hproc), 0, 0, 
					   24, 0xf0000000)
	assert_success(success)
	hcrypthash = ctypes.c_void_p()
	success = a32.CryptCreateHash(hproc, 0x00008003, 0, 0, 
			    	      ctypes.byref(hcrypthash))
	assert_success(success)
	tbuff = ctypes.create_string_buffer(key)
	tbuff_len = ctypes.c_int(len(key))
	success = a32.CryptHashData(hcrypthash, tbuff, tbuff_len, 1)
	assert_success(success)
	vcryptkey = ctypes.c_void_p()
	success = a32.CryptDeriveKey(hproc, 0x00006610, hcrypthash, 
				     0x00000001,
			   	     ctypes.byref(vcryptkey))
	assert_success(success)
	tbuff = ctypes.create_string_buffer(data, len(data)+1000)
	tbuff_len = ctypes.c_int(len(data))
	success = a32.CryptDecrypt(vcryptkey, 0, 1, 0, tbuff,
			 	   ctypes.byref(tbuff_len))
	assert_success(success)
	plaintext = tbuff.raw[:tbuff_len.value]
	return plaintext

def get_resources(pe_name):
	pe = pefile.PE(pe_name)
	entries = []
	rsc_struct = {}
	for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
		for entry in rsrc.directory.entries:
			if entry.name != None and entry.name.string != b'SCRIPT':
				entries.append(entry)
	for entry in entries:
		off = entry.directory.entries[0].data.struct.OffsetToData
		size = entry.directory.entries[0].data.struct.Size
		name = entry.name.string.decode('UTF-8')
		rsc_struct[name] = pe.get_memory_mapped_image()[off:off+size]
	return rsc_struct

def find_key(key_list, key_word):
	for key in key_list:
		if key[-1] == key_word:
			return key
	return None

def convert_dat(rsc_struct):
	keys = list(rsc_struct.keys())
	dat = rsc_struct[find_key(keys, '1')]
	dat += rsc_struct[find_key(keys, '2')]
	dat += rsc_struct[find_key(keys, '3')]
	return dat

if __name__ == '__main__':
	if len(sys.argv) < 3:
		print('Usage: python nanocore_extract.py <sample.exe> <key>')
		exit()
	key = sys.argv[2]
	sample_name = sys.argv[1]
	rsc_struct = get_resources(sample_name)
	dat = convert_dat(rsc_struct)
	dec_dat = decrypt(key, dat)
	print('All went well, writing to ' + sample_name+'.out')
	f = open(sample_name+'.out', 'wb')
	f.write(dec_dat)
	f.close()
