import os,aes256,rsa_lib,rsa,hashlib
def ra_encrypt(r_file_name,block_size,pub_key):
	(path,filename) = os.path.split(r_file_name)
	if path:
		path=path+"\\"
	md5=hashlib.md5()
	w_file_name=path+str(int(time.time()*1000))+".ra.tmp"
	w=open(w_file_name, 'wb')
	r=open(r_file_name, 'rb')
	#开始处理头
	pwd1=aes256.get_random_key()
	pwd2=aes256.get_random_key()
	rsa_crypted=rsa.encrypt(pwd1+pwd2,pub_key)
	rsa_size=len(rsa_crypted)
	file_name_size=len(filename)
	head=bytes("RA",encoding='utf-8')+block_size.to_bytes(4, byteorder='big')+rsa_size.to_bytes(2, byteorder='big')+rsa_crypted
	md5.update(head)
	w.write(head)
	#头写入完毕
	#开始处理第一部分加密共512个字节
	data=r.read(511-file_name_size)
	first_block=file_name_size.to_bytes(1, byteorder='big')+bytes(filename,encoding='utf-8')+data
	first_block=aes256.aes_cbc_encrypt(first_block,pwd1)
	md5.update(first_block)
	w.write(first_block)
	#第一部分加密处理&写入完毕
	#第二部分(主部分)加密&处理写入开始
	data=r.read(block_size)
	while data:
		data=aes256.aes_cbc_encrypt(data,pwd2)
		md5.update(data)
		w.write(data)
		data=r.read(block_size)
	r.close()
	w.close()
	md5_value=md5.hexdigest()
	os.rename(w_file_name,path+md5_value)
	return md5_value
def ra_decrypt(r_file_name,prv_key):
	(path,filename) = os.path.split(r_file_name)
	if path:
		path=path+"\\"
	md5=hashlib.md5()
	r=open(r_file_name, 'rb')
	#读入头
	data=r.read(8)
	if data[0:2].decode()!="RA":
		return("该文件不是RSA-AES加密文件")
	block_size=int.from_bytes(data[2:6],byteorder='big', signed=False)
	rsa_size=int.from_bytes(data[6:8],byteorder='big', signed=False)
	#读入加密的rsa数据
	data=r.read(rsa_size)
	passwd=rsa.decrypt(data,prv_key)
	pwd1=passwd[0:32]
	pwd2=passwd[32:64]
	data=r.read(544)
	data=aes256.aes_cbc_decrypt(data,pwd1)
	file_name_size=int.from_bytes(data[0:1],byteorder='big', signed=False)
	filename=data[1:1+file_name_size].decode("utf-8")
	w_file_name=path+filename
	if os.path.exists(w_file_name):
		return("文件："+w_file_name+"已存在，请删除或重命名原文件")
	w=open(w_file_name, 'wb')
	w.write(data[1+file_name_size:])
	data=r.read(block_size+32)
	while data:
		data=aes256.aes_cbc_decrypt(data,pwd2)
		w.write(data)
		data=r.read(block_size+32)
	r.close()
	w.close()
