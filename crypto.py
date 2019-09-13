"""
Created on Fri Aug 23 19:31:29 2019

@author: Root
"""

from PIL import Image
import binascii
import argparse
import base64
import getpass
from Crypto.Cipher import AES
#import Crypto as crypto

def rgb2hex(r, g, b):
	return '#{:02x}{:02x}{:02x}'.format(r, g, b)

def hex2rgb(hexcode):
	hexcode = hexcode[1:]
	return tuple(int(hexcode[i:i+2], 16) for i in (0, 2, 4)) #tuple(map(ord, hexcode[1:].decode('hex')))

def str2bin(message):
	binary = bin(int(binascii.hexlify(message), 16))
	return binary[2:]

def bin2str(binary):
	message = binascii.unhexlify('%x' % (int('0b'+binary,2)))
	return message

def encode(hexcode, digit):
	if hexcode[-1] in ('0','1', '2', '3', '4', '5'):
		hexcode = hexcode[:-1] + digit
		return hexcode
	else:
		return None

def decode(hexcode):
	if hexcode[-1] in ('0', '1'):
		return hexcode[-1]
	else:
		return None

def hide(filename, message):
	img = Image.open(filename)
	binary = str2bin(message) + '1111111111111110'
	if img.mode in ('RGBA'):
		img = img.convert('RGBA')
		datas = img.getdata()
		newData = []
		digit = 0
		temp = ''
		for item in datas:
			if (digit < len(binary)):
				newpix = encode(rgb2hex(item[0],item[1],item[2]),binary[digit])
				if newpix is None:
					newData.append(item)
				else:
					r, g, b = hex2rgb(newpix)
					newData.append((r,g,b,255))
					digit += 1
			else:
				newData.append(item)
		img.putdata(newData)
		img.save(filename, "PNG")
		return "Completed!"

	return "Incorrect Image Mode, Couldn't Hide"

def retr(filename):
	img = Image.open(filename)
	binary = ''
	if img.mode in ('RGBA'):
		img = img.convert('RGBA')
		datas = img.getdata()
		for item in datas:
			digit = decode(rgb2hex(item[0],item[1],item[2]))
			if digit == None:
				pass
			else:
				binary = binary + digit
				if binary[-16:] == '1111111111111110':
					print ("Success! Encrypted message is : ")
					return bin2str(binary[:-16])
		return bin2str(binary)
	return "Incorrect Image Mode, Couldn't Retrieve"

def Main():
	parser = argparse.ArgumentParser()

	# input json
	parser.add_argument('--path', default='/workspace/test.png', help = 'Target Picture Path to hide text')
	parser.add_argument('--dest', default='/workspace/test.png', help='target picture path to retrieve text')
	parser.add_argument('--hide', default=None, help='target picture path to retrieve text')
	parser.add_argument('--retrieve', default=True, help='target picture path to retrieve text')
	args = parser.parse_args()

	if not args.hide is None:
		text = input("Enter a message to hide: ")
		password=getpass.getpass()
		#password = raw_input("Enter your password: ")
		cipher = AES.new(password.rjust(16), AES.MODE_ECB)
		encoded = base64.b64encode(cipher.encrypt( text.rjust(32) ))
		print(encoded, type(encoded))
		print(hide(args.path, encoded))

	elif not args.retrieve is None:
		password=getpass.getpass()
		#password = raw_input("Enter your password: ")
		cipher = AES.new(password.rjust(16),AES.MODE_ECB)
		decoded = cipher.decrypt(base64.b64decode(retr(args.dest)))
		print(decoded.strip())

	else:
		print(parser.usage)

if __name__ == '__main__':
	Main()
