import json
import copy
import time
import threading
import sys
import datetime
import base64
import os
import socket
import thread
import email.utils as eut

blocked_ports = []
blacklist = "blacklist.txt"
authentication = "authentication.txt"
max_ports = 10
cacheDirectory = "./cache"
cache_buf = 3
buf_size = 4096
cache_occurence = 2
admins = []

if len(sys.argv) == 1:
	print "argument missing: python %s <proxy_port>" % sys.argv[0]
	raise SystemExit

try:
	PortNumber = sys.argv[1]
	proxy_port = int(PortNumber)
	print PortNumber
except:
	print "Please provide proper (an integer) port number."
	raise SystemExit

if os.path.isdir(cacheDirectory):
	pass;
else:
	os.makedirs(cacheDirectory)

f = open(authentication, "rb")
data = ""
chunklen=1;
while chunklen:
	chunk = f.read()
	chunklen=len(chunk)
	data += chunk
f.close()
admin = data.splitlines()
print admin
for d in admin:
	admins.append(base64.b64encode(d))

f = open(blacklist, "rb")
data = ""
chunklen = 1
while chunklen:
	chunk = f.read()
	chunklen=len(chunk)
	data += chunk
f.close()
blocked_ports = data.splitlines()
print blocked_ports

for file in os.listdir(cacheDirectory):
	os.remove(cacheDirectory + "/" + file)

def acquire_access(fileurl):
	if fileurl not in locks:
		lock = threading.Lock()
		locks[fileurl] = lock
	elif fileurl in locks:
		lock = locks[fileurl]
	lock.acquire()

def break_access(fileurl):
	if fileurl not in locks:
		print "Lock problem is present."
		sys.exit()
	elif fileurl in locks:
		lock = locks[fileurl]
		lock.release()

def submit_log(client_addr, fileurl):
	try:
		fileurl = fileurl.replace("/", "__")
		if fileurl not in logs:
			logs[fileurl] = []
		logs[fileurl].append({
				"datetime" : time.strptime(time.ctime(), "%a %b %d %H:%M:%S %Y"),
				"client" : json.dumps(client_addr),
			})
	except:
		print "submit Error"
		return False

def cache_currentInfo(fileurl):

	if fileurl[0] is "/":
		fileurl = fileurl.replace("/", "", 1)
	else:
		pass
	cache_path = cacheDirectory + "/" + fileurl.replace("/", "__")
	print cache_path

	if ~os.path.isfile(cache_path):
		return cache_path, None
	last_mtime = time.strptime(time.ctime(os.path.getmtime(cache_path)), "%a %b %d %H:%M:%S %Y")
	print last_mtime
	return cache_path, last_mtime

def cache_space(fileurl):
	cache_files = os.listdir(cacheDirectory)
	if cache_buf > len(cache_files):
		return
	for file in cache_files:
		acquire_access(file)
	
	last_mtime = min(logs[file][-1]["datetime"] for file in cache_files)
	file_to_del = [file for file in cache_files if logs[file][-1]["datetime"] == last_mtime][0]
	print file_to_del

	os.remove(cacheDirectory + "/" + file_to_del)
	for file in cache_files:
		break_access(file)

def parsingDetails(client_addr, client_data):
	try:
		lines = client_data.splitlines()
		while True:
			if lines[len(lines)-1] != '':
				break
			lines.remove('')
		line1_tokens = lines[0].split()
		url = line1_tokens[1]

		url_pos = url.find("://")
		protocol = "http"
		if url_pos != -1:
			protocol = url[:url_pos]
			url = url[(url_pos+3):]
		print protocol
		temp=url.find("/")
		if url.find("/") == -1:
			temp = len(url)
		if url.find(":") > temp or url.find(":")==-1:
			server_port = 80
			server_url = url[:temp]
		elif url.find(":") <= temp and url.find(":") != -1:
			server_port = int(url[(url.find(":")+1):temp])
			server_url = url[:url.find(":")]

		auth_line = [ line for line in lines if "Authorization" in line]
		auth_b64 = None
		if len(auth_line):
			auth_b64 = auth_line[0].split()[2]
		
		line1_tokens[1] = url[temp:]
		lines[0] = ' '.join(line1_tokens)
		newline="\r\n"
		client_data = newline.join(lines) + newline+newline
		print client_data

		return {
			"server_port" : server_port,
			"server_url" : server_url,
			"total_url" : url,
			"client_data" : client_data,
			"protocol" : protocol,
			"method" : line1_tokens[0],
			"auth_b64" : auth_b64,
		}

	except :
		print "parsingDetails Error"
		print
		return None

def get_method(client_socket, client_addr, details):

	try:
		cache_path = details["cache_path"]
		last_mtime = details["last_mtime"]
		client_data = details["client_data"]
		do_cache = details["do_cache"]

		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket.connect((details["server_url"], details["server_port"]))
		server_socket.send(details["client_data"])

		reply = server_socket.recv(buf_size)

		if "304 Not Modified" or last_mtime not in reply:
			if ~do_cache:
				print "Without caching serving %s to %s" % (cache_path, str(client_addr))
				while len(reply):
					client_socket.send(reply)
					reply = server_socket.recv(buf_size)
					print reply
				client_socket.send("\r\n\r\n")
			elif do_cache:
				print "Caching file while serving %s to %s" % (cache_path, str(client_addr))
				cache_space(details["total_url"])
				acquire_access(details["total_url"])
				f = open(cache_path, "w+")
				while len(reply):
					client_socket.send(reply)
					f.write(reply)
					reply = server_socket.recv(buf_size)
				f.close()
				break_access(details["total_url"])
				client_socket.send("\r\n\r\n")

		elif "304 Not Modified" and last_mtime in reply:
			print "returning cached file %s to %s" % (cache_path, str(client_addr))
			acquire_access(details["total_url"])
			f = open(cache_path, 'rb')
			chunk = f.read(buf_size)
			while chunk:
				client_socket.send(chunk)
				chunk = f.read(buf_size)
			f.close()
			break_access(details["total_url"])

		server_socket.close()
		client_socket.close()
		return

	except:
		server_socket.close()
		client_socket.close()
		print "get request error"
		return


def post_method(client_socket, client_addr, details):
	try:
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket.connect((details["server_url"], details["server_port"]))
		server_socket.send(details["client_data"])
		print server_socket

		while True:
			reply = server_socket.recv(buf_size)
			if ~len(reply):
				break
			elif len(reply):
				client_socket.send(reply)

		server_socket.close()
		print cli_socket
		client_socket.close()
		return

	except:
		server_socket.close()
		client_socket.close()
		print "post request error"
		return

def handle_one_request_(client_socket, client_addr, client_data):

	details = parsingDetails(client_addr, client_data)
	if not details:
		print "No details exist."
		client_socket.close()
		return

	block_status = True
	if details["auth_b64"] in admins:
		block_status = False
	if not details["auth_b64"]:
		block_status = True
	if not (details["server_url"] + ":" + str(details["server_port"])) in blocked_ports:
		block_status = False

	if block_status:
		newline="\r\n"
		client_socket.send("HTTP/1.0 200 OK"+newline)
		client_socket.send("Content-Length: 11"+newline)
		client_socket.send(newline)
		print block_status
		client_socket.send("Error"+newline)
		client_socket.send(newline+newline)
		print "Block status : ", block_status

	elif details["method"] == "POST":
		post_method(client_socket, client_addr, details)

	elif details["method"] == "GET":
		acquire_access(details["total_url"])
		submit_log(client_addr, details["total_url"])
		try:
			log_arr = logs[details["total_url"].replace("/", "__")]
			do_cache = True
			if cache_occurence > len(log_arr): 
				do_cache = False
			if datetime.datetime.fromtimestamp(time.mktime(log_arr[len(log_arr)-cache_occurence]["datetime"])) + datetime.timedelta(minutes=10) < datetime.datetime.now():
				do_cache = False
		except:
			print "Caching Error"
			do_cache = False

		cache_path, last_mtime = cache_currentInfo(details["total_url"])
		break_access(details["total_url"])
		details["last_mtime"],details["cache_path"],details["do_cache"] = last_mtime,cache_path,do_cache

		if details["last_mtime"]:
			lines = details["client_data"].splitlines()
			while True:
				if lines[len(lines)-1] != '':
					break;
				lines.remove('')
			header = time.strftime("%A %B %-d %H:%M:%S ", details["last_mtime"])
			header = "If-Modified-Till-Now: " + header
			lines.append(header)
			newline="\r\n"
			details["client_data"] = newline.join(lines) + newline+newline
		get_method(client_socket, client_addr, details)


	client_socket.close()
	print client_addr, "closed"
	print

def start_proxy_server():
	try:
		socket_for_proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		socket_for_proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		socket_for_proxy.bind(('', proxy_port))
		socket_for_proxy.listen(max_ports)

		print "Providing the server with proxy at port %s on %s..." % (
			str(socket_for_proxy.getsockname()[1]),
			str(socket_for_proxy.getsockname()[0])
			)

	except:
		print "Error in start of proxy server ..."
		socket_for_proxy.close()
		raise SystemExit

	while True:
		try:
			returnValue = socket_for_proxy.accept()
			cli_socket = returnValue[0]
			cli_address = returnValue[1]
			client_data = cli_socket.recv(buf_size)

			print
			print "at time:[%s] - - with address: %s \"%s\"" % (
				str(datetime.datetime.now()),
				str(cli_address),
				client_data.splitlines()[0]
				)

			thread.start_new_thread(
				handle_one_request_,
				(
					cli_socket,
					cli_address,
					client_data
				)
			)
			print

		except KeyboardInterrupt:
			cli_socket.close()
			socket_for_proxy.close()
			break


logs = {}
locks = {}
start_proxy_server()