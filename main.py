# python 3.14.3

import socket
import struct
import os
from threading import Thread

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout


def get_stun_external_address(sock: socket.socket, stun_server="stun.l.google.com", stun_port=19302, timeout=5) -> tuple[str, int]:
	"""
	Определяет внешний IP и порт через STUN-сервер.
	Поддерживает IPv4 и IPv6 (только стандартная библиотека Python).
	"""
	# Transaction ID (12 случайных байт)
	tid = os.urandom(12)
	
	# STUN Header: Type(2) | Length(2) | Magic Cookie(4) | Transaction ID(12)
	# 0x0001 = Binding Request, Length = 0
	request = struct.pack('!HHI12s', 0x0001, 0, 0x2112A442, tid)

	sock.settimeout(timeout)
	try:
		sock.sendto(request, (stun_server, stun_port))
		response, _ = sock.recvfrom(1024)
	except:
		print(stun_server, stun_port)
		raise
	
	if len(response) < 20:
		raise RuntimeError("Слишком короткий ответ от STUN-сервера")

	# Парсим заголовок ответа
	msg_type, msg_len, magic, resp_tid = struct.unpack('!HHI12s', response[:20])
	if magic != 0x2112A442 or resp_tid != tid:
		raise RuntimeError("Неверный ответ: магическое число или ID транзакции не совпадают")

	# Маска для XOR-декодирования IPv6 (Magic Cookie + Transaction ID = 16 байт)
	xor_mask_ipv6 = struct.pack('!I', 0x2112A442) + tid

	offset = 20
	while offset < 20 + msg_len:
		attr_type, attr_len = struct.unpack('!HH', response[offset:offset+4])
		offset += 4
		val = response[offset:offset+attr_len]
		# Выравнивание атрибута до 4 байт (RFC 5389)
		offset += (attr_len + 3) & ~3

		# 0x0020 = XOR-MAPPED-ADDRESS, 0x0001 = MAPPED-ADDRESS (fallback)
		if attr_type in (0x0020, 0x0001):
			if len(val) < 8:
				continue

			# Согласно RFC 5389: байт 0 - резерв (0x00), байт 1 - семейство адресов
			family = val[1]
			port_raw = struct.unpack('!H', val[2:4])[0]
			is_xor = (attr_type == 0x0020)

			if family == 0x01:  # IPv4
				if len(val) < 8:
					continue
				ip_raw = struct.unpack('!I', val[4:8])[0]
				
				if is_xor:
					ip_raw ^= 0x2112A442
					port = port_raw ^ 0x2112
				else:
					port = port_raw
					
				ip = f"{(ip_raw >> 24) & 0xFF}.{(ip_raw >> 16) & 0xFF}.{(ip_raw >> 8) & 0xFF}.{ip_raw & 0xFF}"
				return ip, port

			elif family == 0x02:  # IPv6
				if len(val) < 20:
					continue
				ip_bytes = val[4:20]
				
				if is_xor:
					# Побайтовое XOR с 16-байтовой маской
					ip_bytes = bytes(a ^ b for a, b in zip(ip_bytes, xor_mask_ipv6))
					port = port_raw ^ 0x2112
				else:
					port = port_raw
					
				# Конвертация 16 байт в строку IPv6
				ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
				return ip, port
			else:
				raise RuntimeError(f"Неподдерживаемое семейство адресов: {family:#x}")

	raise RuntimeError("Атрибут с адресом (XOR-MAPPED-ADDRESS / MAPPED-ADDRESS) не найден в ответе")


def get_my_code(stuns: list[tuple[str, int]]) -> str:
	host: str | None = None
	port: int | None = None

	for sh, sp in stuns:
		ip, ext_port = get_stun_external_address(sock, sh, sp)
		if host is None:
			host = ip
		elif ip != host:
			raise Exception('Айпи поменялся во промя тестирования')
		
		if port is None:
			port = ext_port
		elif ext_port != port:
			raise Exception('Порт поменялся во время тестирования')

	if host is None:
		raise Exception('Хост не получен')
	if port is None:
		raise Exception('Порт не получен')

	return to_hex((host, port))


def to_hex(addr: tuple[str, int]) -> str:
	'''Возвращает строку содержащую 6 байт в формате HEX'''
	res = ''
	for x in addr[0].split('.', 3):
		res += f'{hex(int(x)).upper()[2:]:0>2}'
	res += f'{hex(addr[1]  % 256).upper()[2:]:0>2}'
	res += f'{hex(addr[1] // 256).upper()[2:]:0>2}'
	return res


def from_hex(addr: str) -> tuple[str, int]:
	'''Принимает строку содержащую 6 байт в формате HEX'''
	if len(addr) != 12:
		raise Exception('HEX Адрес неверной длинны')
	addr = addr.upper()
	for s in addr:
		if s not in tuple('0123456789ABCDEF'):
			raise Exception('HEX Адрес содержит неверные символы')
	host = '.'.join([str(int(addr[i*2:i*2+2], 16)) for i in range(4)])

	# 0,1  2,3  4,5  6,7   8,9  10,11 
	port = int(addr[8:10], 16) + int(addr[10:12], 16) * 256
	return host,port


if __name__ == "__main__":
	stuns = [
		("stun.sipnet.ru",  3478),
		("stun.zadarma.com", 3478),
	]

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind(('0.0.0.0', 55555))

	try:
		code = get_my_code(stuns)
		print(f'✅ Код подключения: {code}')
	except Exception as e:
		print(f"❌ Ошибка: {e}")
		exit(0)

	users: list[tuple[str, int]] = []

	while True:
		try:
			code = input('Введите код подключения >')
			addr = from_hex(code)
			users.append(addr)
			break
		except KeyboardInterrupt:
			exit(0)
		except Exception as e:
			print(f"❌ Ошибка: {e}")

	running = True
	def recv_message():
		global running
		while running:
			try:
				data, oa = sock.recvfrom(1024)
				other_addr = (str(oa[0]), int(oa[1]), )
				if other_addr not in users:
					users.append(other_addr)
				rele = f'{to_hex(other_addr)}: '.encode('UTF-8') + data
				message = data.decode('UTF-8')
				print(f'{to_hex(tuple(oa))}: {message}')
				for user in users:
					if user == other_addr:
						continue
					try:
						sock.sendto(rele, user)
					except:
						pass 
			except socket.timeout:
				pass
			except Exception as e:
				print(f"❌ Ошибка: {e}")
				running = False

	Thread(target=recv_message, daemon=True).start()
	session = PromptSession()
	while running:
		try:
			with patch_stdout():
				message: str = session.prompt("Вы > ")
		except KeyboardInterrupt:
			exit(0)
		except Exception as e:
				print(f"❌ Ошибка: {e}")
				running = False
				continue

		if (message == 'exit') or (message == 'выход'):
			running = False
			continue

		data = message.encode('UTF-8', errors='ignore')
		if len(data) > 1024:
			print("❌ Ошибка: Слишком длинное сообщение")
			continue

		try:
			for user in users:
				sock.sendto(data, user)
		except Exception as e:
			print(f"❌ Ошибка: {e}")
			running = False
			continue 

	sock.close()
