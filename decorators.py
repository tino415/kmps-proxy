import re, logging

packet_status_filter = re.compile(".+");

logger = logging.getLogger('sip_proxy')

def controll_message(function):

	def wrapper(*args, **kwargs):
		logger.info( "\n[{0}]:\nargs:\n{1}\nkwarg:\n{2}\n".format(function.__name__, args, kwargs))
		result = function(*args, **kwargs)
		logger.info(result)
		return result
	
	return wrapper

def receive(function):
	
	def wrapper(*args, **kwargs):
		logger.info("Receiving packet from {}:\n{}\n".format(args[2], args[1]))
		function(*args, **kwargs)
	
	return wrapper

def send(function):
	
	def wrapper(*args, **kwargs):
		logger.info("Sending packet to {}:\n{}\n".format(args[2], args[1]))
		function(*args, **kwargs)
	
	return wrapper

def auth(function):
	
	def wrapper(*args, **kwargs):
		result = function(*args, **kwargs)
		if result:
			logger.info("Packet sender authorized\n")
		else:
			logger.info("Unable to authorize sender\n")
		return result
	
	return wrapper

def stop(function):
	
	def wrapper(*args, **kwargs):
		logger.info("Server is stopping\n")
		function(*args, **kwargs)
		logger.info("Server stopped\n")
	
	return wrapper

def start(function):

	def wrapper(*args, **kwargs):
		logger.info("Starting SIP server\n")
		function(*args, **kwargs)
		logger.info("Server ip_address:\t{}\n\tport:{}\n".format(args[0].ip, args[0].port))
	
	return wrapper

def register(function):
	
	def wrapper(*args, **kwargs):
		logger.info("Registering user {}\n".format(args[1].get_sending_client()))
		function(*args, **kwargs)
	
	return wrapper

def invite(function):
	
	def wrapper(*args, **kwargs):
		logger.info("User {} is inviting {} to call\n".format(
			args[1].get_sending_client(), 
			args[1].get_requested_client()))
		
		function(*args, **kwargs)
	
	return wrapper
