def controll_message(function):

	def wrapper(*args, **kwargs):
		print "\n[{0}]:\nargs:\n{1}\nkwarg:\n{2}\n".format(function.__name__, args, kwargs)
		result = function(*args, **kwargs)
		print result
		return result
	
	return wrapper
