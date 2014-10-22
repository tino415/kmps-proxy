import time

def controllMessage(function):
    if not hasattr(controllMessage, "start_time"):
        controllMessage.start_time = time.time()

    def wrappe(*args, **kvargs):
        exec_time =  time.time() - controllMessage.start_time
        print "[",exec_time,"] - called {0}".format(function.__name__)
        return function(*args, **kvargs)

    return wrappe

