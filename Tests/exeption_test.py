def test_func(flag : int):
    try:
        if flag == 1:
            raise TimeoutError
        elif flag == -1:
            raise ConnectionResetError
        elif flag == 0:
            raise ConnectionError
    except ConnectionError as e:
        if type(e) is TimeoutError:
            print("TimeoutError was cought by ConnectionError exception!")
        elif type(e) is ConnectionResetError:
            print("ConnectionResetError was cought by ConnectionError exception!")
        else:
            print("Exception was NOT TimeoutError!")
    
    print("After exception handling.")

test_func(-1)

if(issubclass(TimeoutError, ConnectionError)):
    print("TimeoutError is a subclass of ConnectionError!")
