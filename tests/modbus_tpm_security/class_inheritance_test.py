class FirstClass:
    __main_attribute : int
    __second_attribute : str

    def __init__(self, value_int : int, value_str : str) -> None:
        self.__main_attribute = value_int
        self.__second_attribute = value_str

    def do_something(self):
        print("Doing something...")

    def get_main_attribute(self):
        return self.__main_attribute
    
    def get_second_attribute(self):
        return self.__second_attribute


class Subclass(FirstClass):
    def __init__(self, value: int) -> None:
        super().__init__(value, str(value))

    def get_main_attribute(self):
        return super().get_main_attribute()
    
    def get_second_attribute(self):
        return super().get_second_attribute()
    

obj = Subclass(22)

obj.do_something()
print(obj.get_main_attribute())
print(obj.get_second_attribute())

print("\n--------------------------\n")
list1 = list()
list1.append("abc")
list1.append("ABC")
list1.append("xyz")
list1.append("XYZ")

list1_str = str(list1)

print(list1_str)