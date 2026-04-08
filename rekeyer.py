class RekeyStates:
    REKEY_NONE = 0x00
    REKEY_INIT = 0x01
    REKEY_REPLY = 0x02
    REKEY_SWITCH = 0x03
    REKEY_SWITCH_ACK = 0x04
    REKEY_FAIL = 0x05

    @staticmethod
    def is_valid(rekey_flag : int):
        if rekey_flag in range(RekeyStates.REKEY_NONE, RekeyStates.REKEY_FAIL + 1):
            return True
        return False


class Rekeyer:
    __current_state : int

    def __init__(self, state : int) -> None:
        Rekeyer.__current_state = state
    
    def handle_message(self, message : bytes, is_initiator : bool):
        if is_initiator == True:
            pass
        else:
            pass

    def init_rekey(self):
        pass
    def handle_reply(self):
        pass
    def handle_switch(self):
        pass
    def handle_switch_ack(self):
        pass
    def handle_fail(self):
        pass
    

class RekeyInitiator(Rekeyer):
    def __init__(self, state : int) -> None:
        super().__init__(state)

    def handle_message(self, message : bytes, is_initiator = True):
        return super().handle_message(message, is_initiator)


class RekeyReplier(Rekeyer):
    def __init__(self, state : int) -> None:
        super().__init__(state)

    def handle_message(self, message : bytes, is_initiator = False):
        return super().handle_message(message, is_initiator)

        